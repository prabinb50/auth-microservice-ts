import bcrypt from "bcrypt";
const saltRounds = 10;
import { getRefreshTokenExpiryDate, signAccessToken, signRefreshToken } from "../utils/jwt";
import { deleteRefreshToken, findRefreshToken, saveRefreshToken } from "./tokenService";
import { UserRole } from "../utils/customTypes";
import prisma from "../utils/prisma";
import logger from "../utils/logger";

// constants for account locking
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION_MINUTES = 30;

// register new user with email verification disabled by default
export const registerUser = async (email: string, password: string, role: UserRole = "USER") => {
    // hash password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // create user with emailVerified = false
    const newUser = await prisma.user.create({
        data: {
            email,
            password: hashedPassword,
            role,
            emailVerified: false,
        },
    });

    logger.info('user created in database', { 
        userId: newUser.id, 
        email: newUser.email,
        role: newUser.role 
    });

    // call email service to send verification email
    try {
        const emailServiceUrl = process.env.EMAIL_SERVICE_URL || 'http://localhost:8001';
        const response = await fetch(`${emailServiceUrl}/email/send-verification`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ userId: newUser.id, email: newUser.email })
        });

        if (!response.ok) {
            logger.error('failed to send verification email', { 
                userId: newUser.id,
                status: response.status,
                statusText: response.statusText 
            });
        } else {
            logger.info('verification email sent', { 
                userId: newUser.id, 
                email: newUser.email 
            });
        }
    } catch (error) {
        logger.error('error calling email service', { 
            error: error instanceof Error ? error.message : 'unknown',
            userId: newUser.id 
        });
    }

    return newUser;
};

// find user by id
export const findUserById = async (id: string) => {
    return prisma.user.findUnique({
        where: { id },
        select: {
            id: true,
            email: true,
            role: true,
            emailVerified: true,
            createdAt: true,
            updatedAt: true,
        },
    });
};

// find user by email
export const findUserByEmail = async (email: string) => {
    return prisma.user.findUnique({
        where: { email },
    });
};

// login user - check email verification status
export const loginUser = async (email: string, password: string) => {
    // find user
    const user = await findUserByEmail(email);
    if (!user) {
        logger.warn('login failed - user not found', { email });
        throw new Error("user not found");
    }

    // check if email is verified
    if (!user.emailVerified) {
        logger.warn('login failed - email not verified', { 
            userId: user.id, 
            email 
        });
        const error: any = new Error("please verify your email before logging in");
        error.code = "EMAIL_NOT_VERIFIED";
        throw error;
    }

    // check if account is locked
    if (user.accountLockedUntil) {
        const now = new Date();
        if (user.accountLockedUntil > now) {
            logger.warn('login failed - account locked', { 
                userId: user.id,
                lockedUntil: user.accountLockedUntil 
            });
            const error: any = new Error("account is locked due to multiple failed login attempts");
            error.lockedUntil = user.accountLockedUntil;
            throw error;
        } else {
            // lock expired, reset attempts
            await prisma.user.update({
                where: { id: user.id },
                data: {
                    failedLoginAttempts: 0,
                    accountLockedUntil: null,
                },
            });
            logger.info('account lock expired - reset', { userId: user.id });
        }
    }

    // verify password
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
        // increment failed attempts
        const newAttempts = user.failedLoginAttempts + 1;
        
        logger.warn('login failed - invalid password', { 
            userId: user.id,
            failedAttempts: newAttempts 
        });

        // check if should lock account
        if (newAttempts >= MAX_FAILED_ATTEMPTS) {
            const lockUntil = new Date();
            lockUntil.setMinutes(lockUntil.getMinutes() + LOCK_DURATION_MINUTES);
            
            await prisma.user.update({
                where: { id: user.id },
                data: {
                    failedLoginAttempts: newAttempts,
                    accountLockedUntil: lockUntil,
                },
            });
            
            logger.warn('account locked due to failed attempts', { 
                userId: user.id,
                lockUntil 
            });

            const error: any = new Error("account locked due to multiple failed login attempts");
            error.lockedUntil = lockUntil;
            throw error;
        } else {
            // just increment attempts
            await prisma.user.update({
                where: { id: user.id },
                data: {
                    failedLoginAttempts: newAttempts,
                },
            });
            
            throw new Error("invalid password");
        }
    }

    // successful login - reset failed attempts
    await prisma.user.update({
        where: { id: user.id },
        data: {
            failedLoginAttempts: 0,
            accountLockedUntil: null,
        },
    });

    logger.info('login successful - generating tokens', { 
        userId: user.id,
        role: user.role 
    });

    // generate tokens with role
    const accessToken = signAccessToken(user.id, user.role);
    const refreshToken = signRefreshToken(user.id, user.role);

    // save refresh token in db
    const expiresAt = getRefreshTokenExpiryDate();
    await saveRefreshToken(user.id, refreshToken, expiresAt);

    return { 
        accessToken, 
        refreshToken, 
        user: {
            id: user.id,
            email: user.email,
            role: user.role,
        }
    };
};

// rotate refresh token with role
export const rotateRefreshToken = async (oldToken: string) => {
    const found = await findRefreshToken(oldToken);
    if (!found) {
        logger.warn('refresh token not found in database');
        const err: any = new Error("refresh token not found");
        err.status = 401;
        throw err;
    }

    // check expiry
    const now = new Date();
    if (found.expiresAt < now) {
        await deleteRefreshToken(oldToken);
        logger.warn('refresh token expired', { userId: found.userId });
        const err: any = new Error("refresh token expired");
        err.status = 401;
        throw err;
    }

    // get user to fetch current role
    const user = await prisma.user.findUnique({
        where: { id: found.userId },
    });

    if (!user) {
        logger.error('user not found during token rotation', { 
            userId: found.userId 
        });
        const err: any = new Error("user not found");
        err.status = 404;
        throw err;
    }

    // delete old refresh token from db (rotation)
    await deleteRefreshToken(oldToken);

    logger.info('rotating refresh token', { 
        userId: user.id,
        role: user.role 
    });

    // issue new tokens with current role
    const newAccessToken = signAccessToken(user.id, user.role);
    const newRefreshToken = signRefreshToken(user.id, user.role);
    const expiresAt = getRefreshTokenExpiryDate();

    // save new refresh token
    await saveRefreshToken(user.id, newRefreshToken, expiresAt);

    return { 
        accessToken: newAccessToken, 
        refreshToken: newRefreshToken, 
        expiresAt, 
        userId: user.id 
    };
};

// logout user by deleting refresh token(s)
export const logoutUser = async (token?: string, userId?: string) => {
    if (token) {
        await deleteRefreshToken(token);
        logger.info('refresh token deleted', { token: token.substring(0, 10) + '...' });
    } else if (userId) {
        await prisma.refreshToken.deleteMany({ where: { userId } });
        logger.info('all refresh tokens deleted for user', { userId });
    }
};

// update user role (admin only)
export const updateUserRole = async (userId: string, newRole: UserRole) => {
    const user = await prisma.user.update({
        where: { id: userId },
        data: { role: newRole },
        select: {
            id: true,
            email: true,
            role: true,
            updatedAt: true,
        },
    });
    
    logger.info('user role updated', { 
        userId, 
        newRole 
    });

    return user;
};

// get all users (admin only)
export const getAllUsers = async () => {
    return prisma.user.findMany({
        select: {
            id: true,
            email: true,
            role: true,
            emailVerified: true,
            failedLoginAttempts: true,
            accountLockedUntil: true,
            createdAt: true,
            updatedAt: true,
        },
        orderBy: {
            createdAt: 'desc',
        },
    });
};

// delete user by id (admin only)
export const deleteUserById = async (userId: string) => {
    // check if user exists
    const user = await prisma.user.findUnique({
        where: { id: userId },
    });

    if (!user) {
        logger.warn('delete user failed - user not found', { userId });
        throw new Error("user not found");
    }

    // delete user (cascade will delete related tokens)
    await prisma.user.delete({
        where: { id: userId },
    });

    logger.info('user deleted', { 
        userId, 
        email: user.email 
    });

    return { message: "user deleted successfully", deletedUser: { id: user.id, email: user.email } };
};

// delete all users except admins (super admin only)
export const deleteAllNonAdminUsers = async () => {
    // delete all non-admin users
    const result = await prisma.user.deleteMany({
        where: {
            role: "USER",
        },
    });

    logger.warn('all non-admin users deleted', { 
        count: result.count 
    });

    return { 
        message: "all non-admin users deleted successfully", 
        deletedCount: result.count 
    };
};

// delete all users including admins (super admin only)
export const deleteAllUsers = async (excludeUserId?: string) => {
    // delete all users except the one performing the action
    let result;
    
    if (excludeUserId) {
        result = await prisma.user.deleteMany({
            where: {
                id: { not: excludeUserId }
            }
        });
    } else {
        result = await prisma.user.deleteMany();
    }

    logger.warn('all users deleted', { 
        count: result.count,
        excludedUserId: excludeUserId 
    });

    return { 
        message: "all users deleted successfully", 
        deletedCount: result.count 
    };
};
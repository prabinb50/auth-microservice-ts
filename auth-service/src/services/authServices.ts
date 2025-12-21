import bcrypt from "bcrypt";
const saltRounds = 10;
import { getRefreshTokenExpiryDate, signAccessToken, signRefreshToken } from "../utils/jwt";
import { deleteRefreshToken, findRefreshToken, saveRefreshToken } from "./tokenService";
import { UserRole } from "../utils/customTypes";
import prisma from "../utils/prisma";
import logger from "../utils/logger";
import { Request } from "express";
import { createSession, deactivateSession, updateSessionActivity } from "./sessionService";
import {
  logUserRegistration,
  logUserLogin,
  logLoginFailed,
  logAccountLocked,
  logAccountUnlocked,
  logTokenRefreshed,
  logRoleChanged,
  logUserDeleted,
  logUsersBulkDeleted,
} from "./auditService";

// constants for account locking
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION_MINUTES = 30;

// register new user with email verification disabled by default
export const registerUser = async (email: string, password: string, role: UserRole = "USER", req: Request) => {
    // hash password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // create user with emailVerified = false
    const newUser = await prisma.user.create({
        data: {
            email,
            password: hashedPassword,
            role,
            emailVerified: false,
            tokenVersion: 0,  
        },
    });

    logger.info('user created in database', { 
        userId: newUser.id, 
        email: newUser.email,
        role: newUser.role 
    });

    // log registration
    await logUserRegistration(newUser.id, email, req);

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
            lastLoginAt: true,
            lastLoginIp: true,
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

// login user - check email verification status and track session
export const loginUser = async (email: string, password: string, req: Request) => {
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

        // log failed login
        await logLoginFailed(user.id, email, 'email not verified', req);

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

            // log failed login
            await logLoginFailed(user.id, email, 'account locked', req);

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

            // log account unlocked
            await logAccountUnlocked(user.id, email);
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

            // log account locked
            await logAccountLocked(user.id, email, lockUntil, req);
            
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

            // log failed login
            await logLoginFailed(user.id, email, 'invalid password', req);
            
            throw new Error("invalid password");
        }
    }

    // get ip address
    const ipAddress = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() 
                      || req.headers['x-real-ip'] as string
                      || req.ip 
                      || req.socket.remoteAddress 
                      || 'unknown';

    // successful login - reset failed attempts and update last login
    await prisma.user.update({
        where: { id: user.id },
        data: {
            failedLoginAttempts: 0,
            accountLockedUntil: null,
            lastLoginAt: new Date(),
            lastLoginIp: ipAddress,
        },
    });

    logger.info('login successful - generating tokens', { 
        userId: user.id,
        role: user.role,
        ipAddress 
    });

    // log successful login
    await logUserLogin(user.id, email, req);

    // generate tokens with role and tokenVersion
    const accessToken = signAccessToken(user.id, user.role, user.tokenVersion);
    const refreshToken = signRefreshToken(user.id, user.role, user.tokenVersion);

    // save refresh token in db
    const expiresAt = getRefreshTokenExpiryDate();
    await saveRefreshToken(user.id, refreshToken, expiresAt);

    // create session
    await createSession(user.id, refreshToken, expiresAt, req);

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

// rotate refresh token with role and update session
export const rotateRefreshToken = async (oldToken: string, req: Request) => {
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
        await deactivateSession(oldToken);
        logger.warn('refresh token expired', { userId: found.userId });
        const err: any = new Error("refresh token expired");
        err.status = 401;
        throw err;
    }

    // get user to fetch current role and tokenVersion
    const user = await prisma.user.findUnique({
        where: { id: found.userId },
        select: { role: true, tokenVersion: true }
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

    // deactivate old session
    await deactivateSession(oldToken);

    logger.info('rotating refresh token', { 
        userId: found.userId,
        role: user.role,
        tokenVersion: user.tokenVersion
    });

    // log token refreshed
    await logTokenRefreshed(found.userId, req);

    // issue new tokens with current role and tokenVersion
    const newAccessToken = signAccessToken(found.userId, user.role, user.tokenVersion);
    const newRefreshToken = signRefreshToken(found.userId, user.role, user.tokenVersion);
    const expiresAt = getRefreshTokenExpiryDate();

    // save new refresh token
    await saveRefreshToken(found.userId, newRefreshToken, expiresAt);

    // update session activity
    await updateSessionActivity(oldToken);

    return { 
        accessToken: newAccessToken, 
        refreshToken: newRefreshToken, 
        expiresAt, 
        userId: found.userId 
    };
};

// logout user by deleting refresh token(s) and deactivating session
export const logoutUser = async (token?: string, userId?: string) => {
    if (token) {
        await deleteRefreshToken(token);
        await deactivateSession(token);
        logger.info('refresh token deleted and session deactivated', { 
            token: token.substring(0, 10) + '...' 
        });
    } else if (userId) {
        await prisma.refreshToken.deleteMany({ where: { userId } });
        await prisma.session.updateMany({ 
            where: { userId }, 
            data: { isActive: false } 
        });
        logger.info('all refresh tokens deleted and sessions deactivated for user', { userId });
    }
};

// update user role (admin only)
export const updateUserRole = async (userId: string, newRole: UserRole, adminId: string, req: Request) => {
    // get current user to log old role
    const currentUser = await prisma.user.findUnique({
        where: { id: userId },
        select: { role: true, email: true },
    });

    if (!currentUser) {
        throw new Error('user not found');
    }

    const oldRole = currentUser.role;

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
        newRole,
        oldRole,
        adminId 
    });

    // log role change
    await logRoleChanged(userId, currentUser.email, adminId, oldRole, newRole, req);

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
            lastLoginAt: true,
            lastLoginIp: true,
            createdAt: true,
            updatedAt: true,
        },
        orderBy: {
            createdAt: 'desc',
        },
    });
};

// delete user by id (admin only)
export const deleteUserById = async (userId: string, adminId: string, req: Request) => {
    // check if user exists
    const user = await prisma.user.findUnique({
        where: { id: userId },
    });

    if (!user) {
        logger.warn('delete user failed - user not found', { userId });
        throw new Error("user not found");
    }

    // delete user (cascade will delete related tokens and sessions)
    await prisma.user.delete({
        where: { id: userId },
    });

    logger.info('user deleted', { 
        userId, 
        email: user.email,
        adminId 
    });

    // log user deletion
    await logUserDeleted(userId, user.email, adminId, req);

    return { message: "user deleted successfully", deletedUser: { id: user.id, email: user.email } };
};

// delete all users except admins (super admin only)
export const deleteAllNonAdminUsers = async (adminId: string, req: Request) => {
    // delete all non-admin users
    const result = await prisma.user.deleteMany({
        where: {
            role: "USER",
        },
    });

    logger.warn('all non-admin users deleted', { 
        count: result.count,
        adminId 
    });

    // log bulk deletion
    await logUsersBulkDeleted(adminId, result.count, 'non-admins', req);

    return { 
        message: "all non-admin users deleted successfully", 
        deletedCount: result.count 
    };
};

// delete all users including admins (super admin only)
export const deleteAllUsers = async (excludeUserId: string, req: Request) => {
    // delete all users except the one performing the action
    const result = await prisma.user.deleteMany({
        where: {
            id: { not: excludeUserId }
        }
    });

    logger.warn('all users deleted', { 
        count: result.count,
        excludedUserId: excludeUserId 
    });

    // log bulk deletion
    await logUsersBulkDeleted(excludeUserId, result.count, 'all users', req);

    return { 
        message: "all users deleted successfully", 
        deletedCount: result.count 
    };
};
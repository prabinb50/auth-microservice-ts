import bcrypt from "bcrypt";
const saltRounds = 10;
import { PrismaClient } from "../generated/prisma";
import { getRefreshTokenExpiryDate, signAccessToken, signRefreshToken } from "../utils/jwt";
import { deleteRefreshToken, findRefreshToken, saveRefreshToken } from "./tokenService";
import { UserRole } from "../utils/customTypes";

const prisma = new PrismaClient();

// register a new user with role
export const registerUser = async (email: string, password: string, role: UserRole = "USER") => {
    // hash the password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // save to database with role
    const newUser = await prisma.user.create({
        data: {
            email,
            password: hashedPassword,
            role,
        },
    });
    return newUser;
};

// find user by id
export const findUserById = async (id: number) => {
    return prisma.user.findUnique({
        where: { id },
        select: {
            id: true,
            email: true,
            role: true,
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

// login user with role in token
export const loginUser = async (email: string, password: string) => {
    // find user
    const user = await findUserByEmail(email);
    if (!user) {
        throw new Error("user not found");
    }

    // compare passwords
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
        throw new Error("invalid password");
    }

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
        const err: any = new Error("refresh token not found");
        err.status = 401;
        throw err;
    }

    // check expiry
    const now = new Date();
    if (found.expiresAt < now) {
        await deleteRefreshToken(oldToken);
        const err: any = new Error("refresh token expired");
        err.status = 401;
        throw err;
    }

    // get user to fetch current role
    const user = await prisma.user.findUnique({
        where: { id: found.userId },
    });

    if (!user) {
        const err: any = new Error("user not found");
        err.status = 404;
        throw err;
    }

    // delete old refresh token from db (rotation)
    await deleteRefreshToken(oldToken);

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
export const logoutUser = async (token?: string, userId?: number) => {
    // if token provided, delete that token, else delete all tokens for userId
    if (token) {
        await deleteRefreshToken(token);
    } else if (userId) {
        await prisma.refreshToken.deleteMany({ where: { userId } });
    }
};

// update user role (admin only)
export const updateUserRole = async (userId: number, newRole: UserRole) => {
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
    return user;
};

// get all users (admin only)
export const getAllUsers = async () => {
    return prisma.user.findMany({
        select: {
            id: true,
            email: true,
            role: true,
            createdAt: true,
            updatedAt: true,
        },
        orderBy: {
            createdAt: 'desc',
        },
    });
};
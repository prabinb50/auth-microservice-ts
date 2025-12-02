import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
const saltRounds = 10;
import { PrismaClient } from "../generated/prisma";
import { getRefreshTokenExpiryDate, signAccessToken, signRefreshToken } from "../utils/jwt";
import { deleteRefreshToken, findRefreshToken, saveRefreshToken } from "./tokenService";

const prisma = new PrismaClient();

// register a new user
export const registerUser = async (email: string, password: string) => {
    // hash the password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // save to database
    const newUser = await prisma.user.create({
        data: {
            email,
            password: hashedPassword,
        },
    });
    return newUser;
};

// find user by id
export const findUserById = async (id: number) => {
    return prisma.user.findUnique({
        where: { id },
    });
};

// find user by email
export const findUserByEmail = async (email: string) => {
    return prisma.user.findUnique({
        where: { email },
    });
};

// login user
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

    // generate tokens
    const accessToken = signAccessToken({ userId: user.id });
    const refreshToken = signRefreshToken({ userId: user.id });

    // save refresh token in db
    const expiresAt = getRefreshTokenExpiryDate();
    await saveRefreshToken(user.id, refreshToken, expiresAt);

    return { accessToken, refreshToken, user };
};

// rotate refresh token (validate old token, delete it, create new one)
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
        // token expired. delete it (cleanup) and reject
        await deleteRefreshToken(oldToken);
        const err: any = new Error("refresh token expired");
        err.status = 401;
        throw err;
    }

    // get user id
    const userId = found.userId;

    // delete old refresh token from db (rotation)
    await deleteRefreshToken(oldToken);

    // issue new tokens
    const newAccessToken = signAccessToken({ userId });
    const newRefreshToken = signRefreshToken({ userId });
    const expiresAt = getRefreshTokenExpiryDate();

    // save new refresh token
    await saveRefreshToken(userId, newRefreshToken, expiresAt);

    return { accessToken: newAccessToken, refreshToken: newRefreshToken, expiresAt, userId };
};

// logout user by deleting refresh token(s)
export const logoutUser = async (token?: string, userId?: number) => {
    // if token provided, delete that token, otherwise delete all tokens for user
    if (token) {
        await deleteRefreshToken(token);
    } else if (userId) {
        // delete all refresh tokens for user
        await prisma.refreshToken.deleteMany({ where: { userId } });
    }
};


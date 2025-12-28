import jwt, { SignOptions } from "jsonwebtoken";
import { TokenPayload, UserRole } from "./customTypes";
import env from "../config/env";

// secrets for access and refresh tokens
const ACCESS_SECRET = env.jwt.accessSecret;
const REFRESH_SECRET = env.jwt.refreshSecret;

// token expiry durations
const ACCESS_EXPIRES = env.jwt.accessTokenExpiry;
const REFRESH_EXPIRES = env.jwt.refreshTokenExpiry;

if (!ACCESS_SECRET || !REFRESH_SECRET) {
    throw new Error("missing jwt access or refresh secrets in environment variables");
}

// generate access token with role and tokenVersion
export const signAccessToken = (userId: string, role: UserRole, tokenVersion: number): string => {
    const payload: TokenPayload = { userId, role, tokenVersion };
    return jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES } as SignOptions);
};

// generate refresh token with role and tokenVersion
export const signRefreshToken = (userId: string, role: UserRole, tokenVersion: number): string => {
    const payload: TokenPayload = { userId, role, tokenVersion };
    return jwt.sign(payload, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES } as SignOptions);
};

// verify access token
export const verifyAccessToken = (token: string): TokenPayload => {
    try {
        const decoded = jwt.verify(token, ACCESS_SECRET) as TokenPayload;
        return decoded;
    } catch (err) {
        throw new Error("invalid or expired access token");
    }
};

// verify refresh token
export const verifyRefreshToken = (token: string): TokenPayload => {
    try {
        const decoded = jwt.verify(token, REFRESH_SECRET) as TokenPayload;
        return decoded;
    } catch (err) {
        throw new Error("invalid or expired refresh token");
    }
};

// get refresh token expiry date as Date
export const getRefreshTokenExpiryDate = (): Date => {
    const val = REFRESH_EXPIRES;
    const num = parseInt(val.replace(/\D/g, ""), 10) || 7;
    
    if (val.includes("d")) {
        const d = new Date();
        d.setDate(d.getDate() + num);
        return d;
    }
    if (val.includes("h")) {
        const d = new Date();
        d.setHours(d.getHours() + num);
        return d;
    }
    if (val.includes("m")) {
        const d = new Date();
        d.setMinutes(d.getMinutes() + num);
        return d;
    }

    const d = new Date();
    d.setDate(d.getDate() + 7);
    return d;
};
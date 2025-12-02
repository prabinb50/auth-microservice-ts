import jwt, { SignOptions } from "jsonwebtoken";

// secrets for access and refresh tokens
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET as string;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET as string;

// token expiry durations
const ACCESS_EXPIRES = process.env.ACCESS_TOKEN_EXPIRES || "15m";
const REFRESH_EXPIRES = process.env.REFRESH_TOKEN_EXPIRES || "7d";

if (!ACCESS_SECRET || !REFRESH_SECRET) {
    throw new Error("missing jwt access or refresh secrets in environment variables");
}

// generate access token 
export const signAccessToken = (payload: object): string => {
    return jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES } as SignOptions);
};

// generate refresh token   
export const signRefreshToken = (payload: object): string => {
    return jwt.sign(payload, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES } as SignOptions);
};

// verify access token
export const verifyAccessToken = (token: string): any => {
    try {
        return jwt.verify(token, ACCESS_SECRET);
    } catch (err) {
        throw new Error("invalid or expired access token");
    }
};

// verify refresh token
export const verifyRefreshToken = (token: string): any => {
    try {
        return jwt.verify(token, REFRESH_SECRET);
    } catch (err) {
        throw new Error("invalid or expired refresh token");
    }
};

// get refresh token expiry date as Date
export const getRefreshTokenExpiryDate = (): Date => {
    // parse formats like '7d', '24h', '30m'
    const val = process.env.REFRESH_TOKEN_EXPIRES || "7d";

    // extract number and unit
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

    // fallback 7 days
    const d = new Date();
    d.setDate(d.getDate() + 7);
    return d;
};

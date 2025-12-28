import { Response } from "express";
import env from "../config/env";

// cookie name for refresh token
const COOKIE_NAME = env.cookie.name;
const NODE_ENV = env.nodeEnv;

export const setRefreshTokenCookie = (res: Response, token: string, expiresAt: Date) => {
    // secure only in production
    const secure = NODE_ENV === "production";

    // when frontend is on different domain, production needs sameSite none
    const sameSite: "lax" | "strict" | "none" = NODE_ENV === "production" ? "none" : "lax";

    // set cookie
    res.cookie(COOKIE_NAME, token, {
        httpOnly: true,
        secure,
        sameSite,
        expires: expiresAt,
        path: "/",
    });
};

// clear refresh token cookie
export const clearRefreshTokenCookie = (res: Response) => {
    res.clearCookie(COOKIE_NAME, { httpOnly: true, path: "/" });
};

// helper to read cookie name in controllers
export const getRefreshCookieName = (): string => COOKIE_NAME;

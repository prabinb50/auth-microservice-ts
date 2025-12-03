import { Response } from "express";

// cookie name for refresh token
const COOKIE_NAME = process.env.REFRESH_COOKIE_NAME || "jid";
const NODE_ENV = process.env.NODE_ENV || "development";

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
        path: "/auth",
    });
};

// clear refresh token cookie
export const clearRefreshTokenCookie = (res: Response) => {
    res.clearCookie(COOKIE_NAME, { httpOnly: true, path: "/auth" });
};

// helper to read cookie name in controllers
export const getRefreshCookieName = (): string => COOKIE_NAME;

import { Request, Response } from "express";
import { AuthenticatedRequest } from "../utils/customTypes";
import { registerUser, findUserByEmail, loginUser, findUserById, rotateRefreshToken, logoutUser } from "../services/authServices";
import { clearRefreshTokenCookie, getRefreshCookieName, setRefreshTokenCookie } from "../utils/cookie";
import { getRefreshTokenExpiryDate } from "../utils/jwt";

// handle user registration request
export const signUp = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        // check if required fields are missing
        // if (!email || !password) {
        //     return res.status(400).json({ message: "Email and password are required" });
        // }

        // check if user already exists
        const existingUser = await findUserByEmail(email);
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        // register user
        const user = await registerUser(email, password);
        if (!user) {
            return res.status(404).json({ message: "Could not register user, please register first" });
        }

        return res.status(201).json({ message: "User registered successfully", user });

    } catch (error) {
        console.error("Signup error:", error);
        return res.status(500).json({ message: "Registration failed", error: error instanceof Error ? error.message : "Unknown error" });
    }
};

// handle user login
export const login = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        // validate input
        // if (!email || !password) {
        //     return res.status(400).json({ message: "Email and password are required" });
        // }

        const { accessToken, refreshToken, user } = await loginUser(email, password);

        // set refresh cookie
        const expiresAt = getRefreshTokenExpiryDate();
        setRefreshTokenCookie(res, refreshToken, expiresAt);

        // return access token and basic user data
        return res.status(200).json({
            message: "login successful",
            accessToken,
            user: { id: user.id, email: user.email },
        });
    } catch (error) {
        console.error("Login error:", error);
        const message = error instanceof Error ? error.message : "Unknown error";
        return res.status(400).json({ message: "Login failed", error: message });
    }
};

// refresh handler
export const refresh = async (req: Request, res: Response) => {
    try {
        const cookieName = getRefreshCookieName();
        const refreshToken = req.cookies?.[cookieName];
        if (!refreshToken) {
            return res.status(401).json({ message: "refresh token missing" });
        }

        // rotate tokens: validate old token (in db), delete it, issue new ones
        const rotated = await rotateRefreshToken(refreshToken);

        // set new cookie
        setRefreshTokenCookie(res, rotated.refreshToken, rotated.expiresAt);

        // return new access token
        return res.status(200).json({ message: "token refreshed", accessToken: rotated.accessToken });
    } catch (err: any) {
        console.error("refresh controller error:", err);
        const status = err.status || 401;
        const message = err.message || "refresh failed";
        return res.status(status).json({ message, error: message });
    }
};

// logout handler
export const logout = async (req: Request, res: Response) => {
    try {
        const cookieName = getRefreshCookieName();
        const refreshToken = req.cookies?.[cookieName];

        // if cookie exists delete token from db
        if (refreshToken) {
            await logoutUser(refreshToken);
        }

        // clear cookie
        clearRefreshTokenCookie(res);

        return res.status(200).json({ message: "logged out successfully" });
    } catch (err: any) {
        console.error("logout controller error:", err);
        return res.status(500).json({ message: "logout failed", error: err.message || null });
    }
};

// get user by id
export const getUserById = async (req: AuthenticatedRequest, res: Response) => {
    try {
        // get user id from params
        const userId = req.params.id;

        // find user from database
        const user = await findUserById(Number(userId));
        if (!user) {
            return res.status(404).json({ message: "User not found with the given id" });
        }

        return res.status(200).json({ authenticatedUser: req.user, foundUser: user });
    } catch (error) {
        console.error("GetUserById error:", error);
        const message = error instanceof Error ? error.message : "Unknown error";
        return res.status(400).json({ message: "Failed to get user with the given ID", error: message });
    }
};




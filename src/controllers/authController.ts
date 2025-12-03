import { Request, Response } from "express";
import { AuthenticatedRequest } from "../utils/customTypes";
import { 
    registerUser, 
    findUserByEmail, 
    loginUser, 
    findUserById, 
    rotateRefreshToken, 
    logoutUser,
    updateUserRole,
    getAllUsers
} from "../services/authServices";
import { clearRefreshTokenCookie, getRefreshCookieName, setRefreshTokenCookie } from "../utils/cookie";
import { getRefreshTokenExpiryDate } from "../utils/jwt";

// handle user registration request
export const signUp = async (req: Request, res: Response) => {
    try {
        const { email, password, role } = req.body;

        // check if user already exists
        const existingUser = await findUserByEmail(email);
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        // register user with role
        const user = await registerUser(email, password, role);
        if (!user) {
            return res.status(404).json({ message: "Could not register user" });
        }

        return res.status(201).json({ 
            message: "User registered successfully", 
            user: {
                id: user.id,
                email: user.email,
                role: user.role,
            }
        });
    } catch (error) {
        console.error("Signup error:", error);
        return res.status(500).json({ 
            message: "Registration failed", 
            error: error instanceof Error ? error.message : "Unknown error" 
        });
    }
};

// handle user login
export const login = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        const { accessToken, refreshToken, user } = await loginUser(email, password);

        // set refresh cookie
        const expiresAt = getRefreshTokenExpiryDate();
        setRefreshTokenCookie(res, refreshToken, expiresAt);

        // return access token and user data with role
        return res.status(200).json({
            message: "login successful",
            accessToken,
            user: { 
                id: user.id, 
                email: user.email,
                role: user.role,
            },
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

        const rotated = await rotateRefreshToken(refreshToken);

        // set new cookie
        setRefreshTokenCookie(res, rotated.refreshToken, rotated.expiresAt);

        // return new access token
        return res.status(200).json({ 
            message: "token refreshed", 
            accessToken: rotated.accessToken 
        });
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

        // if cookie exists then delete token from db
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

// get user by id (authenticated users)
export const getUserById = async (req: AuthenticatedRequest, res: Response) => {
    try {
        // get user id from request parameters
        const userId = req.params.id;

        // find user by id from db
        const user = await findUserById(Number(userId));
        if (!user) {
            return res.status(404).json({ message: "User not found with the given id" });
        }

        return res.status(200).json({ 
            authenticatedUser: req.user, 
            foundUser: user 
        });
    } catch (error) {
        console.error("GetUserById error:", error);
        const message = error instanceof Error ? error.message : "Unknown error";
        return res.status(400).json({ 
            message: "Failed to get user with the given ID", 
            error: message 
        });
    }
};

// get current user profile
export const getProfile = async (req: AuthenticatedRequest, res: Response) => {
    try {
        if (!req.user) {
            return res.status(401).json({ message: "unauthorized" });
        }

        const user = await findUserById(req.user.userId);
        if (!user) {
            return res.status(404).json({ message: "user not found" });
        }

        return res.status(200).json({ user });
    } catch (error) {
        console.error("Get profile error:", error);
        return res.status(500).json({ message: "failed to get profile" });
    }
};

// admin: get all users
export const listAllUsers = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const users = await getAllUsers();
        return res.status(200).json({ 
            message: "users retrieved successfully",
            count: users.length,
            users 
        });
    } catch (error) {
        console.error("List users error:", error);
        return res.status(500).json({ message: "failed to retrieve users" });
    }
};

// admin: update user role
export const changeUserRole = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const { userId, role } = req.body;

        // prevent admin from changing their own role
        if (req.user?.userId === userId) {
            return res.status(400).json({ 
                message: "cannot change your own role" 
            });
        }

        const updatedUser = await updateUserRole(userId, role);

        return res.status(200).json({ 
            message: "user role updated successfully",
            user: updatedUser 
        });
    } catch (error) {
        console.error("Change role error:", error);
        return res.status(500).json({ 
            message: "failed to update user role",
            error: error instanceof Error ? error.message : "Unknown error"
        });
    }
};
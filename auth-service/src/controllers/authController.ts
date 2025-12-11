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
    getAllUsers,
    deleteUserById,
    deleteAllNonAdminUsers,
    deleteAllUsers
} from "../services/authServices";
import { clearRefreshTokenCookie, getRefreshCookieName, setRefreshTokenCookie } from "../utils/cookie";
import { getRefreshTokenExpiryDate } from "../utils/jwt";

// handle user registration
export const signUp = async (req: Request, res: Response) => {
    try {
        const { email, password, role } = req.body;

        // check if user already exists
        const existingUser = await findUserByEmail(email);
        if (existingUser) {
            return res.status(400).json({ message: "user already exists" });
        }

        // register user
        const user = await registerUser(email, password, role);
        if (!user) {
            return res.status(404).json({ message: "could not register user" });
        }

        return res.status(201).json({ 
            message: "user registered successfully. please check your email to verify your account.", 
            user: {
                id: user.id,
                email: user.email,
                role: user.role,
                emailVerified: user.emailVerified,
            }
        });
    } catch (error: any) {
        console.error("signup error:", error);
        return res.status(400).json({ 
            message: "registration failed", 
            error: error?.message || "unknown error" 
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

        return res.status(200).json({
            message: "login successful",
            accessToken,
            user: { 
                id: user.id, 
                email: user.email,
                role: user.role,
            },
        });
    } catch (error: any) {
        console.error("login error:", error);
        
        // handle email not verified
        if (error.code === "EMAIL_NOT_VERIFIED") {
            return res.status(403).json({ 
                message: "email not verified",
                error: "please verify your email before logging in. check your inbox for verification link."
            });
        }
        
        // handle account locked error
        if (error.lockedUntil) {
            return res.status(423).json({ 
                message: "account locked",
                error: "account is locked due to multiple failed login attempts",
                lockedUntil: error.lockedUntil
            });
        }
        
        const message = error instanceof Error ? error.message : "unknown error";
        return res.status(401).json({ message: "login failed", error: message });
    }
};

// refresh token handler
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

        if (refreshToken) {
            await logoutUser(refreshToken);
        }

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
        const userId = req.params.id;
        
        if (!userId || isNaN(Number(userId))) {
            return res.status(400).json({ message: "invalid user id" });
        }

        const user = await findUserById(Number(userId));
        if (!user) {
            return res.status(404).json({ message: "user not found with the given id" });
        }

        return res.status(200).json({ 
            authenticatedUser: req.user, 
            foundUser: user 
        });
    } catch (error) {
        console.error("getUserById error:", error);
        const message = error instanceof Error ? error.message : "unknown error";
        return res.status(400).json({ 
            message: "failed to get user with the given id", 
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
        console.error("get profile error:", error);
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
        console.error("list users error:", error);
        return res.status(500).json({ message: "failed to retrieve users" });
    }
};

// admin: update user role
export const changeUserRole = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const { userId, role } = req.body;

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
        console.error("change role error:", error);
        return res.status(500).json({ 
            message: "failed to update user role",
            error: error instanceof Error ? error.message : "unknown error"
        });
    }
};


// admin: delete user by id
export const deleteUser = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const userId = Number(req.params.id);
        if (isNaN(userId)) {
            return res.status(400).json({ message: "invalid user id" });
        }

        // prevent admin from deleting their own account
        if (req.user?.userId === userId) {
            return res.status(400).json({ 
                message: "cannot delete your own account" 
            });
        }

        const result = await deleteUserById(userId);

        return res.status(200).json(result);
    } catch (error) {
        console.error("delete user error:", error);
        return res.status(500).json({ 
            message: "failed to delete user",
            error: error instanceof Error ? error.message : "unknown error"
        });
    }
};

// admin: delete all non-admin users
export const deleteAllNonAdmins = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const result = await deleteAllNonAdminUsers();

        return res.status(200).json(result);
    } catch (error) {
        console.error("delete all non-admins error:", error);
        return res.status(500).json({ 
            message: "failed to delete users",
            error: error instanceof Error ? error.message : "unknown error"
        });
    }
};

// super admin: delete all users (with confirmation)
export const deleteAllUsersHandler = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const { confirmation } = req.body;

        // require explicit confirmation
        if (confirmation !== "DELETE_ALL_USERS") {
            return res.status(400).json({ 
                message: "confirmation required",
                error: "send { confirmation: 'DELETE_ALL_USERS' } to proceed"
            });
        }

        // exclude the current admin from deletion
        const result = await deleteAllUsers(req.user?.userId);

        return res.status(200).json(result);
    } catch (error) {
        console.error("delete all users error:", error);
        return res.status(500).json({ 
            message: "failed to delete users",
            error: error instanceof Error ? error.message : "unknown error"
        });
    }
};
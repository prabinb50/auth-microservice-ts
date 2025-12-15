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
import { validate as validateUUID } from 'uuid';
import logger from "../utils/logger";

// handle user registration
export const signUp = async (req: Request, res: Response) => {
    try {
        const { email, password, role } = req.body;

        logger.info('signup attempt', { email, role: role || 'USER' });

        // check if user already exists
        const existingUser = await findUserByEmail(email);
        if (existingUser) {
            logger.warn('signup failed - user already exists', { email });
            return res.status(400).json({ message: "user already exists" });
        }

        // register user
        const user = await registerUser(email, password, role);
        if (!user) {
            logger.error('signup failed - could not register user', { email });
            return res.status(404).json({ message: "could not register user" });
        }

        logger.info('user registered successfully', { 
            userId: user.id, 
            email: user.email 
        });

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
        logger.error('signup error', { 
            error: error.message, 
            stack: error.stack 
        });
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

        logger.info('login attempt', { email, ip: req.ip });

        const { accessToken, refreshToken, user } = await loginUser(email, password, req);

        // set refresh cookie
        const expiresAt = getRefreshTokenExpiryDate();
        setRefreshTokenCookie(res, refreshToken, expiresAt);

        logger.info('login successful', { 
            userId: user.id, 
            email: user.email,
            role: user.role 
        });

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
        logger.error('login error', { 
            error: error.message,
            code: error.code,
            email: req.body.email,
            ip: req.ip 
        });
        
        // handle email not verified
        if (error.code === "EMAIL_NOT_VERIFIED") {
            return res.status(403).json({ 
                message: "email not verified",
                error: "please verify your email before logging in. check your inbox for verification link."
            });
        }
        
        // handle account locked error
        if (error.lockedUntil) {
            logger.warn('account locked', { 
                email: req.body.email, 
                lockedUntil: error.lockedUntil 
            });
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
            logger.warn('refresh failed - token missing', { ip: req.ip });
            return res.status(401).json({ message: "refresh token missing" });
        }

        const rotated = await rotateRefreshToken(refreshToken);

        // set new cookie
        setRefreshTokenCookie(res, rotated.refreshToken, rotated.expiresAt);

        logger.info('token refreshed successfully', { userId: rotated.userId });

        return res.status(200).json({ 
            message: "token refreshed", 
            accessToken: rotated.accessToken 
        });
    } catch (err: any) {
        logger.error('refresh token error', { 
            error: err.message,
            ip: req.ip 
        });
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
            logger.info('user logged out', { ip: req.ip });
        }

        clearRefreshTokenCookie(res);

        return res.status(200).json({ message: "logged out successfully" });
    } catch (err: any) {
        logger.error('logout error', { 
            error: err.message,
            ip: req.ip 
        });
        return res.status(500).json({ message: "logout failed", error: err.message || null });
    }
};

// get user by id
export const getUserById = async (req: AuthenticatedRequest, res: Response) => {
    try {
        // check if user is authenticated
        if (!req.user) {
            logger.warn('unauthorized get user by id attempt');
            return res.status(401).json({ message: "unauthorized" });
        }

        const userId = req.params.id;
        
        // validate uuid format using uuid package
        if (!userId || !validateUUID(userId)) {
            logger.warn('invalid user id format', { userId, requesterId: req.user.userId });
            return res.status(400).json({ 
                message: "invalid user id format",
                error: "user id must be a valid uuid"
            });
        }

        const user = await findUserById(userId);
        if (!user) {
            logger.warn('user not found', { userId, requesterId: req.user.userId });
            return res.status(404).json({ message: "user not found with the given id" });
        }

        logger.info('user retrieved', { 
            userId, 
            requesterId: req.user.userId 
        });

        return res.status(200).json({ 
            authenticatedUser: req.user, 
            foundUser: user 
        });
    } catch (error) {
        logger.error('get user by id error', { 
            error: error instanceof Error ? error.message : 'unknown',
            userId: req.params.id,
            requesterId: req.user?.userId 
        });
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
            logger.warn('unauthorized profile access attempt');
            return res.status(401).json({ message: "unauthorized" });
        }

        const user = await findUserById(req.user.userId);
        if (!user) {
            logger.error('profile user not found', { userId: req.user.userId });
            return res.status(404).json({ message: "user not found" });
        }

        logger.info('profile retrieved', { userId: req.user.userId });

        return res.status(200).json({ user });
    } catch (error) {
        logger.error('get profile error', { 
            error: error instanceof Error ? error.message : 'unknown',
            userId: req.user?.userId 
        });
        return res.status(500).json({ message: "failed to get profile" });
    }
};

// admin: get all users
export const listAllUsers = async (req: AuthenticatedRequest, res: Response) => {
    try {
        // check if user is authenticated
        if (!req.user) {
            logger.warn('unauthorized list users attempt');
            return res.status(401).json({ message: "unauthorized" });
        }

        const users = await getAllUsers();
        
        logger.info('all users listed', { 
            adminId: req.user.userId,
            count: users.length 
        });

        return res.status(200).json({ 
            message: "users retrieved successfully",
            count: users.length,
            users 
        });
    } catch (error) {
        logger.error('list users error', { 
            error: error instanceof Error ? error.message : 'unknown',
            adminId: req.user?.userId 
        });
        return res.status(500).json({ message: "failed to retrieve users" });
    }
};

// admin: update user role
export const changeUserRole = async (req: AuthenticatedRequest, res: Response) => {
    try {
        // check if user is authenticated
        if (!req.user) {
            logger.warn('unauthorized role change attempt');
            return res.status(401).json({ message: "unauthorized" });
        }

        const { userId, role } = req.body;

        // validate uuid format
        if (!validateUUID(userId)) {
            logger.warn('invalid user id for role change', { 
                userId, 
                adminId: req.user.userId 
            });
            return res.status(400).json({ 
                message: "invalid user id format",
                error: "user id must be a valid uuid"
            });
        }

        // prevent changing own role
        if (req.user.userId === userId) {
            logger.warn('admin attempted to change own role', { 
                adminId: req.user.userId 
            });
            return res.status(400).json({ 
                message: "cannot change your own role" 
            });
        }

        const updatedUser = await updateUserRole(userId, role);

        logger.info('user role updated', { 
            userId, 
            newRole: role,
            adminId: req.user.userId 
        });

        return res.status(200).json({ 
            message: "user role updated successfully",
            user: updatedUser 
        });
    } catch (error) {
        logger.error('change role error', { 
            error: error instanceof Error ? error.message : 'unknown',
            userId: req.body.userId,
            adminId: req.user?.userId 
        });
        return res.status(500).json({ 
            message: "failed to update user role",
            error: error instanceof Error ? error.message : "unknown error"
        });
    }
};

// admin: delete user by id
export const deleteUser = async (req: AuthenticatedRequest, res: Response) => {
    try {
        // check if user is authenticated
        if (!req.user) {
            logger.warn('unauthorized delete user attempt');
            return res.status(401).json({ message: "unauthorized" });
        }

        const userId = req.params.id;
        
        // validate uuid format using uuid package
        if (!userId || !validateUUID(userId)) {
            logger.warn('invalid user id for deletion', { 
                userId, 
                adminId: req.user.userId 
            });
            return res.status(400).json({ 
                message: "invalid user id format",
                error: "user id must be a valid uuid"
            });
        }

        // prevent admin from deleting their own account
        if (req.user.userId === userId) {
            logger.warn('admin attempted to delete own account', { 
                adminId: req.user.userId 
            });
            return res.status(400).json({ 
                message: "cannot delete your own account" 
            });
        }

        const result = await deleteUserById(userId);

        logger.info('user deleted', { 
            userId, 
            adminId: req.user.userId 
        });

        return res.status(200).json(result);
    } catch (error) {
        logger.error('delete user error', { 
            error: error instanceof Error ? error.message : 'unknown',
            userId: req.params.id,
            adminId: req.user?.userId 
        });
        return res.status(500).json({ 
            message: "failed to delete user",
            error: error instanceof Error ? error.message : "unknown error"
        });
    }
};

// admin: delete all non-admin users
export const deleteAllNonAdmins = async (req: AuthenticatedRequest, res: Response) => {
    try {
        // check if user is authenticated
        if (!req.user) {
            logger.warn('unauthorized delete non-admins attempt');
            return res.status(401).json({ message: "unauthorized" });
        }

        const result = await deleteAllNonAdminUsers();

        logger.warn('all non-admin users deleted', { 
            adminId: req.user.userId,
            count: result.deletedCount 
        });

        return res.status(200).json(result);
    } catch (error) {
        logger.error('delete all non-admins error', { 
            error: error instanceof Error ? error.message : 'unknown',
            adminId: req.user?.userId 
        });
        return res.status(500).json({ 
            message: "failed to delete users",
            error: error instanceof Error ? error.message : "unknown error"
        });
    }
};

// super admin: delete all users (with confirmation)
export const deleteAllUsersHandler = async (req: AuthenticatedRequest, res: Response) => {
    try {
        // check if user is authenticated
        if (!req.user) {
            logger.error('delete all users - no authenticated user');
            return res.status(401).json({ message: "unauthorized" });
        }

        const { confirmation } = req.body;

        // require explicit confirmation
        if (confirmation !== "DELETE_ALL_USERS") {
            logger.warn('delete all users - invalid confirmation', { 
                adminId: req.user.userId 
            });
            return res.status(400).json({ 
                message: "confirmation required",
                error: "send { confirmation: 'DELETE_ALL_USERS' } to proceed"
            });
        }

        // exclude the current admin from deletion
        const currentAdminId = req.user.userId;

        const result = await deleteAllUsers(currentAdminId);

        logger.warn('all users deleted', { 
            adminId: currentAdminId,
            count: result.deletedCount 
        });

        return res.status(200).json(result);
    } catch (error) {
        logger.error('delete all users error', { 
            error: error instanceof Error ? error.message : 'unknown',
            adminId: req.user?.userId 
        });
        return res.status(500).json({ 
            message: "failed to delete users",
            error: error instanceof Error ? error.message : "unknown error"
        });
    }
};
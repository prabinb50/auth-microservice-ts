import { Response, NextFunction } from "express";
import { AuthenticatedRequest, UserRole } from "../utils/customTypes";
import { verifyAccessToken } from "../utils/jwt";
import prisma from "../utils/prisma";
import logger from "../utils/logger";

// middleware to protect routes
export const authenticate = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
        // get authorization header
        const authHeader = req.header("Authorization");

        // check if authorization header exists
        if (!authHeader) {
            return res.status(401).json({ 
                message: "authorization header missing",
                error: "please provide authorization header in format: Bearer <token>"
            });
        }

        // validate bearer prefix (case-insensitive)
        if (!authHeader.toLowerCase().startsWith("bearer ")) {
            return res.status(401).json({ 
                message: "invalid authorization format",
                error: "authorization header must be in format: Bearer <token>"
            });
        }

        // extract token
        const token = authHeader.substring(7).trim();

        // check if token exists after bearer prefix
        if (!token) {
            return res.status(401).json({ 
                message: "access token missing",
                error: "bearer token cannot be empty"
            });
        }

        try {
            // verify token and get user data with role and tokenVersion
            const decoded = verifyAccessToken(token);

            // check if tokenVersion matches current user's tokenVersion
            const user = await prisma.user.findUnique({
                where: { id: decoded.userId },
                select: { tokenVersion: true, role: true, emailVerified: true }
            });

            if (!user) {
                logger.warn('token verification failed - user not found', {
                    userId: decoded.userId
                });
                return res.status(401).json({ 
                    message: "invalid token",
                    error: "user not found"
                });
            }

            // check if token version matches (invalidate old tokens after password reset)
            if (decoded.tokenVersion !== user.tokenVersion) {
                logger.warn('token verification failed - token version mismatch', {
                    userId: decoded.userId,
                    tokenVersion: decoded.tokenVersion,
                    currentVersion: user.tokenVersion
                });
                return res.status(401).json({ 
                    message: "token invalidated",
                    error: "please login again. your password was recently changed."
                });
            }

            // attach user to request
            req.user = decoded;

            // pass control to next middleware
            next();
        } catch (error) {
            logger.warn('token verification failed', {
                error: error instanceof Error ? error.message : 'unknown'
            });
            return res.status(401).json({ 
                message: "invalid or expired token",
                error: error instanceof Error ? error.message : "token verification failed"
            });
        }
    } catch (error) {
        logger.error("authentication error", {
            error: error instanceof Error ? error.message : 'unknown'
        });
        return res.status(500).json({ 
            message: "internal server error",
            error: "authentication process failed"
        });
    }
};

// middleware to check if user has admin role
export const requireAdmin = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
        // check if user exists (authenticate should run first)
        if (!req.user) {
            return res.status(401).json({ 
                message: "authentication required",
                error: "user context not found. ensure authenticate middleware runs first"
            });
        }

        // check if user has admin role
        if (req.user.role !== "ADMIN") {
            return res.status(403).json({
                message: "access denied",
                error: "admin privileges required for this operation"
            });
        }
        next();
    } catch (error) {
        console.error("admin check error:", error);
        return res.status(500).json({ 
            message: "internal server error",
            error: "role verification failed"
        });
    }
};

// middleware to check if user has specific role
export const requireRole = (allowedRoles: UserRole[]) => {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
        try {
            // check if user exists
            if (!req.user) {
                return res.status(401).json({ 
                    message: "authentication required",
                    error: "user context not found"
                });
            }

            // check if user has one of the allowed roles
            if (!allowedRoles.includes(req.user.role)) {
                return res.status(403).json({
                    message: "access denied",
                    error: `requires one of these roles: ${allowedRoles.join(", ")}`
                });
            }
            next();
        } catch (error) {
            console.error("role check error:", error);
            return res.status(500).json({ 
                message: "internal server error",
                error: "role verification failed"
            });
        }
    };
};
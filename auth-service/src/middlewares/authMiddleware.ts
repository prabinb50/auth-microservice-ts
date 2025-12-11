import { Response, NextFunction } from "express";
import { AuthenticatedRequest, UserRole } from "../utils/customTypes";
import { verifyAccessToken } from "../utils/jwt";

// middleware to protect routes
export const authenticate = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
        // get token from header
        const token = req.header("Authorization")?.replace("Bearer ", "");

        if (!token) {
            return res.status(401).json({ message: "authorization token missing" });
        }

        try {
            // verify token and get user data with role
            const decoded = verifyAccessToken(token);

            // attach user to request
            req.user = decoded;

            // pass control
            next();
        } catch (error) {
            return res.status(401).json({ message: "invalid token" });
        }
    } catch (error) {
        console.error("authentication error:", error);
        return res.status(500).json({ message: "internal server error" });
    }
};

// middleware to check if user has admin role
export const requireAdmin = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
        // check if user exists (authenticate should run first)
        if (!req.user) {
            return res.status(401).json({ message: "authentication required" });
        }

        // check if user has admin role
        if (req.user.role !== "ADMIN") {
            return res.status(403).json({
                message: "access denied: admin privileges required"
            });
        }

        // user is admin, proceed
        next();
    } catch (error) {
        console.error("admin check error:", error);
        return res.status(500).json({ message: "internal server error" });
    }
};

// middleware to check if user has specific role
export const requireRole = (allowedRoles: UserRole[]) => {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
        try {
            if (!req.user) {
                return res.status(401).json({ message: "authentication required" });
            }

            if (!allowedRoles.includes(req.user.role)) {
                return res.status(403).json({
                    message: `access denied: requires one of these roles: ${allowedRoles.join(", ")}`
                });
            }

            next();
        } catch (error) {
            console.error("role check error:", error);
            return res.status(500).json({ message: "internal server error" });
        }
    };
};
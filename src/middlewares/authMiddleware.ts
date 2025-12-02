import { Response, NextFunction } from "express";
import { AuthenticatedRequest } from "../utils/customTypes";
import { verifyAccessToken } from "../utils/jwt";

// middleware to protect routes
export const authenticate = (req: AuthenticatedRequest, res: Response, next: NextFunction
) => {
    try {
        // get token from header
        const token = req.header("Authorization")?.replace("Bearer ", "");

        if (!token) {
            return res.status(401).json({ message: "authorization token missing" });
        }

        try {
            // verify token
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

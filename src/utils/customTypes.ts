import { Request } from "express";
import { JwtPayload } from "jsonwebtoken";

// user role type
export type UserRole = "USER" | "ADMIN";

// decoded token payload interface
export interface TokenPayload {
    userId: number;
    role: UserRole;
}

// authenticated request with user info
export interface AuthenticatedRequest extends Request {
    user?: TokenPayload;
}
import { Request } from "express";

// user role type
export type UserRole = "USER" | "ADMIN";

// decoded token payload interface
export interface TokenPayload {
    userId: string;
    role: UserRole;
}

// authenticated request with user info
export interface AuthenticatedRequest extends Request {
    user?: TokenPayload;
}
import { z } from "zod";

// register schema
export const registerSchema = z.object({
  email: z.string().email({ message: "invalid email" }).trim(),
  password: z.string().min(6, { message: "password must be at least 6 characters" }).trim(),
  role: z.enum(["USER", "ADMIN"]).optional().default("USER"),
});

// login schema
export const loginSchema = z.object({
  email: z.string().email({ message: "invalid email" }).trim(),
  password: z.string().min(6, { message: "password must be at least 6 characters" }).trim(),
});

// update role schema (admin only)
export const updateRoleSchema = z.object({
  userId: z.number().int().positive({ message: "valid user id required" }),
  role: z.enum(["USER", "ADMIN"], { message: "role must be USER or ADMIN" }),
});
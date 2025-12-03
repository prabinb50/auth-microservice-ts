import { z } from "zod";

// strong password validator
const strongPasswordSchema = z
  .string()
  .min(8, { message: "password must be at least 8 characters long" })
  .regex(/[A-Z]/, { message: "password must contain at least one uppercase letter" })
  .regex(/[a-z]/, { message: "password must contain at least one lowercase letter" })
  .regex(/[0-9]/, { message: "password must contain at least one number" })
  .regex(/[^A-Za-z0-9]/, { message: "password must contain at least one special character (!@#$%^&*)" })
  .trim();

// registration schema
export const registerSchema = z.object({
  email: z.string().email({ message: "invalid email" }).trim(),
  password: strongPasswordSchema,
  role: z.enum(["USER", "ADMIN"]).optional().default("USER"),
});

// login schema
export const loginSchema = z.object({
  email: z.string().email({ message: "invalid email" }).trim(),
  password: z.string().min(6, { message: "password must be at least 6 characters" }).trim(),
});

// update user role schema (admin only)
export const updateRoleSchema = z.object({
  userId: z.number().int().positive({ message: "valid user id required" }),
  role: z.enum(["USER", "ADMIN"], { message: "role must be USER or ADMIN" }),
});
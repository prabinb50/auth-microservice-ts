import { z } from "zod";

// register schema
export const registerSchema = z.object({
  email: z.string().email({ message: "invalid email" }).trim(),
  password: z.string().min(6, { message: "password must be at least 6 characters" }).trim(),
});

// login schema
export const loginSchema = z.object({
  email: z.string().email({ message: "invalid email" }).trim(),
  password: z.string().min(6, { message: "password must be at least 6 characters" }).trim(),
});

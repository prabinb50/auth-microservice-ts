import { z } from 'zod';

// send verification email schema
export const sendVerificationSchema = z.object({
  userId: z.string().uuid({ message: 'invalid user id format' }),
  email: z.string().email({ message: 'invalid email format' }).trim(),
});

// verify email schema
export const verifyEmailSchema = z.object({
  token: z.string().min(1, { message: 'token is required' }).trim(),
});

// forgot password schema
export const forgotPasswordSchema = z.object({
  email: z.string().email({ message: 'invalid email format' }).trim(),
});

// reset password schema
export const resetPasswordSchema = z.object({
  token: z.string().min(1, { message: 'token is required' }).trim(),
  newPassword: z.string()
    .min(8, { message: 'password must be at least 8 characters' })
    .max(100, { message: 'password must not exceed 100 characters' })
    .regex(/[a-z]/, { message: 'password must contain at least one lowercase letter' })
    .regex(/[A-Z]/, { message: 'password must contain at least one uppercase letter' })
    .regex(/[0-9]/, { message: 'password must contain at least one number' })
    .regex(/[^a-zA-Z0-9]/, { message: 'password must contain at least one special character' })
    .trim(),
});

// resend verification schema
export const resendVerificationSchema = z.object({
  email: z.string().email({ message: 'invalid email format' }).trim(),
});

// send magic login link schema
export const sendMagicLinkSchema = z.object({
  userId: z.string().uuid({ message: 'invalid user id format' }),
  email: z.string().email({ message: 'invalid email format' }).trim(),
  ipAddress: z.string().min(1, { message: 'ip address is required' }),
  userAgent: z.string().min(1, { message: 'user agent is required' }),
});
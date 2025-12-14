import { z } from 'zod';

// send verification email schema
export const sendVerificationSchema = z.object({
    userId: z.string().uuid({ message: 'valid user id required' }),
    email: z.string().email({ message: 'invalid email address' }),
});

// verify email schema
export const verifyEmailSchema = z.object({
    token: z.string().min(1, { message: 'verification token required' }),
});

// forgot password schema
export const forgotPasswordSchema = z.object({
    email: z.string().email({ message: 'invalid email address' }),
});

// reset password schema
export const resetPasswordSchema = z.object({
    token: z.string().min(1, { message: 'reset token required' }),
    newPassword: z
        .string()
        .min(8, { message: 'password must be at least 8 characters long' })
        .regex(/[A-Z]/, { message: 'password must contain at least one uppercase letter' })
        .regex(/[a-z]/, { message: 'password must contain at least one lowercase letter' })
        .regex(/[0-9]/, { message: 'password must contain at least one number' })
        .regex(/[^A-Za-z0-9]/, { message: 'password must contain at least one special character' }),
});

// resend verification schema
export const resendVerificationSchema = z.object({
    email: z.string().email({ message: 'invalid email address' }),
});
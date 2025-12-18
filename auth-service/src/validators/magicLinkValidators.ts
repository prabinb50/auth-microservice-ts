import { z } from 'zod';

// magic link request schema
export const magicLinkRequestSchema = z.object({
  email: z
    .string({
      required_error: 'email is required',
    })
    .email({ message: 'invalid email format' })
    .trim()
    .toLowerCase(),
});

// magic link login schema
export const magicLinkLoginSchema = z.object({
  token: z
    .string({
      required_error: 'magic link token is required',
    })
    .min(1, { message: 'magic link token cannot be empty' })
    .trim(),
});
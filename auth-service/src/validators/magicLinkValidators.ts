import { z } from 'zod';

// magic link request schema
export const magicLinkRequestSchema = z.object({
  email: z.string().email({ message: 'invalid email format' }).trim().toLowerCase(),
});

// magic link login schema
export const magicLinkLoginSchema = z.object({
  token: z.string().min(1, { message: 'magic link token is required' }).trim(),
});
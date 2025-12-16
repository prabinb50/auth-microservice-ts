import { z } from 'zod';

// email update schema
export const updateEmailSchema = z.object({
  newEmail: z.string().email({ message: 'invalid email format' }).trim(),
});

// anonymization confirmation schema
export const anonymizationSchema = z.object({
  confirmation: z.literal('ANONYMIZE_MY_ACCOUNT', {
    message: 'confirmation must be "ANONYMIZE_MY_ACCOUNT"',
  }),
});

// permanent deletion confirmation schema
export const permanentDeletionSchema = z.object({
  confirmation: z.literal('PERMANENTLY_DELETE_USER', {
    message: 'confirmation must be "PERMANENTLY_DELETE_USER"',
  }),
});
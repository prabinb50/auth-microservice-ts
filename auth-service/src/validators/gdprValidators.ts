import { z } from 'zod';

// update email schema 
export const updateEmailSchema = z.object({
  newEmail: z.string().email({ message: 'invalid email format' }).trim(),
});

// anonymization schema 
export const anonymizationSchema = z.object({
  confirmation: z.literal('ANONYMIZE_MY_DATA', {
    errorMap: () => ({ message: "confirmation must be exactly 'ANONYMIZE_MY_DATA'" }),
  }),
  password: z.string().min(1, { message: 'password is required for anonymization' }),
});

// permanent deletion schema (admin) 
export const permanentDeletionSchema = z.object({
  confirmation: z.literal('PERMANENTLY_DELETE_USER', {
    errorMap: () => ({ message: "confirmation must be exactly 'PERMANENTLY_DELETE_USER'" }),
  }),
});
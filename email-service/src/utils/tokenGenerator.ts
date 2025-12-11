import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const EMAIL_TOKEN_SECRET = process.env.EMAIL_TOKEN_SECRET || 'email-secret-key-change-in-production';
const VERIFICATION_TOKEN_EXPIRY = '24h'; 
const RESET_TOKEN_EXPIRY = '1h'; 

// generate email verification token
export const generateVerificationToken = (userId: number): string => {
  return jwt.sign({ userId, type: 'email-verification' }, EMAIL_TOKEN_SECRET, {
    expiresIn: VERIFICATION_TOKEN_EXPIRY,
  });
};

// generate password reset token
export const generatePasswordResetToken = (userId: number): string => {
  return jwt.sign({ userId, type: 'password-reset' }, EMAIL_TOKEN_SECRET, {
    expiresIn: RESET_TOKEN_EXPIRY,
  });
};

// verify token
export const verifyEmailToken = (token: string): { userId: number; type: string } => {
  try {
    const decoded = jwt.verify(token, EMAIL_TOKEN_SECRET) as { userId: number; type: string };
    return decoded;
  } catch (error) {
    throw new Error('invalid or expired token');
  }
};

// get verification token expiry date
export const getVerificationTokenExpiry = (): Date => {
  const expiry = new Date();
  expiry.setHours(expiry.getHours() + 24); // 24 hours from now
  return expiry;
};

// get reset token expiry date
export const getResetTokenExpiry = (): Date => {
  const expiry = new Date();
  expiry.setHours(expiry.getHours() + 1); // 1 hour from now
  return expiry;
};
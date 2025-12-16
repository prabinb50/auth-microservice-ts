import jwt, { SignOptions } from 'jsonwebtoken';
import logger from './logger';

const EMAIL_TOKEN_SECRET = process.env.EMAIL_TOKEN_SECRET || 'f3c9e7b1c0a24f8d89e4d12f7a56cbe2b4cd8f7a93d1e56ea4c0b6bfe12d9ca7';
const VERIFICATION_TOKEN_EXPIRY = process.env.VERIFICATION_TOKEN_EXPIRY || '24h';
const RESET_TOKEN_EXPIRY = process.env.RESET_TOKEN_EXPIRY || '1h';
const MAGIC_LINK_TOKEN_EXPIRY = process.env.MAGIC_LINK_TOKEN_EXPIRY || '15m';

// generate verification token
export const generateVerificationToken = (userId: string): string => {
  try {
    const token = jwt.sign(
      { userId, type: 'verification' },
      EMAIL_TOKEN_SECRET,
      { expiresIn: VERIFICATION_TOKEN_EXPIRY } as SignOptions
    );
    logger.debug('verification token generated', { userId });
    return token;
  } catch (error: any) {
    logger.error('failed to generate verification token', { userId, error: error.message });
    throw error;
  }
};

// generate password reset token
export const generatePasswordResetToken = (userId: string): string => {
  try {
    const token = jwt.sign(
      { userId, type: 'password-reset' },
      EMAIL_TOKEN_SECRET,
      { expiresIn: RESET_TOKEN_EXPIRY } as SignOptions
    );
    logger.debug('password reset token generated', { userId });
    return token;
  } catch (error: any) {
    logger.error('failed to generate password reset token', { userId, error: error.message });
    throw error;
  }
};

// generate magic login link token
export const generateMagicLinkToken = (userId: string): string => {
  try {
    const token = jwt.sign(
      { userId, type: 'magic-link' },
      EMAIL_TOKEN_SECRET,
      { expiresIn: MAGIC_LINK_TOKEN_EXPIRY } as SignOptions
    );
    logger.debug('magic link token generated', { userId });
    return token;
  } catch (error: any) {
    logger.error('failed to generate magic link token', { userId, error: error.message });
    throw error;
  }
};

// verify email token
export const verifyEmailToken = (token: string): { userId: string; type: string } => {
  try {
    const decoded = jwt.verify(token, EMAIL_TOKEN_SECRET) as { userId: string; type: string };
    logger.debug('email token verified', { userId: decoded.userId, type: decoded.type });
    return decoded;
  } catch (error: any) {
    logger.warn('failed to verify email token', { error: error.message });
    throw new Error('invalid or expired token');
  }
};

// get verification token expiry date
export const getVerificationTokenExpiry = (): Date => {
  const hours = parseInt(VERIFICATION_TOKEN_EXPIRY) || 24;
  return new Date(Date.now() + hours * 60 * 60 * 1000);
};

// get reset token expiry date
export const getResetTokenExpiry = (): Date => {
  const hours = parseInt(RESET_TOKEN_EXPIRY) || 1;
  return new Date(Date.now() + hours * 60 * 60 * 1000);
};

// get magic link token expiry date
export const getMagicLinkTokenExpiry = (): Date => {
  const minutes = parseInt(MAGIC_LINK_TOKEN_EXPIRY) || 15;
  return new Date(Date.now() + minutes * 60 * 1000);
};
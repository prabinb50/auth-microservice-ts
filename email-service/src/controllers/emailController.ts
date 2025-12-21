import { Request, Response } from 'express';
import {
  sendVerificationEmail,
  verifyEmail,
  sendPasswordResetEmail,
  resetPassword,
  resendVerificationEmail,
  sendMagicLinkEmail,
} from '../services/emailService';
import logger from '../utils/logger';

// helper to get ip address
const getIpAddress = (req: Request): string => {
  return (
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    (req.headers['x-real-ip'] as string) ||
    req.ip ||
    req.socket.remoteAddress ||
    'unknown'
  );
};

// send verification email
export const handleSendVerification = async (req: Request, res: Response) => {
  try {
    const { userId, email } = req.body;

    logger.info('sending verification email', { userId, email });

    await sendVerificationEmail(userId, email);
    
    logger.info('verification email sent successfully', { userId, email });

    return res.status(200).json({ message: 'verification email sent successfully' });
  } catch (error: any) {
    logger.error('send verification error', { 
      error: error.message,
      userId: req.body.userId,
      email: req.body.email 
    });
    return res.status(500).json({ 
      message: 'failed to send verification email', 
      error: error.message 
    });
  }
};

// verify email
export const handleVerifyEmail = async (req: Request, res: Response) => {
  try {
    const { token } = req.body;

    logger.info('verifying email token', { 
      token: token.substring(0, 10) + '...' 
    });

    const result = await verifyEmail(token);
    
    logger.info('email verified successfully');

    return res.status(200).json(result);
  } catch (error: any) {
    logger.error('verify email error', { 
      error: error.message,
      token: req.body.token?.substring(0, 10) + '...' 
    });
    return res.status(400).json({ 
      message: 'email verification failed', 
      error: error.message 
    });
  }
};

// send password reset email
export const handleForgotPassword = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    const ipAddress = getIpAddress(req);
    const userAgent = req.headers['user-agent'] || 'unknown';

    logger.info('password reset requested', { email, ipAddress });

    const result = await sendPasswordResetEmail(email, ipAddress, userAgent);
    
    logger.info('password reset email processed', { email });

    return res.status(200).json(result);
  } catch (error: any) {
    logger.error('forgot password error', { 
      error: error.message,
      email: req.body.email 
    });
    return res.status(500).json({ 
      message: 'failed to send password reset email', 
      error: error.message 
    });
  }
};

// reset password
export const handleResetPassword = async (req: Request, res: Response) => {
  try {
    const { token, newPassword } = req.body;
    const ipAddress = getIpAddress(req);
    const userAgent = req.headers['user-agent'] || 'unknown';

    logger.info('password reset attempt', { 
      token: token.substring(0, 10) + '...',
      ipAddress
    });

    const result = await resetPassword(token, newPassword, ipAddress, userAgent);
    
    logger.info('password reset successfully');

    return res.status(200).json(result);
  } catch (error: any) {
    logger.error('reset password error', { 
      error: error.message,
      token: req.body.token?.substring(0, 10) + '...' 
    });
    return res.status(400).json({ 
      message: 'password reset failed', 
      error: error.message 
    });
  }
};

// resend verification email
export const handleResendVerification = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;

    logger.info('resending verification email', { email });

    const result = await resendVerificationEmail(email);
    
    logger.info('verification email resent successfully', { email });

    return res.status(200).json(result);
  } catch (error: any) {
    logger.error('resend verification error', { 
      error: error.message,
      email: req.body.email 
    });
    return res.status(400).json({ 
      message: 'failed to resend verification email', 
      error: error.message 
    });
  }
};

// send magic login link
export const handleSendMagicLink = async (req: Request, res: Response) => {
  try {
    const { userId, email, ipAddress, userAgent } = req.body;

    logger.info('sending magic login link', { userId, email });

    const result = await sendMagicLinkEmail(userId, email, ipAddress, userAgent);
    
    logger.info('magic login link sent successfully', { userId, email });

    return res.status(200).json(result);
  } catch (error: any) {
    logger.error('send magic link error', { 
      error: error.message,
      userId: req.body.userId,
      email: req.body.email 
    });
    return res.status(500).json({ 
      message: 'failed to send magic login link', 
      error: error.message 
    });
  }
};
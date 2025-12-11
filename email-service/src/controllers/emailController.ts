import { Request, Response } from 'express';
import {
  sendVerificationEmail,
  verifyEmail,
  sendPasswordResetEmail,
  resetPassword,
  resendVerificationEmail,
} from '../services/emailService';

// send verification email
export const handleSendVerification = async (req: Request, res: Response) => {
  try {
    const { userId, email } = req.body;

    await sendVerificationEmail(userId, email);
    
    return res.status(200).json({ message: 'verification email sent successfully' });
  } catch (error: any) {
    console.error('send verification error:', error);
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

    const result = await verifyEmail(token);
    
    return res.status(200).json(result);
  } catch (error: any) {
    console.error('verify email error:', error);
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

    const result = await sendPasswordResetEmail(email);
    
    return res.status(200).json(result);
  } catch (error: any) {
    console.error('forgot password error:', error);
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

    const result = await resetPassword(token, newPassword);
    
    return res.status(200).json(result);
  } catch (error: any) {
    console.error('reset password error:', error);
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

    const result = await resendVerificationEmail(email);
    
    return res.status(200).json(result);
  } catch (error: any) {
    console.error('resend verification error:', error);
    return res.status(400).json({ 
      message: 'failed to resend verification email', 
      error: error.message 
    });
  }
};
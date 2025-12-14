import { Router } from 'express';
import {handleSendVerification, handleVerifyEmail, handleForgotPassword, handleResetPassword, handleResendVerification } from '../controllers/emailController';
import { validate } from '../middlewares/validate';
import {sendVerificationSchema, verifyEmailSchema, forgotPasswordSchema, resetPasswordSchema, resendVerificationSchema} from '../validators/emailValidators';
import { emailSendRateLimiter, verificationRateLimiter } from '../middlewares/rateLimiter';

const router = Router();

// send verification email (called by auth-service)
router.post('/send-verification', emailSendRateLimiter, validate(sendVerificationSchema), handleSendVerification);

// verify email (called by frontend)
router.post('/verify-email', verificationRateLimiter, validate(verifyEmailSchema), handleVerifyEmail);

// resend verification email
router.post('/resend-verification', emailSendRateLimiter, validate(resendVerificationSchema), handleResendVerification);

// forgot password (send reset email)
router.post('/forgot-password', emailSendRateLimiter, validate(forgotPasswordSchema), handleForgotPassword);

// reset password
router.post('/reset-password', verificationRateLimiter, validate(resetPasswordSchema), handleResetPassword);

export default router;
import { Router } from 'express';
import {handleSendVerification, handleVerifyEmail, handleForgotPassword, handleResetPassword, handleResendVerification } from '../controllers/emailController';
import { validate } from '../middlewares/validate';
import {sendVerificationSchema, verifyEmailSchema, forgotPasswordSchema, resetPasswordSchema, resendVerificationSchema} from '../validators/emailValidators';

const router = Router();

// send verification email (called by auth-service)
router.post('/send-verification', validate(sendVerificationSchema), handleSendVerification);

// verify email (called by frontend)
router.post('/verify-email', validate(verifyEmailSchema), handleVerifyEmail);

// resend verification email
router.post('/resend-verification', validate(resendVerificationSchema), handleResendVerification);

// forgot password (send reset email)
router.post('/forgot-password', validate(forgotPasswordSchema), handleForgotPassword);

// reset password
router.post('/reset-password', validate(resetPasswordSchema), handleResetPassword);

export default router;
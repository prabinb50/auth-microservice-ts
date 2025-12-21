import prisma from '../utils/prisma';
import { passwordResetEmailTemplate, verificationEmailTemplate, magicLinkEmailTemplate } from '../templates/emailTemplates';
import { transporter } from '../utils/mailer';
import { generatePasswordResetToken, generateVerificationToken, generateMagicLinkToken, getResetTokenExpiry, getVerificationTokenExpiry, getMagicLinkTokenExpiry } from '../utils/tokenGenerator';
import bcrypt from 'bcrypt';
import logger from '../utils/logger';

const SALT_ROUNDS = 10;

// send verification email
export const sendVerificationEmail = async (userId: string, email: string) => {
  // generate token
  const token = generateVerificationToken(userId);
  const expiresAt = getVerificationTokenExpiry();

  logger.info('creating verification token', { userId, email });

  // save token to database
  await prisma.verificationToken.create({
    data: {
      token,
      userId,
      expiresAt,
    },
  });

  // create verification link
  const verificationLink = `${process.env.CLIENT_URL}/verify-email?token=${token}`;

  logger.info('sending verification email', { userId, email });

  // send email
  await transporter.sendMail({
    from: `"Auth Service" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'verify your email address',
    html: verificationEmailTemplate(verificationLink, email.split('@')[0]),
  });

  logger.info('verification email sent', { userId, email });

  return { message: 'verification email sent successfully' };
};

// verify email token
export const verifyEmail = async (token: string) => {
  // find token in database
  const verificationToken = await prisma.verificationToken.findUnique({
    where: { token },
    include: { user: true },
  });

  if (!verificationToken) {
    logger.warn('invalid verification token');
    throw new Error('invalid verification token');
  }

  // check if token expired
  if (verificationToken.expiresAt < new Date()) {
    await prisma.verificationToken.delete({ where: { token } });
    logger.warn('verification token expired', { userId: verificationToken.userId });
    throw new Error('verification token expired');
  }

  // check if already verified
  if (verificationToken.user.emailVerified) {
    logger.warn('email already verified', { userId: verificationToken.userId });
    throw new Error('email already verified');
  }

  logger.info('verifying email', {
    userId: verificationToken.userId,
    email: verificationToken.user.email
  });

  // update user email verified status
  await prisma.user.update({
    where: { id: verificationToken.userId },
    data: { emailVerified: true },
  });

  // delete used token
  await prisma.verificationToken.delete({ where: { token } });

  logger.info('email verified successfully', {
    userId: verificationToken.userId
  });

  return { message: 'email verified successfully' };
};

// send password reset email
export const sendPasswordResetEmail = async (email: string, ipAddress?: string, userAgent?: string) => {
  // find user by email
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    logger.warn('password reset requested for non-existent email', { email });
    // don't reveal if user exists or not (security best practice)
    return { message: 'if email exists, password reset link has been sent' };
  }

  logger.info('generating password reset token', {
    userId: user.id,
    email
  });

  // generate reset token
  const token = generatePasswordResetToken(user.id);
  const expiresAt = getResetTokenExpiry();

  // delete any existing reset tokens for this user
  await prisma.passwordResetToken.deleteMany({
    where: { userId: user.id },
  });

  // save new token to database
  await prisma.passwordResetToken.create({
    data: {
      token,
      userId: user.id,
      expiresAt,
    },
  });

  // create audit log in auth-service
  try {
    const authServiceUrl = process.env.AUTH_SERVICE_URL || 'http://localhost:8000';
    await fetch(`${authServiceUrl}/auth/internal/audit-log`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userId: user.id,
        action: 'PASSWORD_RESET_REQUESTED',
        resource: email,
        ipAddress: ipAddress || 'unknown',
        userAgent: userAgent || null,
        metadata: { email },
      }),
    });
    logger.info('password reset requested audit log created', { userId: user.id });
  } catch (error) {
    logger.error('failed to create audit log', {
      userId: user.id,
      error: error instanceof Error ? error.message : 'unknown'
    });
  }

  // create reset link
  const resetLink = `${process.env.CLIENT_URL}/reset-password?token=${token}`;

  logger.info('sending password reset email', { userId: user.id, email });

  // send email
  await transporter.sendMail({
    from: `"Auth Service" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'reset your password',
    html: passwordResetEmailTemplate(resetLink, user.email.split('@')[0]),
  });

  logger.info('password reset email sent', { userId: user.id, email });

  return { message: 'if email exists, password reset link has been sent' };
};

// reset password
export const resetPassword = async (token: string, newPassword: string, ipAddress?: string, userAgent?: string) => {
  // find token in database
  const resetToken = await prisma.passwordResetToken.findUnique({
    where: { token },
    include: { user: true },
  });

  if (!resetToken) {
    logger.warn('invalid reset token');
    throw new Error('invalid reset token');
  }

  // check if token expired
  if (resetToken.expiresAt < new Date()) {
    await prisma.passwordResetToken.delete({ where: { token } });
    logger.warn('reset token expired', { userId: resetToken.userId });
    throw new Error('reset token expired');
  }

  // check if token already used
  if (resetToken.used) {
    logger.warn('reset token already used', { userId: resetToken.userId });
    throw new Error('reset token already used');
  }

  logger.info('resetting password', {
    userId: resetToken.userId,
    email: resetToken.user.email
  });

  // hash new password
  const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

  // increment tokenVersion to invalidate all existing tokens
  const updatedUser = await prisma.user.update({
    where: { id: resetToken.userId },
    data: {
      password: hashedPassword,
      failedLoginAttempts: 0,
      accountLockedUntil: null,
      tokenVersion: { increment: 1 },  
    },
    select: {
      id: true,
      email: true,
      tokenVersion: true
    }
  });

  logger.info('password updated and tokenVersion incremented', {
    userId: updatedUser.id,
    newTokenVersion: updatedUser.tokenVersion
  });

  // mark token as used
  await prisma.passwordResetToken.update({
    where: { token },
    data: { used: true },
  });

  // delete all refresh tokens for this user (force re-login)
  await prisma.refreshToken.deleteMany({
    where: { userId: resetToken.userId },
  });

  // deactivate all sessions
  await prisma.session.updateMany({
    where: { userId: resetToken.userId },
    data: { isActive: false }
  });

  logger.info('all refresh tokens and sessions invalidated', {
    userId: resetToken.userId
  });

  // create audit log in auth-service
  try {
    const authServiceUrl = process.env.AUTH_SERVICE_URL || 'http://localhost:8000';
    await fetch(`${authServiceUrl}/auth/internal/audit-log`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userId: resetToken.userId,
        action: 'PASSWORD_RESET_COMPLETED',
        resource: updatedUser.email,
        ipAddress: ipAddress || 'unknown',
        userAgent: userAgent || null,
        metadata: {
          email: updatedUser.email,
          tokenVersionIncremented: true,
          newTokenVersion: updatedUser.tokenVersion
        },
      }),
    });
    logger.info('password reset completed audit log created', { userId: resetToken.userId });
  } catch (error) {
    logger.error('failed to create audit log', {
      userId: resetToken.userId,
      error: error instanceof Error ? error.message : 'unknown'
    });
  }

  logger.info('password reset successfully', {
    userId: resetToken.userId
  });

  return { message: 'password reset successfully. all existing sessions have been terminated. please login again.' };
};

// resend verification email
export const resendVerificationEmail = async (email: string) => {
  // find user
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    logger.warn('resend verification - user not found', { email });
    throw new Error('user not found');
  }

  if (user.emailVerified) {
    logger.warn('resend verification - email already verified', {
      userId: user.id,
      email
    });
    throw new Error('email already verified');
  }

  logger.info('resending verification email', {
    userId: user.id,
    email
  });

  // delete old verification tokens
  await prisma.verificationToken.deleteMany({
    where: { userId: user.id },
  });

  // send new verification email
  return await sendVerificationEmail(user.id, user.email);
};

// send magic login link - updated to support new user signups
export const sendMagicLinkEmail = async (
  userId: string,
  email: string,
  ipAddress: string,
  userAgent: string,
  isNewUser: boolean = false
) => {
  try {
    logger.info('generating magic link token', { userId, email, isNewUser });

    // generate magic link token
    const token = generateMagicLinkToken(userId);
    const expiresAt = getMagicLinkTokenExpiry();

    // save token to database
    await prisma.magicLinkToken.create({
      data: {
        token,
        userId,
        expiresAt,
        ipAddress,
        userAgent,
      },
    });

    logger.info('magic link token saved to database', {
      userId,
      expiresAt,
      isNewUser,
    });

    // create magic link
    const magicLink = `${process.env.CLIENT_URL}/magic-login?token=${token}`;

    logger.info('sending magic link email', { userId, email, isNewUser });

    // customize email subject based on new/existing user
    const subject = isNewUser 
      ? 'welcome! your magic login link'
      : 'your magic login link';

    // send email
    await transporter.sendMail({
      from: `"Auth Service" <${process.env.EMAIL_USER}>`,
      to: email,
      subject,
      html: magicLinkEmailTemplate(magicLink, email.split('@')[0], isNewUser),
    });

    logger.info('magic link email sent successfully', { userId, email, isNewUser });

    return { message: 'magic login link sent successfully' };
  } catch (error: any) {
    logger.error('failed to send magic link email', {
      userId,
      email,
      error: error.message,
    });
    throw error;
  }
};
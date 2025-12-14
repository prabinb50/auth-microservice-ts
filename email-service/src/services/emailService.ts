import prisma from '../utils/prisma';
import { passwordResetEmailTemplate, verificationEmailTemplate } from '../templates/emailTemplates';
import { transporter } from '../utils/mailer';
import { generatePasswordResetToken, generateVerificationToken, getResetTokenExpiry, getVerificationTokenExpiry } from '../utils/tokenGenerator';
import bcrypt from 'bcrypt';

const SALT_ROUNDS = 10;

// send verification email
export const sendVerificationEmail = async (userId: string, email: string) => {
  // generate token
  const token = generateVerificationToken(userId);
  const expiresAt = getVerificationTokenExpiry();

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

  // send email
  await transporter.sendMail({
    from: `"Auth Service" <${process.env.SMTP_USER}>`,
    to: email,
    subject: 'verify your email address',
    html: verificationEmailTemplate(verificationLink, email.split('@')[0]),
  });

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
    throw new Error('invalid verification token');
  }

  // check if token expired
  if (verificationToken.expiresAt < new Date()) {
    await prisma.verificationToken.delete({ where: { token } });
    throw new Error('verification token expired');
  }

  // check if already verified
  if (verificationToken.user.emailVerified) {
    throw new Error('email already verified');
  }

  // update user email verified status
  await prisma.user.update({
    where: { id: verificationToken.userId },
    data: { emailVerified: true },
  });

  // delete used token
  await prisma.verificationToken.delete({ where: { token } });

  return { message: 'email verified successfully' };
};

// send password reset email
export const sendPasswordResetEmail = async (email: string) => {
  // find user by email
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    // don't reveal if user exists or not (security best practice)
    return { message: 'if email exists, password reset link has been sent' };
  }

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

  // create reset link
  const resetLink = `${process.env.CLIENT_URL}/reset-password?token=${token}`;

  // send email
  await transporter.sendMail({
    from: `"Auth Service" <${process.env.SMTP_USER}>`,
    to: email,
    subject: 'reset your password',
    html: passwordResetEmailTemplate(resetLink, user.email.split('@')[0]),
  });

  return { message: 'if email exists, password reset link has been sent' };
};

// reset password
export const resetPassword = async (token: string, newPassword: string) => {
  // find token in database
  const resetToken = await prisma.passwordResetToken.findUnique({
    where: { token },
    include: { user: true },
  });

  if (!resetToken) {
    throw new Error('invalid reset token');
  }

  // check if token expired
  if (resetToken.expiresAt < new Date()) {
    await prisma.passwordResetToken.delete({ where: { token } });
    throw new Error('reset token expired');
  }

  // check if token already used
  if (resetToken.used) {
    throw new Error('reset token already used');
  }

  // hash new password
  const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

  // update user password
  await prisma.user.update({
    where: { id: resetToken.userId },
    data: { 
      password: hashedPassword,
      failedLoginAttempts: 0,
      accountLockedUntil: null,
    },
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

  return { message: 'password reset successfully' };
};

// resend verification email
export const resendVerificationEmail = async (email: string) => {
  // find user
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    throw new Error('user not found');
  }

  if (user.emailVerified) {
    throw new Error('email already verified');
  }

  // delete old verification tokens
  await prisma.verificationToken.deleteMany({
    where: { userId: user.id },
  });

  // send new verification email
  return await sendVerificationEmail(user.id, user.email);
};
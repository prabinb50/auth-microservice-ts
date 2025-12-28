import prisma from '../utils/prisma';
import logger from '../utils/logger';
import { Request } from 'express';
import { signAccessToken, signRefreshToken, getRefreshTokenExpiryDate } from '../utils/jwt';
import { saveRefreshToken } from './tokenService';
import { createSession } from './sessionService';
import { createAuditLog } from './auditService';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import env from '../config/env';

// helper function to get ip address
const getIpAddress = (req: Request): string => {
  return (
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    (req.headers['x-real-ip'] as string) ||
    req.ip ||
    req.socket.remoteAddress ||
    'unknown'
  );
};

// request magic login link - supports both new user registration and existing user login
export const requestMagicLink = async (email: string, req: Request) => {
  try {
    logger.info('magic link requested', { email });

    // find user by email
    let user = await prisma.user.findUnique({
      where: { email },
    });

    let isNewUser = false;

    // if user doesn't exist, create a new user (passwordless signup)
    if (!user) {
      logger.info('creating new user via magic link (passwordless)', { email });

      // generate a secure random password (never shown to user)
      const secureRandomPassword = crypto.randomBytes(32).toString('hex');

      // hash the random password
      const hashedPassword = await bcrypt.hash(secureRandomPassword, 10);

      // create new user with auto-verified email (magic link proves ownership)
      user = await prisma.user.create({
        data: {
          email,
          password: hashedPassword, // secure random password
          role: 'USER',
          emailVerified: false, // will be verified upon magic link click
        },
      });

      isNewUser = true;

      logger.info('new user created via magic link', {
        userId: user.id,
        email: user.email,
        isPasswordless: true,
      });

      // log user registration
      await createAuditLog({
        userId: user.id,
        action: 'USER_REGISTER',
        resource: email,
        ipAddress: getIpAddress(req),
        userAgent: req.headers['user-agent'] || null,
        metadata: {
          registrationMethod: 'magic-link',
          passwordless: true,
        },
      });
    } else {
      logger.info('existing user found for magic link', {
        userId: user.id,
        email: user.email,
      });
    }

    // check if account is locked
    if (user.accountLockedUntil) {
      const now = new Date();
      if (user.accountLockedUntil > now) {
        const lockDuration = Math.ceil((user.accountLockedUntil.getTime() - now.getTime()) / 60000);

        logger.warn('magic link requested for locked account', {
          userId: user.id,
          email,
          lockDuration,
        });

        throw new Error(`account is locked. try again in ${lockDuration} minutes`);
      } else {
        // unlock account if lock period expired
        await prisma.user.update({
          where: { id: user.id },
          data: {
            accountLockedUntil: null,
            failedLoginAttempts: 0,
          },
        });

        logger.info('account unlocked automatically', { userId: user.id });
      }
    }

    const ipAddress = getIpAddress(req);
    const userAgent = req.headers['user-agent'] || null;

    // log magic link request
    await createAuditLog({
      userId: user.id,
      action: 'MAGIC_LINK_REQUESTED',
      resource: email,
      ipAddress,
      userAgent,
      metadata: {
        email,
        isNewUser,
        isPasswordless: true,
      },
    });

    // delete any existing unused magic link tokens for this user
    await prisma.magicLinkToken.deleteMany({
      where: {
        userId: user.id,
        used: false,
      },
    });

    logger.info('deleted old unused magic link tokens', { userId: user.id });

    // call email service to generate and send magic link
    const emailServiceUrl = env.services.emailServiceUrl;

    const response = await fetch(`${emailServiceUrl}/email/send-magic-link`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userId: user.id,
        email: user.email,
        ipAddress,
        userAgent,
        isNewUser, // pass this to email service for custom message
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      logger.error('failed to send magic link email', {
        userId: user.id,
        status: response.status,
        error: errorText,
      });
      throw new Error('failed to send magic link email');
    }

    logger.info('magic link email sent successfully', {
      userId: user.id,
      email: user.email,
      isNewUser,
    });

    // log magic link sent
    await createAuditLog({
      userId: user.id,
      action: 'MAGIC_LINK_SENT',
      resource: email,
      ipAddress,
      userAgent,
      metadata: {
        email,
        isNewUser,
        isPasswordless: true,
      },
    });

    // return generic message (security best practice)
    return {
      message: isNewUser
        ? 'account created! a magic login link has been sent to your email'
        : 'a magic login link has been sent to your email',
    };
  } catch (error: any) {
    logger.error('magic link request failed', {
      email,
      error: error.message,
    });
    throw error;
  }
};

// verify magic link token and login user
export const verifyMagicLinkAndLogin = async (token: string, req: Request) => {
  try {
    logger.info('verifying magic link token', {
      token: token.substring(0, 10) + '...',
    });

    // find token in database
    const magicLinkToken = await prisma.magicLinkToken.findUnique({
      where: { token },
      include: { user: true },
    });

    if (!magicLinkToken) {
      logger.warn('invalid magic link token');

      throw new Error('invalid or expired magic link');
    }

    // check if token already used
    if (magicLinkToken.used) {
      logger.warn('magic link token already used', {
        userId: magicLinkToken.userId,
        usedAt: magicLinkToken.usedAt,
      });

      throw new Error('this magic link has already been used');
    }

    // check if token expired
    if (magicLinkToken.expiresAt < new Date()) {
      // delete expired token
      await prisma.magicLinkToken.delete({ where: { token } });

      logger.warn('magic link token expired', {
        userId: magicLinkToken.userId,
        expiresAt: magicLinkToken.expiresAt,
      });

      throw new Error('magic link has expired. please request a new one');
    }

    const user = magicLinkToken.user;

    // check if account is locked
    if (user.accountLockedUntil) {
      const now = new Date();
      if (user.accountLockedUntil > now) {
        const lockDuration = Math.ceil((user.accountLockedUntil.getTime() - now.getTime()) / 60000);

        logger.warn('magic link login attempt for locked account', {
          userId: user.id,
          lockDuration,
        });

        // log failed attempt
        await createAuditLog({
          userId: user.id,
          action: 'MAGIC_LINK_FAILED',
          resource: user.email,
          ipAddress: getIpAddress(req),
          userAgent: req.headers['user-agent'] || null,
          metadata: { reason: 'account locked' },
          success: false,
          errorMessage: 'account is locked',
        });

        throw new Error(`account is locked. try again in ${lockDuration} minutes`);
      }
    }

    const ipAddress = getIpAddress(req);
    const userAgent = req.headers['user-agent'] || null;

    // mark token as used
    await prisma.magicLinkToken.update({
      where: { token },
      data: {
        used: true,
        usedAt: new Date(),
        ipAddress,
        userAgent,
      },
    });

    logger.info('magic link token marked as used', { userId: user.id });

    // update user last login info and auto-verify email
    await prisma.user.update({
      where: { id: user.id },
      data: {
        lastLoginAt: new Date(),
        lastLoginIp: ipAddress,
        failedLoginAttempts: 0,
        accountLockedUntil: null,
        // auto-verify email on magic link login (proves email ownership)
        emailVerified: true,
      },
    });

    logger.info('user last login updated and email verified', { userId: user.id });

    // generate auth tokens with tokenVersion
    const accessToken = signAccessToken(user.id, user.role, user.tokenVersion);
    const refreshToken = signRefreshToken(user.id, user.role, user.tokenVersion);
    const expiresAt = getRefreshTokenExpiryDate();

    // save refresh token to database
    await saveRefreshToken(user.id, refreshToken, expiresAt);

    logger.info('refresh token saved', { userId: user.id });

    // create session
    await createSession(user.id, refreshToken, expiresAt, req);

    logger.info('session created', { userId: user.id });

    // log successful magic link login
    await createAuditLog({
      userId: user.id,
      action: 'MAGIC_LINK_LOGIN',
      resource: user.email,
      ipAddress,
      userAgent,
      metadata: {
        email: user.email,
        emailVerified: true,
        loginMethod: 'passwordless',
      },
    });

    logger.info('magic link login successful', {
      userId: user.id,
      email: user.email,
      role: user.role,
    });

    return {
      message: 'login successful',
      accessToken,
      refreshToken,
      expiresAt,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        emailVerified: user.emailVerified,
      },
    };
  } catch (error: any) {
    logger.error('magic link verification failed', {
      token: token.substring(0, 10) + '...',
      error: error.message,
    });
    throw error;
  }
};

// get magic link token status (for debugging/admin)
export const getMagicLinkTokenStatus = async (userId: string) => {
  try {
    const tokens = await prisma.magicLinkToken.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 10,
      select: {
        id: true,
        used: true,
        usedAt: true,
        expiresAt: true,
        createdAt: true,
        ipAddress: true,
      },
    });

    logger.info('magic link tokens retrieved', {
      userId,
      count: tokens.length,
    });

    return tokens;
  } catch (error: any) {
    logger.error('failed to get magic link token status', {
      userId,
      error: error.message,
    });
    throw error;
  }
};

// cleanup expired magic link tokens
export const cleanupExpiredMagicLinkTokens = async () => {
  try {
    const result = await prisma.magicLinkToken.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });

    logger.info('expired magic link tokens cleaned up', {
      deletedCount: result.count,
    });

    return result.count;
  } catch (error: any) {
    logger.error('failed to cleanup expired magic link tokens', {
      error: error.message,
    });
    throw error;
  }
};
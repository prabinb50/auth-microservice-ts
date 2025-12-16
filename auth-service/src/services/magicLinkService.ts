import prisma from '../utils/prisma';
import logger from '../utils/logger';
import { Request } from 'express';
import { signAccessToken, signRefreshToken, getRefreshTokenExpiryDate } from '../utils/jwt';
import { saveRefreshToken } from './tokenService';
import { createSession } from './sessionService';
import { createAuditLog } from './auditService';

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

// request magic login link
export const requestMagicLink = async (email: string, req: Request) => {
  try {
    logger.info('magic link requested', { email });

    // find user by email
    const user = await prisma.user.findUnique({
      where: { email },
    });

    // don't reveal if user exists or not (security best practice)
    if (!user) {
      logger.warn('magic link requested for non-existent email', { email });
      
      // still return success to prevent email enumeration
      return {
        message: 'if this email is registered, a magic login link has been sent',
      };
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
      metadata: { email },
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
    const emailServiceUrl = process.env.EMAIL_SERVICE_URL || 'http://localhost:8001';
    
    const response = await fetch(`${emailServiceUrl}/email/send-magic-link`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userId: user.id,
        email: user.email,
        ipAddress,
        userAgent,
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
    });

    // log magic link sent
    await createAuditLog({
      userId: user.id,
      action: 'MAGIC_LINK_SENT',
      resource: email,
      ipAddress,
      userAgent,
      metadata: { email },
    });

    return {
      message: 'if this email is registered, a magic login link has been sent',
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

    // update user last login info
    await prisma.user.update({
      where: { id: user.id },
      data: {
        lastLoginAt: new Date(),
        lastLoginIp: ipAddress,
        failedLoginAttempts: 0,
        accountLockedUntil: null,
        // auto-verify email on magic link login
        emailVerified: true,
      },
    });

    logger.info('user last login updated', { userId: user.id });

    // generate auth tokens
    const accessToken = signAccessToken(user.id, user.role);
    const refreshToken = signRefreshToken(user.id, user.role);
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
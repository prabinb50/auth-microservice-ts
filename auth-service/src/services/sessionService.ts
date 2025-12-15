import prisma from '../utils/prisma';
import logger from '../utils/logger';
import { Request } from 'express';
import { UAParser } from 'ua-parser-js';
import { logSessionRevoked } from './auditService';

// create new session
export const createSession = async (
  userId: string,
  refreshToken: string,
  expiresAt: Date,
  req: Request
) => {
  try {
    const parser = new UAParser(req.headers['user-agent']);
    const browser = parser.getBrowser();
    const os = parser.getOS();
    const device = parser.getDevice();

    // get ip address (handle proxy)
    const ipAddress = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() 
                      || req.headers['x-real-ip'] as string
                      || req.ip 
                      || req.socket.remoteAddress 
                      || 'unknown';

    // create session record
    const session = await prisma.session.create({
      data: {
        userId,
        refreshToken,
        expiresAt,
        deviceName: device.model || 'Unknown Device',
        deviceType: device.type || 'desktop',
        browser: browser.name ? `${browser.name} ${browser.version || ''}`.trim() : 'Unknown',
        os: os.name ? `${os.name} ${os.version || ''}`.trim() : 'Unknown',
        ipAddress,
        isActive: true,
        lastActivityAt: new Date(),
      },
    });

    logger.info('session created', {
      sessionId: session.id,
      userId,
      deviceType: session.deviceType,
      browser: session.browser,
      ipAddress: session.ipAddress,
    });

    return session;
  } catch (error: any) {
    logger.error('failed to create session', {
      userId,
      error: error.message,
    });
    throw error;
  }
};

// update session activity
export const updateSessionActivity = async (refreshToken: string) => {
  try {
    await prisma.session.update({
      where: { refreshToken },
      data: { lastActivityAt: new Date() },
    });

    logger.debug('session activity updated', { refreshToken: refreshToken.substring(0, 10) + '...' });
  } catch (error: any) {
    logger.error('failed to update session activity', {
      error: error.message,
    });
  }
};

// get all active sessions for user
export const getUserSessions = async (userId: string) => {
  try {
    const sessions = await prisma.session.findMany({
      where: {
        userId,
        isActive: true,
        expiresAt: { gte: new Date() },
      },
      orderBy: { lastActivityAt: 'desc' },
      select: {
        id: true,
        deviceName: true,
        deviceType: true,
        browser: true,
        os: true,
        ipAddress: true,
        country: true,
        city: true,
        lastActivityAt: true,
        createdAt: true,
        isActive: true,
      },
    });

    logger.info('user sessions retrieved', {
      userId,
      sessionCount: sessions.length,
    });

    return sessions;
  } catch (error: any) {
    logger.error('failed to get user sessions', {
      userId,
      error: error.message,
    });
    throw error;
  }
};

// revoke specific session
export const revokeSession = async (sessionId: string, userId: string, req: Request) => {
  try {
    // find session
    const session = await prisma.session.findFirst({
      where: {
        id: sessionId,
        userId,
      },
    });

    if (!session) {
      throw new Error('session not found');
    }

    // delete refresh token
    await prisma.refreshToken.deleteMany({
      where: { token: session.refreshToken },
    });

    // mark session as inactive
    await prisma.session.update({
      where: { id: sessionId },
      data: { isActive: false },
    });

    logger.info('session revoked', {
      sessionId,
      userId,
    });

    // log session revoked
    await logSessionRevoked(userId, sessionId, req);

    return { message: 'session revoked successfully' };
  } catch (error: any) {
    logger.error('failed to revoke session', {
      sessionId,
      userId,
      error: error.message,
    });
    throw error;
  }
};

// revoke all sessions except current
export const revokeAllOtherSessions = async (userId: string, currentRefreshToken: string) => {
  try {
    // get all sessions except current
    const sessions = await prisma.session.findMany({
      where: {
        userId,
        refreshToken: { not: currentRefreshToken },
        isActive: true,
      },
    });

    // delete all refresh tokens except current
    await prisma.refreshToken.deleteMany({
      where: {
        userId,
        token: { not: currentRefreshToken },
      },
    });

    // mark all other sessions as inactive
    await prisma.session.updateMany({
      where: {
        userId,
        refreshToken: { not: currentRefreshToken },
      },
      data: { isActive: false },
    });

    logger.warn('all other sessions revoked', {
      userId,
      revokedCount: sessions.length,
    });

    return {
      message: 'all other sessions logged out successfully',
      revokedCount: sessions.length,
    };
  } catch (error: any) {
    logger.error('failed to revoke all other sessions', {
      userId,
      error: error.message,
    });
    throw error;
  }
};

// revoke all sessions for user
export const revokeAllSessions = async (userId: string) => {
  try {
    // delete all refresh tokens
    await prisma.refreshToken.deleteMany({
      where: { userId },
    });

    // mark all sessions as inactive
    const result = await prisma.session.updateMany({
      where: { userId, isActive: true },
      data: { isActive: false },
    });

    logger.warn('all sessions revoked', {
      userId,
      revokedCount: result.count,
    });

    return {
      message: 'logged out from all devices successfully',
      revokedCount: result.count,
    };
  } catch (error: any) {
    logger.error('failed to revoke all sessions', {
      userId,
      error: error.message,
    });
    throw error;
  }
};

// cleanup expired sessions
export const cleanupExpiredSessions = async () => {
  try {
    const result = await prisma.session.deleteMany({
      where: {
        expiresAt: { lt: new Date() },
      },
    });

    logger.info('expired sessions cleaned up', {
      deletedCount: result.count,
    });

    return result.count;
  } catch (error: any) {
    logger.error('failed to cleanup expired sessions', {
      error: error.message,
    });
    throw error;
  }
};

// get session by refresh token
export const getSessionByRefreshToken = async (refreshToken: string) => {
  try {
    return await prisma.session.findUnique({
      where: { refreshToken },
    });
  } catch (error: any) {
    logger.error('failed to get session by refresh token', {
      error: error.message,
    });
    return null;
  }
};

// deactivate session
export const deactivateSession = async (refreshToken: string) => {
  try {
    await prisma.session.updateMany({
      where: { refreshToken },
      data: { isActive: false },
    });

    logger.info('session deactivated', {
      refreshToken: refreshToken.substring(0, 10) + '...',
    });
  } catch (error: any) {
    logger.error('failed to deactivate session', {
      error: error.message,
    });
  }
};
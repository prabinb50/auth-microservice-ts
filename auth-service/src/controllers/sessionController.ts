import { Response } from 'express';
import { AuthenticatedRequest } from '../utils/customTypes';
import {
  getUserSessions,
  revokeSession,
  revokeAllOtherSessions,
  revokeAllSessions,
} from '../services/sessionService';
import { getRefreshCookieName } from '../utils/cookie';
import logger from '../utils/logger';
import { logLogoutAllDevices, logLogoutOtherDevices } from '../services/auditService';

// get all active sessions for current user
export const getActiveSessions = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      logger.warn('unauthorized sessions access attempt');
      return res.status(401).json({ message: 'unauthorized' });
    }

    const sessions = await getUserSessions(req.user.userId);

    logger.info('active sessions retrieved', {
      userId: req.user.userId,
      sessionCount: sessions.length,
    });

    return res.status(200).json({
      message: 'active sessions retrieved successfully',
      sessions,
    });
  } catch (error: any) {
    logger.error('get active sessions error', {
      error: error.message,
      userId: req.user?.userId,
    });
    return res.status(500).json({
      message: 'failed to retrieve sessions',
      error: error.message,
    });
  }
};

// revoke specific session
export const revokeSpecificSession = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      logger.warn('unauthorized session revoke attempt');
      return res.status(401).json({ message: 'unauthorized' });
    }

    const { sessionId } = req.params;

    if (!sessionId) {
      return res.status(400).json({
        message: 'session id is required',
      });
    }

    // revokeSession now includes req for audit logging
    const result = await revokeSession(sessionId, req.user.userId, req);

    logger.info('session revoked', {
      sessionId,
      userId: req.user.userId,
    });

    return res.status(200).json(result);
  } catch (error: any) {
    logger.error('revoke session error', {
      error: error.message,
      sessionId: req.params.sessionId,
      userId: req.user?.userId,
    });
    return res.status(500).json({
      message: 'failed to revoke session',
      error: error.message,
    });
  }
};

// logout from all other devices
export const logoutOtherDevices = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      logger.warn('unauthorized logout other devices attempt');
      return res.status(401).json({ message: 'unauthorized' });
    }

    // get current refresh token
    const cookieName = getRefreshCookieName();
    const currentRefreshToken = req.cookies?.[cookieName];

    if (!currentRefreshToken) {
      return res.status(400).json({
        message: 'no active session found',
      });
    }

    const result = await revokeAllOtherSessions(req.user.userId, currentRefreshToken);

    // log logout other devices
    await logLogoutOtherDevices(req.user.userId, result.revokedCount, req);

    logger.info('logged out from other devices', {
      userId: req.user.userId,
      revokedCount: result.revokedCount,
    });

    return res.status(200).json(result);
  } catch (error: any) {
    logger.error('logout other devices error', {
      error: error.message,
      userId: req.user?.userId,
    });
    return res.status(500).json({
      message: 'failed to logout from other devices',
      error: error.message,
    });
  }
};

// logout from all devices
export const logoutAllDevices = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      logger.warn('unauthorized logout all devices attempt');
      return res.status(401).json({ message: 'unauthorized' });
    }

    const result = await revokeAllSessions(req.user.userId);

    // log logout all devices
    await logLogoutAllDevices(req.user.userId, result.revokedCount, req);

    logger.info('logged out from all devices', {
      userId: req.user.userId,
      revokedCount: result.revokedCount,
    });

    return res.status(200).json(result);
  } catch (error: any) {
    logger.error('logout all devices error', {
      error: error.message,
      userId: req.user?.userId,
    });
    return res.status(500).json({
      message: 'failed to logout from all devices',
      error: error.message,
    });
  }
};
import { Request, Response } from 'express';
import { AuthenticatedRequest } from '../utils/customTypes';
import {
  requestMagicLink,
  verifyMagicLinkAndLogin,
  getMagicLinkTokenStatus,
} from '../services/magicLinkService';
import { setRefreshTokenCookie } from '../utils/cookie';
import logger from '../utils/logger';

// request magic login link (handles both new user signup and existing user login)
export const handleMagicLinkRequest = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;

    logger.info('magic link request received', { email });

    const result = await requestMagicLink(email, req);

    logger.info('magic link request processed successfully', { email });

    return res.status(200).json(result);
  } catch (error: any) {
    logger.error('magic link request error', {
      email: req.body.email,
      error: error.message,
    });

    return res.status(400).json({
      message: 'failed to process magic link request',
      error: error.message,
    });
  }
};

// verify magic link token and login
export const handleMagicLinkLogin = async (req: Request, res: Response) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        message: 'magic link token is required',
      });
    }

    logger.info('magic link login attempt', {
      token: token.substring(0, 10) + '...',
    });

    const result = await verifyMagicLinkAndLogin(token, req);

    // set refresh token cookie
    setRefreshTokenCookie(res, result.refreshToken, result.expiresAt);

    logger.info('magic link login successful', {
      userId: result.user.id,
      email: result.user.email,
    });

    return res.status(200).json({
      message: result.message,
      accessToken: result.accessToken,
      user: result.user,
    });
  } catch (error: any) {
    logger.error('magic link login error', {
      token: req.body.token?.substring(0, 10) + '...',
      error: error.message,
    });

    return res.status(400).json({
      message: 'magic link login failed',
      error: error.message,
    });
  }
};

// get magic link token status (authenticated users - own tokens only)
export const handleGetMagicLinkStatus = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ message: 'unauthorized' });
    }

    const tokens = await getMagicLinkTokenStatus(req.user.userId);

    logger.info('magic link status retrieved', {
      userId: req.user.userId,
      count: tokens.length,
    });

    return res.status(200).json({
      message: 'magic link tokens retrieved',
      tokens,
    });
  } catch (error: any) {
    logger.error('get magic link status error', {
      userId: req.user?.userId,
      error: error.message,
    });

    return res.status(500).json({
      message: 'failed to get magic link status',
      error: error.message,
    });
  }
};
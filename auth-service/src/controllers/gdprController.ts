import { Response } from 'express';
import { AuthenticatedRequest } from '../utils/customTypes';
import {
  exportUserData,
  anonymizeUserData,
  permanentlyDeleteUser,
  updateUserEmail,
  getDataRetentionInfo,
} from '../services/gdprService';
import logger from '../utils/logger';

// export user data (gdpr article 15)
export const handleDataExport = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user?.userId) {
      logger.warn('unauthorized data export attempt');
      return res.status(401).json({ message: 'unauthorized' });
    }

    const userId = req.user.userId;

    logger.info('processing gdpr data export request', { userId });

    const data = await exportUserData(userId, req);

    // set headers for file download
    res.setHeader('Content-Type', 'application/json');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename=gdpr-data-export-${userId}-${Date.now()}.json`
    );

    logger.info('gdpr data export completed', { userId });

    return res.status(200).json(data);
  } catch (error: any) {
    logger.error('gdpr data export error', {
      userId: req.user?.userId,
      error: error.message,
    });
    return res.status(500).json({
      message: 'failed to export user data',
      error: error.message,
    });
  }
};

// anonymize user account (gdpr article 17)
export const handleAccountAnonymization = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user?.userId) {
      logger.warn('unauthorized anonymization attempt');
      return res.status(401).json({ message: 'unauthorized' });
    }

    const userId = req.user.userId;
    const { confirmation } = req.body;

    if (confirmation !== 'ANONYMIZE_MY_ACCOUNT') {
      return res.status(400).json({
        message: 'confirmation required',
        error: 'send { confirmation: "ANONYMIZE_MY_ACCOUNT" } to proceed',
      });
    }

    logger.warn('processing account anonymization', { userId });

    const result = await anonymizeUserData(userId, req);

    logger.warn('account anonymization completed', { userId });

    return res.status(200).json(result);
  } catch (error: any) {
    logger.error('account anonymization error', {
      userId: req.user?.userId,
      error: error.message,
    });
    return res.status(500).json({
      message: 'failed to anonymize account',
      error: error.message,
    });
  }
};

// permanently delete user (admin only)
export const handlePermanentDeletion = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user?.userId) {
      logger.warn('unauthorized permanent deletion attempt');
      return res.status(401).json({ message: 'unauthorized' });
    }

    const adminId = req.user.userId;
    const { userId } = req.params;

    if (!userId) {
      return res.status(400).json({
        message: 'user id is required',
      });
    }

    const { confirmation } = req.body;

    if (confirmation !== 'PERMANENTLY_DELETE_USER') {
      return res.status(400).json({
        message: 'confirmation required',
        error: 'send { confirmation: "PERMANENTLY_DELETE_USER" } to proceed',
      });
    }

    // prevent admin from deleting themselves
    if (adminId === userId) {
      return res.status(400).json({
        message: 'cannot delete your own account',
      });
    }

    logger.warn('processing permanent user deletion', {
      targetUserId: userId,
      adminId,
    });

    const result = await permanentlyDeleteUser(userId, adminId, req);

    logger.warn('permanent user deletion completed', {
      targetUserId: userId,
      adminId,
    });

    return res.status(200).json(result);
  } catch (error: any) {
    logger.error('permanent deletion error', {
      targetUserId: req.params.userId,
      adminId: req.user?.userId,
      error: error.message,
    });
    return res.status(500).json({
      message: 'failed to permanently delete user',
      error: error.message,
    });
  }
};

// update user email (gdpr article 16)
export const handleEmailUpdate = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user?.userId) {
      logger.warn('unauthorized email update attempt');
      return res.status(401).json({ message: 'unauthorized' });
    }

    const userId = req.user.userId;
    const { newEmail } = req.body;

    if (!newEmail) {
      return res.status(400).json({
        message: 'new email is required',
      });
    }

    logger.info('processing email update', {
      userId,
      newEmail,
    });

    const result = await updateUserEmail(userId, newEmail, req);

    logger.info('email update completed', { userId });

    return res.status(200).json(result);
  } catch (error: any) {
    logger.error('email update error', {
      userId: req.user?.userId,
      error: error.message,
    });
    return res.status(500).json({
      message: 'failed to update email',
      error: error.message,
    });
  }
};

// get data retention info
export const handleDataRetentionInfo = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user?.userId) {
      logger.warn('unauthorized data retention info request');
      return res.status(401).json({ message: 'unauthorized' });
    }

    const userId = req.user.userId;

    logger.info('fetching data retention info', { userId });

    const info = await getDataRetentionInfo(userId);

    return res.status(200).json({
      message: 'data retention information retrieved',
      ...info,
    });
  } catch (error: any) {
    logger.error('data retention info error', {
      userId: req.user?.userId,
      error: error.message,
    });
    return res.status(500).json({
      message: 'failed to retrieve data retention info',
      error: error.message,
    });
  }
};
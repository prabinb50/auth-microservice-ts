import { Response, Request } from 'express';
import { AuthenticatedRequest } from '../utils/customTypes';
import {
  getUserAuditLogs,
  getAllAuditLogs,
  getAdminActionLogs,
  createAuditLog,
} from '../services/auditService';
import logger from '../utils/logger';

// get audit logs for current user
export const getMyAuditLogs = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      logger.warn('unauthorized audit log access attempt');
      return res.status(401).json({ message: 'unauthorized' });
    }

    const limit = parseInt(req.query.limit as string) || 50;
    const logs = await getUserAuditLogs(req.user.userId, limit);

    logger.info('user audit logs retrieved', {
      userId: req.user.userId,
      count: logs.length,
    });

    return res.status(200).json({
      message: 'audit logs retrieved successfully',
      logs,
    });
  } catch (error: any) {
    logger.error('get user audit logs error', {
      error: error.message,
      userId: req.user?.userId,
    });
    return res.status(500).json({
      message: 'failed to retrieve audit logs',
      error: error.message,
    });
  }
};

// get all audit logs (admin only)
export const getAllAuditLogsHandler = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      logger.warn('unauthorized audit logs access attempt');
      return res.status(401).json({ message: 'unauthorized' });
    }

    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 50;
    const userId = req.query.userId as string;
    const action = req.query.action as any;
    const success = req.query.success === 'true' ? true : req.query.success === 'false' ? false : undefined;

    const filters: any = {};
    if (userId) filters.userId = userId;
    if (action) filters.action = action;
    if (success !== undefined) filters.success = success;

    const result = await getAllAuditLogs(page, limit, filters);

    logger.info('all audit logs retrieved', {
      adminId: req.user.userId,
      page,
      total: result.total,
    });

    return res.status(200).json({
      message: 'audit logs retrieved successfully',
      ...result,
    });
  } catch (error: any) {
    logger.error('get all audit logs error', {
      error: error.message,
      adminId: req.user?.userId,
    });
    return res.status(500).json({
      message: 'failed to retrieve audit logs',
      error: error.message,
    });
  }
};

// get admin action logs (admin only)
export const getAdminActionsHandler = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      logger.warn('unauthorized admin actions access attempt');
      return res.status(401).json({ message: 'unauthorized' });
    }

    const adminId = req.query.adminId as string;
    const limit = parseInt(req.query.limit as string) || 50;

    const logs = await getAdminActionLogs(adminId, limit);

    logger.info('admin action logs retrieved', {
      requesterId: req.user.userId,
      targetAdminId: adminId,
      count: logs.length,
    });

    return res.status(200).json({
      message: 'admin action logs retrieved successfully',
      logs,
    });
  } catch (error: any) {
    logger.error('get admin actions error', {
      error: error.message,
      adminId: req.user?.userId,
    });
    return res.status(500).json({
      message: 'failed to retrieve admin action logs',
      error: error.message,
    });
  }
};

// create audit log (called by email-service)
export const createAuditLogHandler = async (req: Request, res: Response) => {
  try {
    const { userId, action, resource, ipAddress, userAgent, metadata, success, errorMessage } = req.body;

    logger.info('creating audit log from external service', {
      userId,
      action,
      resource
    });

    await createAuditLog({
      userId,
      action,
      resource: resource || null,
      ipAddress: ipAddress || null,
      userAgent: userAgent || null,
      metadata: metadata || {},
      success: success !== undefined ? success : true,
      errorMessage: errorMessage || null,
    });

    logger.info('audit log created successfully', { userId, action });

    return res.status(201).json({
      message: 'audit log created successfully',
    });
  } catch (error: any) {
    logger.error('create audit log error', {
      error: error.message,
      body: req.body
    });
    return res.status(500).json({
      message: 'failed to create audit log',
      error: error.message,
    });
  }
};
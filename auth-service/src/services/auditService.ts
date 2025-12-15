import prisma from '../utils/prisma';
import logger from '../utils/logger';
import { Request } from 'express';

// audit action type
export type AuditAction =
  | 'USER_REGISTER'
  | 'USER_LOGIN'
  | 'USER_LOGOUT'
  | 'USER_LOGOUT_ALL_DEVICES'
  | 'USER_LOGOUT_OTHER_DEVICES'
  | 'EMAIL_VERIFIED'
  | 'PASSWORD_RESET_REQUESTED'
  | 'PASSWORD_RESET_COMPLETED'
  | 'TOKEN_REFRESHED'
  | 'ROLE_CHANGED'
  | 'USER_DELETED'
  | 'USERS_BULK_DELETED'
  | 'SESSION_REVOKED'
  | 'ACCOUNT_LOCKED'
  | 'ACCOUNT_UNLOCKED'
  | 'LOGIN_FAILED'
  | 'VERIFICATION_EMAIL_SENT'
  | 'RESET_EMAIL_SENT';

interface AuditLogData {
  userId: string;
  performedBy?: string | null;
  action: AuditAction;
  resource?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: any;
  success?: boolean;
  errorMessage?: string | null;
}

// create audit log entry
export const createAuditLog = async (data: AuditLogData) => {
  try {
    const auditLog = await prisma.auditLog.create({
      data: {
        userId: data.userId,
        performedBy: data.performedBy ?? null,
        action: data.action,
        resource: data.resource ?? null,
        ipAddress: data.ipAddress ?? null,
        userAgent: data.userAgent ?? null,
        metadata: data.metadata || {},
        success: data.success !== undefined ? data.success : true,
        errorMessage: data.errorMessage ?? null,
      },
    });

    logger.info('audit log created', {
      auditId: auditLog.id,
      action: data.action,
      userId: data.userId,
      success: data.success,
    });

    return auditLog;
  } catch (error: any) {
    logger.error('failed to create audit log', {
      error: error.message,
      action: data.action,
      userId: data.userId,
    });
  }
};

// log user registration
export const logUserRegistration = async (userId: string, email: string, req: Request) => {
  const ipAddress = getIpAddress(req);
  const userAgent = req.headers['user-agent'] || null;

  await createAuditLog({
    userId,
    action: 'USER_REGISTER',
    resource: email,
    ipAddress,
    userAgent,
    metadata: { email },
  });
};

// log successful login
export const logUserLogin = async (userId: string, email: string, req: Request) => {
  const ipAddress = getIpAddress(req);
  const userAgent = req.headers['user-agent'] || null;

  await createAuditLog({
    userId,
    action: 'USER_LOGIN',
    resource: email,
    ipAddress,
    userAgent,
    metadata: { email },
  });
};

// log failed login attempt
export const logLoginFailed = async (userId: string, email: string, reason: string, req: Request) => {
  const ipAddress = getIpAddress(req);
  const userAgent = req.headers['user-agent'] || null;

  await createAuditLog({
    userId,
    action: 'LOGIN_FAILED',
    resource: email,
    ipAddress,
    userAgent,
    metadata: { email, reason },
    success: false,
    errorMessage: reason,
  });
};

// log logout
export const logUserLogout = async (userId: string, req: Request) => {
  const ipAddress = getIpAddress(req);
  const userAgent = req.headers['user-agent'] || null;

  await createAuditLog({
    userId,
    action: 'USER_LOGOUT',
    ipAddress,
    userAgent,
  });
};

// log logout from all devices
export const logLogoutAllDevices = async (userId: string, revokedCount: number, req: Request) => {
  const ipAddress = getIpAddress(req);
  const userAgent = req.headers['user-agent'] || null;

  await createAuditLog({
    userId,
    action: 'USER_LOGOUT_ALL_DEVICES',
    ipAddress,
    userAgent,
    metadata: { revokedCount },
  });
};

// log logout from other devices
export const logLogoutOtherDevices = async (userId: string, revokedCount: number, req: Request) => {
  const ipAddress = getIpAddress(req);
  const userAgent = req.headers['user-agent'] || null;

  await createAuditLog({
    userId,
    action: 'USER_LOGOUT_OTHER_DEVICES',
    ipAddress,
    userAgent,
    metadata: { revokedCount },
  });
};

// log email verification
export const logEmailVerified = async (userId: string, email: string) => {
  await createAuditLog({
    userId,
    action: 'EMAIL_VERIFIED',
    resource: email,
    metadata: { email },
  });
};

// log password reset request
export const logPasswordResetRequested = async (userId: string, email: string, req: Request) => {
  const ipAddress = getIpAddress(req);
  const userAgent = req.headers['user-agent'] || null;

  await createAuditLog({
    userId,
    action: 'PASSWORD_RESET_REQUESTED',
    resource: email,
    ipAddress,
    userAgent,
    metadata: { email },
  });
};

// log password reset completion
export const logPasswordResetCompleted = async (userId: string, email: string, req: Request) => {
  const ipAddress = getIpAddress(req);
  const userAgent = req.headers['user-agent'] || null;

  await createAuditLog({
    userId,
    action: 'PASSWORD_RESET_COMPLETED',
    resource: email,
    ipAddress,
    userAgent,
    metadata: { email },
  });
};

// log token refresh
export const logTokenRefreshed = async (userId: string, req: Request) => {
  const ipAddress = getIpAddress(req);
  const userAgent = req.headers['user-agent'] || null;

  await createAuditLog({
    userId,
    action: 'TOKEN_REFRESHED',
    ipAddress,
    userAgent,
  });
};

// log role change (admin action)
export const logRoleChanged = async (
  targetUserId: string,
  targetEmail: string,
  adminId: string,
  oldRole: string,
  newRole: string,
  req: Request
) => {
  const ipAddress = getIpAddress(req);
  const userAgent = req.headers['user-agent'] || null;

  await createAuditLog({
    userId: targetUserId,
    performedBy: adminId,
    action: 'ROLE_CHANGED',
    resource: targetEmail,
    ipAddress,
    userAgent,
    metadata: {
      targetEmail,
      oldRole,
      newRole,
    },
  });
};

// log user deletion (admin action)
export const logUserDeleted = async (
  targetUserId: string,
  targetEmail: string,
  adminId: string,
  req: Request
) => {
  const ipAddress = getIpAddress(req);
  const userAgent = req.headers['user-agent'] || null;

  await createAuditLog({
    userId: targetUserId,
    performedBy: adminId,
    action: 'USER_DELETED',
    resource: targetEmail,
    ipAddress,
    userAgent,
    metadata: {
      targetEmail,
      deletedBy: adminId,
    },
  });
};

// log bulk user deletion (admin action)
export const logUsersBulkDeleted = async (
  adminId: string,
  deletedCount: number,
  deleteType: string,
  req: Request
) => {
  const ipAddress = getIpAddress(req);
  const userAgent = req.headers['user-agent'] || null;

  await createAuditLog({
    userId: adminId,
    performedBy: adminId,
    action: 'USERS_BULK_DELETED',
    ipAddress,
    userAgent,
    metadata: {
      deletedCount,
      deleteType,
    },
  });
};

// log session revoked
export const logSessionRevoked = async (userId: string, sessionId: string, req: Request) => {
  const ipAddress = getIpAddress(req);
  const userAgent = req.headers['user-agent'] || null;

  await createAuditLog({
    userId,
    action: 'SESSION_REVOKED',
    resource: sessionId,
    ipAddress,
    userAgent,
    metadata: { sessionId },
  });
};

// log account locked
export const logAccountLocked = async (
  userId: string,
  email: string,
  lockUntil: Date,
  req: Request
) => {
  const ipAddress = getIpAddress(req);
  const userAgent = req.headers['user-agent'] || null;

  await createAuditLog({
    userId,
    action: 'ACCOUNT_LOCKED',
    resource: email,
    ipAddress,
    userAgent,
    metadata: {
      email,
      lockUntil,
      reason: 'multiple failed login attempts',
    },
  });
};

// log account unlocked
export const logAccountUnlocked = async (userId: string, email: string) => {
  await createAuditLog({
    userId,
    action: 'ACCOUNT_UNLOCKED',
    resource: email,
    metadata: {
      email,
      reason: 'lock expired',
    },
  });
};

// log verification email sent
export const logVerificationEmailSent = async (userId: string, email: string, req: Request) => {
  const ipAddress = getIpAddress(req);
  const userAgent = req.headers['user-agent'] || null;

  await createAuditLog({
    userId,
    action: 'VERIFICATION_EMAIL_SENT',
    resource: email,
    ipAddress,
    userAgent,
    metadata: { email },
  });
};

// log reset email sent
export const logResetEmailSent = async (userId: string, email: string, req: Request) => {
  const ipAddress = getIpAddress(req);
  const userAgent = req.headers['user-agent'] || null;

  await createAuditLog({
    userId,
    action: 'RESET_EMAIL_SENT',
    resource: email,
    ipAddress,
    userAgent,
    metadata: { email },
  });
};

// get audit logs for user
export const getUserAuditLogs = async (userId: string, limit: number = 50) => {
  return await prisma.auditLog.findMany({
    where: { userId },
    orderBy: { createdAt: 'desc' },
    take: limit,
    select: {
      id: true,
      action: true,
      resource: true,
      ipAddress: true,
      metadata: true,
      success: true,
      errorMessage: true,
      createdAt: true,
      admin: {
        select: {
          id: true,
          email: true,
        },
      },
    },
  });
};

// get all audit logs (admin only)
export const getAllAuditLogs = async (
  page: number = 1,
  limit: number = 50,
  filters?: {
    userId?: string;
    action?: AuditAction;
    success?: boolean;
    startDate?: Date;
    endDate?: Date;
  }
) => {
  const where: any = {};

  if (filters?.userId) {
    where.userId = filters.userId;
  }

  if (filters?.action) {
    where.action = filters.action;
  }

  if (filters?.success !== undefined) {
    where.success = filters.success;
  }

  if (filters?.startDate || filters?.endDate) {
    where.createdAt = {};
    if (filters.startDate) {
      where.createdAt.gte = filters.startDate;
    }
    if (filters.endDate) {
      where.createdAt.lte = filters.endDate;
    }
  }

  const [logs, total] = await Promise.all([
    prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip: (page - 1) * limit,
      take: limit,
      include: {
        user: {
          select: {
            id: true,
            email: true,
            role: true,
          },
        },
        admin: {
          select: {
            id: true,
            email: true,
            role: true,
          },
        },
      },
    }),
    prisma.auditLog.count({ where }),
  ]);

  return {
    logs,
    total,
    page,
    limit,
    totalPages: Math.ceil(total / limit),
  };
};

// get admin action logs
export const getAdminActionLogs = async (adminId?: string, limit: number = 50) => {
  const where: any = {
    performedBy: adminId ? adminId : { not: null },
  };

  return await prisma.auditLog.findMany({
    where,
    orderBy: { createdAt: 'desc' },
    take: limit,
    include: {
      user: {
        select: {
          id: true,
          email: true,
          role: true,
        },
      },
      admin: {
        select: {
          id: true,
          email: true,
          role: true,
        },
      },
    },
  });
};

// helper to get ip address
const getIpAddress = (req: Request): string => {
  return (
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    (req.headers['x-real-ip'] as string) ||
    req.ip ||
    req.socket.remoteAddress ||
    'unknown'
  );
};
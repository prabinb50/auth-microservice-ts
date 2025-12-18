import prisma from '../utils/prisma';
import logger from '../utils/logger';
import { Request } from 'express';
import { createAuditLog } from './auditService';

// interface for user consent
interface UserConsent {
  marketing: boolean;
  analytics: boolean;
  functional: boolean;
  updatedAt: Date;
}

// interface for gdpr data export
interface GdprDataExport {
  personalData: {
    id: string;
    email: string;
    role: string;
    emailVerified: boolean;
    createdAt: Date;
    updatedAt: Date;
    lastLoginAt: Date | null;
    lastLoginIp: string | null;
  };
  sessions: any[];
  auditLogs: any[];
  consents: UserConsent | null;
  refreshTokens: {
    id: string;
    createdAt: Date;
    expiresAt: Date;
  }[];
  exportDate: Date;
  retentionPeriod: string;
}

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

// export all user data (gdpr article 15 - right to access)
export const exportUserData = async (userId: string, req: Request): Promise<GdprDataExport> => {
  try {
    logger.info('gdpr data export initiated', { userId });

    // fetch user data
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        role: true,
        emailVerified: true,
        createdAt: true,
        updatedAt: true,
        lastLoginAt: true,
        lastLoginIp: true,
      },
    });

    if (!user) {
      throw new Error('user not found');
    }

    // fetch sessions
    const sessions = await prisma.session.findMany({
      where: { userId },
      select: {
        id: true,
        deviceName: true,
        deviceType: true,
        browser: true,
        os: true,
        ipAddress: true,
        country: true,
        city: true,
        isActive: true,
        lastActivityAt: true,
        createdAt: true,
        expiresAt: true,
      },
    });

    // fetch audit logs
    const auditLogs = await prisma.auditLog.findMany({
      where: { userId },
      select: {
        id: true,
        action: true,
        resource: true,
        ipAddress: true,
        userAgent: true,
        metadata: true,
        success: true,
        errorMessage: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    // fetch refresh tokens (without actual token values for security)
    const refreshTokens = await prisma.refreshToken.findMany({
      where: { userId },
      select: {
        id: true,
        createdAt: true,
        expiresAt: true,
      },
    });

    // construct gdpr export
    const gdprExport: GdprDataExport = {
      personalData: user,
      sessions,
      auditLogs,
      consents: null, // will be implemented when consent table is added
      refreshTokens,
      exportDate: new Date(),
      retentionPeriod: process.env.AUDIT_LOG_RETENTION_DAYS || '90 days',
    };

    // log data export
    await createAuditLog({
      userId,
      action: 'USER_DATA_EXPORTED',
      ipAddress: getIpAddress(req),
      userAgent: req.headers['user-agent'] || null,
      metadata: {
        exportedSections: ['personalData', 'sessions', 'auditLogs', 'refreshTokens'],
        recordCounts: {
          sessions: sessions.length,
          auditLogs: auditLogs.length,
          refreshTokens: refreshTokens.length,
        },
      },
    });

    logger.info('gdpr data export completed', {
      userId,
      sessionCount: sessions.length,
      auditLogCount: auditLogs.length,
    });

    return gdprExport;
  } catch (error: any) {
    logger.error('gdpr data export failed', {
      userId,
      error: error.message,
    });
    throw error;
  }
};

// anonymize user data (gdpr article 17 - right to erasure)
export const anonymizeUserData = async (userId: string, req: Request) => {
  try {
    logger.warn('gdpr user anonymization initiated', { userId });

    // get user email before deletion for audit
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { email: true },
    });

    if (!user) {
      throw new Error('user not found');
    }

    // create final audit log before anonymization
    await createAuditLog({
      userId,
      action: 'USER_DATA_ANONYMIZED',
      resource: user.email,
      ipAddress: getIpAddress(req),
      userAgent: req.headers['user-agent'] || null,
      metadata: {
        reason: 'gdpr right to erasure request',
        originalEmail: user.email,
      },
    });

    // anonymize audit logs (keep for legal compliance but remove identifiable data)
    await prisma.auditLog.updateMany({
      where: { userId },
      data: {
        resource: 'anonymized',
        ipAddress: 'anonymized',
        userAgent: 'anonymized',
        metadata: { anonymized: true },
      },
    });

    // delete all user sessions
    await prisma.session.deleteMany({
      where: { userId },
    });

    // delete all refresh tokens
    await prisma.refreshToken.deleteMany({
      where: { userId },
    });

    // delete verification tokens
    await prisma.verificationToken.deleteMany({
      where: { userId },
    });

    // delete password reset tokens
    await prisma.passwordResetToken.deleteMany({
      where: { userId },
    });

    // delete magic link tokens
    await prisma.magicLinkToken.deleteMany({
      where: { userId },
    });

    // anonymize user record (keep for audit trail but remove personal data)
    await prisma.user.update({
      where: { id: userId },
      data: {
        email: `anonymized_${userId}@deleted.local`,
        password: 'anonymized',
        emailVerified: false,
        lastLoginIp: null,
        lastLoginAt: null,
        failedLoginAttempts: 0,
        accountLockedUntil: null,
      },
    });

    logger.warn('gdpr user anonymization completed', {
      userId,
      originalEmail: user.email,
    });

    return {
      message: 'user data anonymized successfully',
      userId,
      anonymizedAt: new Date(),
    };
  } catch (error: any) {
    logger.error('gdpr user anonymization failed', {
      userId,
      error: error.message,
    });
    throw error;
  }
};

// permanently delete user (complete erasure)
export const permanentlyDeleteUser = async (userId: string, adminId: string, req: Request) => {
  try {
    logger.warn('gdpr permanent user deletion initiated', { userId, adminId });

    // get user data for final audit
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { email: true, role: true },
    });

    if (!user) {
      throw new Error('user not found');
    }

    // create system-level audit log (not linked to user since user will be deleted)
    await createAuditLog({
      userId: adminId,
      performedBy: adminId,
      action: 'USER_PERMANENTLY_DELETED',
      resource: user.email,
      ipAddress: getIpAddress(req),
      userAgent: req.headers['user-agent'] || null,
      metadata: {
        deletedUserId: userId,
        deletedUserEmail: user.email,
        deletedUserRole: user.role,
        reason: 'gdpr permanent deletion',
      },
    });

    // delete user (cascade will delete all related data)
    await prisma.user.delete({
      where: { id: userId },
    });

    logger.warn('gdpr permanent user deletion completed', {
      userId,
      email: user.email,
      adminId,
    });

    return {
      message: 'user permanently deleted',
      deletedUserId: userId,
      deletedAt: new Date(),
    };
  } catch (error: any) {
    logger.error('gdpr permanent user deletion failed', {
      userId,
      adminId,
      error: error.message,
    });
    throw error;
  }
};

// update user email (gdpr article 16 - right to rectification)
export const updateUserEmail = async (
  userId: string,
  newEmail: string,
  req: Request
) => {
  try {
    logger.info('updating user email', { userId, newEmail });

    // check if email already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: newEmail },
    });

    if (existingUser && existingUser.id !== userId) {
      throw new Error('email already in use');
    }

    // get current email
    const currentUser = await prisma.user.findUnique({
      where: { id: userId },
      select: { email: true },
    });

    if (!currentUser) {
      throw new Error('user not found');
    }

    // delete old verification tokens
    await prisma.verificationToken.deleteMany({
      where: { userId },
    });

    // update email and mark as unverified
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: {
        email: newEmail,
        emailVerified: false,
      },
    });

    // log email update
    await createAuditLog({
      userId,
      action: 'EMAIL_UPDATED',
      resource: newEmail,
      ipAddress: getIpAddress(req),
      userAgent: req.headers['user-agent'] || null,
      metadata: {
        oldEmail: currentUser.email,
        newEmail,
      },
    });

    logger.info('email updated in database', {
      userId,
      oldEmail: currentUser.email,
      newEmail,
    });

    // call email service to send verification email for new address
    try {
      const emailServiceUrl = process.env.EMAIL_SERVICE_URL || 'http://localhost:8001';
      
      logger.info('calling email service to send verification', {
        userId,
        newEmail,
        emailServiceUrl,
      });

      const response = await fetch(`${emailServiceUrl}/email/send-verification`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: updatedUser.id,
          email: newEmail,
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        logger.error('failed to send verification email to new address', {
          userId,
          newEmail,
          status: response.status,
          error: errorText,
        });
        throw new Error('failed to send verification email');
      }

      logger.info('verification email sent to new address', {
        userId,
        newEmail,
      });
    } catch (emailError: any) {
      logger.error('error calling email service', {
        userId,
        newEmail,
        error: emailError.message,
      });
      throw new Error('email updated but verification email failed to send');
    }

    logger.info('user email update completed successfully', {
      userId,
      oldEmail: currentUser.email,
      newEmail,
    });

    return {
      message: 'email updated successfully. please verify your new email address.',
      user: {
        id: updatedUser.id,
        email: updatedUser.email,
        emailVerified: updatedUser.emailVerified,
      },
    };
  } catch (error: any) {
    logger.error('user email update failed', {
      userId,
      error: error.message,
    });
    throw error;
  }
};

// get data retention info
export const getDataRetentionInfo = async (userId: string) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        createdAt: true,
        updatedAt: true,
        lastLoginAt: true,
      },
    });

    if (!user) {
      throw new Error('user not found');
    }

    const retentionDays = parseInt(process.env.AUDIT_LOG_RETENTION_DAYS || '90');
    const auditLogCutoff = new Date();
    auditLogCutoff.setDate(auditLogCutoff.getDate() - retentionDays);

    return {
      accountCreated: user.createdAt,
      lastUpdated: user.updatedAt,
      lastLogin: user.lastLoginAt,
      dataRetention: {
        auditLogs: `${retentionDays} days`,
        auditLogCutoffDate: auditLogCutoff,
        personalData: 'retained until account deletion',
        sessions: 'retained until expiry or logout',
      },
      gdprRights: [
        'right to access (data export)',
        'right to rectification (update personal data)',
        'right to erasure (anonymization or deletion)',
        'right to data portability (json export)',
        'right to object (opt-out of processing)',
      ],
    };
  } catch (error: any) {
    logger.error('failed to get data retention info', {
      userId,
      error: error.message,
    });
    throw error;
  }
};
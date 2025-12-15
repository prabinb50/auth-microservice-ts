import dotenv from 'dotenv';
dotenv.config();

import prisma from '../src/utils/prisma';
import logger from '../src/utils/logger';

// cleanup old audit logs based on retention policy
async function cleanupOldAuditLogs() {
  try {
    const retentionDays = parseInt(process.env.AUDIT_LOG_RETENTION_DAYS || '90');
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    logger.info('starting audit logs cleanup', { 
      retentionDays, 
      cutoffDate 
    });

    const result = await prisma.auditLog.deleteMany({
      where: {
        createdAt: {
          lt: cutoffDate,
        },
      },
    });

    logger.info('audit logs cleanup completed', { 
      deletedCount: result.count,
      retentionDays 
    });

    console.log(`✅ Cleanup completed: ${result.count} audit logs deleted (older than ${retentionDays} days)`);
    process.exit(0);
  } catch (error: any) {
    logger.error('audit logs cleanup failed', { error: error.message });
    console.error('❌ Cleanup failed:', error.message);
    process.exit(1);
  }
}

cleanupOldAuditLogs();
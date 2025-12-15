import dotenv from 'dotenv';
dotenv.config();

import prisma from '../src/utils/prisma';
import logger from '../src/utils/logger';

// cleanup expired sessions
async function cleanupExpiredSessions() {
  try {
    logger.info('starting expired sessions cleanup');

    const result = await prisma.session.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });

    logger.info('expired sessions cleanup completed', { 
      deletedCount: result.count 
    });

    console.log(`✅ Cleanup completed: ${result.count} expired sessions deleted`);
    process.exit(0);
  } catch (error: any) {
    logger.error('sessions cleanup failed', { error: error.message });
    console.error('❌ Cleanup failed:', error.message);
    process.exit(1);
  }
}

cleanupExpiredSessions();
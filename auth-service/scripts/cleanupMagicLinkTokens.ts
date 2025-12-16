import dotenv from 'dotenv';
dotenv.config();

import prisma from '../src/utils/prisma';
import logger from '../src/utils/logger';

// cleanup expired and used magic link tokens
async function cleanupMagicLinkTokens() {
  try {
    logger.info('starting magic link tokens cleanup');

    const now = new Date();

    // delete expired tokens
    const expiredResult = await prisma.magicLinkToken.deleteMany({
      where: {
        expiresAt: {
          lt: now,
        },
      },
    });

    logger.info('expired magic link tokens deleted', {
      count: expiredResult.count,
    });

    // delete used tokens older than 7 days (for audit trail)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const usedResult = await prisma.magicLinkToken.deleteMany({
      where: {
        used: true,
        usedAt: {
          lt: sevenDaysAgo,
        },
      },
    });

    logger.info('old used magic link tokens deleted', {
      count: usedResult.count,
    });

    const totalDeleted = expiredResult.count + usedResult.count;

    logger.info('magic link tokens cleanup completed', {
      totalDeleted,
      expired: expiredResult.count,
      oldUsed: usedResult.count,
    });

    console.log(`✅ cleanup completed: ${totalDeleted} magic link tokens deleted`);
    console.log(`   - expired: ${expiredResult.count}`);
    console.log(`   - old used tokens: ${usedResult.count}`);

    process.exit(0);
  } catch (error: any) {
    logger.error('magic link tokens cleanup failed', {
      error: error.message,
    });
    console.error('❌ cleanup failed:', error.message);
    process.exit(1);
  }
}

cleanupMagicLinkTokens();
import { PrismaClient } from "../generated/prisma";
import logger from "./logger";

// ensure database url is defined
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  logger.error('DATABASE_URL environment variable is not defined');
  throw new Error('DATABASE_URL environment variable is not defined');
}

// create singleton prisma instance
const globalForPrisma = global as unknown as { prisma: PrismaClient };

const prisma = globalForPrisma.prisma || new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
  datasources: {
    db: {
      url: databaseUrl,
    },
  },
});

// store instance globally in development to prevent hot-reload issues
if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = prisma;
}

// handle initial connection
prisma.$connect()
  .then(() => {
    logger.info('database connected successfully');
  })
  .catch((error) => {
    logger.error('database connection failed', { 
      error: error.message,
      stack: error.stack 
    });
    process.exit(1);
  });

// graceful shutdown handlers
const disconnect = async (): Promise<void> => {
  await prisma.$disconnect();
  logger.info('database disconnected');
};

process.on('SIGINT', async () => {
  await disconnect();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await disconnect();
  process.exit(0);
});

export default prisma;
export { disconnect };
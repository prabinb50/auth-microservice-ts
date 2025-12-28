import dotenv from 'dotenv';
import path from 'path';

// load environment variables from .env file
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

// validate required environment variables
const requiredEnvVars = [
  'DATABASE_URL',
  'JWT_ACCESS_SECRET',
  'JWT_REFRESH_SECRET',
];

const missingEnvVars = requiredEnvVars.filter((key) => !process.env[key]);

if (missingEnvVars.length > 0) {
  throw new Error(
    `missing required environment variables: ${missingEnvVars.join(', ')}`
  );
}

// helper function to parse boolean
const parseBoolean = (value: string | undefined, defaultValue: boolean): boolean => {
  if (!value) return defaultValue;
  return value.toLowerCase() === 'true';
};

// helper function to parse integer
const parseInteger = (value: string | undefined, defaultValue: number): number => {
  if (!value) return defaultValue;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? defaultValue : parsed;
};

// helper function to parse float
const parseFloat = (value: string | undefined, defaultValue: number): number => {
  if (!value) return defaultValue;
  const parsed = Number(value);
  return isNaN(parsed) ? defaultValue : parsed;
};

// centralized environment configuration
export const env = {
  // node environment
  nodeEnv: process.env.NODE_ENV || 'development',
  isDevelopment: (process.env.NODE_ENV || 'development') === 'development',
  isProduction: process.env.NODE_ENV === 'production',

  // server configuration
  server: {
    port: parseInteger(process.env.PORT, 8000),
    host: process.env.HOST || 'localhost',
  },

  // database configuration
  database: {
    url: process.env.DATABASE_URL as string,
    connectionPoolSize: parseInteger(process.env.DB_CONNECTION_POOL_SIZE, 20),
    connectionTimeout: parseInteger(process.env.DB_CONNECTION_TIMEOUT, 10000),
    poolTimeout: parseInteger(process.env.DB_POOL_TIMEOUT, 10000),
  },

  // jwt configuration
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET as string,
    refreshSecret: process.env.JWT_REFRESH_SECRET as string,
    accessTokenExpiry: process.env.ACCESS_TOKEN_EXPIRES || '15m',
    refreshTokenExpiry: process.env.REFRESH_TOKEN_EXPIRES || '7d',
  },

  // cookie configuration
  cookie: {
    name: process.env.REFRESH_COOKIE_NAME || 'jid',
  },

  // external services
  services: {
    emailServiceUrl: process.env.EMAIL_SERVICE_URL || 'http://localhost:8001',
  },

  // frontend configuration
  client: {
    url: process.env.CLIENT_URL || 'http://localhost:5173',
  },

  // cors configuration
  cors: {
    allowedOrigins: process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(',').map((origin) => origin.trim())
      : ['http://localhost:5173'],
  },

  // logging configuration
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    filePath: process.env.LOG_FILE_PATH || './logs/auth-service.log',
    maxSize: process.env.LOG_MAX_SIZE || '10m',
    maxFiles: process.env.LOG_MAX_FILES || '14d',
  },

  // audit configuration
  audit: {
    retentionDays: parseInteger(process.env.AUDIT_LOG_RETENTION_DAYS, 90),
  },

  // sentry configuration
  sentry: {
    dsn: process.env.SENTRY_DSN || '',
    environment: process.env.SENTRY_ENVIRONMENT || 'development',
    enabled: parseBoolean(process.env.SENTRY_ENABLED, false),
    tracesSampleRate: parseFloat(process.env.SENTRY_TRACES_SAMPLE_RATE, 1.0),
    profilesSampleRate: parseFloat(process.env.SENTRY_PROFILES_SAMPLE_RATE, 1.0),
  },

  // magic link configuration
  magicLink: {
    expiryMinutes: parseInteger(process.env.MAGIC_LINK_EXPIRY_MINUTES, 15),
  },
} as const;

// prevent runtime mutation
Object.freeze(env);

export default env;
import dotenv from 'dotenv';
import path from 'path';

// load environment variables from .env file
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

// validate required environment variables
const requiredEnvVars = [
  'DATABASE_URL',

  // SMTP (provider-level variables)
  'SMTP_HOST',
  'SMTP_PORT',
  'SMTP_APP_USERNAME',
  'SMTP_APP_PASSWORD',

  // Optional but recommended
  'SMTP_FROM_EMAIL',
  'SMTP_FROM_NAME',
];

const missingEnvVars = requiredEnvVars.filter(
  (key) => !process.env[key]
);

if (missingEnvVars.length > 0) {
  throw new Error(
    `Missing required environment variables: ${missingEnvVars.join(', ')}`
  );
}

// helper function to parse boolean
const parseBoolean = (
  value: string | undefined,
  defaultValue: boolean
): boolean => {
  if (value === undefined) return defaultValue;
  return value.toLowerCase() === 'true';
};

// helper function to parse integer
const parseInteger = (
  value: string | undefined,
  defaultValue: number
): number => {
  if (!value) return defaultValue;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? defaultValue : parsed;
};

// helper function to parse float
const parseFloatValue = (
  value: string | undefined,
  defaultValue: number
): number => {
  if (!value) return defaultValue;
  const parsed = Number(value);
  return isNaN(parsed) ? defaultValue : parsed;
};

// centralized environment configuration
export const env = {
  /* ------------------------------ Node env ------------------------------ */
  nodeEnv: process.env.NODE_ENV || 'development',
  isDevelopment: (process.env.NODE_ENV || 'development') === 'development',
  isProduction: process.env.NODE_ENV === 'production',

  /* ----------------------------- Server config --------------------------- */
  server: {
    port: parseInteger(process.env.EMAIL_SERVICE_PORT, 8001),
    host: process.env.HOST || 'localhost',
  },

  /* ---------------------------- Database config --------------------------- */
  database: {
    url: process.env.DATABASE_URL as string,
    connectionPoolSize: parseInteger(process.env.DB_CONNECTION_POOL_SIZE, 20),
    connectionTimeout: parseInteger(process.env.DB_CONNECTION_TIMEOUT, 10000),
    poolTimeout: parseInteger(process.env.DB_POOL_TIMEOUT, 10000),
  },

  /* ----------------------------- Email config ----------------------------- */
  email: {
    host: process.env.SMTP_HOST as string,
    port: parseInteger(process.env.SMTP_PORT, 587),

    auth: {
      user: process.env.SMTP_APP_USERNAME as string,
      pass: process.env.SMTP_APP_PASSWORD as string,
    },

    from: {
      email:
        process.env.SMTP_FROM_EMAIL ||
        (process.env.SMTP_APP_USERNAME as string),
      name: process.env.SMTP_FROM_NAME || 'FUSOBOTICS RECRUITMENT',
    },

    secure: parseBoolean(process.env.EMAIL_SECURE, false),
  },

  /* -------------------------- external services --------------------------- */
  services: {
    authServiceUrl:
      process.env.AUTH_SERVICE_URL || 'http://localhost:8000',
  },

  /* ---------------------------- frontend config --------------------------- */
  client: {
    url: process.env.CLIENT_URL || 'http://localhost:5173',
  },

  /* ------------------------------- CORS ---------------------------------- */
  cors: {
    allowedOrigins: process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim())
      : ['http://localhost:5173', 'http://localhost:3000'],
  },

  /* ------------------------------ token config ---------------------------- */
  tokens: {
    secret: process.env.EMAIL_TOKEN_SECRET || 'f3c9e7b1c0a24f8d89e4d12f7a56cbe2b4cd8f7a93d1e56ea4c0b6bfe12d9ca7',
    verificationExpiry: process.env.VERIFICATION_TOKEN_EXPIRY || '24h',
    resetExpiry: process.env.RESET_TOKEN_EXPIRY || '1h',
    magicLinkExpiry: process.env.MAGIC_LINK_TOKEN_EXPIRY || '15m',
  },

  /* ------------------------------ logging -------------------------------- */
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    filePath: process.env.LOG_FILE_PATH || './logs/email-service.log',
    maxSize: process.env.LOG_MAX_SIZE || '10m',
    maxFiles: process.env.LOG_MAX_FILES || '14d',
  },

  /* ------------------------------ sentry --------------------------------- */
  sentry: {
    dsn: process.env.SENTRY_DSN || '',
    environment: process.env.SENTRY_ENVIRONMENT || 'development',
    enabled: parseBoolean(process.env.SENTRY_ENABLED, false),
    tracesSampleRate: parseFloatValue(process.env.SENTRY_TRACES_SAMPLE_RATE, 1.0),
    profilesSampleRate: parseFloatValue(process.env.SENTRY_PROFILES_SAMPLE_RATE, 1.0),
  },
} as const;

// prevent runtime mutation
Object.freeze(env);

export default env;

import 'dotenv/config';

import { initSentry, captureException } from './src/config/sentry';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import emailRoutes from './src/routes/emailRoutes';
import { sanitizeInput } from './src/middlewares/sanitize';
import { apiRateLimiter } from './src/middlewares/rateLimiter';
import logger, { morganStream } from './src/utils/logger';
import { requestLogger } from './src/utils/requestLogger';
import env from './src/config/env';

initSentry();

const app = express();

// trust proxy (required for https redirection behind reverse proxy)
app.set('trust proxy', 1);

/* ------------------------------- HTTPS ENFORCE ------------------------------- */
if (env.isProduction) {
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.header('x-forwarded-proto') !== 'https') {
      logger.warn('redirecting http to https', {
        url: req.url,
        ip: req.ip,
      });
      return res.redirect(301, `https://${req.header('host')}${req.url}`);
    }
    next();
  });
}

/* ------------------------------- SECURITY HEADERS ---------------------------- */
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    frameguard: { action: 'deny' },
    noSniff: true,
    xssFilter: true,
  })
);

/* -------------------------------- LOGGING ----------------------------------- */
app.use(morgan('combined', { stream: morganStream }));
app.use(requestLogger);

/* --------------------------------- MIDDLEWARES ------------------------------- */
app.use(compression());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(sanitizeInput);

/* ----------------------------------- CORS ------------------------------------ */
const allowedOrigins = [
  env.client.url,
  env.services.authServiceUrl,
  ...env.cors.allowedOrigins,
];

const uniqueAllowedOrigins = [...new Set(allowedOrigins)];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true); 

      if (uniqueAllowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      logger.warn('cors policy blocked request', { origin });
      return callback(
        new Error(
          'the cors policy for this site does not allow access from the specified origin.'
        ),
        false
      );
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    maxAge: 86400,
    preflightContinue: false,
    optionsSuccessStatus: 204,
  })
);

app.disable('x-powered-by');

/* -------------------------------- RATE LIMITER ------------------------------- */
app.use(apiRateLimiter);

/* ----------------------------------- ROUTES ---------------------------------- */
app.use('/email', emailRoutes);

app.get('/', (_req: Request, res: Response) => {
  logger.info('health check accessed');
  res.status(200).json({
    status: 'ok',
    service: 'email-service',
    timestamp: new Date().toISOString(),
  });
});

/* ---------------------------------- 404 HANDLER ------------------------------ */
app.use((req: Request, res: Response) => {
  logger.warn('endpoint not found', {
    path: req.originalUrl,
    method: req.method,
    ip: req.ip,
  });

  res.status(404).json({
    message: 'endpoint not found',
    path: req.originalUrl,
  });
});

/* ------------------------------- GLOBAL ERROR HANDLER ------------------------ */
app.use((err: any, req: Request, res: Response, _next: NextFunction) => {
  logger.error('global error handler', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
  });

  if (process.env.SENTRY_ENABLED === 'true') {
    captureException(err, {
      url: req.url,
      method: req.method,
      ip: req.ip,
    });
  }

  const errorResponse = {
    message: err.message || 'internal server error',
    ...(env.isDevelopment && {
      stack: err.stack,
      error: err,
    }),
  };

  res.status(err.status || 500).json(errorResponse);
});

/* ------------------------------- START SERVER -------------------------------- */
app.listen(env.server.port, env.server.host, () => {
  logger.info('email service started', {
    port: env.server.port,
    host: env.server.host,
    environment: env.nodeEnv,
    sentryEnabled: process.env.SENTRY_ENABLED === 'true',
  });
});

/* ------------------------------- GRACEFUL SHUTDOWN --------------------------- */
const gracefulShutdown = () => {
  logger.info('received shutdown signal, closing server gracefully');

  if (process.env.SENTRY_ENABLED === 'true') {
    const Sentry = require('./src/config/sentry').default;
    Sentry.close(2000).then(() => {
      logger.info('sentry flushed');
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

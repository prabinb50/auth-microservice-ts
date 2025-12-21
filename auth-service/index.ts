import 'dotenv/config';

import { initSentry } from './src/config/sentry';
initSentry();

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import authRoutes from './src/routes/authRoutes';
import cookieParser from 'cookie-parser';
import { sanitizeInput } from './src/middlewares/sanitize';
import { apiRateLimiter } from './src/middlewares/loginRateLimiter';
import logger, { morganStream } from './src/utils/logger';
import { requestLogger } from './src/utils/requestLogger';
import { captureException } from './src/config/sentry';

// configure the server
const app = express();

// trust proxy (for production behind nginx/cloudflare)
app.set('trust proxy', 1);

// enforce https in production
if (process.env.NODE_ENV === 'production') {
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

// security headers with helmet
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
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true,
    },
    frameguard: {
      action: 'deny',
    },
    noSniff: true,
    xssFilter: true,
  })
);

// logging middleware with winston
app.use(morgan('combined', { stream: morganStream }));

// custom request logger
app.use(requestLogger);

// compression middleware
app.use(compression());

// middleware for json with size limit
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// input sanitization
app.use(sanitizeInput);

// middleware for cookies
app.use(cookieParser());

// cors configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map((origin) => origin.trim())
  : ['http://localhost:5173'];

app.use(
  cors({
    origin: (origin, callback) => {
      // allow requests with no origin (mobile apps, postman, etc.)
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      logger.warn('cors policy blocked request', { origin });
      const msg =
        'the cors policy for this site does not allow access from the specified origin.';
      return callback(new Error(msg), false);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['set-cookie'],
    maxAge: 86400, // 24 hours
    preflightContinue: false,
    optionsSuccessStatus: 204,
  })
);

// disable x-powered-by header
app.disable('x-powered-by');

// apply general rate limiting to all routes
app.use(apiRateLimiter);

// routes
app.use('/auth', authRoutes);

// health check endpoint
app.get('/', (_req: Request, res: Response) => {
  logger.info('health check accessed');
  res.status(200).json({
    status: 'ok',
    service: 'auth-service',
    timestamp: new Date().toISOString(),
  });
});

// 404 handler
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

// global error handler
app.use((err: any, req: Request, res: Response, _next: NextFunction) => {
  // log error
  logger.error('global error handler', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
  });

  // send error to sentry 
  if (process.env.SENTRY_ENABLED === 'true') {
    captureException(err, {
      url: req.url,
      method: req.method,
      ip: req.ip,
      userId: (req as any).user?.id,
    });
  }

  // don't leak error details in production
  const errorResponse = {
    message: err.message || 'internal server error',
    ...(process.env.NODE_ENV === 'development' && {
      stack: err.stack,
      error: err,
    }),
  };

  res.status(err.status || 500).json(errorResponse);
});

const PORT = process.env.PORT || 8000;
const HOST = process.env.HOST || 'localhost';

app.listen(PORT, () => {
  logger.info('auth service started', {
    port: PORT,
    host: HOST,
    environment: process.env.NODE_ENV || 'development',
    sentryEnabled: process.env.SENTRY_ENABLED === 'true',
  });
});

// graceful shutdown
const gracefulShutdown = () => {
  logger.info('received shutdown signal, closing server gracefully');
  
  // close sentry and wait for events to flush
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
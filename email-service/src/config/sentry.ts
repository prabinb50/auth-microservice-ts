import * as Sentry from '@sentry/node';
import logger from '../utils/logger';

// check if sentry is enabled
const isSentryEnabled = process.env.SENTRY_ENABLED === 'true' && !!process.env.SENTRY_DSN;

// initialize sentry
export const initSentry = () => {
  if (!isSentryEnabled) {
    logger.info('sentry is disabled or dsn not configured');
    return;
  }

  try {
    Sentry.init({
      dsn: process.env.SENTRY_DSN,
      environment: process.env.SENTRY_ENVIRONMENT || 'development',

      // performance & profiling 
      tracesSampleRate: parseFloat(process.env.SENTRY_TRACES_SAMPLE_RATE || '1.0'),
      profilesSampleRate: parseFloat(process.env.SENTRY_PROFILES_SAMPLE_RATE || '1.0'),

      // enable performance monitoring
      enableTracing: true,

      // sanitize sensitive data
      beforeSend(event) {
        // remove sensitive headers
        if (event.request?.headers) {
          delete event.request.headers.authorization;
          delete event.request.headers.cookie;
        }

        // remove passwords from request data
        if (event.request?.data) {
          try {
            const data =
              typeof event.request.data === 'string'
                ? JSON.parse(event.request.data)
                : event.request.data;

            if (data?.newPassword) {
              data.newPassword = '[REDACTED]';
              event.request.data =
                typeof event.request.data === 'string'
                  ? JSON.stringify(data)
                  : data;
            }
          } catch {
            // ignore json parsing errors
          }
        }

        return event;
      },

      // ignore business logic errors (not bugs)
      ignoreErrors: [
        'invalid verification token',
        'verification token expired',
        'email already verified',
        'invalid reset token',
        'reset token expired',
        'reset token already used',
        'user not found',
      ],

      // release tracking
      release: process.env.npm_package_version || '1.0.0',
    });

    logger.info('sentry initialized successfully', {
      environment: process.env.SENTRY_ENVIRONMENT,
      tracesSampleRate: process.env.SENTRY_TRACES_SAMPLE_RATE,
      profilesSampleRate: process.env.SENTRY_PROFILES_SAMPLE_RATE,
    });
  } catch (error: any) {
    logger.error('failed to initialize sentry', { error: error.message });
  }
};

// capture exception manually
export const captureException = (error: Error, context?: Record<string, any>) => {
  if (!isSentryEnabled) return;

  Sentry.captureException(error, {
    contexts: context ? { custom: context } : undefined,
  });
};

// capture message manually
export const captureMessage = (
  message: string,
  level: Sentry.SeverityLevel = 'info',
  context?: Record<string, any>
) => {
  if (!isSentryEnabled) return;

  Sentry.captureMessage(message, {
    level,
    contexts: context ? { custom: context } : undefined,
  });
};

// add breadcrumb for tracking user actions
export const addBreadcrumb = (breadcrumb: Sentry.Breadcrumb) => {
  if (!isSentryEnabled) return;
  Sentry.addBreadcrumb(breadcrumb);
};

// export sentry for middleware usage
export default Sentry;
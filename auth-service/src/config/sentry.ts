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

  const dsn = process.env.SENTRY_DSN;
  if (!dsn) {
    logger.warn('sentry dsn not configured');
    return;
  }

  try {
    Sentry.init({
      dsn: dsn, 
      environment: process.env.SENTRY_ENVIRONMENT || 'development',

      // performance & profiling 
      tracesSampleRate: parseFloat(process.env.SENTRY_TRACES_SAMPLE_RATE || '1.0'),
      profilesSampleRate: parseFloat(process.env.SENTRY_PROFILES_SAMPLE_RATE || '1.0'),

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

            if (data?.password) {
              data.password = '[REDACTED]';
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
        'unauthorized',
        'invalid credentials',
        'user not found',
        'email not verified',
        'account locked',
        'refresh token missing',
        'invalid or expired token',
        'too many failed attempts',
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

  if (context) {
    Sentry.captureException(error, { extra: context });
  } else {
    Sentry.captureException(error);
  }
};

// capture message manually
export const captureMessage = (
  message: string,
  level: Sentry.SeverityLevel = 'info',
  context?: Record<string, any>
) => {
  if (!isSentryEnabled) return;

  if (context) {
    Sentry.captureMessage(message, { level, extra: context });
  } else {
    Sentry.captureMessage(message, level);
  }
};

// set user context for error tracking
export const setUserContext = (user: {
  id: string;
  email: string;
  role: string;
}) => {
  if (!isSentryEnabled) return;

  Sentry.setUser({
    id: user.id,
    email: user.email,
    role: user.role,
  });
};

// clear user context (on logout)
export const clearUserContext = () => {
  if (!isSentryEnabled) return;
  Sentry.setUser(null);
};

// add breadcrumb for tracking user actions
export const addBreadcrumb = (breadcrumb: Sentry.Breadcrumb) => {
  if (!isSentryEnabled) return;
  Sentry.addBreadcrumb(breadcrumb);
};

// export sentry for middleware usage
export default Sentry;
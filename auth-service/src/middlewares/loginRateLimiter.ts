import rateLimit from "express-rate-limit";

// rate limiter for login endpoint
export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each ip to 5 login requests per window
  message: {
    message: "too many login attempts from this ip, please try again after 15 minutes"
  },
  standardHeaders: true, // return rate limit info in ratelimit-* headers
  legacyHeaders: false, // disable x-ratelimit-* headers
  skipSuccessfulRequests: false,
  skipFailedRequests: false,
  handler: (req, res) => {
    res.status(429).json({
      message: "too many login attempts from this ip",
      retryAfter: "15 minutes"
    });
  },
});

// general api rate limiter
export const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each ip to 100 requests per window
  message: {
    message: "too many requests from this ip, please try again later"
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      message: "too many requests from this ip",
      retryAfter: "15 minutes"
    });
  },
});

// strict rate limiter for registration
export const registerRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // limit each ip to 3 registration attempts per hour
  message: {
    message: "too many registration attempts from this ip"
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // don't count successful registrations
  handler: (req, res) => {
    res.status(429).json({
      message: "too many registration attempts from this ip",
      retryAfter: "1 hour"
    });
  },
});

// rate limiter for password reset
export const passwordResetRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // limit to 3 password reset requests per hour
  message: {
    message: "too many password reset attempts"
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      message: "too many password reset attempts from this ip",
      retryAfter: "1 hour"
    });
  },
});
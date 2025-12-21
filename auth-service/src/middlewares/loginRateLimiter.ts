import rateLimit from "express-rate-limit";

// rate limiter for login endpoint
export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each ip to 5 login requests per window
  message: {
    message: "too many login attempts from this ip, please try again after 15 minutes"
  },
  standardHeaders: true, 
  legacyHeaders: false, 
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
    windowMs: 15 * 60 * 1000, 
    max: 100, 
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
  windowMs: 60 * 60 * 1000, 
  max: 3, 
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
  windowMs: 60 * 60 * 1000, 
  max: 3, 
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
import rateLimit from "express-rate-limit";

// general api rate limiter for email service
export const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // limit each ip to 50 requests per window
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

// rate limiter for sending emails
export const emailSendRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // limit to 5 emails per hour per ip
  message: {
    message: "too many email requests"
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      message: "too many email requests from this ip",
      retryAfter: "1 hour"
    });
  },
});

// rate limiter for verification attempts
export const verificationRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit to 10 verification attempts per 15 minutes
  message: {
    message: "too many verification attempts"
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      message: "too many verification attempts",
      retryAfter: "15 minutes"
    });
  },
});
import nodemailer from 'nodemailer';
import logger from './logger';

// create reusable transporter
export const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.EMAIL_PORT || '587'),
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// verify connection on startup
transporter.verify()
  .then(() => {
    logger.info('email-service: smtp connection verified successfully');
  })
  .catch((error) => {
    logger.error('email-service: smtp connection verification failed', { error: error.message });
  });
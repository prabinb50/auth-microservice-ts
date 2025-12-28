import nodemailer from 'nodemailer';
import logger from './logger';
import { env } from '../config/env';

// create reusable transporter
export const transporter = nodemailer.createTransport({
  host: env.email.host,
  port: env.email.port,
  secure: env.email.secure, 
  // secure: false, 
  // secure: process.env.EMAIL_SECURE === 'true', 
  auth: {
    user: env.email.auth.user,
    pass: env.email.auth.pass,
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
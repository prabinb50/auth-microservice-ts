import nodemailer from 'nodemailer';

// create reusable transporter
export const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.EMAIL_PORT || '587'),
  secure: process.env.EMAIL_SECURE === 'true', // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// verify connection on startup
transporter.verify((error: any) => {
  if (error) {
    console.error('smtp connection error:', error);
  } else {
    console.log('email service ready to send emails');
  }
});
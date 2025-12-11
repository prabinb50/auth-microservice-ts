// verification email template
export const verificationEmailTemplate = (verificationLink: string, userName: string = 'User'): string => {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .button { 
          display: inline-block; 
          padding: 12px 24px; 
          background-color: #007bff; 
          color: #ffffff; 
          text-decoration: none; 
          border-radius: 4px; 
          margin: 20px 0;
        }
        .footer { margin-top: 30px; font-size: 12px; color: #666; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>verify your email address</h2>
        <p>hello ${userName},</p>
        <p>thank you for registering! please verify your email address by clicking the button below:</p>
        <a href="${verificationLink}" class="button">verify email</a>
        <p>or copy and paste this link into your browser:</p>
        <p>${verificationLink}</p>
        <p>this link will expire in 24 hours.</p>
        <div class="footer">
          <p>if you didn't create this account, please ignore this email.</p>
        </div>
      </div>
    </body>
    </html>
  `;
};

// password reset email template
export const passwordResetEmailTemplate = (resetLink: string, userName: string = 'User'): string => {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .button { 
          display: inline-block; 
          padding: 12px 24px; 
          background-color: #dc3545; 
          color: #ffffff; 
          text-decoration: none; 
          border-radius: 4px; 
          margin: 20px 0;
        }
        .warning { 
          background-color: #fff3cd; 
          border-left: 4px solid #ffc107; 
          padding: 12px; 
          margin: 20px 0;
        }
        .footer { margin-top: 30px; font-size: 12px; color: #666; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>reset your password</h2>
        <p>hello ${userName},</p>
        <p>we received a request to reset your password. click the button below to set a new password:</p>
        <a href="${resetLink}" class="button">reset password</a>
        <p>or copy and paste this link into your browser:</p>
        <p>${resetLink}</p>
        <div class="warning">
          <strong>security note:</strong> this link will expire in 1 hour.
        </div>
        <div class="footer">
          <p>if you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
        </div>
      </div>
    </body>
    </html>
  `;
};
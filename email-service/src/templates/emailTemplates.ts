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

// magic login link email template
export const magicLinkEmailTemplate = (magicLink: string, userName: string = 'User'): string => {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9; }
        .content { background-color: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .button { 
          display: inline-block; 
          padding: 14px 28px; 
          background-color: #28a745; 
          color: #ffffff !important; 
          text-decoration: none; 
          border-radius: 6px; 
          margin: 20px 0;
          font-weight: bold;
          font-size: 16px;
        }
        .button:hover {
          background-color: #218838;
        }
        .info-box { 
          background-color: #e7f3ff; 
          border-left: 4px solid #007bff; 
          padding: 15px; 
          margin: 20px 0;
          border-radius: 4px;
        }
        .warning { 
          background-color: #fff3cd; 
          border-left: 4px solid #ffc107; 
          padding: 15px; 
          margin: 20px 0;
          border-radius: 4px;
        }
        .footer { margin-top: 30px; font-size: 12px; color: #666; text-align: center; }
        .link-text {
          word-break: break-all;
          background-color: #f4f4f4;
          padding: 10px;
          border-radius: 4px;
          font-family: monospace;
          font-size: 12px;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="content">
          <h2 style="color: #28a745; margin-top: 0;">🔐 your magic login link</h2>
          <p>hello ${userName},</p>
          <p>you requested a magic login link to access your account. click the button below to log in instantly without a password:</p>
          
          <div style="text-align: center;">
            <a href="${magicLink}" class="button">login instantly</a>
          </div>

          <div class="info-box">
            <strong>💡 what is a magic link?</strong><br>
            magic links let you log in securely without typing a password. just click the link and you're in!
          </div>

          <p>or copy and paste this link into your browser:</p>
          <div class="link-text">${magicLink}</div>

          <div class="warning">
            <strong>⚠️ security notes:</strong><br>
            • this link will expire in <strong>15 minutes</strong><br>
            • the link can only be used <strong>once</strong><br>
            • anyone with this link can access your account - keep it private
          </div>

          <div class="footer">
            <p><strong>didn't request this link?</strong></p>
            <p>if you didn't request a magic login link, please ignore this email. your account is still secure.</p>
            <p style="margin-top: 20px; color: #999;">
              this is an automated email from auth service. please do not reply to this email.
            </p>
          </div>
        </div>
      </div>
    </body>
    </html>
  `;
};
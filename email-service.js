/**
 * Email Utility Module
 * Handles sending emails via Mailjet API
 */

let mailjet = null;

/**
 * Get or initialize Mailjet connection
 * @returns {Object} Mailjet connection instance
 * @throws {Error} If API keys are not configured
 */
function getMailjetClient() {
  if (!mailjet) {
    if (!process.env.MJ_APIKEY_PUBLIC || !process.env.MJ_APIKEY_PRIVATE) {
      throw new Error('Mailjet API keys not configured. Set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE in environment variables.');
    }
    mailjet = require('node-mailjet').connect(
      process.env.MJ_APIKEY_PUBLIC,
      process.env.MJ_APIKEY_PRIVATE
    );
  }
  return mailjet;
}

/**
 * Send email verification link
 * @param {string} userEmail - Recipient email address
 * @param {string} verificationToken - Unique verification token
 * @param {string} userName - User's full name
 * @returns {Promise<Object>} Result from Mailjet API
 */
async function sendVerificationEmail(userEmail, verificationToken, userName) {
  try {
    const client = getMailjetClient();
    const verificationLink = `${process.env.BASE_URL || 'http://localhost:3000'}/verify-email?token=${verificationToken}`;

    const request = client
      .post('send', { version: 'v3.1' })
      .request({
        Messages: [
          {
            From: {
              Email: process.env.FROM_EMAIL || 'noreply@attendence.app',
              Name: 'Attendance Management System'
            },
            To: [
              {
                Email: userEmail,
                Name: userName
              }
            ],
            Subject: 'Verify Your Email - Attendance System',
            TextPart: `Hello ${userName},\n\nPlease verify your email address by clicking the link below:\n\n${verificationLink}\n\nThis link will expire in 24 hours.\n\nIf you did not register for an account, please ignore this email.\n\nBest regards,\nAttendance Management System`,
            HTMLPart: `
              <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                  <h2>Email Verification Required</h2>
                  <p>Hello <strong>${userName}</strong>,</p>
                  <p>Thank you for registering with the Attendance Management System. Please verify your email address to activate your account.</p>
                  
                  <div style="margin: 30px 0;">
                    <a href="${verificationLink}" style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
                      Verify Email Address
                    </a>
                  </div>
                  
                  <p>Or copy this link in your browser:</p>
                  <p style="background-color: #f5f5f5; padding: 10px; word-break: break-all; border-radius: 4px;">
                    ${verificationLink}
                  </p>
                  
                  <p style="color: #666; font-size: 14px;">
                    <strong>Note:</strong> This verification link will expire in 24 hours. If you need a new verification email, please try registering again.
                  </p>
                  
                  <p style="color: #666; font-size: 12px;">
                    If you did not register for this account, please ignore this email.
                  </p>
                  
                  <hr style="border: none; border-top: 1px solid #ddd; margin-top: 40px;">
                  <p style="color: #999; font-size: 12px;">
                    Attendance Management System | BRACU
                  </p>
                </body>
              </html>
            `
          }
        ]
      });

    const result = await request;
    console.log('[Email] Verification email sent successfully to:', userEmail);
    return { success: true, messageId: result.body.Messages[0].ID };
  } catch (error) {
    console.error('[Email] Error sending verification email:', error.message);
    throw error;
  }
}

/**
 * Send password reset email
 * @param {string} userEmail - Recipient email address
 * @param {string} resetToken - Unique reset token
 * @param {string} userName - User's full name
 * @returns {Promise<Object>} Result from Mailjet API
 */
async function sendPasswordResetEmail(userEmail, resetToken, userName) {
  try {
    const client = getMailjetClient();
    const resetLink = `${process.env.BASE_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;

    const request = client
      .post('send', { version: 'v3.1' })
      .request({
        Messages: [
          {
            From: {
              Email: process.env.FROM_EMAIL || 'noreply@attendence.app',
              Name: 'Attendance Management System'
            },
            To: [
              {
                Email: userEmail,
                Name: userName
              }
            ],
            Subject: 'Password Reset - Attendance System',
            TextPart: `Hello ${userName},\n\nYou requested a password reset. Click the link below to reset your password:\n\n${resetLink}\n\nThis link will expire in 1 hour.\n\nIf you did not request this, please ignore this email.\n\nBest regards,\nAttendance Management System`,
            HTMLPart: `
              <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                  <h2>Password Reset Request</h2>
                  <p>Hello <strong>${userName}</strong>,</p>
                  <p>You requested a password reset for your account. Click the button below to create a new password.</p>
                  
                  <div style="margin: 30px 0;">
                    <a href="${resetLink}" style="background-color: #28a745; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
                      Reset Password
                    </a>
                  </div>
                  
                  <p style="color: #666; font-size: 14px;">
                    <strong>Note:</strong> This password reset link will expire in 1 hour.
                  </p>
                  
                  <p style="color: #666; font-size: 12px;">
                    If you did not request this password reset, please ignore this email. Your account is still secure.
                  </p>
                  
                  <hr style="border: none; border-top: 1px solid #ddd; margin-top: 40px;">
                  <p style="color: #999; font-size: 12px;">
                    Attendance Management System | BRACU
                  </p>
                </body>
              </html>
            `
          }
        ]
      });

    const result = await request;
    console.log('[Email] Password reset email sent successfully to:', userEmail);
    return { success: true, messageId: result.body.Messages[0].ID };
  } catch (error) {
    console.error('[Email] Error sending password reset email:', error.message);
    throw error;
  }
}

/**
 * Send account notification email
 * @param {string} userEmail - Recipient email address
 * @param {string} userName - User's full name
 * @param {string} subject - Email subject
 * @param {string} message - Email message
 * @returns {Promise<Object>} Result from Mailjet API
 */
async function sendNotificationEmail(userEmail, userName, subject, message) {
  try {
    const client = getMailjetClient();

    const request = client
      .post('send', { version: 'v3.1' })
      .request({
        Messages: [
          {
            From: {
              Email: process.env.FROM_EMAIL || 'noreply@attendence.app',
              Name: 'Attendance Management System'
            },
            To: [
              {
                Email: userEmail,
                Name: userName
              }
            ],
            Subject: subject,
            TextPart: message,
            HTMLPart: `
              <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                  <h2>${subject}</h2>
                  <p>Hello <strong>${userName}</strong>,</p>
                  <p>${message}</p>
                  
                  <hr style="border: none; border-top: 1px solid #ddd; margin-top: 40px;">
                  <p style="color: #999; font-size: 12px;">
                    Attendance Management System | BRACU
                  </p>
                </body>
              </html>
            `
          }
        ]
      });

    const result = await request;
    console.log('[Email] Notification email sent successfully to:', userEmail);
    return { success: true, messageId: result.body.Messages[0].ID };
  } catch (error) {
    console.error('[Email] Error sending notification email:', error.message);
    throw error;
  }
}

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendNotificationEmail
};

import bcrypt from "bcryptjs";
import { connectDB } from "../lib/db.js";
import { getTransporter } from "../lib/mailer.js";
import { sendSmsOtp } from "../lib/msg91.js";
import PasswordReset from "../models/PasswordReset.js";
import UserAuth from "../models/UserAuth.js";
import { withSentry } from "../lib/sentry.js";

/**
 * Find a user by member_id or mobile number.
 * Searches the shared 'users' MongoDB collection directly.
 */
async function findUserByIdOrMobile(input) {
  // Try member_id first (exact match)
  let u = await UserAuth.findOne({ member_id: input }).select('member_id name email mobile password_hash role').lean();
  if (u) return u;

  // Try mobile lookup (all common formats)
  const digits = input.replace(/\D/g, '');
  const last10 = digits.slice(-10);
  if (last10.length >= 10) {
    u = await UserAuth.findOne({
      mobile: { $in: [last10, '+91' + last10, '91' + last10, '0' + last10, digits] }
    }).select('member_id name email mobile password_hash role').lean();
  }
  return u || null;
}

/**
 * Combined password handler
 * POST /api/password?action=forgot        → sends OTP to member's email/SMS
 * POST /api/password?action=reset         → verifies OTP and resets password
 * POST /api/password?action=reset-default → resets to Welcome@123 (no OTP needed)
 *
 * Uses MongoDB directly — no Railway dependency.
 */
async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const action = req.query.action || req.body?.action;

  /* ── FORGOT PASSWORD (Send OTP) ─────────────────────────────── */
  if (action === "forgot") {
    try {
      await connectDB();

      const { memberId } = req.body;
      if (!memberId) {
        return res.status(400).json({ error: "Member ID is required" });
      }

      console.log(`[password/forgot] Looking up user for: ${memberId}`);

      const u = await findUserByIdOrMobile(memberId);
      if (!u) {
        return res.status(404).json({ error: "Member/Supporter ID ya registered mobile nahi mila. Apna Member ID (FWF-XXXXXX / FWSS-XXXX) ya 10-digit mobile number enter karein." });
      }

      const { email, mobile, member_id: effectiveMemberId } = u;

      // Must have at least email OR mobile to send OTP
      if (!email && !mobile) {
        return res.status(422).json({ error: "Account mein koi email ya mobile nahi hai. Admin se contact karein." });
      }

      // Generate 6-digit OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

      // Store OTP — email may be null if no email, that's ok for SMS-only
      await PasswordReset.create({ memberId: effectiveMemberId, email: email || `mobile_${mobile}`, otp, expiresAt, used: false });

      // Send SMS OTP via MSG91
      if (mobile) {
        try {
          const smsResult = await sendSmsOtp({ mobile, otp, type: 'forgot' });
          if (smsResult?.type === 'success') console.log(`✅ SMS OTP sent to ${mobile}`);
          else console.warn('⚠️ MSG91 SMS OTP result:', JSON.stringify(smsResult));
        } catch (smsErr) {
          console.error('⚠️ MSG91 forgot-password SMS failed:', smsErr.message);
        }
      }

      // Send OTP email (only if email exists)
      if (email) {
        try {
          const mailFrom = process.env.MAIL_FROM || 'FWF <noreply@fwfindia.org>';
          const transporter = getTransporter();
          await transporter.sendMail({
            from: mailFrom,
            to: email,
            subject: "Password Reset OTP - FWF",
            html: `
              <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 12px 12px 0 0; text-align: center;">
                  <h1 style="color: #ffffff; margin: 0; font-size: 28px;">Password Reset Request</h1>
                </div>
                <div style="background: #f8f9fa; padding: 40px 30px; border-radius: 0 0 12px 12px;">
                  <p style="color: #333; font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
                    Hello <strong>${effectiveMemberId}</strong>,
                  </p>
                  <p style="color: #333; font-size: 16px; line-height: 1.6; margin-bottom: 30px;">
                    We received a request to reset your password. Use the OTP below to complete the process:
                  </p>
                  <div style="background: #ffffff; border: 2px dashed #667eea; border-radius: 8px; padding: 20px; text-align: center; margin-bottom: 30px;">
                    <div style="font-size: 14px; color: #666; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 1px;">Your OTP Code</div>
                    <div style="font-size: 36px; font-weight: bold; color: #667eea; letter-spacing: 8px;">${otp}</div>
                  </div>
                  <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
                    <p style="color: #856404; font-size: 14px; margin: 0;">
                      <strong>⚠️ Important:</strong> This OTP will expire in 15 minutes. If you didn't request this, please ignore this email.
                    </p>
                  </div>
                  <p style="color: #666; font-size: 14px; line-height: 1.6; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
                    Best regards,<br><strong>Foundris Welfare Foundation Team</strong>
                  </p>
                </div>
              </div>
            `
          });
          console.log(`[password/forgot] OTP email sent to ${email}`);
        } catch (mailErr) {
          console.error(`[password/forgot] Email FAILED for ${effectiveMemberId}:`, mailErr.message);
          if (!mobile) {
            // No SMS fallback → can't deliver OTP → abort
            await PasswordReset.deleteOne({ memberId: effectiveMemberId, otp }).catch(() => {});
            return res.status(503).json({ error: `Email delivery failed: ${mailErr.message}` });
          }
          // If SMS was also sent, continue even if email fails
          console.warn('[password/forgot] Email failed but SMS sent — continuing');
        }
      }

      const maskedEmail = email ? email.replace(/(.{2})(.*)(@.*)/, "$1***$3") : null;
      const maskedMobile = mobile ? String(mobile).replace(/\D/g,'').slice(-10).replace(/(\d{2})(\d+)(\d{2})/, '$1***$3') : null;

      return res.json({
        ok: true,
        message: "OTP sent" + (email ? " to your registered email" : "") + (mobile ? (email ? " & SMS" : " via SMS") : ""),
        actualMemberId: effectiveMemberId,
        email: maskedEmail,
        mobile: maskedMobile
      });

    } catch (error) {
      console.error("[password/forgot] Unexpected error:", error.message, error.stack);
      return res.status(500).json({ error: "Something went wrong. Please try again." });
    }
  }

  /* ── RESET PASSWORD (Verify OTP & Update) ───────────────────── */
  if (action === "reset") {
    try {
      await connectDB();

      const { memberId, otp, newPassword } = req.body;

      if (!memberId || !otp || !newPassword) {
        return res.status(400).json({ error: "All fields are required" });
      }

      if (newPassword.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters" });
      }

      // Find valid OTP
      const resetRequest = await PasswordReset.findOne({
        memberId,
        otp,
        used: false,
        expiresAt: { $gt: new Date() }
      }).sort({ createdAt: -1 });

      if (!resetRequest) {
        return res.status(400).json({ error: "Invalid or expired OTP" });
      }

      // Update password directly in MongoDB
      const u = await findUserByIdOrMobile(memberId);
      if (!u) {
        return res.status(404).json({ error: "User not found" });
      }

      const newHash = await bcrypt.hash(newPassword, 10);
      await UserAuth.updateOne({ _id: u._id }, { $set: { password_hash: newHash } });

      // Mark OTP as used
      resetRequest.used = true;
      await resetRequest.save();
      console.log(`[password/reset] Password updated for ${memberId}`);

      return res.json({
        ok: true,
        message: "Password reset successful! You can now login with your new password."
      });

    } catch (error) {
      console.error("[password/reset] Error:", error);
      return res.status(500).json({ error: "Failed to reset password. Please try again." });
    }
  }

  /* ── RESET TO DEFAULT PASSWORD (No OTP required) ───────────── */
  if (action === "reset-default") {
    try {
      await connectDB();

      const { memberId } = req.body;
      if (!memberId) {
        return res.status(400).json({ error: "Member ID is required" });
      }

      const u = await findUserByIdOrMobile(memberId);
      if (!u) {
        return res.status(404).json({ error: "Member/Supporter ID ya registered mobile nahi mila. Apna Member ID (FWF-XXXXXX / FWSS-XXXX) ya 10-digit mobile number enter karein." });
      }

      const newHash = await bcrypt.hash("Welcome@123", 10);
      await UserAuth.updateOne({ _id: u._id }, { $set: { password_hash: newHash } });

      console.log(`[password/reset-default] Password reset to default for ${u.member_id}`);
      return res.json({
        ok: true,
        message: "Password reset to default (Welcome@123). Please login and change it immediately."
      });

    } catch (error) {
      console.error("[password/reset-default] Error:", error);
      return res.status(500).json({ error: "Failed to reset password. Please try again." });
    }
  }

  return res.status(400).json({ error: "Invalid action. Use ?action=forgot or ?action=reset" });
}

export default withSentry(handler);


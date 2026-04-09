import { connectDB } from "../lib/db.js";
import { getTransporter } from "../lib/mailer.js";
import { sendSmsOtp } from "../lib/msg91.js";
import PasswordReset from "../models/PasswordReset.js";
import { withSentry } from "../lib/sentry.js";

/**
 * Combined password handler
 * POST /api/password?action=forgot  → sends OTP to member's email
 * POST /api/password?action=reset   → verifies OTP and resets password
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

      const backendUrl = process.env.BACKEND_URL || "https://fwf-production.up.railway.app";
      console.log(`[password/forgot] Looking up email for ${memberId} via ${backendUrl}`);

      const internalKey = process.env.INTERNAL_API_KEY;
      let response;
      try {
        response = await fetch(`${backendUrl}/api/auth/get-user-email`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-internal-api-key": internalKey
          },
          body: JSON.stringify({ memberId })
        });
      } catch (fetchErr) {
        console.error(`[password/forgot] Failed to reach backend:`, fetchErr.message);
        return res.status(502).json({ error: "Could not connect to authentication server. Please try again later." });
      }

      if (response.status === 403) {
        console.error('[password/forgot] Internal API key rejected by backend — check INTERNAL_API_KEY env var on Vercel');
        return res.status(503).json({ error: "Authentication service misconfigured. Contact support." });
      }
      if (!response.ok) {
        return res.status(404).json({ error: "Member/Supporter ID ya registered mobile nahi mila. Apna Member ID (FWF-XXXXXX) ya Supporter ID (FWSS-XXXX) enter karein." });
      }

      const { email, mobile, memberId: actualMemberId } = await response.json();
      const effectiveMemberId = actualMemberId || memberId;

      // Generate 6-digit OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

      await PasswordReset.create({ memberId: effectiveMemberId, email, otp, expiresAt, used: false });

      // Send SMS OTP via MSG91 (awaited so Vercel doesn't kill it early)
      if (mobile) {
        try {
          const smsResult = await sendSmsOtp({ mobile, otp, type: 'forgot' });
          if (smsResult?.type === 'success') console.log(`✅ SMS OTP sent to ${mobile}`);
          else console.warn('⚠️ MSG91 SMS OTP result:', JSON.stringify(smsResult));
        } catch (smsErr) {
          console.error('⚠️ MSG91 forgot-password SMS failed:', smsErr.message);
        }
      }

      // Send OTP email
      try {
        const mailFrom = process.env.MAIL_FROM || 'FWF <noreply@fwfindia.org>';
        console.log(`[password/forgot] Sending OTP email to ${email} from ${mailFrom} (RESEND_API_KEY set: ${!!process.env.RESEND_API_KEY})`);
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
        console.error(`[password/forgot] Email FAILED for ${memberId}:`, mailErr.message, mailErr.stack || '');
        // Delete the OTP record since we couldn't deliver it
        await PasswordReset.deleteOne({ memberId: effectiveMemberId, otp }).catch(() => {});
        return res.status(503).json({ error: `Email delivery failed: ${mailErr.message}` });
      }

      return res.json({
        ok: true,
        message: "OTP sent to your registered email" + (mobile ? " & SMS" : ""),
        actualMemberId: effectiveMemberId,
        email: email.replace(/(.{2})(.*)(@.*)/, "$1***$3"),
        mobile: mobile ? String(mobile).replace(/\D/g,'').slice(-10).replace(/(\d{2})(\d+)(\d{2})/, '$1***$3') : null
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

      // Update password in backend
      const backendUrl = process.env.BACKEND_URL || "https://fwf-production.up.railway.app";
      console.log(`[password/reset] Updating password for ${memberId} via ${backendUrl}`);

      const internalKey = process.env.INTERNAL_API_KEY;
      let response;
      try {
        response = await fetch(`${backendUrl}/api/auth/update-password`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-internal-api-key": internalKey
          },
          body: JSON.stringify({ memberId, newPassword })
        });
      } catch (fetchErr) {
        console.error(`[password/reset] Failed to reach backend:`, fetchErr.message);
        return res.status(502).json({ error: "Could not connect to authentication server. Please try again later." });
      }

      if (response.status === 403) {
        console.error('[password/reset] Internal API key rejected by backend — check INTERNAL_API_KEY env var on Vercel');
        return res.status(503).json({ error: "Authentication service misconfigured. Contact support." });
      }
      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        return res.status(400).json({ error: error.error || "Failed to update password" });
      }

      // Mark OTP as used only after successful update
      resetRequest.used = true;
      await resetRequest.save();
      console.log(`[password/reset] Password updated successfully for ${memberId}`);

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
      const { memberId } = req.body;
      if (!memberId) {
        return res.status(400).json({ error: "Member ID is required" });
      }

      const backendUrl = process.env.BACKEND_URL || "https://fwf-production.up.railway.app";
      const internalKey = process.env.INTERNAL_API_KEY;

      // Verify member exists first
      let verifyRes;
      try {
        verifyRes = await fetch(`${backendUrl}/api/auth/get-user-email`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-internal-api-key": internalKey },
          body: JSON.stringify({ memberId })
        });
      } catch (fetchErr) {
        return res.status(502).json({ error: "Could not connect to authentication server. Please try again later." });
      }

      if (verifyRes.status === 403) {
        return res.status(503).json({ error: "Authentication service misconfigured. Contact support." });
      }
      if (!verifyRes.ok) {
        return res.status(404).json({ error: "Member/Supporter ID ya registered mobile nahi mila. Apna Member ID (FWF-XXXXXX) ya Supporter ID (FWSS-XXXX) enter karein." });
      }

      // Reset password to default
      let updateRes;
      try {
        updateRes = await fetch(`${backendUrl}/api/auth/update-password`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-internal-api-key": internalKey },
          body: JSON.stringify({ memberId, newPassword: "Welcome@123" })
        });
      } catch (fetchErr) {
        return res.status(502).json({ error: "Could not connect to authentication server. Please try again later." });
      }

      if (!updateRes.ok) {
        const err = await updateRes.json().catch(() => ({}));
        return res.status(400).json({ error: err.error || "Failed to reset password" });
      }

      console.log(`[password/reset-default] Password reset to default for ${memberId}`);
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

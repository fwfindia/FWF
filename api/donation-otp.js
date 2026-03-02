import crypto from "crypto";
import { connectDB } from "../lib/db.js";
import { getTransporter } from "../lib/mailer.js";
import { sendSmsOtp } from "../lib/msg91.js";
import DonationOtp from "../models/DonationOtp.js";
import { withSentry } from "../lib/sentry.js";

const HIGH_VALUE_THRESHOLD = 50000;

async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  await connectDB();
  const { action, email, mobile, name, amount, otp } = req.body || {};

  /* ── SEND OTP ───────────────────────────────────────────────── */
  if (action === "send") {
    if (!email || !mobile || !name || !amount) {
      return res.status(400).json({ error: "email, mobile, name, and amount are required" });
    }
    if (Number(amount) < HIGH_VALUE_THRESHOLD) {
      return res.status(400).json({ error: "OTP verification is only required for donations ≥ ₹50,000" });
    }

    // Rate-limit: max 3 OTP requests from the same email in 10 minutes
    const recentCount = await DonationOtp.countDocuments({
      email,
      created_at: { $gte: new Date(Date.now() - 10 * 60 * 1000) }
    });
    if (recentCount >= 3) {
      return res.status(429).json({ error: "Too many OTP requests. Please wait 10 minutes before trying again." });
    }

    // Delete previous unverified OTPs for this email
    await DonationOtp.deleteMany({ email, verified: false });

    const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt    = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await DonationOtp.create({
      email,
      mobile,
      name,
      amount: Number(amount),
      otp: generatedOtp,
      expires_at: expiresAt
    });

    // Send SMS OTP via MSG91 (awaited so Vercel doesn't kill it early)
    try {
      const smsResult = await sendSmsOtp({ mobile, otp: generatedOtp, type: 'donation' });
      if (smsResult?.type === 'success') console.log(`✅ SMS OTP sent to ${mobile}`);
      else console.warn('⚠️ MSG91 SMS OTP result:', JSON.stringify(smsResult));
    } catch (smsErr) {
      console.error('⚠️ MSG91 donation SMS failed:', smsErr.message);
    }

    // Send email with OTP
    const transporter = getTransporter();
    await transporter.sendMail({
      from: process.env.MAIL_FROM,
      to:   email,
      subject: "FWF — Donation Verification OTP",
      html: `
      <div style="font-family:'Segoe UI',sans-serif;max-width:580px;margin:0 auto">
        <div style="background:linear-gradient(135deg,#ff416c,#ff4b2b);padding:30px;border-radius:12px 12px 0 0;text-align:center">
          <h1 style="color:#fff;margin:0;font-size:22px">🔒 High-Value Donation Verification</h1>
        </div>
        <div style="background:#f8f9fa;padding:32px 30px;border-radius:0 0 12px 12px">
          <p style="color:#333;font-size:15px">Dear <strong>${name}</strong>,</p>
          <p style="color:#333;font-size:15px">
            You are making a donation of <strong style="color:#ff416c">₹${Number(amount).toLocaleString('en-IN')}</strong> to
            Foundris Welfare Foundation.
          </p>
          <p style="color:#555;font-size:14px">
            As per FCRA / Income-Tax Act regulations, identity verification via OTP is mandatory for donations of
            ₹50,000 or more.
          </p>
          <div style="background:#fff;border:2px dashed #ff416c;border-radius:10px;padding:22px;text-align:center;margin:24px 0">
            <div style="font-size:12px;color:#888;text-transform:uppercase;letter-spacing:2px;margin-bottom:8px">Your OTP Code</div>
            <div style="font-size:40px;font-weight:900;color:#ff416c;letter-spacing:12px">${generatedOtp}</div>
          </div>
          <div style="background:#fff3cd;border-left:4px solid #ffc107;padding:12px 16px;border-radius:4px;margin-bottom:20px">
            <p style="color:#856404;font-size:13px;margin:0">
              ⚠️ OTP expires in <strong>10 minutes</strong>.
              If you did not initiate this donation, please ignore this email — your account is safe.
            </p>
          </div>
          <p style="color:#999;font-size:12px;border-top:1px solid #eee;padding-top:16px;margin-top:0">
            Foundris Welfare Foundation &nbsp;·&nbsp; <a href="https://www.fwfindia.org" style="color:#ff416c">www.fwfindia.org</a>
          </p>
        </div>
      </div>`
    });

    const maskedEmail  = email.replace(/(.{2})(.*)(@.*)/, "$1***$3");
    const maskedMobile = mobile.replace(/(\d{2})(\d{6})(\d{2})/, "$1******$3");

    return res.json({
      ok: true,
      message: `OTP sent to ${maskedEmail}`,
      maskedEmail,
      maskedMobile
    });
  }

  /* ── VERIFY OTP ─────────────────────────────────────────────── */
  if (action === "verify") {
    if (!email || !otp) {
      return res.status(400).json({ error: "email and otp are required" });
    }

    const record = await DonationOtp.findOne({
      email,
      verified:   false,
      expires_at: { $gt: new Date() }
    }).sort({ created_at: -1 });

    if (!record) {
      return res.status(400).json({ error: "OTP has expired or was not found. Please request a new OTP." });
    }

    // Block after 5 failed attempts
    if (record.attempts >= 5) {
      await record.deleteOne();
      return res.status(400).json({ error: "Too many incorrect attempts. Please request a new OTP." });
    }

    if (record.otp !== otp.trim()) {
      record.attempts += 1;
      await record.save();
      return res.status(400).json({ error: `Incorrect OTP. ${5 - record.attempts} attempt(s) remaining.` });
    }

    // OTP correct — generate verified_token
    const verifiedToken = crypto.randomBytes(32).toString("hex");
    record.verified        = true;
    record.verified_token  = verifiedToken;
    await record.save();

    return res.json({
      ok: true,
      verified_token: verifiedToken,
      message: "OTP verified successfully! Proceed to payment."
    });
  }

  return res.status(400).json({ error: "Invalid action. Use 'send' or 'verify'." });
}

export default withSentry(handler);

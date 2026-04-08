import { connectDB } from "../../lib/db.js";
import mongoose from "mongoose";

const BACKEND_URL = process.env.BACKEND_URL || "https://fwf-production.up.railway.app";
const DONATION_POINTS_PERCENT = 10;
const POINT_VALUE = 10; // 1 point = ₹10

function getModels() {
  // User
  let User;
  try { User = mongoose.model("User"); } catch {
    User = mongoose.model("User", new mongoose.Schema({}, { strict: false }));
  }

  // Donation
  let Donation;
  try { Donation = mongoose.model("Donation"); } catch {
    Donation = mongoose.model("Donation", new mongoose.Schema({
      donation_id:   { type: String },
      member_id:     { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
      amount:        { type: Number, required: true },
      points_earned: { type: Number, default: 0 },
      donor_name:    { type: String, default: "Anonymous" },
      donor_email:   { type: String, default: null },
      donor_mobile:  { type: String, default: null },
      source:        { type: String, default: "self" },
      recurring:     { type: Boolean, default: false },
      kyc_status:    { type: String, default: "not_required" },
      created_at:    { type: Date, default: Date.now }
    }, { strict: false }));
  }

  // PointsLedger
  let PointsLedger;
  try { PointsLedger = mongoose.model("PointsLedger"); } catch {
    PointsLedger = mongoose.model("PointsLedger", new mongoose.Schema({
      user_id:     { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      points:      { type: Number },
      type:        { type: String },
      description: { type: String },
      created_at:  { type: Date, default: Date.now }
    }, { strict: false }));
  }

  return { User, Donation, PointsLedger };
}

async function nextDonationId(Donation) {
  const last = await Donation.findOne({ donation_id: { $regex: /^DON-\d{6}$/ } })
    .sort({ created_at: -1 }).select("donation_id").lean();
  let n = 0;
  if (last?.donation_id) {
    const m = last.donation_id.match(/(\d{6})$/);
    if (m) n = parseInt(m[1], 10);
  }
  return `DON-${(n + 1).toString().padStart(6, "0")}`;
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  // ── Step 1: Verify auth by calling Railway /api/member/me with forwarded cookie ──
  const cookie = req.headers.cookie || "";
  let meData;
  try {
    const authRes = await fetch(`${BACKEND_URL}/api/member/me`, {
      headers: { Cookie: cookie }
    });
    if (!authRes.ok) {
      const e = await authRes.json().catch(() => ({ error: "Unauthorized" }));
      return res.status(authRes.status).json(e);
    }
    meData = await authRes.json();
  } catch (err) {
    console.error("[self-donate] Auth check failed:", err.message);
    return res.status(502).json({ error: "Auth service unavailable. Try again." });
  }

  const u = meData.user;
  if (!u) return res.status(401).json({ error: "Session expired. Please login again." });

  // ── Step 2: Validate input ──
  const { amount, monthly } = req.body || {};
  const amt = parseFloat(amount);
  if (!amt || amt <= 0) return res.status(400).json({ error: "Valid amount required" });

  // ── Step 3: MongoDB operations ──
  try {
    await connectDB();
    const { User, Donation, PointsLedger } = getModels();

    const pointsRupees = amt * (DONATION_POINTS_PERCENT / 100);
    const points = pointsRupees / POINT_VALUE;
    const donationId = await nextDonationId(Donation);

    await Donation.create({
      donation_id:  donationId,
      member_id:    u._id,
      amount:       amt,
      points_earned: points,
      donor_name:   u.name || "Anonymous",
      donor_email:  u.email || null,
      donor_mobile: u.mobile || null,
      source:       "self",
      recurring:    !!monthly,
      kyc_status:   "not_required"
    });

    await User.updateOne({ _id: u._id }, {
      $inc: {
        "wallet.points_balance":         points,
        "wallet.points_from_donations":  points,
        "wallet.total_points_earned":    points
      },
      $set: { "wallet.updated_at": new Date() }
    });

    await PointsLedger.create({
      user_id:     u._id,
      points,
      type:        "donation",
      description: `Self donation ₹${amt} by ${u.name || "Unknown"} → ${points} points`
    });

    return res.json({
      ok: true,
      donationId,
      points,
      message: `₹${amt} donation recorded successfully!`
    });
  } catch (err) {
    console.error("[self-donate] DB error:", err.message);
    return res.status(500).json({ error: "Donation failed: " + err.message });
  }
}

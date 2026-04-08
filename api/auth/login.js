import { connectDB } from "../../lib/db.js";
import mongoose from "mongoose";

// Minimal inline User model for mobile lookup (same collection as Railway backend)
function getUserModel() {
  try {
    return mongoose.model("User");
  } catch {
    return mongoose.model(
      "User",
      new mongoose.Schema({ member_id: String, mobile: String }, { strict: false })
    );
  }
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const { memberId, password } = req.body || {};
  if (!memberId || !password) {
    return res.status(400).json({ error: "Member ID and password are required" });
  }

  let effectiveMemberId = memberId;

  // If input looks like a mobile number (10–12 digits), resolve to actual member_id via MongoDB
  const digits = memberId.replace(/\D/g, "");
  if (/^\d{10,12}$/.test(digits)) {
    try {
      await connectDB();
      const User = getUserModel();
      const last10 = digits.slice(-10);
      const user = await User.findOne({
        mobile: { $in: [last10, "+91" + last10, "91" + last10, digits] },
      })
        .select("member_id")
        .lean();

      if (user?.member_id) {
        effectiveMemberId = user.member_id;
        console.log(`[auth/login] Mobile ${memberId} resolved → ${effectiveMemberId}`);
      } else {
        console.log(`[auth/login] Mobile ${memberId} not found in DB, forwarding as-is`);
      }
    } catch (err) {
      console.error("[auth/login] Mobile lookup error:", err.message);
      // Fall through — Railway will return its own error
    }
  }

  // Proxy to Railway backend
  const backendUrl =
    process.env.BACKEND_URL || "https://fwf-production.up.railway.app";

  try {
    const railwayRes = await fetch(`${backendUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ memberId: effectiveMemberId, password }),
    });

    // Forward Set-Cookie header(s) from Railway so JWT cookie is set on fwfindia.org
    const setCookies =
      typeof railwayRes.headers.getSetCookie === "function"
        ? railwayRes.headers.getSetCookie()
        : [railwayRes.headers.get("set-cookie")].filter(Boolean);

    if (setCookies.length) {
      res.setHeader("Set-Cookie", setCookies);
    }

    const data = await railwayRes.json();
    return res.status(railwayRes.status).json(data);
  } catch (err) {
    console.error("[auth/login] Railway proxy failed:", err.message);
    return res
      .status(502)
      .json({ error: "Authentication service unavailable. Please try again." });
  }
}

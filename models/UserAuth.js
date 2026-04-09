/**
 * Minimal User schema for Vercel serverless functions.
 * Uses the same 'users' collection as the Railway backend.
 * Only includes fields needed for password reset operations.
 */
import mongoose from 'mongoose';

const userAuthSchema = new mongoose.Schema({
  member_id: { type: String, index: true },
  name:      { type: String },
  mobile:    { type: String, index: true },
  email:     { type: String },
  password_hash: { type: String },
  role:      { type: String },
  membership_active: { type: Boolean }
}, {
  collection: 'users',   // Must match Railway backend's collection
  strict: false          // Allow extra fields from Railway model
});

// Prevent model re-registration on serverless warm starts
export default mongoose.models.UserAuth || mongoose.model('UserAuth', userAuthSchema);

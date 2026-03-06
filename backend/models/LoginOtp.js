import mongoose from 'mongoose';

const loginOtpSchema = new mongoose.Schema({
  memberId:  { type: String, required: true, index: true },
  otp:       { type: String, required: true },
  attempts:  { type: Number, default: 0 },
  expiresAt: { type: Date, required: true }
});

// Auto-delete after expiry
loginOtpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export default mongoose.model('LoginOtp', loginOtpSchema);

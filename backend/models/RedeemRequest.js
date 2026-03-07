import mongoose from 'mongoose';

const redeemRequestSchema = new mongoose.Schema({
  user_id:         { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  supporter_id:    { type: String, required: true },
  name:            { type: String },
  mobile:          { type: String },
  points:          { type: Number, required: true, min: 1 },
  amount_inr:      { type: Number, required: true },
  payment_method:  { type: String, enum: ['upi', 'phonepe_gpay', 'bank'], required: true },
  upi_id:          { type: String },
  phone_number:    { type: String },
  bank_account:    { type: String },
  ifsc:            { type: String },
  bank_name:       { type: String },
  cause:           { type: String },
  status:          { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  admin_notes:     { type: String },
  processed_by:    { type: String },
  processed_at:    { type: Date },
  created_at:      { type: Date, default: Date.now },
  updated_at:      { type: Date, default: Date.now }
});

redeemRequestSchema.index({ supporter_id: 1 });
redeemRequestSchema.index({ status: 1 });
redeemRequestSchema.index({ created_at: -1 });

export default mongoose.models.RedeemRequest || mongoose.model('RedeemRequest', redeemRequestSchema);

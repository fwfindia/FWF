import mongoose from 'mongoose';

const phonePeDonationIntentSchema = new mongoose.Schema({
  merchant_transaction_id: { type: String, required: true, unique: true, index: true },
  merchant_user_id: { type: String, default: null },
  amount: { type: Number, required: true },
  donor_name: { type: String, default: 'Anonymous' },
  donor_email: { type: String, default: null },
  donor_mobile: { type: String, default: null },
  donor_pan: { type: String, default: null },
  donor_address: { type: String, default: null },
  want_80g: { type: Boolean, default: false },
  verified_token: { type: String, default: null },
  ref_code: { type: String, default: null },
  member_id_input: { type: String, default: null },
  redirect_url: { type: String, default: null },
  payment_id: { type: String, default: null },
  donation_id: { type: String, default: null },
  status: { type: String, enum: ['created', 'initiated', 'pending', 'completed', 'failed'], default: 'created', index: true },
  completed_at: { type: Date, default: null },
  phonepe_response: { type: Object, default: null },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
}, {
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

phonePeDonationIntentSchema.index({ status: 1, created_at: -1 });

export default mongoose.models.PhonePeDonationIntent || mongoose.model('PhonePeDonationIntent', phonePeDonationIntentSchema);
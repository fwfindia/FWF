import mongoose from 'mongoose';

const walletSchema = new mongoose.Schema({
  balance_inr: { type: Number, default: 0 },
  lifetime_earned_inr: { type: Number, default: 0 },
  lifetime_applied_inr: { type: Number, default: 0 },
  points_balance: { type: Number, default: 0 },
  points_from_donations: { type: Number, default: 0 },
  points_from_referrals: { type: Number, default: 0 },
  points_from_quiz: { type: Number, default: 0 },
  points_from_social_tasks: { type: Number, default: 0 },
  total_points_earned: { type: Number, default: 0 },
  updated_at: { type: Date, default: Date.now }
}, { _id: false });

const memberProjectSchema = new mongoose.Schema({
  project_id: Number,
  project_name: String,
  project_cost: Number,
  target60_inr: Number,
  cash_credited_inr: { type: Number, default: 0 },
  wallet_applied_inr: { type: Number, default: 0 },
  eligible_flag: { type: Boolean, default: false },
  eligible_on: Date
}, { _id: false });

const userSchema = new mongoose.Schema({
  member_id: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  mobile: { type: String, unique: true, sparse: true },
  email: { type: String, unique: true, sparse: true },
  password_hash: { type: String, required: true },
  role: { type: String, enum: ['member', 'admin', 'supporter'], default: 'member', index: true },
  membership_active: { type: Boolean, default: false },
  first_login_done: { type: Boolean, default: false },
  referral_code: { type: String, unique: true, sparse: true },
  referred_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  avatar_url: String,
  bio: String,
  
  // Embedded wallet (1-to-1 relationship)
  wallet: { type: walletSchema, default: () => ({}) },
  
  // Embedded member project (1-to-1 relationship)
  member_project: memberProjectSchema,

  // Razorpay subscription for monthly auto-debit
  razorpay_subscription_id: { type: String, sparse: true, index: true },
  subscription_status:       { type: String, enum: ['active','halted','cancelled','completed','pending'], default: 'pending' },

  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
}, { 
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

// Indexes for common queries
userSchema.index({ role: 1, membership_active: 1 });
userSchema.index({ created_at: -1 });

// Virtual for user ID (compatibility with SQLite id field)
userSchema.virtual('id').get(function() {
  return this._id.toString();
});

// Ensure virtuals are included in JSON
userSchema.set('toJSON', { virtuals: true });
userSchema.set('toObject', { virtuals: true });

export default mongoose.model('User', userSchema);

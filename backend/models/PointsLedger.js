import mongoose from 'mongoose';

const pointsLedgerSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  points: { type: Number, required: true },
  type: { 
    type: String, 
    enum: ['donation', 'referral', 'quiz', 'quiz_prize', 'social_task', 'redeem', 'adjustment', 'loan_repayment'], 
    required: true,
    index: true 
  },
  description: String,
  reference_id: { type: String, default: null },
  created_at: { type: Date, default: Date.now }
}, { 
  timestamps: { createdAt: 'created_at', updatedAt: false }
});

// Compound indexes for audit queries
pointsLedgerSchema.index({ user_id: 1, created_at: -1 });
pointsLedgerSchema.index({ type: 1, created_at: -1 });
pointsLedgerSchema.index({ created_at: -1 });

export default mongoose.model('PointsLedger', pointsLedgerSchema);

import mongoose from 'mongoose';

const quizParticipationSchema = new mongoose.Schema({
  quiz_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Quiz', required: true },
  quiz_ref: { type: String, required: true }, // quiz_id string e.g. "M2506"
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  member_id: { type: String, required: true },
  name: { type: String, required: true },
  enrollment_number: { type: String, unique: true, required: true }, // FWF-M2506-83742
  payment_id: { type: String }, // Razorpay payment id
  amount_paid: { type: Number, required: true },
  points_earned: { type: Number, default: 0 }, // 10% of entry fee as points
  answers: [{
    q_no: Number,
    selected: Number, // index of selected option
    is_correct: Boolean
  }],
  score: { type: Number, default: 0 },
  quiz_submitted: { type: Boolean, default: false },
  quiz_started_at: { type: Date },
  submitted_at: { type: Date },
  speed_seconds: { type: Number },
  referred_by: { type: String }, // referral code of who referred
  referrer_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: {
    type: String,
    enum: ['enrolled', 'submitted', 'won', 'lost', 'failed'],
    default: 'enrolled'
  },
  prize_won: { type: Number, default: 0 },
  created_at: { type: Date, default: Date.now }
}, {
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

// One user can participate in a quiz only once
quizParticipationSchema.index({ quiz_id: 1, user_id: 1 }, { unique: true });
quizParticipationSchema.index({ user_id: 1, created_at: -1 });
quizParticipationSchema.index({ enrollment_number: 1 });
quizParticipationSchema.index({ referred_by: 1 });

export default mongoose.model('QuizParticipation', quizParticipationSchema);

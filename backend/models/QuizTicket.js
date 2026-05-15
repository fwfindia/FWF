import mongoose from 'mongoose';

const quizTicketSchema = new mongoose.Schema({
  // Seller (FWF member who generated the link; null for direct purchases)
  seller_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  seller_support_id: { type: String, unique: true, sparse: true }, // FWF-ST-XXXXX

  // Quiz reference
  quiz_ref: { type: String, index: true },          // quiz_id string e.g. "M2506"
  quiz_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Quiz' },

  // Shareable token for the buyer link (null for direct purchases)
  token: { type: String, unique: true, sparse: true, index: true },

  // How this ticket was created
  sale_type: { type: String, enum: ['ticket_link', 'direct'], default: 'ticket_link' },

  // Buyer info
  buyer_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true }, // for direct purchases
  buyer_name: { type: String },
  buyer_contact: { type: String },
  buyer_email: { type: String },

  // Status tracking
  ticket_status: {
    type: String,
    enum: ['pending', 'converted', 'failed'],  // pending = link not yet used; converted = buyer paid; failed = buyer failed quiz
    default: 'pending'
  },

  ticket_price: { type: Number, default: 100 },
  points_earned: { type: Number, default: 0 },

  // Filled on conversion
  participation_id: { type: mongoose.Schema.Types.ObjectId, ref: 'QuizParticipation' },
  converted_at: { type: Date },

  sold_at: { type: Date, default: Date.now }
}, {
  timestamps: { createdAt: 'sold_at', updatedAt: false }
});

quizTicketSchema.index({ seller_id: 1, sold_at: -1 });
quizTicketSchema.index({ quiz_ref: 1, seller_id: 1 });
quizTicketSchema.index({ sold_at: -1 });

export default mongoose.model('QuizTicket', quizTicketSchema);

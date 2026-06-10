import mongoose from 'mongoose';

const pushSubscriptionSchema = new mongoose.Schema({
  user_id:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  member_id: { type: String },
  endpoint:  { type: String, required: true, unique: true },
  keys: {
    p256dh: { type: String, required: true },
    auth:   { type: String, required: true }
  },
  user_agent: { type: String },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
});

pushSubscriptionSchema.index({ user_id: 1 });

export default mongoose.model('PushSubscription', pushSubscriptionSchema);

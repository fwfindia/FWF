import mongoose from 'mongoose';

const receiptSchema = new mongoose.Schema({
  receipt_id:     { type: String, unique: true },          // RCP-000001
  token:          { type: String, unique: true },          // secure public access token
  type:           { type: String, enum: ['membership', 'donation', 'quiz', 'renewal', 'other'], required: true },

  // Who
  user_id:        { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  member_id:      { type: String, default: null },
  customer_name:  { type: String, required: true },
  customer_email: { type: String, default: null },
  customer_mobile:{ type: String, default: null },
  customer_pan:   { type: String, default: null },   // for 80G
  customer_address:{ type: String, default: null },

  // What
  description:    { type: String },
  line_items: [{
    name:        { type: String },
    description: { type: String },
    amount:      { type: Number },
    quantity:    { type: Number, default: 1 }
  }],
  subtotal:       { type: Number, default: 0 },
  tax:            { type: Number, default: 0 },       // GST
  total:          { type: Number, required: true },
  currency:       { type: String, default: 'INR' },

  // Generic gateway metadata
  payment_gateway: { type: String, default: null },
  payment_txn_id:  { type: String, default: null },
  payment_order_ref:{ type: String, default: null },

  // Razorpay
  razorpay_payment_id:     { type: String, default: null },
  razorpay_order_id:       { type: String, default: null },
  razorpay_subscription_id:{ type: String, default: null },
  razorpay_invoice_id:     { type: String, default: null },  // if Razorpay invoice is created
  razorpay_invoice_url:    { type: String, default: null },  // Razorpay short_url

  // Reference (back-link to the originating record)
  reference_id:   { type: String, default: null },    // donation_id / member_id / quiz_id

  // Status
  status:         { type: String, enum: ['generated', 'sent', 'viewed', 'cancelled'], default: 'generated' },
  is_80g:         { type: Boolean, default: false },   // whether 80G certificate applies
  email_sent:     { type: Boolean, default: false },
  email_sent_at:  { type: Date, default: null },
  viewed_at:      { type: Date, default: null },
  views:          { type: Number, default: 0 },

  // Zoho Books sync
  zoho_salesreceipt_id: { type: String, default: null },
  zoho_synced_at:       { type: Date, default: null },

  created_at:     { type: Date, default: Date.now }
});

receiptSchema.index({ member_id: 1, created_at: -1 });
receiptSchema.index({ payment_txn_id: 1 });
receiptSchema.index({ razorpay_payment_id: 1 });
receiptSchema.index({ token: 1 });
receiptSchema.index({ type: 1, created_at: -1 });
receiptSchema.index({ is_80g: 1 });

export default mongoose.models.Receipt || mongoose.model('Receipt', receiptSchema);

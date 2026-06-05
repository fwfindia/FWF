const mongoose = require('mongoose');

const LoanAgreementSchema = new mongoose.Schema({
  loanId:       { type: String, unique: true, required: true },
  memberId:     { type: String, required: true },
  memberName:   String,
  memberEmail:  String,
  memberMobile: String,
  amount:       { type: Number, required: true },
  tenure:       { type: Number, required: true }, // months
  emi:          { type: Number, required: true },
  moratorium:   { type: Number, default: 0 },
  purpose:      { type: String, required: true },
  notes:        String,

  status: {
    type: String,
    enum: ['pending_acceptance', 'accepted', 'mandate_done', 'active', 'closed', 'rejected'],
    default: 'pending_acceptance'
  },

  createdAt:   { type: Date, default: Date.now },
  acceptedAt:  Date,
  mandateAt:   Date,
  disbursedAt: Date,
  closedAt:    Date,
  createdBy:   String,

  // Filled by admin on disburse
  disbursedAmount: Number,
  utrNumber:       String,
  disbursedBy:     String,
  disbursedMode:   String,

  // Filled by member during mandate setup
  mandateBankName:      String,
  mandateAccountNo:     String,
  mandateIfsc:          String,
  mandateAccountHolder: String,
  mandateType:          String, // nach | upi | manual

  // Denormalized for quick stats
  totalRepaid: { type: Number, default: 0 }
});

module.exports = mongoose.models.LoanAgreement || mongoose.model('LoanAgreement', LoanAgreementSchema);

const mongoose = require('mongoose');

const LoanRepaymentSchema = new mongoose.Schema({
  repayId:    { type: String, unique: true, required: true },
  loanId:     { type: String, required: true },
  memberId:   String,
  memberName: String,
  amount:     { type: Number, required: true },
  date:       { type: Date,   required: true },
  mode:       String,
  utrRef:     String,
  remarks:    String,
  recordedBy: String,
  createdAt:  { type: Date, default: Date.now }
});

module.exports = mongoose.models.LoanRepayment || mongoose.model('LoanRepayment', LoanRepaymentSchema);

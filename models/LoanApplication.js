const mongoose = require('mongoose')

const documentSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  originalName: { type: String, required: true },
  mimeType: { type: String, required: true },
  size: { type: Number, required: true },
}, { _id: false })

const loanApplicationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  loanType: { type: String, enum: ['crop-loan', 'tractor-loan'], required: true },
  fullName: { type: String, required: true, trim: true, maxlength: 100 },
  townVillage: { type: String, required: true, trim: true, maxlength: 100 },
  tehsilTaluka: { type: String, required: true, trim: true, maxlength: 100 },
  district: { type: String, required: true, trim: true, maxlength: 100 },
  identityProof: { type: documentSchema, required: true },
  landRecord712: { type: documentSchema, required: true },
  landRecord8a: { type: documentSchema, required: true },
  mutationRecord: { type: documentSchema, required: true },
  boundaryMap: { type: documentSchema, required: true },
  status: { type: String, enum: ['submitted', 'under-review', 'approved', 'rejected'], default: 'submitted' },
  adminFeedback: { type: String, trim: true, maxlength: 1000, default: '' },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  reviewedAt: { type: Date },
}, { timestamps: true })

module.exports = mongoose.model('LoanApplication', loanApplicationSchema)
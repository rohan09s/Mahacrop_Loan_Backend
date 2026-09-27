const mongoose = require('mongoose')

const notificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  application: { type: mongoose.Schema.Types.ObjectId, ref: 'LoanApplication', required: true, unique: true },
  type: { type: String, enum: ['approved', 'rejected'], required: true },
  loanType: { type: String, enum: ['crop-loan', 'tractor-loan'], required: true },
  message: { type: String, required: true, trim: true, maxlength: 1000 },
  readAt: { type: Date, default: null },
}, { timestamps: true })

module.exports = mongoose.model('Notification', notificationSchema)
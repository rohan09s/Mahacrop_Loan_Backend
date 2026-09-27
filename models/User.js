const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true, trim: true, minlength: 2, maxlength: 100 },
  mobileNumber: { type: String, required: true, unique: true, match: /^[6-9]\d{9}$/ },
  townVillage: { type: String, required: true, trim: true, maxlength: 100 },
  tehsilTaluka: { type: String, required: true, trim: true, maxlength: 100 },
  district: { type: String, required: true, trim: true, maxlength: 100 },
  passwordHash: { type: String, required: true, select: false },
  recoveryPhraseHash: { type: String, required: true, select: false },
}, { timestamps: true })

module.exports = mongoose.model('User', userSchema)
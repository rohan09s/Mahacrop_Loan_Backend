require('dotenv').config()

const crypto = require('node:crypto')
const dns = require('node:dns')
const fs = require('node:fs')
const path = require('node:path')
const bcrypt = require('bcryptjs')
const cors = require('cors')
const MongoStore = require('connect-mongo').default
const express = require('express')
const rateLimit = require('express-rate-limit')
const session = require('express-session')
const mongoose = require('mongoose')
const multer = require('multer')
const Admin = require('./models/Admin')
const LoanApplication = require('./models/LoanApplication')
const Notification = require('./models/Notification')
const User = require('./models/User')

dns.setServers(process.env.DNS_SERVERS
  ? process.env.DNS_SERVERS.split(',').map((server) => server.trim())
  : ['1.1.1.1', '8.8.8.8'])

const app = express()
const port = Number(process.env.PORT) || 5000
const sessionDuration = 7 * 24 * 60 * 60 * 1000
const uploadDirectory = path.join(__dirname, 'private-uploads')
const requiredDocuments = ['identityProof', 'landRecord712', 'landRecord8a', 'mutationRecord', 'boundaryMap']

fs.mkdirSync(uploadDirectory, { recursive: true })

app.set('trust proxy', 1)
app.use(cors({ origin: process.env.FRONTEND_ORIGIN || 'http://localhost:5173', credentials: true }))
app.use(express.json({ limit: '20kb' }))
app.use(session({
  name: 'mahacrop.sid',
  secret: process.env.SESSION_SECRET || 'local-development-session-secret-change-me',
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI, collectionName: 'sessions', ttl: sessionDuration / 1000 }),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: sessionDuration },
}))

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false })
const resetLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 5, standardHeaders: 'draft-8', legacyHeaders: false })
const upload = multer({
  storage: multer.diskStorage({
    destination: uploadDirectory,
    filename: (_request, file, callback) => callback(null, `${crypto.randomUUID()}${path.extname(file.originalname).toLowerCase()}`),
  }),
  limits: { fileSize: 10 * 1024 * 1024, files: 5 },
  fileFilter: (_request, file, callback) => {
    if (!['image/jpeg', 'image/png', 'image/webp', 'application/pdf'].includes(file.mimetype)) {
      return callback(new Error('फक्त JPG, PNG, WEBP किंवा PDF फाइल अपलोड करा.'))
    }
    return callback(null, true)
  },
})

function normalizeMobile(value) {
  return value?.toString().trim().replace(/[०-९]/g, (digit) => String('०१२३४५६७८९'.indexOf(digit)))
}

function publicUser(user) {
  return {
    id: user._id,
    fullName: user.fullName,
    mobileNumber: user.mobileNumber,
    townVillage: user.townVillage,
    tehsilTaluka: user.tehsilTaluka,
    district: user.district,
  }
}

function requireAuth(request, response, next) {
  if (!request.session.userId) return response.status(401).json({ message: 'कृपया आधी लॉग इन करा.' })
  return next()
}

function requireAdmin(request, response, next) {
  if (!request.session.adminId) return response.status(401).json({ message: 'प्रशासक म्हणून लॉग इन करा.' })
  return next()
}

function establishSession(request, values) {
  return new Promise((resolve, reject) => {
    request.session.regenerate((regenerateError) => {
      if (regenerateError) return reject(regenerateError)
      Object.assign(request.session, values)
      request.session.save((saveError) => saveError ? reject(saveError) : resolve())
    })
  })
}

function removeUploadedFiles(files) {
  Object.values(files || {}).flat().forEach((file) => fs.rm(file.path, { force: true }, () => {}))
}

function handleError(error, _request, response, _next) {
  console.error(error)
  if (error instanceof multer.MulterError) {
    return response.status(400).json({ message: error.code === 'LIMIT_FILE_SIZE' ? 'प्रत्येक फाइलचा आकार १० MB पेक्षा कमी असावा.' : 'अपलोड केलेल्या फाइल्स तपासा.' })
  }
  if (error.message?.startsWith('फक्त JPG')) return response.status(400).json({ message: error.message })
  return response.status(500).json({ message: 'सर्व्हरमध्ये त्रुटी आली. कृपया पुन्हा प्रयत्न करा.' })
}

app.get('/api/health', (_request, response) => {
  response.json({ status: 'ok', database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' })
})

app.get('/api/auth/session', async (request, response, next) => {
  if (!request.session.userId) return response.json({ user: null })
  try {
    const user = await User.findById(request.session.userId)
    if (!user) {
      request.session.destroy(() => {})
      return response.json({ user: null })
    }
    request.session.touch()
    return response.json({ user: publicUser(user) })
  } catch (error) {
    return next(error)
  }
})

app.post('/api/auth/register', authLimiter, async (request, response, next) => {
  const { fullName, townVillage, tehsilTaluka, district } = request.body
  const mobileNumber = normalizeMobile(request.body.mobileNumber)
  const password = request.body.password?.toString()
  const recoveryPhrase = request.body.recoveryPhrase?.toString().trim()
  if (![fullName, mobileNumber, townVillage, tehsilTaluka, district, password, recoveryPhrase].every((value) => value?.toString().trim())) {
    return response.status(400).json({ message: 'कृपया सर्व माहिती भरा.' })
  }
  if (!/^[6-9]\d{9}$/.test(mobileNumber)) return response.status(400).json({ message: 'वैध १० अंकी मोबाईल क्रमांक भरा.' })
  if (password.length < 8) return response.status(400).json({ message: 'पासवर्ड किमान ८ अक्षरांचा असावा.' })
  if (recoveryPhrase.length < 8) return response.status(400).json({ message: 'पुनर्प्राप्ती वाक्य किमान ८ अक्षरांचे असावे.' })

  try {
    if (await User.exists({ mobileNumber })) return response.status(409).json({ message: 'या मोबाईल क्रमांकाचे खाते आधीपासून आहे. लॉग इन करा.' })
    const user = await User.create({
      fullName: fullName.trim(), mobileNumber, townVillage: townVillage.trim(),
      tehsilTaluka: tehsilTaluka.trim(), district: district.trim(),
      passwordHash: await bcrypt.hash(password, 12), recoveryPhraseHash: await bcrypt.hash(recoveryPhrase, 12),
    })
    await establishSession(request, { userId: user._id.toString() })
    return response.status(201).json({ user: publicUser(user) })
  } catch (error) {
    return next(error)
  }
})

app.post('/api/auth/login', authLimiter, async (request, response, next) => {
  const mobileNumber = normalizeMobile(request.body.mobileNumber)
  const password = request.body.password?.toString() || ''
  if (!/^[6-9]\d{9}$/.test(mobileNumber || '') || !password) return response.status(400).json({ message: 'मोबाईल क्रमांक आणि पासवर्ड भरा.' })
  try {
    const user = await User.findOne({ mobileNumber }).select('+passwordHash')
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) return response.status(401).json({ message: 'मोबाईल क्रमांक किंवा पासवर्ड चुकीचा आहे.' })
    await establishSession(request, { userId: user._id.toString() })
    return response.json({ user: publicUser(user) })
  } catch (error) {
    return next(error)
  }
})

app.post('/api/auth/logout', (request, response) => {
  request.session.destroy((error) => {
    if (error) return response.status(500).json({ message: 'लॉग आउट करता आले नाही.' })
    response.clearCookie('mahacrop.sid', { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' })
    return response.json({ success: true })
  })
})

app.patch('/api/auth/recovery-phrase', requireAuth, async (request, response, next) => {
  const currentPassword = request.body.currentPassword?.toString() || ''
  const recoveryPhrase = request.body.recoveryPhrase?.toString().trim() || ''
  if (!currentPassword || recoveryPhrase.length < 8) return response.status(400).json({ message: 'सध्याचा पासवर्ड आणि किमान ८ अक्षरांचे पुनर्प्राप्ती वाक्य भरा.' })
  try {
    const user = await User.findById(request.session.userId).select('+passwordHash')
    if (!user || !(await bcrypt.compare(currentPassword, user.passwordHash))) return response.status(401).json({ message: 'सध्याचा पासवर्ड चुकीचा आहे.' })
    await User.updateOne({ _id: user._id }, { $set: { recoveryPhraseHash: await bcrypt.hash(recoveryPhrase, 12) } })
    return response.json({ success: true, message: 'पुनर्प्राप्ती वाक्य सुरक्षितपणे जतन केले.' })
  } catch (error) {
    return next(error)
  }
})

app.get('/api/admin/session', async (request, response, next) => {
  if (!request.session.adminId) return response.json({ admin: null })
  try {
    const admin = await Admin.findById(request.session.adminId).select('username')
    if (!admin) {
      request.session.destroy(() => {})
      return response.json({ admin: null })
    }
    request.session.touch()
    return response.json({ admin: { username: admin.username } })
  } catch (error) {
    return next(error)
  }
})

app.post('/api/admin/login', authLimiter, async (request, response, next) => {
  const username = request.body.username?.toString().trim().toLowerCase()
  const password = request.body.password?.toString() || ''
  if (!username || !password) return response.status(400).json({ message: 'वापरकर्तानाव आणि पासवर्ड भरा.' })
  try {
    const admin = await Admin.findOne({ username }).select('+passwordHash')
    if (!admin || !(await bcrypt.compare(password, admin.passwordHash))) return response.status(401).json({ message: 'वापरकर्तानाव किंवा पासवर्ड चुकीचा आहे.' })
    await establishSession(request, { adminId: admin._id.toString() })
    return response.json({ admin: { username: admin.username } })
  } catch (error) {
    return next(error)
  }
})

app.post('/api/admin/logout', requireAdmin, (request, response) => {
  request.session.destroy((error) => {
    if (error) return response.status(500).json({ message: 'लॉग आउट करता आले नाही.' })
    response.clearCookie('mahacrop.sid', { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' })
    return response.json({ success: true })
  })
})

app.post('/api/admin/reset-password', resetLimiter, async (request, response, next) => {
  const username = request.body.username?.toString().trim().toLowerCase()
  const recoveryKey = request.body.recoveryKey?.toString() || ''
  const password = request.body.password?.toString() || ''
  if (!username || !recoveryKey || password.length < 12) return response.status(400).json({ message: 'वापरकर्तानाव, रिकव्हरी की आणि किमान १२ अक्षरांचा पासवर्ड भरा.' })
  if (!process.env.ADMIN_RESET_KEY || recoveryKey !== process.env.ADMIN_RESET_KEY) return response.status(401).json({ message: 'रिकव्हरी की चुकीची आहे.' })
  try {
    const admin = await Admin.findOne({ username }).select('+passwordHash')
    if (!admin) return response.status(404).json({ message: 'प्रशासक खाते सापडले नाही.' })
    admin.passwordHash = await bcrypt.hash(password, 12)
    await admin.save()
    await mongoose.connection.collection('sessions').deleteMany({ 'session.adminId': admin._id.toString() })
    request.session.destroy(() => {})
    return response.json({ success: true, message: 'पासवर्ड बदलला. नव्या पासवर्डने लॉग इन करा.' })
  } catch (error) {
    return next(error)
  }
})

app.post('/api/auth/reset-password', resetLimiter, async (request, response, next) => {
  const mobileNumber = normalizeMobile(request.body.mobileNumber)
  const recoveryPhrase = request.body.recoveryPhrase?.toString().trim() || ''
  const password = request.body.password?.toString() || ''
  if (!/^[6-9]\d{9}$/.test(mobileNumber || '') || recoveryPhrase.length < 8 || password.length < 8) {
    return response.status(400).json({ message: 'मोबाईल क्रमांक, पुनर्प्राप्ती वाक्य आणि किमान ८ अक्षरांचा नवीन पासवर्ड भरा.' })
  }
  try {
    const user = await User.findOne({ mobileNumber }).select('+recoveryPhraseHash')
    if (!user) return response.status(400).json({ message: 'मोबाईल क्रमांक किंवा पुनर्प्राप्ती वाक्य चुकीचे आहे.' })
    if (!user.recoveryPhraseHash) return response.status(400).json({ message: 'या खात्यासाठी पुनर्प्राप्ती वाक्य सेट केलेले नाही. लॉग इन करून खाते मेनूमधून ते सेट करा.' })
    if (!(await bcrypt.compare(recoveryPhrase, user.recoveryPhraseHash))) {
      return response.status(400).json({ message: 'मोबाईल क्रमांक किंवा पुनर्प्राप्ती वाक्य चुकीचे आहे.' })
    }
    user.passwordHash = await bcrypt.hash(password, 12)
    await user.save()
    await mongoose.connection.collection('sessions').deleteMany({ 'session.userId': user._id.toString() })
    request.session.destroy(() => {})
    return response.json({ success: true, message: 'नवीन पासवर्ड सेट झाला. कृपया लॉग इन करा.' })
  } catch (error) {
    return next(error)
  }
})

app.post('/api/applications', requireAuth, upload.fields(requiredDocuments.map((name) => ({ name, maxCount: 1 }))), async (request, response, next) => {
  try {
    const files = request.files || {}
    if (requiredDocuments.some((field) => !files[field]?.[0])) {
      removeUploadedFiles(files)
      return response.status(400).json({ message: 'कृपया सर्व आवश्यक कागदपत्रे जोडा.' })
    }
    const user = await User.findById(request.session.userId)
    if (!user) {
      removeUploadedFiles(files)
      return response.status(401).json({ message: 'तुमचे सत्र संपले आहे. कृपया पुन्हा लॉग इन करा.' })
    }
    const { loanType, fullName, townVillage, tehsilTaluka, district } = request.body
    if (!['crop-loan', 'tractor-loan'].includes(loanType) || ![fullName, townVillage, tehsilTaluka, district].every((value) => value?.trim())) {
      removeUploadedFiles(files)
      return response.status(400).json({ message: 'कृपया अर्जातील सर्व माहिती भरा.' })
    }
    const documentData = Object.fromEntries(requiredDocuments.map((field) => {
      const file = files[field][0]
      return [field, { filename: file.filename, originalName: file.originalname, mimeType: file.mimetype, size: file.size }]
    }))
    const application = await LoanApplication.create({
      user: user._id, loanType, fullName: fullName.trim(), townVillage: townVillage.trim(),
      tehsilTaluka: tehsilTaluka.trim(), district: district.trim(), ...documentData,
    })
    return response.status(201).json({ applicationId: application._id, message: 'अर्ज यशस्वीरित्या जमा झाला.' })
  } catch (error) {
    removeUploadedFiles(request.files)
    return next(error)
  }
})

app.get('/api/admin/applications', requireAdmin, async (_request, response, next) => {
  try {
    const applications = await LoanApplication.find()
      .populate('user', 'fullName mobileNumber townVillage tehsilTaluka district')
      .sort({ createdAt: -1 })
      .lean()
    return response.json({ applications })
  } catch (error) {
    return next(error)
  }
})

app.get('/api/admin/applications/:applicationId/documents/:documentName', requireAdmin, async (request, response, next) => {
  const { applicationId, documentName } = request.params
  if (!requiredDocuments.includes(documentName) || !mongoose.isValidObjectId(applicationId)) return response.status(404).json({ message: 'कागदपत्र सापडले नाही.' })
  try {
    const application = await LoanApplication.findById(applicationId).select(requiredDocuments.join(' '))
    const document = application?.[documentName]
    if (!document) return response.status(404).json({ message: 'कागदपत्र सापडले नाही.' })
    const filePath = path.join(uploadDirectory, path.basename(document.filename))
    if (!fs.existsSync(filePath)) return response.status(404).json({ message: 'फाइल उपलब्ध नाही.' })
    response.set('X-Content-Type-Options', 'nosniff')
    if (request.query.view === '1') {
      response.type(document.mimeType)
      response.set('Content-Disposition', `inline; filename="${encodeURIComponent(path.basename(document.originalName))}"`)
      return response.sendFile(filePath)
    }
    return response.download(filePath, path.basename(document.originalName))
  } catch (error) {
    return next(error)
  }
})

app.patch('/api/admin/applications/:applicationId/review', requireAdmin, async (request, response, next) => {
  const { applicationId } = request.params
  const { decision } = request.body
  const reason = request.body.reason?.toString().trim() || ''
  if (!mongoose.isValidObjectId(applicationId) || !['approved', 'rejected'].includes(decision)) return response.status(400).json({ message: 'अर्जाचा निर्णय तपासा.' })
  if (decision === 'rejected' && !reason) return response.status(400).json({ message: 'नकाराचे कारण लिहा.' })
  try {
    const application = await LoanApplication.findById(applicationId)
    if (!application) return response.status(404).json({ message: 'अर्ज सापडला नाही.' })
    application.status = decision
    application.adminFeedback = decision === 'rejected' ? reason : ''
    application.reviewedBy = request.session.adminId
    application.reviewedAt = new Date()
    await application.save()

    const loanLabel = application.loanType === 'crop-loan' ? 'पीक कर्ज' : 'ट्रॅक्टर कर्ज'
    const message = decision === 'approved'
      ? `तुमचा ${loanLabel} अर्ज मंजूर झाला आहे.`
      : `तुमचा ${loanLabel} अर्ज नाकारण्यात आला आहे. कारण: ${reason}`
    await Notification.findOneAndUpdate(
      { application: application._id },
      { $set: { user: application.user, type: decision, loanType: application.loanType, message, readAt: null } },
      { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true },
    )
    return response.json({ application })
  } catch (error) {
    return next(error)
  }
})

app.get('/api/notifications', requireAuth, async (request, response, next) => {
  try {
    const notifications = await Notification.find({ user: request.session.userId }).sort({ createdAt: -1 }).lean()
    return response.json({ notifications, unreadCount: notifications.filter((notification) => !notification.readAt).length })
  } catch (error) {
    return next(error)
  }
})

app.patch('/api/notifications/:notificationId/read', requireAuth, async (request, response, next) => {
  try {
    const readAt = request.body.read === false ? null : new Date()
    const notification = await Notification.findOneAndUpdate(
      { _id: request.params.notificationId, user: request.session.userId },
      { $set: { readAt } },
      { new: true },
    )
    if (!notification) return response.status(404).json({ message: 'सूचना सापडली नाही.' })
    return response.json({ notification })
  } catch (error) {
    return next(error)
  }
})

app.patch('/api/notifications/read-all', requireAuth, async (request, response, next) => {
  try {
    await Notification.updateMany({ user: request.session.userId, readAt: null }, { $set: { readAt: new Date() } })
    return response.json({ success: true })
  } catch (error) {
    return next(error)
  }
})

app.use(handleError)

async function start() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required. Copy .env.example to .env and configure MongoDB.')
  if (process.env.NODE_ENV === 'production' && (!process.env.SESSION_SECRET || !process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD || !process.env.ADMIN_RESET_KEY)) {
    throw new Error('Production requires SESSION_SECRET, admin credentials, and ADMIN_RESET_KEY.')
  }
  await mongoose.connect(process.env.MONGO_URI)
  const adminUsername = (process.env.ADMIN_USERNAME || 'admin').trim().toLowerCase()
  const adminPassword = process.env.ADMIN_PASSWORD || 'ChangeMeAdmin123!'
  if (!(await Admin.exists({ username: adminUsername }))) {
    await Admin.create({ username: adminUsername, passwordHash: await bcrypt.hash(adminPassword, 12) })
    if (process.env.NODE_ENV !== 'production') console.warn(`Created development admin "${adminUsername}". Configure ADMIN_PASSWORD before deployment.`)
  }
  app.listen(port, () => console.log(`Mahacrop Loan API listening on port ${port}`))
}

start().catch((error) => {
  console.error(error.message)
  process.exit(1)
})
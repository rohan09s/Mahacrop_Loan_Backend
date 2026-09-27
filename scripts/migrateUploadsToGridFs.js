require('dotenv').config()

const dns = require('node:dns')
const fs = require('node:fs')
const path = require('node:path')
const mongoose = require('mongoose')
const LoanApplication = require('../models/LoanApplication')

if (process.env.DNS_SERVERS) {
  dns.setServers(process.env.DNS_SERVERS.split(',').map((server) => server.trim()))
} else {
  dns.setServers(['1.1.1.1', '8.8.8.8'])
}

const uploadDirectory = path.join(__dirname, '..', 'private-uploads')
const bucketName = 'loanDocuments'
const documentFields = ['identityProof', 'landRecord712', 'landRecord8a', 'mutationRecord', 'boundaryMap']

function copyToGridFs(bucket, filePath, originalName, mimeType) {
  return new Promise((resolve, reject) => {
    const uploadStream = bucket.openUploadStream(path.basename(filePath), {
      metadata: { originalName, mimeType },
    })
    uploadStream.once('error', reject)
    uploadStream.once('finish', () => resolve(uploadStream.id))
    fs.createReadStream(filePath).once('error', reject).pipe(uploadStream)
  })
}

async function migrate() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required.')
  await mongoose.connect(process.env.MONGO_URI)
  const bucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, { bucketName })
  const applications = await LoanApplication.find()
  let migrated = 0
  let missing = 0

  for (const application of applications) {
    for (const field of documentFields) {
      const document = application[field]
      if (!document?.filename || mongoose.isValidObjectId(document.filename)) continue
      const sourcePath = path.join(uploadDirectory, path.basename(document.filename))
      if (!fs.existsSync(sourcePath)) {
        console.warn(`Missing local file for ${application._id} (${field}): ${path.basename(document.filename)}`)
        missing += 1
        continue
      }
      const fileId = await copyToGridFs(bucket, sourcePath, document.originalName, document.mimeType)
      application.set(`${field}.filename`, fileId.toString())
      await application.save()
      migrated += 1
      console.log(`Migrated ${application._id} (${field})`)
    }
  }

  console.log(`Migration finished: ${migrated} copied to GridFS; ${missing} local files missing.`)
}

migrate()
  .catch((error) => {
    console.error(error)
    process.exitCode = 1
  })
  .finally(() => mongoose.disconnect())

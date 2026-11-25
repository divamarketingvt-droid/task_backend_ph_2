import mongoose from "mongoose";

// One personal mailbox (Gmail / Zoho Mail / Yahoo Mail / other IMAP) per app user.
// The mailbox (app) password is stored ENCRYPTED (AES-256-GCM, see services/mailCrypto.js)
// and is never sent back to the browser.
const serverSchema = new mongoose.Schema(
  {
    host: { type: String, required: true },
    port: { type: Number, required: true },
    secure: { type: Boolean, default: true },
  },
  { _id: false }
);

const mailAccountSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, unique: true },
    admin_id: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null, index: true },
    provider: { type: String, enum: ["gmail", "zoho", "yahoo", "custom"], required: true },
    email: { type: String, required: true, trim: true, lowercase: true },
    displayName: { type: String, default: "", trim: true, maxlength: 120 },
    imap: { type: serverSchema, required: true },
    smtp: { type: serverSchema, required: true },
    // Gmail already keeps a copy of mail sent over SMTP; other providers get one appended to Sent
    saveSentCopy: { type: Boolean, default: true },
    secret: {
      iv: { type: String, required: true },
      tag: { type: String, required: true },
      data: { type: String, required: true },
    },
    lastError: { type: String, default: "" },
    connectedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

export default mongoose.models.MailAccount || mongoose.model("MailAccount", mailAccountSchema);

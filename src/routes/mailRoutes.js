// /api/mail — the logged-in user's own mailbox (Gmail / Zoho Mail / Yahoo Mail / other IMAP).
// Mounted behind the normal login (protect). Every route works ONLY on req.user's mailbox.
import express from "express";
import dns from "node:dns/promises";
import net from "node:net";
import multer from "multer";
import MailAccount from "../models/MailAccount.js";
import { rateLimit } from "../middleware/integrationAuth.js";
import {
  PROVIDERS,
  providerList,
  resolveServers,
  verifyMailbox,
  encryptSecret,
  listFolders,
  listMessages,
  readMessage,
  getAttachment,
  setFlags,
  deleteMessage,
  sendMessage,
  closeMailConnection,
  MailError,
  EMAIL_RE,
  MAX_PAGE_SIZE,
} from "../services/mailService.js";

const router = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024, files: 10, fields: 20, fieldSize: 1024 * 1024 },
});

const userKey = (req) => String(req.user?._id || "");
// Connecting tries a login on someone else's server: keep it slow for guessing
const connectLimit = rateLimit({ prefix: "mail-connect", keyOf: userKey, limitOf: () => 10, windowMs: 15 * 60 * 1000 });
const sendLimit = rateLimit({ prefix: "mail-send", keyOf: userKey, limitOf: () => Number(process.env.MAIL_SEND_PER_HOUR || 100), windowMs: 60 * 60 * 1000 });
const readLimit = rateLimit({ prefix: "mail-read", keyOf: userKey, limitOf: () => 240, windowMs: 60 * 1000 });

const publicAccount = (a) =>
  a && {
    provider: a.provider,
    providerLabel: PROVIDERS[a.provider]?.label || a.provider,
    email: a.email,
    displayName: a.displayName,
    imap: a.imap,
    smtp: a.smtp,
    saveSentCopy: a.saveSentCopy,
    lastError: a.lastError,
    connectedAt: a.connectedAt,
  };

const sendError = (res, next, err) => {
  if (err instanceof MailError) {
    return res.status(err.status).json({ success: false, code: err.code, message: err.message });
  }
  if (err instanceof multer.MulterError) {
    const message = err.code === "LIMIT_FILE_SIZE" ? "Each attachment can be at most 15 MB" : err.code === "LIMIT_FILE_COUNT" ? "At most 10 attachments" : "Invalid upload";
    return res.status(413).json({ success: false, code: "upload_error", message });
  }
  return next(err);
};

const myAccount = async (req) => {
  const acc = await MailAccount.findOne({ user: req.user._id });
  if (!acc) throw new MailError("Connect your mailbox first", 404, "not_connected");
  return acc;
};

const folderOf = (req) => {
  const f = String(req.query.folder || req.body?.folder || "INBOX");
  if (!f || f.length > 300 || /[\r\n\0]/.test(f)) throw new MailError("Invalid folder");
  return f;
};

const uidOf = (req) => {
  const uid = Number(req.params.uid);
  if (!Number.isInteger(uid) || uid < 1) throw new MailError("Invalid email id");
  return uid;
};

// A "custom" server must be a public internet address (not this server or the private network)
const isPrivateIp = (ip) => {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v = ip.toLowerCase();
  return v === "::1" || v === "::" || v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80") || v.startsWith("::ffff:");
};

const ensurePublicHost = async (host) => {
  let addrs;
  try {
    addrs = await dns.lookup(host, { all: true });
  } catch {
    throw new MailError(`Server "${host}" was not found`);
  }
  if (!addrs.length || addrs.some((a) => isPrivateIp(a.address))) throw new MailError(`Server "${host}" is not allowed`);
};

/* ---------- account ---------- */

// GET /api/mail/providers — Gmail / Zoho / Yahoo / Other, with app-password help
router.get("/providers", (req, res) => res.json({ success: true, data: providerList() }));

// GET /api/mail/account — my connected mailbox (never the password)
router.get("/account", async (req, res, next) => {
  try {
    const acc = await MailAccount.findOne({ user: req.user._id }).lean();
    res.json({ success: true, data: publicAccount(acc) || null });
  } catch (err) {
    next(err);
  }
});

// POST /api/mail/account — connect (or replace) my mailbox; logs in to IMAP + SMTP first
router.post("/account", connectLimit, async (req, res, next) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "").replace(/\s+/g, ""); // Google shows app passwords with spaces
    if (!EMAIL_RE.test(email)) throw new MailError("Enter a valid email address");
    if (password.length < 4 || password.length > 256) throw new MailError("Enter the app password");
    const servers = resolveServers(req.body);
    if (servers.provider === "custom") {
      await ensurePublicHost(servers.imap.host);
      await ensurePublicHost(servers.smtp.host);
    }

    await verifyMailbox({ email, password, ...servers });

    const saveSentCopy = req.body?.saveSentCopy === undefined ? PROVIDERS[servers.provider].saveSentCopy : Boolean(req.body.saveSentCopy);
    closeMailConnection(req.user._id);
    const acc = await MailAccount.findOneAndUpdate(
      { user: req.user._id },
      {
        user: req.user._id,
        admin_id: req.user.admin_id || (req.user.role === "Admin" ? req.user._id : null),
        provider: servers.provider,
        email,
        displayName: String(req.body?.displayName || req.user.name || "").trim().slice(0, 120),
        imap: servers.imap,
        smtp: servers.smtp,
        saveSentCopy,
        secret: encryptSecret(password),
        lastError: "",
        connectedAt: new Date(),
      },
      { upsert: true, new: true, setDefaultsOnInsert: true, runValidators: true }
    );
    res.status(201).json({ success: true, message: "Mailbox connected", data: publicAccount(acc) });
  } catch (err) {
    sendError(res, next, err);
  }
});

// PATCH /api/mail/account — change display name / "save copy in Sent" (no reconnect needed)
router.patch("/account", async (req, res, next) => {
  try {
    const acc = await myAccount(req);
    if (req.body?.displayName !== undefined) acc.displayName = String(req.body.displayName).trim().slice(0, 120);
    if (req.body?.saveSentCopy !== undefined) acc.saveSentCopy = Boolean(req.body.saveSentCopy);
    await acc.save();
    res.json({ success: true, data: publicAccount(acc) });
  } catch (err) {
    sendError(res, next, err);
  }
});

// DELETE /api/mail/account — disconnect; the encrypted password is deleted
router.delete("/account", async (req, res, next) => {
  try {
    closeMailConnection(req.user._id);
    await MailAccount.deleteOne({ user: req.user._id });
    res.json({ success: true, message: "Mailbox disconnected" });
  } catch (err) {
    next(err);
  }
});

/* ---------- reading ---------- */

const remember = async (acc, err) => {
  if (err instanceof MailError && ["auth_failed", "reconnect_required"].includes(err.code)) {
    await MailAccount.updateOne({ _id: acc._id }, { lastError: err.message }).catch(() => {});
  }
};

const handler = (fn) => async (req, res, next) => {
  let acc;
  try {
    acc = await myAccount(req);
    const data = await fn(req, acc, res);
    if (data !== undefined) res.json({ success: true, data });
    if (acc.lastError) MailAccount.updateOne({ _id: acc._id }, { lastError: "" }).catch(() => {});
  } catch (err) {
    if (acc) await remember(acc, err);
    sendError(res, next, err);
  }
};

// GET /api/mail/folders
router.get("/folders", readLimit, handler((req, acc) => listFolders(acc)));

// GET /api/mail/messages?folder=INBOX&page=1&limit=25&search=
router.get(
  "/messages",
  readLimit,
  handler((req, acc) => {
    const page = Math.max(1, Math.min(100000, Number.parseInt(req.query.page, 10) || 1));
    const limit = Math.max(5, Math.min(MAX_PAGE_SIZE, Number.parseInt(req.query.limit, 10) || 25));
    const search = String(req.query.search || "").trim().slice(0, 100);
    return listMessages(acc, { folder: folderOf(req), page, limit, search });
  })
);

// GET /api/mail/messages/:uid?folder= — full email (marks it read)
router.get("/messages/:uid", readLimit, handler((req, acc) => readMessage(acc, folderOf(req), uidOf(req))));

// GET /api/mail/messages/:uid/attachments/:index?folder=
router.get(
  "/messages/:uid/attachments/:index",
  readLimit,
  handler(async (req, acc, res) => {
    const index = Number(req.params.index);
    if (!Number.isInteger(index) || index < 0 || index > 500) throw new MailError("Invalid attachment");
    const file = await getAttachment(acc, folderOf(req), uidOf(req), index);
    const safeName = file.filename.replace(/[\r\n"\\]/g, "_");
    res.set("Content-Type", file.contentType);
    // always a download — an HTML attachment must never run as a page of this API
    res.set("Content-Disposition", `attachment; filename="${safeName.replace(/[^\x20-\x7e]/g, "_")}"; filename*=UTF-8''${encodeURIComponent(file.filename)}`);
    res.set("X-Content-Type-Options", "nosniff");
    res.set("Cache-Control", "private, no-store");
    res.send(file.content);
    return undefined;
  })
);

// PATCH /api/mail/messages/:uid { folder, seen?, flagged? }
router.patch(
  "/messages/:uid",
  handler((req, acc) => {
    const { seen, flagged } = req.body || {};
    if (seen === undefined && flagged === undefined) throw new MailError("Nothing to change");
    return setFlags(acc, folderOf(req), uidOf(req), {
      seen: seen === undefined ? undefined : Boolean(seen),
      flagged: flagged === undefined ? undefined : Boolean(flagged),
    });
  })
);

// DELETE /api/mail/messages/:uid?folder= — to Trash (deleted for good when already in Trash)
router.delete("/messages/:uid", handler((req, acc) => deleteMessage(acc, folderOf(req), uidOf(req))));

/* ---------- sending ---------- */

// POST /api/mail/send  (multipart/form-data: to, cc, bcc, subject, text, inReplyTo, references, files[])
router.post("/send", sendLimit, (req, res, next) => {
  upload.array("files", 10)(req, res, async (uploadErr) => {
    if (uploadErr) return sendError(res, next, uploadErr);
    let acc;
    try {
      acc = await myAccount(req);
      const result = await sendMessage(acc, { ...req.body, files: req.files || [] });
      res.status(201).json({ success: true, message: "Email sent", data: result });
    } catch (err) {
      if (acc) await remember(acc, err);
      sendError(res, next, err);
    }
  });
});

export default router;

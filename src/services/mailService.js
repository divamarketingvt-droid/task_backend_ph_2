// src/services/mailService.js
// Personal mailbox inside BizBoard: read mail over IMAP, send over SMTP.
// Works with Gmail, Zoho Mail, Yahoo Mail and any other IMAP/SMTP mailbox, using the
// provider's free "app password" — no paid API, no Google/Microsoft app review.
//
// Security:
//   • the app password is encrypted with AES-256-GCM before it is saved
//     (key: MAIL_ENCRYPTION_KEY, or derived from JWT_SECRET when that is not set)
//   • it is decrypted only in memory, to log in to the mail server; it is never returned to
//     the browser and never logged
//   • every request works only on the logged-in user's own mailbox
import crypto from "node:crypto";
import { ImapFlow } from "imapflow";
import { simpleParser } from "mailparser";
import { convert as htmlToText } from "html-to-text";
import nodemailer from "nodemailer";
import MailComposer from "nodemailer/lib/mail-composer/index.js";

/* ==================== PROVIDERS ==================== */

const ZOHO_REGIONS = ["com", "in", "eu", "com.au", "jp", "com.cn", "sa", "ca"];

export const PROVIDERS = {
  gmail: {
    label: "Gmail",
    imap: { host: "imap.gmail.com", port: 993, secure: true },
    smtp: { host: "smtp.gmail.com", port: 465, secure: true },
    saveSentCopy: false, // Gmail stores mail sent over SMTP in "Sent Mail" by itself
    help: "Google Account → Security → turn on 2-Step Verification → App passwords → create one for \"Mail\".",
    helpUrl: "https://myaccount.google.com/apppasswords",
  },
  zoho: {
    label: "Zoho Mail",
    // host depends on the data-centre region and on personal vs. business (custom domain) account
    imap: { host: "imap.zoho.com", port: 993, secure: true },
    smtp: { host: "smtp.zoho.com", port: 465, secure: true },
    saveSentCopy: true,
    help: "Zoho Mail → Settings → Mail Accounts → IMAP Access: turn it on. With 2-factor login, create an app password under Zoho Accounts → Security → App Passwords.",
    helpUrl: "https://accounts.zoho.com/home#security/app_password",
  },
  yahoo: {
    label: "Yahoo Mail",
    imap: { host: "imap.mail.yahoo.com", port: 993, secure: true },
    smtp: { host: "smtp.mail.yahoo.com", port: 465, secure: true },
    saveSentCopy: true,
    help: "Yahoo Account Info → Account Security → Generate app password → choose \"Other app\".",
    helpUrl: "https://login.yahoo.com/account/security",
  },
  custom: {
    label: "Other (IMAP / SMTP)",
    imap: null,
    smtp: null,
    saveSentCopy: true,
    help: "Enter the IMAP and SMTP servers from your mail provider's help page.",
    helpUrl: "",
  },
};

export const providerList = () =>
  Object.entries(PROVIDERS).map(([id, p]) => ({
    id,
    label: p.label,
    help: p.help,
    helpUrl: p.helpUrl,
    saveSentCopy: p.saveSentCopy,
    ...(id === "zoho" ? { regions: ZOHO_REGIONS } : {}),
  }));

export class MailError extends Error {
  constructor(message, status = 400, code = "mail_error") {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
export const EMAIL_RE = /^[^\s@<>(),;:"\[\]\\]+@[^\s@<>(),;:"\[\]\\]+\.[^\s@<>(),;:"\[\]\\]{2,}$/;

const cleanServer = (s, name) => {
  const host = String(s?.host || "").trim().toLowerCase();
  const port = Number(s?.port);
  if (!HOST_RE.test(host)) throw new MailError(`${name} server: enter a valid host name`);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new MailError(`${name} server: enter a valid port`);
  // never let a user point the server at our own machine / private network
  if (/^(localhost|.*\.local|.*\.internal)$/.test(host)) throw new MailError(`${name} server: this host is not allowed`);
  return { host, port, secure: s?.secure === undefined ? port === 993 || port === 465 : Boolean(s.secure) };
};

// Server settings for a connect request (body from the "Connect mailbox" form)
export const resolveServers = (body) => {
  const provider = String(body?.provider || "");
  const preset = PROVIDERS[provider];
  if (!preset) throw new MailError("Choose Gmail, Zoho Mail, Yahoo Mail or Other");
  if (provider === "custom") {
    return { provider, imap: cleanServer(body.imap, "IMAP"), smtp: cleanServer(body.smtp, "SMTP") };
  }
  if (provider === "zoho") {
    const region = ZOHO_REGIONS.includes(body?.zohoRegion) ? body.zohoRegion : "com";
    const pro = Boolean(body?.zohoBusiness); // custom-domain (organization) accounts use imappro/smtppro
    return {
      provider,
      imap: { host: `${pro ? "imappro" : "imap"}.zoho.${region}`, port: 993, secure: true },
      smtp: { host: `${pro ? "smtppro" : "smtp"}.zoho.${region}`, port: 465, secure: true },
    };
  }
  return { provider, imap: { ...preset.imap }, smtp: { ...preset.smtp } };
};

/* ==================== PASSWORD ENCRYPTION ==================== */

const encryptionKey = () => {
  const raw = String(process.env.MAIL_ENCRYPTION_KEY || "").trim();
  if (raw) {
    const buf = /^[0-9a-f]{64}$/i.test(raw) ? Buffer.from(raw, "hex") : Buffer.from(raw, "base64");
    if (buf.length === 32) return buf;
    return crypto.createHash("sha256").update(raw).digest(); // any passphrase → 32 bytes
  }
  const jwt = String(process.env.JWT_SECRET || "");
  if (!jwt) throw new MailError("The server has no encryption key for mail passwords", 500, "no_key");
  return crypto.createHash("sha256").update(`bizboard-mail:${jwt}`).digest();
};

export const encryptSecret = (plain) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const data = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
  return { iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: data.toString("base64") };
};

export const decryptSecret = (secret) => {
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey(), Buffer.from(secret.iv, "base64"));
    decipher.setAuthTag(Buffer.from(secret.tag, "base64"));
    return Buffer.concat([decipher.update(Buffer.from(secret.data, "base64")), decipher.final()]).toString("utf8");
  } catch {
    // the server key changed (MAIL_ENCRYPTION_KEY / JWT_SECRET) → the user connects again
    throw new MailError("Your mailbox must be connected again (the server key changed).", 409, "reconnect_required");
  }
};

/* ==================== CONNECTIONS ==================== */

// Swappable in tests (no real mail server there)
export const connectors = {
  imap: (cfg) => new ImapFlow(cfg),
  smtp: (cfg) => nodemailer.createTransport(cfg),
};

const imapConfig = (acc, password) => ({
  host: acc.imap.host,
  port: acc.imap.port,
  secure: acc.imap.secure,
  auth: { user: acc.email, pass: password },
  logger: false,
  emitLogs: false,
  connectionTimeout: 20 * 1000,
  greetingTimeout: 15 * 1000,
  socketTimeout: 60 * 1000,
});

const smtpConfig = (acc, password) => ({
  host: acc.smtp.host,
  port: acc.smtp.port,
  secure: acc.smtp.secure,
  requireTLS: !acc.smtp.secure,
  auth: { user: acc.email, pass: password },
  connectionTimeout: 20 * 1000,
  greetingTimeout: 15 * 1000,
  socketTimeout: 60 * 1000,
});

// Turn mail-server errors into messages a user understands
export const friendlyError = (err, where = "IMAP") => {
  if (err instanceof MailError) return err;
  const text = `${err?.responseText || ""} ${err?.response || ""} ${err?.message || ""} ${err?.code || ""}`;
  if (err?.authenticationFailed || /AUTHENTICATIONFAILED|Invalid credentials|535|534|auth.*fail|Username and Password not accepted|EAUTH/i.test(text)) {
    return new MailError(
      "The mail server refused the login. Use an app password (not your normal password) and check that IMAP is turned on.",
      400,
      "auth_failed"
    );
  }
  if (/ETIMEDOUT|ECONNREFUSED|ENOTFOUND|EAI_AGAIN|ECONNRESET|timeout|Greeting never received/i.test(text)) {
    const blocked = where === "SMTP" && process.env.RENDER
      ? " Render's free plan blocks outgoing SMTP — sending works on the Hostinger server."
      : "";
    return new MailError(`Could not reach the ${where} server ${blocked}`.trim(), 502, "unreachable");
  }
  return new MailError(`The mail server returned an error (${where}).`, 502, "server_error");
};

// A short-lived connection pool: one IMAP connection per user, closed after 90 s idle.
const POOL_IDLE_MS = 90 * 1000;
const pool = new Map(); // userId → { client, key, timer }

const poolKey = (acc) => `${acc._id}:${acc.updatedAt?.valueOf?.() || ""}`;

const dropPooled = (userId) => {
  const entry = pool.get(userId);
  if (!entry) return;
  pool.delete(userId);
  clearTimeout(entry.timer);
  entry.client.logout().catch(() => entry.client.close?.());
};

export const closeMailConnection = (userId) => dropPooled(String(userId));

const getImap = async (acc) => {
  const userId = String(acc.user);
  const key = poolKey(acc);
  const existing = pool.get(userId);
  if (existing && existing.key === key && existing.client.usable) {
    clearTimeout(existing.timer);
    existing.timer = setTimeout(() => dropPooled(userId), POOL_IDLE_MS);
    existing.timer.unref?.();
    return existing.client;
  }
  if (existing) dropPooled(userId);

  const client = connectors.imap(imapConfig(acc, decryptSecret(acc.secret)));
  client.on?.("error", () => dropPooled(userId)); // a dropped socket must not crash the server
  try {
    await client.connect();
  } catch (err) {
    throw friendlyError(err, "IMAP");
  }
  const entry = { client, key, timer: null };
  entry.timer = setTimeout(() => dropPooled(userId), POOL_IDLE_MS);
  entry.timer.unref?.();
  pool.set(userId, entry);
  client.on?.("close", () => {
    if (pool.get(userId) === entry) {
      clearTimeout(entry.timer);
      pool.delete(userId);
    }
  });
  return client;
};

// Run fn(client) with the mailbox opened (and locked, so parallel requests do not collide)
const withMailbox = async (acc, folder, fn) => {
  const client = await getImap(acc);
  let lock;
  try {
    lock = await client.getMailboxLock(folder);
  } catch (err) {
    if (/NONEXISTENT|not exist|Mailbox doesn't exist|Unknown Mailbox/i.test(`${err?.responseText} ${err?.message}`)) {
      throw new MailError("This folder does not exist", 404, "no_folder");
    }
    dropPooled(String(acc.user));
    throw friendlyError(err, "IMAP");
  }
  try {
    return await fn(client);
  } catch (err) {
    if (err instanceof MailError) throw err;
    throw friendlyError(err, "IMAP");
  } finally {
    lock.release();
  }
};

/* ==================== VERIFY (connect form) ==================== */

// Log in to IMAP and SMTP once with the given settings. Throws MailError when either fails.
export const verifyMailbox = async ({ email, password, imap, smtp }) => {
  const acc = { email, imap, smtp };
  const client = connectors.imap(imapConfig(acc, password));
  client.on?.("error", () => {});
  try {
    await client.connect();
  } catch (err) {
    throw friendlyError(err, "IMAP");
  } finally {
    client.logout?.().catch?.(() => {});
  }
  try {
    const transport = connectors.smtp(smtpConfig(acc, password));
    await transport.verify();
    transport.close?.();
  } catch (err) {
    throw friendlyError(err, "SMTP");
  }
};

/* ==================== FOLDERS ==================== */

const SPECIAL = { "\\Inbox": "inbox", "\\Sent": "sent", "\\Drafts": "drafts", "\\Trash": "trash", "\\Junk": "spam", "\\Flagged": "starred", "\\All": "all", "\\Archive": "archive" };
const ORDER = ["inbox", "starred", "sent", "drafts", "archive", "spam", "trash", "all"];

const guessSpecial = (path) => {
  const p = path.toLowerCase();
  if (p === "inbox") return "inbox";
  if (/(^|\/|\.)sent( mail| items| messages)?$/.test(p)) return "sent";
  if (/(^|\/|\.)drafts?$/.test(p)) return "drafts";
  if (/(^|\/|\.)(trash|deleted( items| messages)?|bin)$/.test(p)) return "trash";
  if (/(^|\/|\.)(spam|junk( e-?mail)?|bulk( mail)?)$/.test(p)) return "spam";
  if (/(^|\/|\.)archive$/.test(p)) return "archive";
  return "";
};

export const listFolders = async (acc) => {
  const client = await getImap(acc);
  let boxes;
  try {
    boxes = await client.list({ statusQuery: { unseen: true, messages: true } });
  } catch (err) {
    dropPooled(String(acc.user));
    throw friendlyError(err, "IMAP");
  }
  const folders = boxes
    .filter((b) => !b.flags?.has?.("\\Noselect") && !b.flags?.has?.("\\NonExistent"))
    .map((b) => ({
      path: b.path,
      name: b.name,
      special: SPECIAL[b.specialUse] || guessSpecial(b.path),
      unseen: b.status?.unseen ?? 0,
      total: b.status?.messages ?? 0,
    }));
  const rank = (f) => (f.special ? ORDER.indexOf(f.special) : ORDER.length);
  return folders.sort((a, b) => rank(a) - rank(b) || a.path.localeCompare(b.path));
};

const findSpecial = async (acc, special) => (await listFolders(acc)).find((f) => f.special === special)?.path || "";

/* ==================== MESSAGES ==================== */

const addr = (list) =>
  (list || []).map((a) => ({ name: a.name || "", address: (a.address || "").toLowerCase() })).filter((a) => a.address || a.name);

const hasAttachments = (node) => {
  if (!node) return false;
  if (node.disposition === "attachment") return true;
  return (node.childNodes || []).some(hasAttachments);
};

const summary = (m) => ({
  uid: m.uid,
  subject: m.envelope?.subject || "(no subject)",
  from: addr(m.envelope?.from)[0] || null,
  to: addr(m.envelope?.to),
  date: m.envelope?.date || m.internalDate || null,
  seen: m.flags?.has?.("\\Seen") ?? false,
  flagged: m.flags?.has?.("\\Flagged") ?? false,
  attachments: hasAttachments(m.bodyStructure),
  size: m.size || 0,
});

export const MAX_PAGE_SIZE = 50;

export const listMessages = async (acc, { folder = "INBOX", page = 1, limit = 25, search = "" } = {}) =>
  withMailbox(acc, folder, async (client) => {
    const total = client.mailbox.exists || 0;
    const query = { uid: true, envelope: true, flags: true, internalDate: true, size: true, bodyStructure: true };
    let items = [];
    let count = total;

    if (search) {
      const uids = (await client.search({ or: [{ subject: search }, { from: search }, { to: search }] }, { uid: true })) || [];
      uids.sort((a, b) => b - a);
      count = uids.length;
      const slice = uids.slice((page - 1) * limit, page * limit);
      if (slice.length) for await (const m of client.fetch(slice, query, { uid: true })) items.push(summary(m));
    } else if (total > 0) {
      const end = total - (page - 1) * limit;
      if (end >= 1) {
        const start = Math.max(1, end - limit + 1);
        for await (const m of client.fetch(`${start}:${end}`, query)) items.push(summary(m));
      }
    }
    items.sort((a, b) => b.uid - a.uid);
    return { items, page, limit, total: count, pages: Math.max(1, Math.ceil(count / limit)), unseen: client.mailbox.unseen ?? null };
  });

const MAX_MESSAGE_BYTES = 30 * 1024 * 1024;
const MAX_INLINE_IMAGE_BYTES = 2 * 1024 * 1024;

const downloadParsed = async (client, uid) => {
  const meta = await client.fetchOne(String(uid), { uid: true, size: true, flags: true }, { uid: true });
  if (!meta) throw new MailError("This email no longer exists", 404, "not_found");
  if (meta.size > MAX_MESSAGE_BYTES) throw new MailError("This email is too large to open here (over 30 MB)", 413, "too_large");
  const { content } = await client.download(String(uid), undefined, { uid: true });
  return { meta, parsed: await simpleParser(content) };
};

const listedAttachments = (parsed) =>
  (parsed.attachments || [])
    .map((a, index) => ({ index, filename: a.filename || `attachment-${index + 1}`, contentType: a.contentType, size: a.size, inline: Boolean(a.related && a.cid), cid: a.cid || "" }))
    .filter((a) => !a.inline);

// Inline (cid:) images → data: URIs, so they show inside the sandboxed viewer
const inlineCidImages = (html, attachments) => {
  if (!html) return html;
  let budget = MAX_INLINE_IMAGE_BYTES * 4;
  for (const a of attachments || []) {
    if (!a.cid || !/^image\//.test(a.contentType) || a.size > MAX_INLINE_IMAGE_BYTES || a.size > budget) continue;
    budget -= a.size;
    const uri = `data:${a.contentType};base64,${a.content.toString("base64")}`;
    html = html.split(`cid:${a.cid}`).join(uri);
  }
  return html;
};

export const readMessage = async (acc, folder, uid) =>
  withMailbox(acc, folder, async (client) => {
    const { meta, parsed } = await downloadParsed(client, uid);
    if (!meta.flags?.has?.("\\Seen")) {
      await client.messageFlagsAdd(String(uid), ["\\Seen"], { uid: true }).catch(() => {});
    }
    return {
      uid: Number(uid),
      folder,
      subject: parsed.subject || "(no subject)",
      from: addr(parsed.from?.value)[0] || null,
      to: addr(parsed.to?.value),
      cc: addr(parsed.cc?.value),
      replyTo: addr(parsed.replyTo?.value),
      date: parsed.date || null,
      messageId: parsed.messageId || "",
      references: [].concat(parsed.references || []),
      html: inlineCidImages(parsed.html || "", parsed.attachments) || "",
      // HTML-only emails: plain text too, for the quote in Reply / Forward
      text: parsed.text || (parsed.html ? htmlToText(parsed.html, { wordwrap: false, selectors: [{ selector: "img", format: "skip" }, { selector: "a", options: { ignoreHref: true } }] }) : ""),
      flagged: meta.flags?.has?.("\\Flagged") ?? false,
      attachments: listedAttachments(parsed),
    };
  });

export const getAttachment = async (acc, folder, uid, index) =>
  withMailbox(acc, folder, async (client) => {
    const { parsed } = await downloadParsed(client, uid);
    const a = (parsed.attachments || [])[index];
    if (!a) throw new MailError("Attachment not found", 404, "not_found");
    return { filename: a.filename || `attachment-${index + 1}`, contentType: a.contentType || "application/octet-stream", content: a.content };
  });

export const setFlags = async (acc, folder, uid, { seen, flagged }) =>
  withMailbox(acc, folder, async (client) => {
    const ops = [];
    if (seen !== undefined) ops.push(seen ? client.messageFlagsAdd(String(uid), ["\\Seen"], { uid: true }) : client.messageFlagsRemove(String(uid), ["\\Seen"], { uid: true }));
    if (flagged !== undefined) ops.push(flagged ? client.messageFlagsAdd(String(uid), ["\\Flagged"], { uid: true }) : client.messageFlagsRemove(String(uid), ["\\Flagged"], { uid: true }));
    await Promise.all(ops);
    return { uid: Number(uid), seen, flagged };
  });

// Delete = move to Trash; already in Trash (or no Trash folder) → delete for good
export const deleteMessage = async (acc, folder, uid) => {
  const trash = await findSpecial(acc, "trash");
  return withMailbox(acc, folder, async (client) => {
    if (trash && trash !== folder) {
      await client.messageMove(String(uid), trash, { uid: true });
      return { moved: trash };
    }
    await client.messageDelete(String(uid), { uid: true });
    return { deleted: true };
  });
};

/* ==================== SEND ==================== */

export const MAX_RECIPIENTS = 50;
export const MAX_SEND_BYTES = 20 * 1024 * 1024; // all attachments together (Gmail's limit is 25 MB)

export const parseRecipients = (value, field) => {
  const list = String(value || "")
    .split(/[,;\n]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const m = /^(.*)<([^>]+)>\s*$/.exec(s);
      const address = (m ? m[2] : s).trim().toLowerCase();
      const name = m ? m[1].trim().replace(/^"|"$/g, "") : "";
      if (!EMAIL_RE.test(address)) throw new MailError(`${field}: "${s}" is not a valid email address`);
      return name ? { name, address } : address;
    });
  return list;
};

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

export const sendMessage = async (acc, input) => {
  const to = parseRecipients(input.to, "To");
  const cc = parseRecipients(input.cc, "Cc");
  const bcc = parseRecipients(input.bcc, "Bcc");
  if (!to.length && !cc.length && !bcc.length) throw new MailError("Add at least one recipient");
  if (to.length + cc.length + bcc.length > MAX_RECIPIENTS) throw new MailError(`At most ${MAX_RECIPIENTS} recipients per email`);
  const subject = String(input.subject || "").replace(/[\r\n]+/g, " ").slice(0, 400);
  const text = String(input.text || "").slice(0, 500000);
  const files = input.files || [];
  if (files.reduce((n, f) => n + f.size, 0) > MAX_SEND_BYTES) throw new MailError("Attachments are too large (20 MB in total)", 413, "too_large");

  const headerId = (v) => (/^<[^<>\s]{3,250}>$/.test(String(v || "").trim()) ? String(v).trim() : undefined);
  const references = String(input.references || "").split(/\s+/).map(headerId).filter(Boolean).slice(-20);

  const mail = {
    from: acc.displayName ? { name: acc.displayName, address: acc.email } : acc.email,
    to,
    cc,
    bcc,
    subject,
    text,
    html: `<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5;white-space:pre-wrap">${escapeHtml(text)}</div>`,
    inReplyTo: headerId(input.inReplyTo),
    references: references.length ? references : undefined,
    attachments: files.map((f) => ({ filename: f.originalname, content: f.buffer, contentType: f.mimetype })),
  };

  const password = decryptSecret(acc.secret);
  let info;
  try {
    const transport = connectors.smtp(smtpConfig(acc, password));
    info = await transport.sendMail(mail);
    transport.close?.();
  } catch (err) {
    throw friendlyError(err, "SMTP");
  }

  // Keep a copy in "Sent" (Gmail does that by itself)
  if (acc.saveSentCopy) {
    try {
      const sent = await findSpecial(acc, "sent");
      if (sent) {
        const raw = await new MailComposer({ ...mail, bcc: undefined, messageId: info?.messageId }).compile().build();
        const client = await getImap(acc);
        await client.append(sent, raw, ["\\Seen"]);
      }
    } catch {
      /* the email was sent; only the copy failed */
    }
  }
  return { messageId: info?.messageId || "", accepted: info?.accepted || [] };
};

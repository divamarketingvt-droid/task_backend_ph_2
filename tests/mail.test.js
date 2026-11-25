// Email module (/api/mail) — connect Gmail / Zoho / Yahoo, read, send, privacy.
// Real Express app + in-memory MongoDB; the IMAP / SMTP servers are fakes. Run: npm test
import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";

process.env.JWT_SECRET = "test-secret-only-for-tests";
for (const k of ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REFRESH_TOKEN", "SMTP_USER", "SMTP_PASS", "BREVO_API_KEY", "CLOUDINARY_URL", "TASK_INBOX_ENABLED", "RENDER", "TELEGRAM_BOT_TOKEN", "MAIL_ENCRYPTION_KEY"]) process.env[k] = "";
process.env.NODE_ENV = "test";

const { MongoMemoryServer } = await import("mongodb-memory-server");
const mongoose = (await import("mongoose")).default;
const jwt = (await import("jsonwebtoken")).default;
const MailComposer = (await import("nodemailer/lib/mail-composer/index.js")).default;
const mongod = await MongoMemoryServer.create();
process.env.MONGO_URI = mongod.getUri();

const { server } = await import("../src/app.js");
const User = (await import("../src/models/User.js")).default;
const MailAccount = (await import("../src/models/MailAccount.js")).default;
const mail = await import("../src/services/mailService.js");
const { resetRateLimits } = await import("../src/middleware/integrationAuth.js");

/* ---------- fake mail servers ---------- */
const GOOD_PASSWORD = "abcdefghijklmnop";
const raw = await new MailComposer({
  from: "Priya <priya@client.com>",
  to: "me@gmail.com",
  subject: "Quote for March",
  text: "Hello",
  html: "<p>Hello <b>there</b></p>",
  attachments: [{ filename: "quote.pdf", content: Buffer.from("PDF-DATA"), contentType: "application/pdf" }],
}).compile().build();

const state = { imapLogins: [], sent: [], appended: [], flags: [], moved: [] };
const messages = [1, 2, 3].map((uid) => ({
  uid,
  seq: uid,
  envelope: { subject: `Mail ${uid}`, from: [{ name: "Priya", address: "priya@client.com" }], to: [{ address: "me@gmail.com" }], date: new Date(2026, 0, uid) },
  flags: new Set(uid === 3 ? [] : ["\\Seen"]),
  size: raw.length,
  bodyStructure: { childNodes: [{ disposition: "attachment" }] },
}));

class FakeImap {
  constructor(cfg) {
    this.cfg = cfg;
    this.usable = false;
    this.mailbox = null;
  }
  on() {}
  async connect() {
    state.imapLogins.push({ host: this.cfg.host, user: this.cfg.auth.user });
    if (this.cfg.auth.pass !== GOOD_PASSWORD) {
      const e = new Error("Command failed");
      e.authenticationFailed = true;
      throw e;
    }
    this.usable = true;
  }
  async logout() { this.usable = false; }
  async list() {
    return [
      { path: "INBOX", name: "INBOX", specialUse: "\\Inbox", flags: new Set(), status: { unseen: 1, messages: 3 } },
      { path: "Sent", name: "Sent", specialUse: "\\Sent", flags: new Set(), status: { unseen: 0, messages: 0 } },
      { path: "Trash", name: "Trash", flags: new Set(), status: { unseen: 0, messages: 0 } },
    ];
  }
  async getMailboxLock(path) {
    if (!["INBOX", "Sent", "Trash"].includes(path)) {
      const e = new Error("Mailbox doesn't exist");
      e.responseText = "NONEXISTENT";
      throw e;
    }
    this.mailbox = { path, exists: path === "INBOX" ? messages.length : 0, unseen: 1 };
    return { release() {} };
  }
  async *fetch(range) {
    const list = Array.isArray(range) ? messages.filter((m) => range.includes(m.uid)) : messages;
    for (const m of list) yield m;
  }
  async fetchOne(uid) { return messages.find((m) => String(m.uid) === String(uid)); }
  async download() { return { content: Readable.from([raw]) }; }
  async search() { return [1, 3]; }
  async messageFlagsAdd(uid, f) { state.flags.push(["add", uid, ...f]); }
  async messageFlagsRemove(uid, f) { state.flags.push(["remove", uid, ...f]); }
  async messageMove(uid, to) { state.moved.push([uid, to]); }
  async messageDelete() {}
  async append(path, content) { state.appended.push({ path, content: String(content) }); }
}

mail.connectors.imap = (cfg) => new FakeImap(cfg);
mail.connectors.smtp = (cfg) => ({
  async verify() {
    if (cfg.auth.pass !== GOOD_PASSWORD) throw Object.assign(new Error("535 auth"), { code: "EAUTH" });
    return true;
  },
  async sendMail(m) {
    state.sent.push({ cfg, m });
    return { messageId: "<sent-1@test>", accepted: [].concat(m.to) };
  },
  close() {},
});

/* ---------- helpers ---------- */
let base;
const call = async (method, url, { token, json, form } = {}) => {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  let body;
  if (json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(json);
  } else if (form) body = form;
  const res = await fetch(base + url, { method, headers, body });
  const type = res.headers.get("content-type") || "";
  return { status: res.status, headers: res.headers, data: type.includes("json") ? await res.json() : Buffer.from(await res.arrayBuffer()) };
};
const U = {};
const J = {};

before(async () => {
  await mongoose.connect(mongod.getUri());
  await new Promise((r) => server.listen(0, r));
  base = `http://127.0.0.1:${server.address().port}`;
  const mk = (o) => User.create({ password: "Pass@123", status: "Active", emailVerified: true, ...o });
  U.admin = await mk({ name: "Admin A", email: "a@z.io", role: "Admin", companyName: "Org A" });
  U.mgr = await mk({ name: "Manager A", email: "mgr@z.io", role: "Manager", admin_id: U.admin._id, createdBy: U.admin._id });
  U.user = await mk({ name: "Worker A", email: "w@z.io", role: "User", admin_id: U.admin._id, createdBy: U.admin._id });
  for (const k of Object.keys(U)) J[k] = jwt.sign({ id: U[k]._id, role: U[k].role }, process.env.JWT_SECRET, { expiresIn: "1h" });
});

after(async () => {
  for (const k of Object.keys(U)) mail.closeMailConnection(U[k]._id);
  await new Promise((r) => server.close(r));
  await mongoose.disconnect();
  await mongod.stop();
});

/* ---------- tests ---------- */
describe("Email module", () => {
  test("needs login; not connected yet", async () => {
    assert.equal((await call("GET", "/api/mail/account")).status, 401);
    const r = await call("GET", "/api/mail/account", { token: J.user });
    assert.equal(r.status, 200);
    assert.equal(r.data.data, null);
    const m = await call("GET", "/api/mail/messages", { token: J.user });
    assert.equal(m.status, 404);
    assert.equal(m.data.code, "not_connected");
  });

  test("providers list Gmail, Zoho, Yahoo and Other", async () => {
    const r = await call("GET", "/api/mail/providers", { token: J.user });
    assert.deepEqual(r.data.data.map((p) => p.id), ["gmail", "zoho", "yahoo", "custom"]);
  });

  test("wrong app password is refused and nothing is saved", async () => {
    resetRateLimits();
    const r = await call("POST", "/api/mail/account", { token: J.user, json: { provider: "gmail", email: "me@gmail.com", password: "wrong-pass" } });
    assert.equal(r.status, 400);
    assert.equal(r.data.code, "auth_failed");
    assert.equal(await MailAccount.countDocuments({ user: U.user._id }), 0);
  });

  test("connect Gmail: password stored encrypted and never returned", async () => {
    // Google shows app passwords as "abcd efgh ijkl mnop" — spaces are removed
    const r = await call("POST", "/api/mail/account", { token: J.user, json: { provider: "gmail", email: "Me@Gmail.com", password: "abcd efgh ijkl mnop" } });
    assert.equal(r.status, 201, JSON.stringify(r.data));
    assert.equal(r.data.data.email, "me@gmail.com");
    assert.equal(r.data.data.imap.host, "imap.gmail.com");
    assert.equal(r.data.data.saveSentCopy, false);
    const text = JSON.stringify(r.data);
    assert.ok(!text.includes(GOOD_PASSWORD) && !text.includes("secret"));

    const doc = await MailAccount.findOne({ user: U.user._id }).lean();
    assert.ok(!JSON.stringify(doc).includes(GOOD_PASSWORD));
    assert.equal(mail.decryptSecret(doc.secret), GOOD_PASSWORD);
  });

  test("Zoho business account in India uses imappro.zoho.in / smtppro.zoho.in", () => {
    const s = mail.resolveServers({ provider: "zoho", zohoRegion: "in", zohoBusiness: true });
    assert.equal(s.imap.host, "imappro.zoho.in");
    assert.equal(s.smtp.host, "smtppro.zoho.in");
    assert.equal(mail.resolveServers({ provider: "yahoo" }).imap.host, "imap.mail.yahoo.com");
  });

  test("custom server cannot point at this machine or a private network", async () => {
    resetRateLimits();
    for (const host of ["localhost", "127.0.0.1", "mail.internal"]) {
      const r = await call("POST", "/api/mail/account", {
        token: J.mgr,
        json: { provider: "custom", email: "me@corp.com", password: GOOD_PASSWORD, imap: { host, port: 993 }, smtp: { host: "smtp.corp.com", port: 465 } },
      });
      assert.equal(r.status, 400, host);
    }
  });

  test("folders and inbox list (newest first)", async () => {
    const f = await call("GET", "/api/mail/folders", { token: J.user });
    assert.equal(f.status, 200);
    assert.deepEqual(f.data.data.map((x) => x.special), ["inbox", "sent", "trash"]);

    const r = await call("GET", "/api/mail/messages?folder=INBOX&page=1&limit=25", { token: J.user });
    assert.equal(r.status, 200);
    assert.deepEqual(r.data.data.items.map((m) => m.uid), [3, 2, 1]);
    assert.equal(r.data.data.items[0].seen, false);
    assert.equal(r.data.data.items[0].attachments, true);

    const s = await call("GET", "/api/mail/messages?search=priya", { token: J.user });
    assert.deepEqual(s.data.data.items.map((m) => m.uid), [3, 1]);

    const nf = await call("GET", "/api/mail/messages?folder=Nope", { token: J.user });
    assert.equal(nf.status, 404);
  });

  test("open an email: body, attachments, marked as read; download attachment", async () => {
    state.flags.length = 0;
    const r = await call("GET", "/api/mail/messages/3?folder=INBOX", { token: J.user });
    assert.equal(r.status, 200);
    assert.equal(r.data.data.subject, "Quote for March");
    assert.match(r.data.data.html, /<b>there<\/b>/);
    assert.equal(r.data.data.attachments[0].filename, "quote.pdf");
    assert.deepEqual(state.flags[0], ["add", "3", "\\Seen"]);

    const a = await call("GET", `/api/mail/messages/3/attachments/${r.data.data.attachments[0].index}?folder=INBOX`, { token: J.user });
    assert.equal(a.status, 200);
    assert.equal(a.data.toString(), "PDF-DATA");
    assert.match(a.headers.get("content-disposition"), /^attachment;/);
  });

  test("star, and delete moves to Trash", async () => {
    const p = await call("PATCH", "/api/mail/messages/2", { token: J.user, json: { folder: "INBOX", flagged: true } });
    assert.equal(p.status, 200);
    const d = await call("DELETE", "/api/mail/messages/2?folder=INBOX", { token: J.user });
    assert.equal(d.status, 200);
    assert.deepEqual(state.moved.at(-1), ["2", "Trash"]);
  });

  test("send: from my mailbox, with attachment; bad address refused", async () => {
    const bad = new FormData();
    bad.append("to", "not-an-email");
    bad.append("subject", "x");
    const b = await call("POST", "/api/mail/send", { token: J.user, form: bad });
    assert.equal(b.status, 400);

    const form = new FormData();
    form.append("to", "Priya <priya@client.com>, ravi@client.com");
    form.append("subject", "Re: Quote for March");
    form.append("text", "Thanks <b>a lot</b>");
    form.append("inReplyTo", "<abc@client.com>");
    form.append("files", new Blob(["hello"], { type: "text/plain" }), "note.txt");
    const r = await call("POST", "/api/mail/send", { token: J.user, form });
    assert.equal(r.status, 201, JSON.stringify(r.data));
    const sent = state.sent.at(-1);
    assert.equal(sent.cfg.host, "smtp.gmail.com");
    assert.equal(sent.cfg.auth.user, "me@gmail.com");
    assert.equal(sent.m.to.length, 2);
    assert.equal(sent.m.inReplyTo, "<abc@client.com>");
    assert.equal(sent.m.attachments[0].filename, "note.txt");
    assert.match(sent.m.html, /&lt;b&gt;/); // typed text is escaped, never sent as HTML
    assert.equal(state.appended.length, 0); // Gmail keeps its own copy
  });

  test("Yahoo: a copy is saved in Sent", async () => {
    resetRateLimits();
    const c = await call("POST", "/api/mail/account", { token: J.mgr, json: { provider: "yahoo", email: "boss@yahoo.com", password: GOOD_PASSWORD } });
    assert.equal(c.status, 201);
    const form = new FormData();
    form.append("to", "x@client.com");
    form.append("subject", "Hi");
    form.append("text", "Hello");
    assert.equal((await call("POST", "/api/mail/send", { token: J.mgr, form })).status, 201);
    assert.equal(state.appended.at(-1).path, "Sent");
    assert.equal(state.sent.at(-1).cfg.host, "smtp.mail.yahoo.com");
  });

  test("each person sees only their own mailbox", async () => {
    const mine = await call("GET", "/api/mail/account", { token: J.mgr });
    assert.equal(mine.data.data.email, "boss@yahoo.com");
    const admin = await call("GET", "/api/mail/account", { token: J.admin });
    assert.equal(admin.data.data, null); // even the Admin cannot read a member's mailbox
    const list = await call("GET", "/api/mail/messages", { token: J.admin });
    assert.equal(list.status, 404);
  });

  test("disconnect deletes the stored password", async () => {
    const r = await call("DELETE", "/api/mail/account", { token: J.mgr });
    assert.equal(r.status, 200);
    assert.equal(await MailAccount.countDocuments({ user: U.mgr._id }), 0);
  });

  test("changed server key → reconnect_required", async () => {
    process.env.MAIL_ENCRYPTION_KEY = "a".repeat(64);
    mail.closeMailConnection(U.user._id);
    const r = await call("GET", "/api/mail/folders", { token: J.user });
    assert.equal(r.status, 409);
    assert.equal(r.data.code, "reconnect_required");
    process.env.MAIL_ENCRYPTION_KEY = "";
  });
});

// Encrypted login: the same Web Crypto steps the browser runs (frontend/src/services/loginCrypto.js)
import { test, before, after } from "node:test";
import assert from "node:assert/strict";

process.env.JWT_SECRET = "test-secret-only-for-tests";
for (const k of ["SMTP_USER", "SMTP_PASS", "BREVO_API_KEY", "TELEGRAM_BOT_TOKEN", "TASK_INBOX_ENABLED", "RENDER", "LOGIN_RSA_PRIVATE_KEY"]) process.env[k] = "";
process.env.NODE_ENV = "test";

const { MongoMemoryServer } = await import("mongodb-memory-server");
const mongoose = (await import("mongoose")).default;
const mongod = await MongoMemoryServer.create();
const { server } = await import("../src/app.js");
const User = (await import("../src/models/User.js")).default;

let base;
const post = async (json) => {
  const r = await fetch(base + "/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(json) });
  return { status: r.status, data: await r.json() };
};
const subtle = globalThis.crypto.subtle;
const b64 = (buf) => Buffer.from(buf).toString("base64");

const encrypt = async (email, password, { ts = Date.now(), nonce, kid } = {}) => {
  const key = (await (await fetch(base + "/api/auth/login-key")).json()).data;
  const rsa = await subtle.importKey("spki", Buffer.from(key.publicKey, "base64"), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  const aes = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const body = JSON.stringify({ email, password, ts, nonce: nonce || Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("hex") });
  const data = await subtle.encrypt({ name: "AES-GCM", iv }, aes, new TextEncoder().encode(body));
  const wrapped = await subtle.encrypt({ name: "RSA-OAEP" }, rsa, await subtle.exportKey("raw", aes));
  return { encrypted: { kid: kid || key.kid, key: b64(wrapped), iv: b64(iv), data: b64(data) } };
};

before(async () => {
  await mongoose.connect(mongod.getUri());
  await new Promise((r) => server.listen(0, r));
  base = `http://127.0.0.1:${server.address().port}`;
  await User.create({ name: "Admin", email: "enc@test.io", password: "Secret@123", role: "Admin", status: "Active", emailVerified: true });
});
after(async () => {
  await new Promise((r) => server.close(r));
  await mongoose.disconnect();
  await mongod.stop();
});

test("encrypted login works, and the body contains no email or password", async () => {
  const body = await encrypt("enc@test.io", "Secret@123");
  const raw = JSON.stringify(body);
  assert.ok(!raw.includes("enc@test.io") && !raw.includes("Secret@123"));
  const r = await post(body);
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.ok(r.data.data.token);
});

test("wrong password is still refused through the encrypted path", async () => {
  assert.equal((await post(await encrypt("enc@test.io", "Wrong@123"))).status, 401);
});

test("a captured encrypted body cannot be replayed", async () => {
  const body = await encrypt("enc@test.io", "Secret@123");
  assert.equal((await post(body)).status, 200);
  const again = await post(body);
  assert.equal(again.status, 400);
  assert.equal(again.data.code, "login_replayed");
});

test("old, tampered and stale-key bodies are refused", async () => {
  const old = await post(await encrypt("enc@test.io", "Secret@123", { ts: Date.now() - 60 * 60 * 1000 }));
  assert.equal(old.data.code, "login_expired");

  const body = await encrypt("enc@test.io", "Secret@123");
  const d = Buffer.from(body.encrypted.data, "base64");
  d[0] ^= 1;
  body.encrypted.data = d.toString("base64");
  assert.equal((await post(body)).data.code, "bad_encrypted_login");

  const stale = await post(await encrypt("enc@test.io", "Secret@123", { kid: "0000000000000000" }));
  assert.equal(stale.status, 409);
  assert.equal(stale.data.code, "login_key_changed");

  assert.equal((await post({ encrypted: "nonsense" })).status, 400);
});

test("plain login still works (older app versions), unless encryption is required", async () => {
  assert.equal((await post({ email: "enc@test.io", password: "Secret@123" })).status, 200);
  process.env.LOGIN_REQUIRE_ENCRYPTION = "true";
  try {
    const r = await post({ email: "enc@test.io", password: "Secret@123" });
    assert.equal(r.status, 400);
    assert.equal(r.data.code, "encryption_required");
    assert.equal((await post(await encrypt("enc@test.io", "Secret@123"))).status, 200);
  } finally {
    delete process.env.LOGIN_REQUIRE_ENCRYPTION;
  }
});

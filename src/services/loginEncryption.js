// src/services/loginEncryption.js
// Encrypted login: the browser encrypts { email, password } so the request body
// (and the DevTools "Payload" tab) never shows them in plain text.
//
//   1. GET  /api/auth/login-key  → RSA public key (+ key id)
//   2. browser: random AES-256-GCM key encrypts {email,password,ts,nonce};
//      the RSA public key (RSA-OAEP / SHA-256) encrypts that AES key
//   3. POST /api/auth/login  { encrypted: { kid, key, iv, data } }
//   4. here: RSA private key → AES key → plaintext; too old or reused → refused
//
// This sits ON TOP of HTTPS (which already encrypts everything on the network).
// Private key: LOGIN_RSA_PRIVATE_KEY (PEM) if set, otherwise a new key pair is made when
// the server starts (fine for one instance; the browser simply fetches the new key).
import crypto from "crypto";

const MAX_AGE_MS = 2 * 60 * 1000; // an encrypted login is valid for 2 minutes
const CLOCK_SKEW_MS = 5 * 60 * 1000; // browsers with a slightly wrong clock

export class LoginDecryptError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

let keys = null;
const loadKeys = () => {
  if (keys) return keys;
  const pem = String(process.env.LOGIN_RSA_PRIVATE_KEY || "").replace(/\\n/g, "\n").trim();
  let privateKey;
  if (pem) {
    try {
      privateKey = crypto.createPrivateKey(pem);
    } catch {
      console.warn("⚠️ LOGIN_RSA_PRIVATE_KEY is not a valid PEM private key — using a generated key instead");
    }
  }
  if (!privateKey) {
    privateKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
  }
  const publicDer = crypto.createPublicKey(privateKey).export({ type: "spki", format: "der" });
  keys = {
    privateKey,
    publicKey: publicDer.toString("base64"),
    kid: crypto.createHash("sha256").update(publicDer).digest("hex").slice(0, 16),
  };
  return keys;
};

export const getLoginKey = () => {
  const { kid, publicKey } = loadKeys();
  return { kid, alg: "RSA-OAEP-256+A256GCM", publicKey };
};

// One-time numbers already used (replay protection), forgotten after they expire
const seenNonces = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [n, exp] of seenNonces) if (exp <= now) seenNonces.delete(n);
}, 60 * 1000).unref();

const b64 = (v, name) => {
  if (typeof v !== "string" || !/^[A-Za-z0-9+/=_-]+$/.test(v) || v.length > 4096) {
    throw new LoginDecryptError("bad_encrypted_login", `Encrypted login: invalid ${name}`);
  }
  return Buffer.from(v, "base64");
};

export const decryptLogin = (encrypted) => {
  if (!encrypted || typeof encrypted !== "object") {
    throw new LoginDecryptError("bad_encrypted_login", "Encrypted login: invalid format");
  }
  const { privateKey, kid } = loadKeys();
  if (encrypted.kid !== kid) {
    // server restarted / key rotated → the browser fetches the new key and tries again
    throw new LoginDecryptError("login_key_changed", "The login key changed. Please try again.", 409);
  }

  const wrappedKey = b64(encrypted.key, "key");
  const iv = b64(encrypted.iv, "iv");
  const data = b64(encrypted.data, "data");
  if (iv.length !== 12 || data.length < 17) throw new LoginDecryptError("bad_encrypted_login", "Encrypted login: invalid format");

  let plain;
  try {
    const aesKey = crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      wrappedKey
    );
    if (aesKey.length !== 32) throw new Error("bad key length");
    // WebCrypto AES-GCM output = ciphertext followed by the 16-byte tag
    const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
    decipher.setAuthTag(data.subarray(data.length - 16));
    plain = Buffer.concat([decipher.update(data.subarray(0, data.length - 16)), decipher.final()]).toString("utf8");
  } catch {
    throw new LoginDecryptError("bad_encrypted_login", "Encrypted login could not be decrypted");
  }

  let body;
  try {
    body = JSON.parse(plain);
  } catch {
    throw new LoginDecryptError("bad_encrypted_login", "Encrypted login: invalid content");
  }

  const ts = Number(body.ts);
  const age = Date.now() - ts;
  if (!Number.isFinite(ts) || age > MAX_AGE_MS + CLOCK_SKEW_MS || age < -CLOCK_SKEW_MS) {
    throw new LoginDecryptError("login_expired", "This login request is too old. Please try again.");
  }
  const nonce = typeof body.nonce === "string" ? body.nonce : "";
  if (nonce.length < 16 || nonce.length > 64) throw new LoginDecryptError("bad_encrypted_login", "Encrypted login: invalid content");
  if (seenNonces.has(nonce)) throw new LoginDecryptError("login_replayed", "This login request was already used. Please try again.");
  seenNonces.set(nonce, Date.now() + MAX_AGE_MS + 2 * CLOCK_SKEW_MS);

  return { email: String(body.email ?? ""), password: String(body.password ?? "") };
};

// Middleware for POST /api/auth/login: { encrypted } → req.body = { email, password }.
// A plain { email, password } body still works unless LOGIN_REQUIRE_ENCRYPTION=true.
export const decryptLoginBody = (req, res, next) => {
  if (req.body && req.body.encrypted !== undefined) {
    try {
      req.body = decryptLogin(req.body.encrypted);
    } catch (err) {
      if (err instanceof LoginDecryptError) {
        return res.status(err.status).json({ success: false, code: err.code, message: err.message });
      }
      return next(err);
    }
    return next();
  }
  if (String(process.env.LOGIN_REQUIRE_ENCRYPTION || "").toLowerCase() === "true") {
    return res.status(400).json({ success: false, code: "encryption_required", message: "Please refresh the page and log in again." });
  }
  next();
};

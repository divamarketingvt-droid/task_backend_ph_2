// src/middleware/integrationAuth.js
// Authentication for outside systems (Zoho CRM) with an integration API token:
//   Authorization: Bearer bbz_xxxxxxxx
// Login JWTs are NOT accepted here, and integration tokens are NOT accepted by the
// normal routes (those only verify JWTs), so the two never mix.
//
// After a token is checked the request acts as the organization's Admin, so the
// existing scope (admin_id isolation) and permission middleware work unchanged.
import crypto from "crypto";
import User from "../models/User.js";
import IntegrationToken, {
  INTEGRATION_TOKEN_PREFIX,
  hashIntegrationToken,
} from "../models/IntegrationToken.js";

const fail = (res, status, code, message) => res.status(status).json({ success: false, code, message });

// bbz_ + 43 base64url characters
const TOKEN_SHAPE = new RegExp(`^${INTEGRATION_TOKEN_PREFIX}[A-Za-z0-9_-]{43}$`);

// lastUsedAt is written at most once a minute per token (not on every request)
const LAST_USED_WRITE_MS = 60 * 1000;

export const authenticateIntegration = async (req, res, next) => {
  try {
    const header = req.get("authorization") || "";
    const match = /^Bearer\s+(\S+)\s*$/i.exec(header);
    if (!match) {
      res.set("WWW-Authenticate", 'Bearer realm="blizz-board-api"');
      return fail(res, 401, "missing_token", "Missing API token. Send the header  Authorization: Bearer <your API token>");
    }
    const token = match[1];

    if (!TOKEN_SHAPE.test(token)) {
      res.set("WWW-Authenticate", 'Bearer error="invalid_token"');
      return fail(
        res,
        401,
        "invalid_token",
        token.startsWith(INTEGRATION_TOKEN_PREFIX)
          ? "Invalid API token."
          : "Invalid API token. This API needs an integration API token (starts with bbz_), not a login token."
      );
    }

    const hash = hashIntegrationToken(token);
    const doc = await IntegrationToken.findOne({ tokenHash: hash }).select("+tokenHash");
    // compare in constant time (both are 32-byte SHA-256 digests)
    const same =
      doc &&
      crypto.timingSafeEqual(Buffer.from(doc.tokenHash, "hex"), Buffer.from(hash, "hex"));
    if (!same) {
      res.set("WWW-Authenticate", 'Bearer error="invalid_token"');
      return fail(res, 401, "invalid_token", "Invalid API token.");
    }

    if (!doc.isActive) {
      res.set("WWW-Authenticate", 'Bearer error="invalid_token", error_description="revoked"');
      return fail(res, 401, "token_revoked", "This API token has been revoked. Create a new token.");
    }
    const now = new Date();
    if (doc.expiresAt && doc.expiresAt <= now) {
      res.set("WWW-Authenticate", 'Bearer error="invalid_token", error_description="expired"');
      return fail(res, 401, "token_expired", "This API token has expired. Regenerate it or create a new one.");
    }

    // The organization must still exist and be active
    const admin = await User.findById(doc.admin_id);
    if (!admin || admin.role !== "Admin" || admin.status !== "Active") {
      return fail(res, 403, "organization_inactive", "The organization of this API token is not active.");
    }

    req.user = admin; // act as the org's Admin → attachScope gives { admin_id: admin._id }
    req.authType = "integration";
    req.apiToken = {
      id: doc._id,
      name: doc.name,
      permissions: doc.permissions,
      admin_id: doc.admin_id,
    };

    if (!doc.lastUsedAt || now - doc.lastUsedAt > LAST_USED_WRITE_MS) {
      IntegrationToken.updateOne({ _id: doc._id }, { $set: { lastUsedAt: now, lastUsedIp: req.ip || "" } }).catch(() => {});
    }
    next();
  } catch (err) {
    next(err);
  }
};

// The token must carry this permission (e.g. "tasks:write")
export const requireTokenScope = (scope) => (req, res, next) => {
  if (!req.apiToken?.permissions?.includes(scope)) {
    return fail(res, 403, "insufficient_scope", `This API token does not have the "${scope}" permission.`);
  }
  next();
};

/* ==================== RATE LIMITING (in memory, per instance) ==================== */
// Fixed one-minute windows. No extra package or paid service needed; on Render free
// there is a single instance, so the counts are exact.
const buckets = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [key, b] of buckets) if (b.resetAt <= now) buckets.delete(key);
}, 60 * 1000).unref();

const envInt = (name, fallback) => {
  const n = parseInt(process.env[name], 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

export const rateLimit = ({ keyOf, limitOf, windowMs = 60 * 1000, prefix }) => (req, res, next) => {
  const key = keyOf(req);
  if (!key) return next();
  const limit = limitOf();
  const now = Date.now();
  const id = `${prefix}:${key}`;
  let b = buckets.get(id);
  if (!b || b.resetAt <= now) {
    b = { count: 0, resetAt: now + windowMs };
    buckets.set(id, b);
  }
  b.count += 1;
  const resetSec = Math.ceil((b.resetAt - now) / 1000);
  res.set("RateLimit-Limit", String(limit));
  res.set("RateLimit-Remaining", String(Math.max(0, limit - b.count)));
  res.set("RateLimit-Reset", String(resetSec));
  if (b.count > limit) {
    res.set("Retry-After", String(resetSec));
    return fail(res, 429, "rate_limited", `Too many requests. Try again in ${resetSec} seconds.`);
  }
  next();
};

// Before the token is checked: per IP (slows down token guessing)
export const integrationIpLimit = rateLimit({
  prefix: "ip",
  keyOf: (req) => req.ip,
  limitOf: () => envInt("INTEGRATION_RATE_LIMIT_IP_PER_MIN", 120),
});

// After the token is checked: per token
export const integrationTokenLimit = rateLimit({
  prefix: "tok",
  keyOf: (req) => req.apiToken && String(req.apiToken.id),
  limitOf: () => envInt("INTEGRATION_RATE_LIMIT_PER_MIN", 60),
});

// Test helper
export const resetRateLimits = () => buckets.clear();

/* ==================== REQUEST LOG ==================== */
// One line per request. Never logs headers, bodies, tokens or query values.
export const integrationRequestLog = (req, res, next) => {
  if (process.env.NODE_ENV === "test") return next();
  const started = Date.now();
  res.on("finish", () => {
    const who = req.apiToken ? `token=${req.apiToken.id} org=${req.apiToken.admin_id}` : "token=-";
    console.log(
      `[integration] ${req.method} ${req.baseUrl}${req.path} ${res.statusCode} ${Date.now() - started}ms ${who} ip=${req.ip}`
    );
  });
  next();
};

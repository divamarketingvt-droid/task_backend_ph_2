// src/models/IntegrationToken.js
// API tokens for outside systems (Zoho CRM). Separate from user login JWTs.
// Only a SHA-256 hash of the token is stored; the plain token is shown once, when created.
import crypto from "crypto";
import mongoose from "mongoose";

export const INTEGRATION_TOKEN_PREFIX = "bbz_";

// What a token may do. Least privilege: pick only what the integration needs.
export const INTEGRATION_SCOPES = ["tasks:read", "tasks:write", "users:read", "departments:read"];
export const DEFAULT_INTEGRATION_SCOPES = ["tasks:read", "users:read", "departments:read"];

// 32 random bytes → 43 base64url characters after the prefix (256 bits of entropy)
export const generateIntegrationToken = () =>
  INTEGRATION_TOKEN_PREFIX + crypto.randomBytes(32).toString("base64url");

export const hashIntegrationToken = (token) =>
  crypto.createHash("sha256").update(String(token), "utf8").digest("hex");

const integrationTokenSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 80 },
    // never returned by queries unless asked for with .select("+tokenHash")
    tokenHash: { type: String, required: true, unique: true, select: false },
    // first characters of the token, so people can tell their tokens apart ("bbz_AbC1…")
    tokenPreview: { type: String, required: true },
    permissions: {
      type: [{ type: String, enum: INTEGRATION_SCOPES }],
      default: () => [...DEFAULT_INTEGRATION_SCOPES],
    },
    // ⭐ The organization this token belongs to — the token can never see another org
    admin_id: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    expiresAt: { type: Date, default: null }, // null → never expires
    lastUsedAt: { type: Date, default: null },
    lastUsedIp: { type: String, default: "" },
    isActive: { type: Boolean, default: true, index: true },
    revokedAt: { type: Date, default: null },
    revokedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    // the token this one replaced (set by "regenerate")
    replaces: { type: mongoose.Schema.Types.ObjectId, ref: "IntegrationToken", default: null },
  },
  { timestamps: true } // createdAt / updatedAt
);

integrationTokenSchema.methods.statusLabel = function statusLabel(now = new Date()) {
  if (!this.isActive) return "revoked";
  if (this.expiresAt && this.expiresAt <= now) return "expired";
  return "active";
};

// Safe shape for API responses — never includes the hash
integrationTokenSchema.methods.toPublic = function toPublic() {
  return {
    _id: this._id,
    name: this.name,
    tokenPreview: this.tokenPreview,
    permissions: this.permissions,
    admin_id: this.admin_id,
    createdBy: this.createdBy,
    createdAt: this.createdAt,
    expiresAt: this.expiresAt,
    lastUsedAt: this.lastUsedAt,
    isActive: this.isActive,
    revokedAt: this.revokedAt,
    replaces: this.replaces,
    status: this.statusLabel(),
  };
};

export default mongoose.models.IntegrationToken || mongoose.model("IntegrationToken", integrationTokenSchema);

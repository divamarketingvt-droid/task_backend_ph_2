// src/controllers/integrationTokenController.js
// Admins create / list / revoke / regenerate the API tokens their integrations (Zoho CRM) use.
// Admin → only their own organization. SuperAdmin → must name the organization (adminId).
// The plain token is returned ONCE (create / regenerate) and never stored.
import mongoose from "mongoose";
import User from "../models/User.js";
import IntegrationToken, {
  INTEGRATION_SCOPES,
  DEFAULT_INTEGRATION_SCOPES,
  generateIntegrationToken,
  hashIntegrationToken,
} from "../models/IntegrationToken.js";

const MAX_ACTIVE_TOKENS_PER_ORG = 20;

const envInt = (name, fallback) => {
  const n = parseInt(process.env[name], 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};
const defaultDays = () => envInt("INTEGRATION_TOKEN_DEFAULT_DAYS", 180);
const maxDays = () => envInt("INTEGRATION_TOKEN_MAX_DAYS", 730);
const allowNoExpiry = () => String(process.env.INTEGRATION_TOKEN_ALLOW_NO_EXPIRY || "").toLowerCase() === "true";

class InputError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

const send = (res, err) => {
  if (err instanceof InputError) return res.status(err.status).json({ success: false, message: err.message });
  console.error("Integration token error:", err.message);
  return res.status(500).json({ success: false, message: "Something went wrong" });
};

// Which organization the caller manages here
const resolveOrgId = async (req, source) => {
  if (req.user.role === "Admin") return req.user._id;
  if (req.user.role !== "SuperAdmin") throw new InputError("Only an Admin or SuperAdmin can manage API tokens", 403);
  const adminId = source?.adminId;
  if (!adminId) return null; // SuperAdmin listing every org
  if (!mongoose.Types.ObjectId.isValid(adminId)) throw new InputError("Invalid adminId");
  const admin = await User.findOne({ _id: adminId, role: "Admin" }).select("_id").lean();
  if (!admin) throw new InputError("Organization (Admin) not found", 404);
  return admin._id;
};

const parseExpiry = (value) => {
  if (value === undefined) return new Date(Date.now() + defaultDays() * 86400000);
  if (value === null || value === 0 || value === "never") {
    if (!allowNoExpiry()) throw new InputError(`Tokens must expire. Use expiresInDays between 1 and ${maxDays()}.`);
    return null;
  }
  const days = Number(value);
  if (!Number.isInteger(days) || days < 1 || days > maxDays()) {
    throw new InputError(`expiresInDays must be a whole number between 1 and ${maxDays()}`);
  }
  return new Date(Date.now() + days * 86400000);
};

const parsePermissions = (value) => {
  if (value === undefined) return [...DEFAULT_INTEGRATION_SCOPES];
  if (!Array.isArray(value) || value.length === 0) {
    throw new InputError(`permissions must be a non-empty array of: ${INTEGRATION_SCOPES.join(", ")}`);
  }
  const bad = value.filter((p) => !INTEGRATION_SCOPES.includes(p));
  if (bad.length) throw new InputError(`Unknown permission(s): ${bad.join(", ")}. Allowed: ${INTEGRATION_SCOPES.join(", ")}`);
  return [...new Set(value)];
};

const parseName = (value) => {
  const name = typeof value === "string" ? value.trim() : "";
  if (!name) throw new InputError("Token name is required (e.g. \"Zoho CRM\")");
  if (name.length > 80) throw new InputError("Token name must be at most 80 characters");
  return name;
};

const findOwnToken = async (req) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) throw new InputError("Invalid token ID");
  const filter = { _id: req.params.id };
  if (req.user.role !== "SuperAdmin") filter.admin_id = req.user._id; // ⭐ org isolation
  const doc = await IntegrationToken.findOne(filter);
  if (!doc) throw new InputError("API token not found", 404);
  return doc;
};

const issue = async ({ name, permissions, expiresAt, adminId, createdBy, replaces = null }) => {
  const token = generateIntegrationToken();
  const doc = await IntegrationToken.create({
    name,
    permissions,
    expiresAt,
    admin_id: adminId,
    createdBy,
    replaces,
    tokenHash: hashIntegrationToken(token),
    tokenPreview: `${token.slice(0, 10)}…`,
  });
  return { doc, token };
};

const ONCE_NOTE = "Copy this token now — it is shown only once and cannot be retrieved later.";

/* POST /api/integrations/tokens  { name, permissions?, expiresInDays?, adminId? (SuperAdmin) } */
export const createIntegrationToken = async (req, res) => {
  try {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const adminId = await resolveOrgId(req, body);
    if (!adminId) throw new InputError("adminId (the organization's Admin) is required for SuperAdmin");

    const name = parseName(body.name);
    const permissions = parsePermissions(body.permissions);
    const expiresAt = parseExpiry(body.expiresInDays);

    const active = await IntegrationToken.countDocuments({ admin_id: adminId, isActive: true });
    if (active >= MAX_ACTIVE_TOKENS_PER_ORG) {
      throw new InputError(`An organization can have at most ${MAX_ACTIVE_TOKENS_PER_ORG} active API tokens. Revoke an unused one first.`, 409);
    }

    const { doc, token } = await issue({ name, permissions, expiresAt, adminId, createdBy: req.user._id });
    res.status(201).json({ success: true, message: ONCE_NOTE, token, data: doc.toPublic() });
  } catch (err) {
    send(res, err);
  }
};

/* GET /api/integrations/tokens  (?adminId= for SuperAdmin) */
export const listIntegrationTokens = async (req, res) => {
  try {
    const adminId = await resolveOrgId(req, req.query);
    const filter = adminId ? { admin_id: adminId } : {};
    const docs = await IntegrationToken.find(filter).sort({ createdAt: -1 });
    res.json({ success: true, count: docs.length, data: docs.map((d) => d.toPublic()) });
  } catch (err) {
    send(res, err);
  }
};

/* POST /api/integrations/tokens/:id/revoke */
export const revokeIntegrationToken = async (req, res) => {
  try {
    const doc = await findOwnToken(req);
    if (doc.isActive) {
      doc.isActive = false;
      doc.revokedAt = new Date();
      doc.revokedBy = req.user._id;
      await doc.save();
    }
    res.json({ success: true, message: "API token revoked. Requests using it are refused from now on.", data: doc.toPublic() });
  } catch (err) {
    send(res, err);
  }
};

/* POST /api/integrations/tokens/:id/regenerate  { expiresInDays? }
 * Revokes the old token and issues a new one with the same name and permissions. */
export const regenerateIntegrationToken = async (req, res) => {
  try {
    const old = await findOwnToken(req);
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const expiresAt = parseExpiry(body.expiresInDays);
    const permissions = body.permissions !== undefined ? parsePermissions(body.permissions) : old.permissions;

    if (old.isActive) {
      old.isActive = false;
      old.revokedAt = new Date();
      old.revokedBy = req.user._id;
      await old.save();
    }
    const { doc, token } = await issue({
      name: old.name,
      permissions,
      expiresAt,
      adminId: old.admin_id,
      createdBy: req.user._id,
      replaces: old._id,
    });
    res.status(201).json({ success: true, message: `Old token revoked. ${ONCE_NOTE}`, token, data: doc.toPublic() });
  } catch (err) {
    send(res, err);
  }
};

/* DELETE /api/integrations/tokens/:id — removes the record (the token stops working) */
export const deleteIntegrationToken = async (req, res) => {
  try {
    const doc = await findOwnToken(req);
    await doc.deleteOne();
    res.json({ success: true, message: "API token deleted" });
  } catch (err) {
    send(res, err);
  }
};

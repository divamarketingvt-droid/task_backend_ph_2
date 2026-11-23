// src/routes/zohoRoutes.js
// REST API for Zoho CRM (and other integrations) — authenticated with an integration API token:
//   Authorization: Bearer bbz_...        Content-Type: application/json
//
// No duplicate task logic: every endpoint validates its input here, then calls the SAME
// controllers the app uses (getTasks, createTask, updateTask, …) behind the SAME scope and
// permission middleware. The token acts as its organization's Admin, so admin_id isolation
// is applied exactly as for a logged-in Admin.
import express from "express";
import mongoose from "mongoose";
import {
  authenticateIntegration,
  requireTokenScope,
  integrationIpLimit,
  integrationTokenLimit,
  integrationRequestLog,
} from "../middleware/integrationAuth.js";
import { attachScope } from "../middleware/scopeMiddleware.js";
import { attachPermissions, requirePermission } from "../middleware/permissionMiddleware.js";
import {
  getTasks,
  getTaskById,
  createTask,
  updateTask,
  updateTaskStatus,
} from "../controllers/taskController.js";
import { getAllUsers } from "../controllers/userController.js";
import { listDepartments } from "./departmentRoutes.js";
import { TASK_STATUSES, TASK_PRIORITIES } from "../models/Task.js";

const router = express.Router();

/* ==================== AUTH PIPELINE ==================== */
router.use(integrationRequestLog);
router.use(integrationIpLimit);
router.use(authenticateIntegration);
router.use(integrationTokenLimit);
router.use(attachScope); // → req.scope = { admin_id: <org> }, req.adminId
router.use(attachPermissions); // → the org Admin's permissions (set by SuperAdmin)

/* ==================== VALIDATION HELPERS ==================== */
const bad = (res, message, details) =>
  res.status(400).json({ success: false, code: "validation_error", message, ...(details ? { details } : {}) });

const isId = (v) => typeof v === "string" && mongoose.Types.ObjectId.isValid(v) && /^[a-f0-9]{24}$/i.test(v);
const escapeRegex = (v) => String(v).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const isStr = (v, max, min = 0) => typeof v === "string" && v.trim().length >= min && v.length <= max;
const DATE_RX = /^\d{4}-\d{2}-\d{2}(T[\d:.]+(Z|[+-]\d{2}:?\d{2})?)?$/;
const TIME_RX = /^([01]\d|2[0-3]):[0-5]\d$/;

const validId = (req, res, next) =>
  isId(req.params.id) ? next() : bad(res, "Invalid task id — expected a 24-character id");

const requireJson = (req, res, next) => {
  if (!req.is("application/json")) {
    return res.status(415).json({ success: false, code: "unsupported_media_type", message: "Send Content-Type: application/json" });
  }
  if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) return bad(res, "The request body must be a JSON object");
  next();
};

// Allowed task fields and how to check them (same rules as the Task model)
const TASK_FIELDS = {
  name: (v) => isStr(v, 200, 1) || "name must be text, 1–200 characters",
  description: (v) => isStr(v, 5000) || "description must be text, at most 5000 characters",
  dueDate: (v) => v === "" || (typeof v === "string" && DATE_RX.test(v) && !Number.isNaN(Date.parse(v))) || "dueDate must be YYYY-MM-DD (or an ISO date-time), or \"\" to clear",
  dueTime: (v) => v === "" || (typeof v === "string" && TIME_RX.test(v)) || "dueTime must be HH:mm (24-hour)",
  priority: (v) => TASK_PRIORITIES.includes(v) || `priority must be one of: ${TASK_PRIORITIES.join(", ")}`,
  complexity: (v) => (Number.isInteger(v) && v >= 0 && v <= 100) || "complexity must be a whole number 0–100",
  reward: (v) => (typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1000) || "reward must be a number 0–1000",
  assignedUser: (v) => v === null || isStr(v, 254, 1) || "assignedUser must be a user id or email",
  assignedUsers: (v) =>
    (Array.isArray(v) && v.length <= 50 && v.every((x) => isStr(x, 254, 1))) || "assignedUsers must be an array (max 50) of user ids or emails",
  department: (v) => isStr(v, 100) || "department must be text, at most 100 characters",
  departments: (v) =>
    (Array.isArray(v) && v.length <= 20 && v.every((x) => isStr(x, 100, 1))) || "departments must be an array (max 20) of department names",
};
const CREATE_ONLY = {
  status: (v) => TASK_STATUSES.includes(v) || `status must be one of: ${TASK_STATUSES.join(", ")}`,
};

const checkFields = (body, rules) => {
  const errors = [];
  const unknown = Object.keys(body).filter((k) => !rules[k]);
  if (unknown.length) errors.push(`Unknown field(s): ${unknown.join(", ")}. Allowed: ${Object.keys(rules).join(", ")}`);
  for (const [key, rule] of Object.entries(rules)) {
    if (body[key] === undefined) continue;
    const result = rule(body[key]);
    if (result !== true) errors.push(result);
  }
  return errors;
};

const validateCreate = (req, res, next) => {
  const rules = { ...TASK_FIELDS, ...CREATE_ONLY };
  const errors = checkFields(req.body, rules);
  if (req.body.name === undefined) errors.unshift("name is required");
  if (errors.length) return bad(res, errors[0], errors);
  // only the checked fields reach the controller
  req.body = Object.fromEntries(Object.entries(req.body).filter(([k]) => rules[k]));
  next();
};

const validateUpdate = (req, res, next) => {
  if ("status" in req.body) {
    return bad(res, "Change status with PATCH /api/zoho/tasks/:id/status");
  }
  const errors = checkFields(req.body, TASK_FIELDS);
  if (!Object.keys(req.body).length) errors.push("Send at least one field to update");
  if (errors.length) return bad(res, errors[0], errors);
  next();
};

const validateStatus = (req, res, next) => {
  const rules = {
    status: (v) => TASK_STATUSES.includes(v) || `status must be one of: ${TASK_STATUSES.join(", ")}`,
    note: (v) => isStr(v, 2000) || "note must be text, at most 2000 characters",
    score: (v) => (Number.isInteger(v) && v >= 1 && v <= 10) || "score must be a whole number 1–10",
  };
  const errors = checkFields(req.body, rules);
  if (req.body.status === undefined) errors.unshift("status is required");
  if (errors.length) return bad(res, errors[0], errors);
  next();
};

// GET /tasks query: checked, search made literal (no regex injection), paging added
const validateTaskQuery = (req, res, next) => {
  const q = req.query;
  const allowed = ["status", "priority", "department", "assignedTo", "search", "page", "limit"];
  const unknown = Object.keys(q).filter((k) => !allowed.includes(k));
  if (unknown.length) return bad(res, `Unknown query parameter(s): ${unknown.join(", ")}. Allowed: ${allowed.join(", ")}`);
  for (const k of allowed) if (Array.isArray(q[k]) || (q[k] !== undefined && typeof q[k] !== "string")) return bad(res, `${k} must be given once`);

  if (q.status !== undefined && !TASK_STATUSES.includes(q.status)) return bad(res, `status must be one of: ${TASK_STATUSES.join(", ")}`);
  if (q.priority !== undefined && !TASK_PRIORITIES.includes(q.priority)) return bad(res, `priority must be one of: ${TASK_PRIORITIES.join(", ")}`);
  if (q.assignedTo !== undefined && !isId(q.assignedTo)) return bad(res, "assignedTo must be a user id");
  if (q.department !== undefined && q.department.length > 100) return bad(res, "department is too long");
  if (q.search !== undefined && q.search.length > 100) return bad(res, "search must be at most 100 characters");

  const page = q.page === undefined ? 1 : Number(q.page);
  const limit = q.limit === undefined ? 50 : Number(q.limit);
  if (!Number.isInteger(page) || page < 1) return bad(res, "page must be a whole number ≥ 1");
  if (!Number.isInteger(limit) || limit < 1 || limit > 200) return bad(res, "limit must be a whole number 1–200");

  const clean = {};
  for (const k of ["status", "priority", "department", "assignedTo"]) if (q[k]) clean[k] = q[k];
  if (q.search) clean.search = escapeRegex(q.search.trim());
  req.query = clean;
  req.paging = { page, limit };
  next();
};

// Pages the list the shared controller returns
const paginate = (req, res, next) => {
  const json = res.json.bind(res);
  res.json = (payload) => {
    if (!payload?.success || !Array.isArray(payload.data)) return json(payload);
    const { page, limit } = req.paging;
    const total = payload.data.length;
    return json({
      success: true,
      count: Math.min(limit, Math.max(0, total - (page - 1) * limit)),
      total,
      page,
      limit,
      totalPages: Math.max(1, Math.ceil(total / limit)),
      data: payload.data.slice((page - 1) * limit, page * limit),
    });
  };
  next();
};

// Users: only fields an integration needs (no phone, permissions, tokens, settings)
const USER_FIELDS = ["_id", "name", "email", "role", "department", "status", "customRoleName", "createdAt"];
const slimUsers = (req, res, next) => {
  const json = res.json.bind(res);
  res.json = (payload) => {
    if (!payload?.success || !Array.isArray(payload.data)) return json(payload);
    return json({
      success: true,
      count: payload.data.length,
      data: payload.data.map((u) => Object.fromEntries(USER_FIELDS.map((f) => [f, u[f] ?? null]))),
    });
  };
  next();
};

/* ==================== ENDPOINTS ==================== */
const tasksRead = [requireTokenScope("tasks:read"), requirePermission("tasks", "view")];

router.get("/tasks", ...tasksRead, validateTaskQuery, paginate, getTasks);
router.get("/tasks/:id", ...tasksRead, validId, getTaskById);
router.post("/tasks", requireTokenScope("tasks:write"), requirePermission("tasks", "create"), requireJson, validateCreate, createTask);
router.put("/tasks/:id", requireTokenScope("tasks:write"), requirePermission("tasks", "edit"), validId, requireJson, validateUpdate, updateTask);
router.patch("/tasks/:id/status", requireTokenScope("tasks:write"), requirePermission("tasks", "view"), validId, requireJson, validateStatus, updateTaskStatus);

router.get("/users", requireTokenScope("users:read"), requirePermission("users", "view"), slimUsers, getAllUsers);
router.get("/departments", requireTokenScope("departments:read"), listDepartments);

// Unknown /api/zoho/* paths
router.use((req, res) => res.status(404).json({ success: false, code: "not_found", message: `Route not found: ${req.method} ${req.originalUrl}` }));

export default router;

// Who may edit / delete a task: its creator, Admin, SuperAdmin — nobody else.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";

process.env.JWT_SECRET = "test-secret-only-for-tests";
for (const k of ["SMTP_USER", "SMTP_PASS", "BREVO_API_KEY", "TELEGRAM_BOT_TOKEN", "TASK_INBOX_ENABLED", "RENDER", "CLOUDINARY_URL", "CLOUDINARY_CLOUD_NAME", "CLOUDINARY_API_KEY", "CLOUDINARY_API_SECRET"]) process.env[k] = "";
process.env.NODE_ENV = "test";

const { MongoMemoryServer } = await import("mongodb-memory-server");
const mongoose = (await import("mongoose")).default;
const jwt = (await import("jsonwebtoken")).default;
const mongod = await MongoMemoryServer.create();
const { server } = await import("../src/app.js");
const User = (await import("../src/models/User.js")).default;

let base;
const U = {};
const T = {};
const call = async (method, url, token, json) => {
  const r = await fetch(base + url, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(json ? { "Content-Type": "application/json" } : {}) },
    body: json ? JSON.stringify(json) : undefined,
  });
  return { status: r.status, data: await r.json() };
};
const newTask = async (token, assignee, name) => {
  const r = await call("POST", "/api/tasks", token, { name, assignedUser: assignee, department: "Sales" });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  return r.data.data.id;
};

before(async () => {
  await mongoose.connect(mongod.getUri());
  await new Promise((r) => server.listen(0, r));
  base = `http://127.0.0.1:${server.address().port}`;
  const mk = (o) => User.create({ password: "Pass@123", status: "Active", emailVerified: true, ...o });
  U.super = await mk({ name: "Root", email: "root@e.io", role: "SuperAdmin" });
  U.admin = await mk({ name: "Admin", email: "admin@e.io", role: "Admin" });
  const org = { admin_id: U.admin._id, createdBy: U.admin._id, department: "Sales" };
  U.m1 = await mk({ name: "Manager 1", email: "m1@e.io", role: "Manager", ...org });
  U.m2 = await mk({ name: "Manager 2", email: "m2@e.io", role: "Manager", ...org });
  U.user = await mk({ name: "User", email: "u@e.io", role: "User", ...org });
  for (const k of Object.keys(U)) T[k] = jwt.sign({ id: U[k]._id, role: U[k].role }, process.env.JWT_SECRET);
});
after(async () => {
  await new Promise((r) => server.close(r));
  await mongoose.disconnect();
  await mongod.stop();
});

test("Manager 1 gives a task to Manager 2: Manager 2 cannot edit or delete it", async () => {
  const id = await newTask(T.m1, "m2@e.io", "From M1 to M2");
  // Manager 2 (assignee) can see it but not change it
  assert.equal((await call("GET", `/api/tasks/${id}`, T.m2)).status, 200);
  assert.equal((await call("PUT", `/api/tasks/${id}`, T.m2, { name: "changed by M2" })).status, 403);
  assert.equal((await call("DELETE", `/api/tasks/${id}`, T.m2)).status, 403);
  // …but can still work on it (status)
  assert.equal((await call("PATCH", `/api/tasks/${id}/status`, T.m2, { status: "In Progress" })).status, 200);
  // Manager 1 (creator) can edit and delete
  assert.equal((await call("PUT", `/api/tasks/${id}`, T.m1, { name: "edited by M1" })).status, 200);
  assert.equal((await call("DELETE", `/api/tasks/${id}`, T.m1)).status, 200);
});

test("a Manager cannot edit or delete a User's task in his department; the User (creator) can", async () => {
  const id = await newTask(T.user, "u@e.io", "User's own task");
  assert.equal((await call("PUT", `/api/tasks/${id}`, T.m1, { name: "x" })).status, 403);
  assert.equal((await call("DELETE", `/api/tasks/${id}`, T.m1)).status, 403);
  assert.equal((await call("PUT", `/api/tasks/${id}`, T.user, { name: "mine, edited" })).status, 200);
});

test("Admin and SuperAdmin can edit and delete any task in scope", async () => {
  const a = await newTask(T.m1, "m2@e.io", "for admin");
  assert.equal((await call("PUT", `/api/tasks/${a}`, T.admin, { name: "admin edit" })).status, 200);
  assert.equal((await call("DELETE", `/api/tasks/${a}`, T.admin)).status, 200);
  const b = await newTask(T.m1, "m2@e.io", "for super");
  assert.equal((await call("PUT", `/api/tasks/${b}`, T.super, { name: "super edit" })).status, 200);
  assert.equal((await call("DELETE", `/api/tasks/${b}`, T.super)).status, 200);
});

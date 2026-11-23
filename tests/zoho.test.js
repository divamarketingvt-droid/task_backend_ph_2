// Integration API (Zoho CRM) — API tokens, scopes, org isolation, validation, rate limits.
// Real Express app + throwaway in-memory MongoDB. Run: npm test
import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";

process.env.JWT_SECRET = "test-secret-only-for-tests";
for (const k of ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REFRESH_TOKEN", "SMTP_USER", "SMTP_PASS", "BREVO_API_KEY", "CLOUDINARY_URL", "CLOUDINARY_CLOUD_NAME", "CLOUDINARY_API_KEY", "CLOUDINARY_API_SECRET", "TASK_INBOX_ENABLED", "RENDER", "TELEGRAM_BOT_TOKEN"]) process.env[k] = "";
process.env.NODE_ENV = "test";

const { MongoMemoryServer } = await import("mongodb-memory-server");
const mongoose = (await import("mongoose")).default;
const jwt = (await import("jsonwebtoken")).default;
const mongod = await MongoMemoryServer.create();
process.env.MONGO_URI = mongod.getUri();

const { server } = await import("../src/app.js");
const User = (await import("../src/models/User.js")).default;
const IntegrationToken = (await import("../src/models/IntegrationToken.js")).default;
const { hashIntegrationToken } = await import("../src/models/IntegrationToken.js");
const { resetRateLimits } = await import("../src/middleware/integrationAuth.js");

let base;
const call = async (method, url, { token, json, headers = {} } = {}) => {
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  let body;
  if (json !== undefined) {
    h["Content-Type"] ??= "application/json";
    body = typeof json === "string" ? json : JSON.stringify(json);
  }
  const res = await fetch(base + url, { method, headers: h, body });
  const type = res.headers.get("content-type") || "";
  return { status: res.status, data: type.includes("json") ? await res.json() : await res.text(), headers: res.headers };
};

const jwtFor = (u) => jwt.sign({ id: u._id, role: u.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
const U = {};
const J = {}; // login JWTs
const K = {}; // integration tokens

before(async () => {
  await mongoose.connect(mongod.getUri());
  await new Promise((r) => server.listen(0, r));
  base = `http://127.0.0.1:${server.address().port}`;

  const mk = (o) => User.create({ password: "Pass@123", status: "Active", emailVerified: true, ...o });
  U.super = await mk({ name: "Root", email: "root@z.io", role: "SuperAdmin" });
  U.adminA = await mk({ name: "Admin A", email: "a@z.io", role: "Admin", companyName: "Org A" });
  U.adminB = await mk({ name: "Admin B", email: "b@z.io", role: "Admin", companyName: "Org B" });
  U.userA = await mk({ name: "Worker A", email: "worker.a@z.io", role: "User", admin_id: U.adminA._id, createdBy: U.adminA._id });
  U.mgrA = await mk({ name: "Manager A", email: "mgr.a@z.io", role: "Manager", admin_id: U.adminA._id, createdBy: U.adminA._id });
  U.userB = await mk({ name: "Worker B", email: "worker.b@z.io", role: "User", admin_id: U.adminB._id, createdBy: U.adminB._id });
  for (const k of Object.keys(U)) J[k] = jwtFor(U[k]);
});

after(async () => {
  await new Promise((r) => server.close(r));
  await mongoose.disconnect();
  await mongod.stop();
});

describe("Integration API tokens", () => {
  test("Admin creates tokens; the plain token is shown once and only its hash is stored", async () => {
    const r = await call("POST", "/api/integrations/tokens", {
      token: J.adminA,
      json: { name: "Zoho CRM", permissions: ["tasks:read", "tasks:write", "users:read", "departments:read"], expiresInDays: 30 },
    });
    assert.equal(r.status, 201, JSON.stringify(r.data));
    assert.match(r.data.token, /^bbz_[A-Za-z0-9_-]{43}$/);
    assert.equal(r.data.data.status, "active");
    assert.equal(r.data.data.tokenHash, undefined);
    K.a = r.data.token;
    K.aId = r.data.data._id;

    const stored = await IntegrationToken.findById(K.aId).select("+tokenHash").lean();
    assert.equal(stored.tokenHash, hashIntegrationToken(K.a));
    assert.ok(!JSON.stringify(stored).includes(K.a), "plain token never stored");

    const list = await call("GET", "/api/integrations/tokens", { token: J.adminA });
    assert.equal(list.status, 200);
    assert.ok(!JSON.stringify(list.data).includes(K.a), "list never shows the token");
    assert.ok(list.data.data.every((t) => t.tokenHash === undefined));

    const ro = await call("POST", "/api/integrations/tokens", { token: J.adminA, json: { name: "Read only" } });
    assert.equal(ro.status, 201);
    assert.deepEqual(ro.data.data.permissions, ["tasks:read", "users:read", "departments:read"]);
    K.aReadOnly = ro.data.token;

    const b = await call("POST", "/api/integrations/tokens", {
      token: J.adminB, json: { name: "Zoho B", permissions: ["tasks:read", "tasks:write", "users:read", "departments:read"] },
    });
    assert.equal(b.status, 201);
    K.b = b.data.token;
  });

  test("Input checks and who may manage tokens", async () => {
    assert.equal((await call("POST", "/api/integrations/tokens", { token: J.adminA, json: {} })).status, 400);
    assert.equal((await call("POST", "/api/integrations/tokens", { token: J.adminA, json: { name: "x", permissions: ["tasks:delete"] } })).status, 400);
    assert.equal((await call("POST", "/api/integrations/tokens", { token: J.adminA, json: { name: "x", expiresInDays: 99999 } })).status, 400);
    assert.equal((await call("POST", "/api/integrations/tokens", { token: J.adminA, json: { name: "x", expiresInDays: 0 } })).status, 400);
    // Managers / Users cannot
    assert.equal((await call("GET", "/api/integrations/tokens", { token: J.mgrA })).status, 403);
    assert.equal((await call("POST", "/api/integrations/tokens", { token: J.userA, json: { name: "x" } })).status, 403);
    // SuperAdmin must name the organization
    assert.equal((await call("POST", "/api/integrations/tokens", { token: J.super, json: { name: "x" } })).status, 400);
    const sa = await call("POST", "/api/integrations/tokens", { token: J.super, json: { name: "SA for B", adminId: String(U.adminB._id) } });
    assert.equal(sa.status, 201);
    assert.equal(String(sa.data.data.admin_id), String(U.adminB._id));
    // Admin B cannot touch Admin A's token
    assert.equal((await call("POST", `/api/integrations/tokens/${K.aId}/revoke`, { token: J.adminB })).status, 404);
    // An integration token cannot manage tokens (that needs a login)
    assert.equal((await call("GET", "/api/integrations/tokens", { token: K.a })).status, 401);
  });
});

describe("Zoho API authentication", () => {
  test("missing, malformed, unknown and login-JWT tokens are refused with 401", async () => {
    const none = await call("GET", "/api/zoho/tasks");
    assert.equal(none.status, 401);
    assert.equal(none.data.code, "missing_token");

    const jwtTry = await call("GET", "/api/zoho/tasks", { token: J.adminA });
    assert.equal(jwtTry.status, 401);
    assert.equal(jwtTry.data.code, "invalid_token");

    const fake = await call("GET", "/api/zoho/tasks", { token: "bbz_" + "A".repeat(43) });
    assert.equal(fake.status, 401);
    assert.equal(fake.data.code, "invalid_token");
  });

  test("an integration token is not accepted by the normal app routes", async () => {
    assert.equal((await call("GET", "/api/tasks", { token: K.a })).status, 401);
    assert.equal((await call("GET", "/api/users", { token: K.a })).status, 401);
  });

  test("a valid token works and lastUsedAt is recorded", async () => {
    const r = await call("GET", "/api/zoho/tasks", { token: K.a });
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.ok(r.headers.get("ratelimit-limit"));
    const doc = await IntegrationToken.findById(K.aId).lean();
    for (let i = 0; i < 20 && !doc.lastUsedAt; i++) {
      await new Promise((res) => setTimeout(res, 25));
      Object.assign(doc, await IntegrationToken.findById(K.aId).lean());
    }
    assert.ok(doc.lastUsedAt, "lastUsedAt set");
  });
});

describe("Zoho task endpoints", () => {
  test("create → list → get → update → status, all through the existing task logic", async () => {
    const c = await call("POST", "/api/zoho/tasks", {
      token: K.a,
      json: { name: "Call lead ACME", description: "From Zoho", assignedUser: "worker.a@z.io", priority: "High", dueDate: "2030-01-15", dueTime: "10:30" },
    });
    assert.equal(c.status, 201, JSON.stringify(c.data));
    const created = Array.isArray(c.data.data) ? c.data.data[0] : c.data.data;
    K.taskA = String(created.id || created._id);
    const dbTask = await mongoose.model("Task").findById(K.taskA).lean();
    assert.equal(String(dbTask.admin_id), String(U.adminA._id), "task belongs to the token's org");
    assert.equal(String(dbTask.assignedTo), String(U.userA._id));

    const list = await call("GET", "/api/zoho/tasks?priority=High&limit=10", { token: K.a });
    assert.equal(list.status, 200);
    assert.equal(list.data.page, 1);
    assert.ok(list.data.data.some((t) => String(t.id) === K.taskA));

    const one = await call("GET", `/api/zoho/tasks/${K.taskA}`, { token: K.a });
    assert.equal(one.status, 200);
    assert.equal(one.data.data.name, "Call lead ACME");

    const up = await call("PUT", `/api/zoho/tasks/${K.taskA}`, { token: K.a, json: { name: "Call lead ACME (updated)", priority: "Critical" } });
    assert.equal(up.status, 200, JSON.stringify(up.data));
    const after = await mongoose.model("Task").findById(K.taskA).lean();
    assert.equal(after.name, "Call lead ACME (updated)");
    assert.equal(after.priority, "Critical");

    const st = await call("PATCH", `/api/zoho/tasks/${K.taskA}/status`, { token: K.a, json: { status: "In Progress" } });
    assert.ok([200, 403].includes(st.status), JSON.stringify(st.data)); // same rules as the app
  });

  test("search text is treated literally (no regex injection)", async () => {
    const r = await call("GET", `/api/zoho/tasks?search=${encodeURIComponent("(a+)+$")}`, { token: K.a });
    assert.equal(r.status, 200);
    assert.equal(r.data.total, 0);
  });

  test("validation: bad ids, unknown fields, wrong types, wrong content type → 400/415", async () => {
    assert.equal((await call("GET", "/api/zoho/tasks/not-an-id", { token: K.a })).status, 400);
    assert.equal((await call("GET", "/api/zoho/tasks?status=Nope", { token: K.a })).status, 400);
    assert.equal((await call("GET", "/api/zoho/tasks?limit=5000", { token: K.a })).status, 400);
    assert.equal((await call("GET", "/api/zoho/tasks?admin_id=x", { token: K.a })).status, 400);
    assert.equal((await call("POST", "/api/zoho/tasks", { token: K.a, json: { description: "no name" } })).status, 400);
    assert.equal((await call("POST", "/api/zoho/tasks", { token: K.a, json: { name: "x", admin_id: String(U.adminB._id) } })).status, 400);
    assert.equal((await call("POST", "/api/zoho/tasks", { token: K.a, json: { name: "x", priority: "Urgent" } })).status, 400);
    assert.equal((await call("POST", "/api/zoho/tasks", { token: K.a, json: { name: "x", dueDate: "15/01/2030" } })).status, 400);
    assert.equal((await call("POST", "/api/zoho/tasks", { token: K.a, json: "name=x", headers: { "Content-Type": "text/plain" } })).status, 415);
    assert.equal((await call("PUT", `/api/zoho/tasks/${K.taskA}`, { token: K.a, json: {} })).status, 400);
    assert.equal((await call("PUT", `/api/zoho/tasks/${K.taskA}`, { token: K.a, json: { status: "Completed" } })).status, 400);
  });

  test("permission restriction: a read-only token cannot write", async () => {
    assert.equal((await call("GET", "/api/zoho/tasks", { token: K.aReadOnly })).status, 200);
    const w = await call("POST", "/api/zoho/tasks", { token: K.aReadOnly, json: { name: "x" } });
    assert.equal(w.status, 403);
    assert.equal(w.data.code, "insufficient_scope");
    assert.equal((await call("PUT", `/api/zoho/tasks/${K.taskA}`, { token: K.aReadOnly, json: { name: "y" } })).status, 403);
  });

  test("organization isolation: Org B's token never sees or changes Org A's data", async () => {
    assert.equal((await call("GET", `/api/zoho/tasks/${K.taskA}`, { token: K.b })).status, 404);
    assert.equal((await call("PUT", `/api/zoho/tasks/${K.taskA}`, { token: K.b, json: { name: "hacked" } })).status, 404);
    const list = await call("GET", "/api/zoho/tasks", { token: K.b });
    assert.ok(!list.data.data.some((t) => String(t.id) === K.taskA));
    // cannot assign Org A's member
    const c = await call("POST", "/api/zoho/tasks", { token: K.b, json: { name: "x", assignedUser: "worker.a@z.io" } });
    assert.ok(c.status >= 400 && c.status < 500, JSON.stringify(c.data));
    const users = await call("GET", "/api/zoho/users", { token: K.b });
    assert.equal(users.status, 200);
    assert.ok(users.data.data.every((u) => u.email !== "worker.a@z.io"));
    assert.ok((await mongoose.model("Task").findById(K.taskA).lean()).name !== "hacked");
  });
});

describe("Zoho users and departments", () => {
  test("users list has only safe fields; departments list works", async () => {
    const r = await call("GET", "/api/zoho/users", { token: K.a });
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.ok(r.data.data.some((u) => u.email === "worker.a@z.io"));
    for (const u of r.data.data) {
      assert.deepEqual(Object.keys(u).sort(), ["_id", "createdAt", "customRoleName", "department", "email", "name", "role", "status"]);
    }
    const d = await call("GET", "/api/zoho/departments", { token: K.a });
    assert.equal(d.status, 200, JSON.stringify(d.data));
    assert.ok(Array.isArray(d.data.data));
  });
});

describe("Expiry, revocation, regeneration, rate limits", () => {
  test("an expired token gets 401 token_expired", async () => {
    const r = await call("POST", "/api/integrations/tokens", { token: J.adminA, json: { name: "Short", expiresInDays: 1 } });
    await IntegrationToken.updateOne({ _id: r.data.data._id }, { $set: { expiresAt: new Date(Date.now() - 1000) } });
    const x = await call("GET", "/api/zoho/tasks", { token: r.data.token });
    assert.equal(x.status, 401);
    assert.equal(x.data.code, "token_expired");
  });

  test("an inactive organization's token gets 403", async () => {
    await User.updateOne({ _id: U.adminB._id }, { $set: { status: "Inactive" } });
    const x = await call("GET", "/api/zoho/tasks", { token: K.b });
    assert.equal(x.status, 403);
    assert.equal(x.data.code, "organization_inactive");
    await User.updateOne({ _id: U.adminB._id }, { $set: { status: "Active" } });
  });

  test("regenerate revokes the old token and issues a working new one; revoke blocks it", async () => {
    const g = await call("POST", `/api/integrations/tokens/${K.aId}/regenerate`, { token: J.adminA, json: { expiresInDays: 60 } });
    assert.equal(g.status, 201, JSON.stringify(g.data));
    assert.notEqual(g.data.token, K.a);
    assert.deepEqual(g.data.data.permissions, ["tasks:read", "tasks:write", "users:read", "departments:read"]);

    const old = await call("GET", "/api/zoho/tasks", { token: K.a });
    assert.equal(old.status, 401);
    assert.equal(old.data.code, "token_revoked");
    assert.equal((await call("GET", "/api/zoho/tasks", { token: g.data.token })).status, 200);

    const rv = await call("POST", `/api/integrations/tokens/${g.data.data._id}/revoke`, { token: J.adminA });
    assert.equal(rv.status, 200);
    assert.equal(rv.data.data.status, "revoked");
    const x = await call("GET", "/api/zoho/tasks", { token: g.data.token });
    assert.equal(x.status, 401);
    assert.equal(x.data.code, "token_revoked");
  });

  test("too many requests per token → 429 with Retry-After", async () => {
    resetRateLimits();
    process.env.INTEGRATION_RATE_LIMIT_PER_MIN = "3";
    try {
      const codes = [];
      for (let i = 0; i < 4; i++) codes.push((await call("GET", "/api/zoho/departments", { token: K.aReadOnly })).status);
      assert.deepEqual(codes, [200, 200, 200, 429]);
      const last = await call("GET", "/api/zoho/departments", { token: K.aReadOnly });
      assert.ok(Number(last.headers.get("retry-after")) > 0);
      // another token has its own budget
      assert.equal((await call("GET", "/api/zoho/departments", { token: K.b })).status, 200);
    } finally {
      delete process.env.INTEGRATION_RATE_LIMIT_PER_MIN;
      resetRateLimits();
    }
  });
});

# Blizz Board — Zoho CRM Integration API

A REST API that lets Zoho CRM (or any other system) read and create tasks, and read users and departments, in **one organization** of Blizz Board.

It uses its own **API tokens**, which are separate from the normal user login (JWT):

- A login token does **not** work on this API.
- An API token does **not** work on the normal app.

---

## 1. Base URL

| Deployment | Base URL |
|---|---|
| Render | `https://task-backend-mn8a.onrender.com` |
| Hostinger | `https://decent-lightgreen-goshawk-96.hostingersite.com` |

All endpoints below start with **`/api/zoho`**. For example, on Render:

```
https://task-backend-mn8a.onrender.com/api/zoho/tasks
```

> **Render free plan:** the service sleeps after 15 minutes without traffic. The first call after that can take 30–60 seconds.
>
> Set the timeout in Zoho to at least 60 seconds, or call `GET /api/health` first to wake the service.

---

## 2. Authentication

Send these two headers on every request:

```
Authorization: Bearer YOUR_API_TOKEN
Content-Type: application/json
```

- An API token looks like `bbz_` followed by 43 characters, for example `bbz_Xr4…`.
- The token is sent **only** in the `Authorization` header. It is never accepted in the URL.
- Each token belongs to **one organization**, which is an Admin account. It acts as that organization's Admin, so it only ever sees that organization's tasks, users and departments.
- Each token carries **permissions**:

| Permission | Allows |
|---|---|
| `tasks:read` | `GET /tasks`, `GET /tasks/:id` |
| `tasks:write` | `POST /tasks`, `PUT /tasks/:id`, `PATCH /tasks/:id/status` |
| `users:read` | `GET /users` |
| `departments:read` | `GET /departments` |

  If no permissions are given when the token is created, it gets the read-only default: `tasks:read`, `users:read`, `departments:read`.
- The module permissions the SuperAdmin set for the organization still apply. If the organization has no `tasks.create`, a token with `tasks:write` still cannot create tasks.

### Error responses

All errors return `{ "success": false, "code": "...", "message": "..." }`.

| HTTP | `code` | Meaning |
|---|---|---|
| 400 | `validation_error` | A parameter or field is wrong. `details` lists every problem. |
| 401 | `missing_token` | There is no `Authorization: Bearer …` header. |
| 401 | `invalid_token` | The token is unknown or malformed, or a login JWT was sent. |
| 401 | `token_expired` | The token is past its expiry date. Regenerate it. |
| 401 | `token_revoked` | The token was revoked or regenerated. |
| 403 | `insufficient_scope` | The token lacks the needed permission, e.g. `tasks:write`. |
| 403 | `organization_inactive` | The organization's Admin account is inactive or deleted. |
| 403 | *(no code)* | The organization's module permissions do not allow this. |
| 404 | *(no code)* | The task is not found, or it belongs to another organization. |
| 415 | `unsupported_media_type` | The body was not sent as `application/json`. |
| 429 | `rate_limited` | Too many requests. Wait `Retry-After` seconds. |

### Rate limits

- **60 requests per minute per token**, and **120 requests per minute per IP address**. Both can be changed; see section 8.
- Every response carries these headers: `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset`.

---

## 3. Endpoints

### `GET /api/zoho/tasks`: list tasks

All query parameters are optional:

| Parameter | Values |
|---|---|
| `status` | `To Do`, `In Progress`, `Review`, `Completed` |
| `priority` | `Low`, `Medium`, `High`, `Critical` |
| `department` | Department name |
| `assignedTo` | User id (24 characters) |
| `search` | Text, up to 100 characters. Matches name, description, department and Task ID. |
| `page` | Default `1` |
| `limit` | Default `50`, maximum `200` |

Response `200`:

```json
{
  "success": true,
  "count": 1, "total": 1, "page": 1, "limit": 50, "totalPages": 1,
  "data": [
    {
      "id": "674f1c2e9b1d4a0012ab34cd",
      "referenceId": "SAL12",
      "name": "Call lead ACME",
      "description": "From Zoho",
      "department": "Sales",
      "departments": ["Sales"],
      "assignedTo": "674f1b009b1d4a0012ab3400",
      "assignedUser": "Worker A",
      "assignedBy": "674f1a009b1d4a0012ab3300",
      "assignedByName": "Admin A",
      "dueDate": "2030-01-15",
      "dueTime": "10:30",
      "priority": "High",
      "status": "To Do",
      "complexity": 0,
      "reward": 10,
      "taskType": "standard",
      "checklist": [], "subtasks": [], "attachments": [], "customFields": []
    }
  ]
}
```

### `GET /api/zoho/tasks/:id`: one task

`:id` is the task's `id` (24 characters). The response is `200 { "success": true, "data": { …task… } }`. A task in another organization returns `404`.

### `POST /api/zoho/tasks`: create a task

Needs the `tasks:write` permission.

| Field | Type | Notes |
|---|---|---|
| `name` | string, 1–200 | **Required** |
| `description` | string, ≤ 5000 | |
| `assignedUser` | string | A user's email or id, in this organization |
| `assignedUsers` | string[], ≤ 50 | Several assignees. One task is created per person. |
| `department` / `departments` | string / string[] | Department name(s) of this organization |
| `dueDate` | `YYYY-MM-DD` | |
| `dueTime` | `HH:mm` | 24-hour clock |
| `priority` | `Low` \| `Medium` \| `High` \| `Critical` | Default `Medium` |
| `status` | `To Do` \| `In Progress` \| `Review` \| `Completed` | Default `To Do` |
| `complexity` | integer 0–100 | |
| `reward` | number 0–1000 | Points |

Unknown fields are rejected with `400`, which catches typos in the Zoho mapping.

```json
{
  "name": "Follow up: ACME Corp deal",
  "description": "Zoho Deal #4567 — send the revised quote",
  "assignedUser": "worker.a@company.com",
  "department": "Sales",
  "dueDate": "2026-12-05",
  "dueTime": "11:00",
  "priority": "High"
}
```

Response `201`:

```json
{ "success": true, "message": "Task created & assigned", "data": { "id": "674f1c2e9b1d4a0012ab34cd", "referenceId": "SAL13", "...": "..." } }
```

With `assignedUsers`, the response is `{ "success": true, "message": "Task assigned to N users", "taskGroupId": "…", "data": [ …tasks… ] }`.

The assignee gets the same notifications as for a task created in the app: in-app, push, email and Telegram, whichever they have turned on. The task shows the organization's Admin as **Assigned by**.

### `PUT /api/zoho/tasks/:id`: update a task

Needs the `tasks:write` permission.

- Takes the same fields as create, all optional, except `status`. Send at least one field.
- Send `"dueDate": ""` to clear the due date, and `"assignedUser": null` to unassign.

```json
{ "priority": "Critical", "dueDate": "2026-12-03" }
```

Response `200`: `{ "success": true, "message": "Task updated", "data": { …task… } }`

### `PATCH /api/zoho/tasks/:id/status`: change the status

Needs the `tasks:write` permission.

| Field | Type | Notes |
|---|---|---|
| `status` | `To Do` \| `In Progress` \| `Review` \| `Completed` | **Required** |
| `note` | string, ≤ 2000 | Optional comment |
| `score` | integer 1–10 | Review score, needed when marking a task that someone else did as `Completed` |

The same rules apply as in the app. For example, a task must be in `Review` before it can be `Completed`.

### `GET /api/zoho/users`: the organization's members

Needs the `users:read` permission.

```json
{
  "success": true,
  "count": 2,
  "data": [
    { "_id": "674f1b009b1d4a0012ab3400", "name": "Worker A", "email": "worker.a@company.com",
      "role": "User", "department": "Sales", "status": "Active", "customRoleName": "", "createdAt": "2026-11-20T09:12:00.000Z" }
  ]
}
```

Only these fields are returned. Passwords, phone numbers, permissions and settings never are.

### `GET /api/zoho/departments`: the organization's departments

Needs the `departments:read` permission.

```json
{ "success": true, "data": [ { "_id": "…", "name": "Sales", "description": "", "refPrefix": "SAL", "nextReferenceId": "SAL14" } ] }
```

---

## 4. Creating, revoking and regenerating API tokens

Tokens are managed by an **Admin**, for their own organization, or by the **SuperAdmin**, who must pass the `adminId` of the organization. Both use their normal login JWT.

**Step 1: log in to get a JWT**

```bash
BASE=https://task-backend-mn8a.onrender.com
curl -s -X POST $BASE/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourcompany.com","password":"YOUR_PASSWORD"}'
# → copy data.token  (this is the login JWT, valid for the session)
JWT=eyJhbGciOi...
```

**Step 2: create the Zoho token**

```bash
curl -s -X POST $BASE/api/integrations/tokens \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d '{"name":"Zoho CRM","permissions":["tasks:read","tasks:write","users:read","departments:read"],"expiresInDays":365}'
```

Response `201`:

```json
{
  "success": true,
  "message": "Copy this token now — it is shown only once and cannot be retrieved later.",
  "token": "bbz_Xr4…(43 chars)",
  "data": { "_id": "6750…", "name": "Zoho CRM", "tokenPreview": "bbz_Xr4abc…", "permissions": ["…"],
            "expiresAt": "2027-11-23T…", "lastUsedAt": null, "isActive": true, "status": "active" }
}
```

**Copy `token` immediately.** Only a SHA-256 hash is stored, so the token cannot be shown again.

| Body field | Notes |
|---|---|
| `name` | Required, up to 80 characters |
| `permissions` | Optional. Default is read-only. |
| `expiresInDays` | 1 to `INTEGRATION_TOKEN_MAX_DAYS` (default maximum 730). The default is `INTEGRATION_TOKEN_DEFAULT_DAYS` (180). |
| `adminId` | SuperAdmin only: the organization |

**Other token actions** (all need the login JWT):

| Action | Request |
|---|---|
| List tokens, without secrets: name, preview, status, created, expires, last used | `GET $BASE/api/integrations/tokens` |
| Revoke: stops working immediately | `POST $BASE/api/integrations/tokens/<id>/revoke` |
| Regenerate: revokes the old token and returns a new one with the same name and permissions (optional body `{"expiresInDays":365}`) | `POST $BASE/api/integrations/tokens/<id>/regenerate` |
| Delete the record | `DELETE $BASE/api/integrations/tokens/<id>` |

- An organization can have at most 20 active tokens.
- If a token leaks, **regenerate** it, then paste the new token into Zoho.

---

## 5. Setting it up in Zoho CRM

### 5.1 Store the token in Zoho (once)

1. Go to **Zoho CRM → Setup → Developer Hub (Developer Space) → Variables**, and create a variable.
2. Fill it in as follows:
   - **Name:** `Blizz API Token`
   - **API name:** `blizz_api_token`
   - **Type:** Single Line
   - **Value:** the `bbz_…` token
3. Create a second variable `blizz_base_url` with the value `https://task-backend-mn8a.onrender.com`.

This keeps the token out of function code. To rotate the token later, change it in one place.

### 5.2 Create a task from a CRM record (Deluge custom function)

1. Go to **Setup → Automation → Workflow Rules → New Rule**, choose the module (for example **Deals**) and the trigger.
2. Under **Instant Actions**, choose **Function → New Function → Write your own**.
3. Add the argument `dealId` (Deals → Deal Id), and use this code:

```deluge
deal = zoho.crm.getRecordById("Deals", dealId.toLong());
token = zoho.crm.getOrgVariable("blizz_api_token");
base = zoho.crm.getOrgVariable("blizz_base_url");

headersMap = Map();
headersMap.put("Authorization", "Bearer " + token);
headersMap.put("Content-Type", "application/json");

payload = Map();
payload.put("name", "Follow up: " + deal.get("Deal_Name"));
payload.put("description", "Zoho Deal " + dealId + " — stage " + deal.get("Stage"));
payload.put("assignedUser", deal.get("Owner").get("email"));   // must be a Blizz Board user's email
payload.put("priority", "High");
if (deal.get("Closing_Date") != null)
{
	payload.put("dueDate", deal.get("Closing_Date").toString("yyyy-MM-dd"));
}

response = invokeurl
[
	url :base + "/api/zoho/tasks"
	type :POST
	parameters:payload.toString()
	headers:headersMap
	detailed:true
];
info response;
// response.get("responseCode") → 201 when created; response.get("responseText").get("data").get("id") is the task id
```

Save the returned task `id` in a custom field on the Deal, e.g. `Blizz_Task_Id`. Later updates can then call:

```deluge
response = invokeurl
[
	url :base + "/api/zoho/tasks/" + deal.get("Blizz_Task_Id")
	type :PUT
	parameters:{"priority":"Critical"}.toString()
	headers:headersMap
];
```

### 5.3 Reading data in Zoho

The same pattern works with `type :GET`, for example:

- `base + "/api/zoho/tasks?status=In%20Progress&limit=100"`
- `base + "/api/zoho/users"`

### 5.4 What to enter if a Zoho screen asks for the API details field by field

| Zoho field | Value |
|---|---|
| URL | `https://task-backend-mn8a.onrender.com/api/zoho/tasks` (or another endpoint) |
| Method | `POST` / `GET` / `PUT` / `PATCH` |
| Header 1 | `Authorization` = `Bearer bbz_…your token…` |
| Header 2 | `Content-Type` = `application/json` |
| Body type | Raw / JSON |
| Body | The JSON from section 3 |
| Authentication type | None / General. The token goes in the header above, not in Zoho "Connections" (those are for OAuth). |

---

## 6. Testing with cURL

```bash
BASE=https://task-backend-mn8a.onrender.com
TOKEN=bbz_...           # Zoho token with tasks:write
RO=bbz_...              # a read-only token
OTHER=bbz_...           # a token of ANOTHER organization
```

**Valid token** returns 200:

```bash
curl -s "$BASE/api/zoho/tasks?limit=5" -H "Authorization: Bearer $TOKEN"
```

**Invalid token** returns 401 `invalid_token`:

```bash
curl -s "$BASE/api/zoho/tasks" -H "Authorization: Bearer bbz_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

**Login JWT instead of an API token** returns 401 `invalid_token`:

```bash
curl -s "$BASE/api/zoho/tasks" -H "Authorization: Bearer $JWT"
```

**Expired token** returns 401 `token_expired`. Create one with `"expiresInDays":1` and call it the next day.

**Revoked token** returns 401 `token_revoked`:

```bash
curl -s -X POST "$BASE/api/integrations/tokens/<id>/revoke" -H "Authorization: Bearer $JWT"
curl -s "$BASE/api/zoho/tasks" -H "Authorization: Bearer <that token>"
```

**Create a task** returns 201:

```bash
curl -s -X POST "$BASE/api/zoho/tasks" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Zoho test task","assignedUser":"worker@yourcompany.com","priority":"High","dueDate":"2026-12-05"}'
```

**Retrieve tasks** returns 200:

```bash
curl -s "$BASE/api/zoho/tasks?search=Zoho%20test" -H "Authorization: Bearer $TOKEN"
curl -s "$BASE/api/zoho/tasks/<taskId>" -H "Authorization: Bearer $TOKEN"
```

**Update a task** returns 200:

```bash
curl -s -X PUT "$BASE/api/zoho/tasks/<taskId>" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"priority":"Critical","description":"Updated from Zoho"}'
curl -s -X PATCH "$BASE/api/zoho/tasks/<taskId>/status" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"status":"In Progress","note":"Started from Zoho"}'
```

**Organization isolation**: another organization's token gets 404, and its lists never contain this task:

```bash
curl -s "$BASE/api/zoho/tasks/<taskId>" -H "Authorization: Bearer $OTHER"
```

**Permission restriction**: a read-only token gets 403 `insufficient_scope` when it writes:

```bash
curl -s -X POST "$BASE/api/zoho/tasks" -H "Authorization: Bearer $RO" -H "Content-Type: application/json" -d '{"name":"x"}'
```

**Validation** returns 400 with `details`:

```bash
curl -s -X POST "$BASE/api/zoho/tasks" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"x","priority":"Urgent","dueDate":"05/12/2026"}'
```

**Postman:**

1. Create an environment with `BASE` and `TOKEN`.
2. In the collection's **Authorization** tab choose **Bearer Token** = `{{TOKEN}}`.
3. Add the header `Content-Type: application/json`.
4. Requests use URLs like `{{BASE}}/api/zoho/tasks`.

Automated tests covering all of the above are in `tests/zoho.test.js`. Run them with `npm test`.

---

## 7. Security summary

- Tokens have 256 bits of randomness (`crypto.randomBytes(32)`).
- Only the SHA-256 hash is stored, the hash is never returned, and the lookup is compared in constant time.
- The plain token is shown once.
- Tokens can expire (default 180 days), and can be revoked or regenerated at any time. `lastUsedAt` and `lastUsedIp` are recorded.
- Each token is tied to one organization (`admin_id`) and goes through the same scope filter and permission checks as the app.
- Input is validated, unknown fields are rejected, and the search text is escaped.
- Requests are rate limited per token and per IP.
- The request log records method, path, status, time, token **id**, organization and IP. It never records headers, bodies, tokens or passwords.
- The token never goes into frontend code, browser storage or GitHub. Keep it only in Zoho Variables.

---

## 8. Environment variables

All are optional; the defaults are shown.

| Variable | Default | Meaning |
|---|---|---|
| `INTEGRATION_RATE_LIMIT_PER_MIN` | `60` | Requests per minute per token |
| `INTEGRATION_RATE_LIMIT_IP_PER_MIN` | `120` | Requests per minute per IP on `/api/zoho` |
| `INTEGRATION_TOKEN_DEFAULT_DAYS` | `180` | Validity when `expiresInDays` is not given |
| `INTEGRATION_TOKEN_MAX_DAYS` | `730` | Longest allowed validity |
| `INTEGRATION_TOKEN_ALLOW_NO_EXPIRY` | `false` | `true` allows `"expiresInDays": null` (never expires). Not recommended. |

No new secret is needed: tokens are random and stored hashed. The existing `JWT_SECRET` and `MONGO_URI` are unchanged.

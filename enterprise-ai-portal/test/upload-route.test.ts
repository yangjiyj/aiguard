// W6 · 6.2 / 6.10：/api/upload 对控制面 ingest 真实返回的适配。
// 控制面 portal_upload_ingest.go：413 file_too_large、403 file_content_blocked、400 invalid_request，
// 错误体 {"error":{"code","message"}}；成功 {reference:"", text_preview, action, sha256}。
// 上游 message 用 ASCII 占位，门户文案一律引用映射表。
import test, { mock } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { __resetRateLimit } from "../src/lib/rate-limit.js";
import { PORTAL_ERROR_MESSAGES, uploadErrorMessage } from "../src/lib/portal-errors.js";

let ingest: { status: number; body: unknown } = { status: 200, body: {} };
let chatAllowed = true;
let ingestCalls = 0;

const server = createServer(async (req, res) => {
  for await (const _ of req) void _;
  res.setHeader("content-type", "application/json");
  if (req.url === "/admin/v1/portal-integration/users/user-fixture/authorization-context") {
    res.end(JSON.stringify({ data: {
      user_id: "user-fixture", department_id: "d", department_name: "d", department_version: 1,
      chat_allowed: chatAllowed, model_ids: ["m1"],
    } }));
  } else if (req.url === "/admin/v1/portal-integration/policies/file") {
    res.end(JSON.stringify({ allowed_types: ["pdf"], blocked_types: [], review_types: [], max_file_mb: 20, max_zip_ratio: 100, max_attachments: 10 }));
  } else if (req.url === "/admin/v1/portal-integration/upload-ingest") {
    ingestCalls += 1;
    res.statusCode = ingest.status;
    res.end(JSON.stringify(ingest.body));
  } else {
    res.statusCode = 404;
    res.end("{}");
  }
});
let POST: typeof import("../src/app/api/upload/route.js").POST;

test.before(async () => {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  process.env.JJD_CP_URL = `http://127.0.0.1:${address.port}`;
  process.env.JJD_PORTAL_API_SECRET = "s";
  ({ POST } = (await import("../src/app/api/upload/route.js?fixture=upload-route" as string)) as typeof import("../src/app/api/upload/route.js"));
});

mock.module("@/auth", {
  namedExports: { auth: async () => ({ user: { id: "user-fixture", email: "u@x.test", name: "U" } }) },
});

test.after(() => server.close());
test.beforeEach(() => {
  __resetRateLimit();
  chatAllowed = true;
  ingestCalls = 0;
});

function upload() {
  const form = new FormData();
  form.append("file", new File([new Uint8Array([0x61])], "a.txt", { type: "text/plain" }));
  return POST(new Request("http://portal.test/api/upload", { method: "POST", body: form }));
}

test("6.2 403 file_content_blocked keeps 403 and returns table copy + upstream detail", async () => {
  ingest = { status: 403, body: { error: { code: "file_content_blocked", message: "dlp said no" } } };
  const res = await upload();
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error, "file_content_blocked");
  assert.equal(body.message, PORTAL_ERROR_MESSAGES.file_content_blocked);
  assert.equal(body.detail, "dlp said no");
  assert.equal(uploadErrorMessage(res.status, body), PORTAL_ERROR_MESSAGES.file_content_blocked);
});

test("6.2 413 file_too_large is surfaced as size limit, not a generic failure", async () => {
  ingest = { status: 413, body: { error: { code: "file_too_large", message: "too big" } } };
  const res = await upload();
  assert.equal(res.status, 413);
  const body = await res.json();
  assert.equal(body.error, "file_too_large");
  assert.equal(uploadErrorMessage(res.status, body), PORTAL_ERROR_MESSAGES.file_too_large);
});

test("6.2 400 invalid_request keeps its code", async () => {
  ingest = { status: 400, body: { error: { code: "invalid_request", message: "bad" } } };
  const res = await upload();
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, "invalid_request");
});

test("6.2 status without a code falls back by status", async () => {
  ingest = { status: 403, body: {} };
  const res = await upload();
  assert.equal((await res.json()).error, "file_content_blocked");
  ingest = { status: 500, body: {} };
  const res500 = await upload();
  assert.equal(res500.status, 502);
  assert.equal(uploadErrorMessage(res500.status, await res500.json()), PORTAL_ERROR_MESSAGES.upstream_unavailable);
});

test("6.2 success returns the ingest action (default audit)", async () => {
  ingest = { status: 200, body: { reference: "", text_preview: "a", action: "block", sha256: "x" } };
  assert.equal((await (await upload()).json()).action, "block");
  ingest = { status: 200, body: { reference: "ref" } };
  const body = await (await upload()).json();
  assert.equal(body.action, "audit");
  assert.equal(body.reference, "ref");
});

test("6.10 disabled user cannot upload and ingest is never called", async () => {
  chatAllowed = false;
  const res = await upload();
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error, "authorization_denied");
  assert.equal(body.message, PORTAL_ERROR_MESSAGES.authorization_denied);
  assert.equal(ingestCalls, 0);
});

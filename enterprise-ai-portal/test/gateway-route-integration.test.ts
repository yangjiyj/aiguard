import test, { mock } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { __resetRateLimit } from "../src/lib/rate-limit.js";
import { PORTAL_ERROR_MESSAGES } from "../src/lib/portal-errors.js";

interface SeenRequest { path: string; method: string; authorization: string; tenant: string; department: string; loginMode: string; credentialVersion:string; body: string }

test("authenticated models chat records upload handlers use request-time authorization", async (t) => {
  const seen: SeenRequest[] = [];
  let authorizationAllowed = true;
  let localLogin = false;
  let uploadStatus = 200;
  const server = createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += String(chunk);
    seen.push({
      path: req.url ?? "",
      method: req.method ?? "",
      authorization: String(req.headers.authorization ?? ""),
      tenant: String(req.headers["x-jjdguard-tenant-id"] ?? ""),
      department: String(req.headers["x-portal-direct-department"] ?? ""),
      loginMode: String(req.headers["x-portal-direct-login-mode"] ?? ""),
      credentialVersion:String(req.headers["x-portal-direct-local-credential-version"]??""),
      body,
    });
    res.setHeader("content-type", "application/json");
    if (new URL(req.url??"","http://fixture.test").pathname === "/admin/v1/portal-integration/users/user-fixture/authorization-context") {
      res.end(JSON.stringify({ data: {
        user_id: "user-fixture",
        department_id: "dept_latest",
        department_name: "本地账号测试",
        department_version: 2000,
        chat_allowed: authorizationAllowed,
        model_ids: ["fixture-model"],
        local_credential_version:1, local_login_allowed: true, local_external_subject: "oidc-test-subject",
      } }));
    } else if (req.url === "/v1/models") {
      res.end(JSON.stringify({ models: [
        { id: "fixture-model", displayName: "Fixture" },
        { id: "stale-model", displayName: "Stale" },
      ], defaultModelId: "stale-model" }));
    } else if (req.url === "/admin/v1/portal-integration/models") {
      res.end(JSON.stringify({ data: [{ model_name: "fixture-model", capabilities: { supports_image_input: true } }] }));
    } else if (req.url === "/v1/chat/completions") {
      res.setHeader("content-type", "text/event-stream");
      res.end('data: {"choices":[{"delta":{"content":"ok"}}]}\n\ndata: [DONE]\n\n');
    } else if (req.url?.startsWith("/admin/v1/portal-integration/upload-events")) {
      res.end(JSON.stringify({ data: [],total:0 }));
    } else if (req.url === "/admin/v1/portal-integration/policies/file") {
      res.end(JSON.stringify({
        allowed_types: ["pdf"],
        blocked_types: ["pe", "script"],
        review_types: ["zip", "rar", "7z", "unknown"],
        max_file_mb: 20,
        max_zip_ratio: 100,
        max_attachments: 10,
      }));
    } else if (req.url === "/admin/v1/portal-integration/upload-ingest") {
      res.statusCode = uploadStatus;
      res.end(uploadStatus === 403
        ? JSON.stringify({ code: "file_content_blocked", message: "blocked" })
        : JSON.stringify({ reference: "fixture-ref", action: "audit" }));
    } else {
      res.statusCode = 404;
      res.end("{}");
    }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const baseUrl = `http://127.0.0.1:${address.port}`;

  process.env.PORTAL_PROXY_URL = baseUrl;
  process.env.PORTAL_INTERNAL_TOKEN = "portal-proxy-token";
  process.env.JJD_CP_URL = baseUrl;
  process.env.JJD_PORTAL_API_SECRET = "jjd-portal-secret";
  process.env.NEWAPI_CP_URL = "http://legacy-canary.invalid";
  process.env.NEWAPI_PORTAL_API_SECRET = "legacy-secret-canary";

  mock.module("@/auth", {
    namedExports: {
      auth: async () => ({ user: {
        id: "user-fixture",
        externalSubject: "oidc-test-subject",
        localCredentialVersion:1, localLogin,
        email: "u@example.test",
        name: "测试用户",
        department: "security",
        role: "employee",
      } }),
    },
  });
  mock.module("@/lib/prisma", {
    namedExports: {
      prisma: { uploadEvent: { findMany: async () => [] } },
    },
  });

  const meRoute = (await import("../src/app/api/me/route.js?fixture=me" as string)) as typeof import("../src/app/api/me/route.js");
  const modelsRoute = (await import("../src/app/api/models/route.js?fixture=models" as string)) as typeof import("../src/app/api/models/route.js");
  const chatRoute = (await import("../src/app/api/chat/route.js?fixture=chat" as string)) as typeof import("../src/app/api/chat/route.js");
  const recordsRoute = (await import("../src/app/api/me/records/route.js?fixture=records" as string)) as typeof import("../src/app/api/me/records/route.js");
  const uploadRoute = (await import("../src/app/api/upload/route.js?fixture=upload" as string)) as typeof import("../src/app/api/upload/route.js");
  const conversationsRoute = (await import("../src/app/api/conversations/route.js?fixture=conversations" as string)) as typeof import("../src/app/api/conversations/route.js");

  const me = await meRoute.GET();
  assert.equal(me.status, 200);
  assert.equal((await me.json()).user.department, "本地账号测试");
  assert.equal(me.headers.get("cache-control"), "private, no-store");
  const models = await modelsRoute.GET();
  assert.equal(models.status, 200);
  assert.deepEqual(await models.json(), {
    models: [{ id: "fixture-model", displayName: "Fixture", capabilities: { supports_image_input: true } }],
    defaultModelId: "fixture-model",
  });
  assert.equal(models.headers.get("cache-control"), "private, no-store");
  assert.equal(seen.filter(row => row.path === "/v1/models").at(-1)?.loginMode, "oidc");

  const chat = await chatRoute.POST(new Request("http://portal.test/api/chat", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      model: "fixture-model",
      messages: [{ role: "user", content: "hello" }],
    }),
  }));
  assert.equal(chat.status, 200, await chat.text());
  const records = await recordsRoute.GET(new Request("http://portal.test/api/me/records?limit=1"));
  assert.equal(records.status, 200);
  const form = new FormData();
  form.append("file", new File([new Uint8Array([0x78])], "one.txt", { type: "text/plain" }));
  form.append("user", "attacker");
  const upload = await uploadRoute.POST(new Request("http://portal.test/api/upload", { method: "POST", body: form }));
  assert.equal(upload.status, 200, await upload.text());

  const archiveForm = new FormData();
  archiveForm.append(
    "file",
    new File([new Uint8Array([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00])], "review.rar", {
      type: "application/x-rar-compressed",
    }),
  );
  const archiveUpload = await uploadRoute.POST(
    new Request("http://portal.test/api/upload", { method: "POST", body: archiveForm }),
  );
  assert.equal(archiveUpload.status, 200, "portal must send review types to the control plane");

  const cp = seen.filter((request) => request.path.startsWith("/admin/v1/portal-integration/"));
  assert.equal(cp.length, 12);
  assert.deepEqual(cp.map((request) => request.path.split("?")[0]), [
    "/admin/v1/portal-integration/users/user-fixture/authorization-context",
    "/admin/v1/portal-integration/users/user-fixture/authorization-context",
    "/admin/v1/portal-integration/models",
    "/admin/v1/portal-integration/users/user-fixture/authorization-context",
    // W2.3: /api/me/records re-checks the user is still active before reading.
    "/admin/v1/portal-integration/users/user-fixture/authorization-context",
    "/admin/v1/portal-integration/upload-events",
    // 6.10：upload 每次请求先复核账号有效
    "/admin/v1/portal-integration/users/user-fixture/authorization-context",
    "/admin/v1/portal-integration/policies/file",
    "/admin/v1/portal-integration/upload-ingest",
    "/admin/v1/portal-integration/users/user-fixture/authorization-context",
    "/admin/v1/portal-integration/policies/file",
    "/admin/v1/portal-integration/upload-ingest",
  ]);
  assert.deepEqual(cp.map((request) => request.method), ["GET", "GET", "GET", "GET", "GET", "GET", "GET", "GET", "POST", "GET", "GET", "POST"]);
  for (const request of cp) {
    assert.equal(request.authorization, "Bearer jjd-portal-secret");
    assert.equal(request.tenant, "tenant_default");
    assert.doesNotMatch(request.path, /legacy-canary/);
  }
  assert.match(cp[5]!.path, /user_id=user-fixture/);
  assert.match(cp[8]!.body, /\"user_id\":\"user-fixture\"/);
  assert.match(cp[8]!.body, /\"bytes_base64\":\"eA==\"/);
  assert.match(cp[11]!.body, /\"mime_type\":\"application\/x-rar-compressed\"/);

  uploadStatus = 403;
  const blockedForm = new FormData();
  blockedForm.append("file", new File([new Uint8Array([0x78])], "blocked.txt", { type: "text/plain" }));
  const blockedUpload = await uploadRoute.POST(
    new Request("http://portal.test/api/upload", { method: "POST", body: blockedForm }),
  );
  assert.equal(blockedUpload.status, 403, "file DLP block must remain a client-visible 403");
  // 6.2：拦截返回带员工可读文案（映射表），上游原文放 detail
  assert.deepEqual(await blockedUpload.json(), {
    error: "file_content_blocked",
    message: PORTAL_ERROR_MESSAGES.file_content_blocked,
    detail: "blocked",
    status: 403,
  });
  uploadStatus = 200;
  const proxy = seen.filter((request) => request.path === "/v1/models" || request.path === "/v1/chat/completions");
  assert.deepEqual(proxy.map((request) => request.path), ["/v1/models", "/v1/chat/completions"]);
  assert.deepEqual(proxy.map((request) => request.department), ["dept_latest", "dept_latest"]);

  localLogin = true;
  const localModels = await modelsRoute.GET();
  assert.equal(localModels.status, 200);
  assert.equal(seen.filter(row => row.path === "/v1/models").at(-1)?.loginMode, "local");
  assert.equal(seen.filter(row=>row.path==="/v1/models").at(-1)?.credentialVersion,"1");
  localLogin = false;

  const proxyCount = () => seen.filter((request) =>
    request.path === "/v1/models" || request.path === "/v1/chat/completions").length;
  const allowedProxyCount = proxyCount();
  const staleChat = await chatRoute.POST(new Request("http://portal.test/api/chat", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      model: "stale-model",
      messages: [{ role: "user", content: "bypass" }],
    }),
  }));
  assert.equal(staleChat.status, 403);
  assert.equal(proxyCount(), allowedProxyCount, "stale model must be rejected before proxy");

  authorizationAllowed = false;
  assert.equal((await meRoute.GET()).status, 403);
  assert.equal((await modelsRoute.GET()).status, 403);
  const deniedChat = await chatRoute.POST(new Request("http://portal.test/api/chat", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      model: "fixture-model",
      messages: [{ role: "user", content: "denied" }],
    }),
  }));
  assert.equal(deniedChat.status, 403);
  assert.equal(proxyCount(), allowedProxyCount, "inactive/emergency requests must not reach proxy");
  // 6.10：停用账号不能再上传，也不能读会话
  const deniedForm = new FormData();
  deniedForm.append("file", new File([new Uint8Array([0x78])], "denied.txt", { type: "text/plain" }));
  const ingestBefore = seen.filter((r) => r.path === "/admin/v1/portal-integration/upload-ingest").length;
  const deniedUpload = await uploadRoute.POST(
    new Request("http://portal.test/api/upload", { method: "POST", body: deniedForm }),
  );
  assert.equal(deniedUpload.status, 403);
  assert.equal((await deniedUpload.json()).error, "authorization_denied");
  assert.equal(
    seen.filter((r) => r.path === "/admin/v1/portal-integration/upload-ingest").length,
    ingestBefore,
    "inactive user upload must not reach ingest",
  );
  assert.equal((await conversationsRoute.GET(new Request("http://portal.test/api/conversations"))).status, 403);
  authorizationAllowed = true;

  // 证明loader在请求时读取：模块已加载后改变JJD密钥，下一次真实handler必须使用新值。
  process.env.JJD_PORTAL_API_SECRET = "rotated-request-secret";
  const second = await recordsRoute.GET(new Request("http://portal.test/api/me/records?limit=1"));
  assert.equal(second.status, 200);
  assert.equal(seen.at(-1)?.authorization, "Bearer rotated-request-secret");

  __resetRateLimit();
  process.env.JJD_CP_URL = "http://127.0.0.1:1";
  assert.equal((await meRoute.GET()).status, 502, "me must not fall back to the OIDC department");
  assert.equal((await modelsRoute.GET()).status, 502, "models must not serve a degraded/cache result");
  const outageProxyCount = proxyCount();
  const outageChat = await chatRoute.POST(new Request("http://portal.test/api/chat", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      model: "fixture-model",
      messages: [{ role: "user", content: "outage" }],
    }),
  }));
  assert.equal(outageChat.status, 502, "chat must fail closed when CP is unreachable");
  assert.equal(proxyCount(), outageProxyCount, "CP outage must not reach proxy");
  assert.equal(
    (await recordsRoute.GET(new Request("http://portal.test/api/me/records?limit=1"))).status,
    502,
    "records must not fall back to the portal database when CP is unreachable",
  );
  const outageForm = new FormData();
  outageForm.append("file", new File([new Uint8Array([0x79])], "outage.txt", { type: "text/plain" }));
  const outageUpload = await uploadRoute.POST(
    new Request("http://portal.test/api/upload", { method: "POST", body: outageForm }),
  );
  assert.equal(outageUpload.status, 502, "upload must fail closed when CP is unreachable");
});

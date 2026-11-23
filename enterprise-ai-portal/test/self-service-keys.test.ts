process.env.PORTAL_PUBLIC_URL='http://portal.test/chat';
import test, { mock } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";

let session: { user: { id: string } } | null = { user: { id: "employee-1" } };

mock.module("@/auth", {
  namedExports: { auth: async () => session },
});

test("employee creates a model-only API key bound to the signed-in user", async (t) => {
  const seen: Array<{ path: string; method: string; body: string; authorization: string; tenant: string }> = [];
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += String(chunk);
    seen.push({
      path: request.url ?? "",
      method: request.method ?? "",
      body,
      authorization: String(request.headers.authorization ?? ""),
      tenant: String(request.headers["x-jjdguard-tenant-id"] ?? ""),
    });
    response.setHeader("content-type", "application/json");
    if (request.url === "/admin/v1/portal-integration/users/employee-1/authorization-context") {
      response.end(JSON.stringify({ data: {
        user_id: "employee-1",
        department_id: "dept-1",
        department_name: "研发部",
        department_version: 1,
        project_id: "project-1",
        chat_allowed: true,
        model_ids: ["gpt-5.5"],
      } }));
      return;
    }
    if (request.url === "/admin/v1/portal-integration/keys" && request.method === "POST") {
      response.end(JSON.stringify({
        id: "key-1",
        project_id: "project-1",
        user_id: "employee-1",
        name: "本地开发",
        key_prefix: "sk-test",
        scopes: ["chat", "responses", "embeddings", "models"],
        full_key: "sk-test-secret",
        status: "active",
        created_at: "2026-08-07T00:00:00Z",
      }));
      return;
    }
    response.statusCode = 404;
    response.end("{}");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const address = server.address();
  assert.ok(address && typeof address === "object");
  process.env.JJD_CP_URL = `http://127.0.0.1:${address.port}`;
  process.env.JJD_PORTAL_API_SECRET = "portal-secret";

  const route = (await import("../src/app/api/me/keys/route.js?self-service=success" as string)) as typeof import("../src/app/api/me/keys/route.js");
  const result = await route.POST(new Request("http://portal.test/api/me/keys", {
    method: "POST",
    headers: { "content-type": "application/json",origin:"http://portal.test" },
    body: JSON.stringify({
      project_id: "attacker-project",
      name: "本地开发",
      user_id: "attacker",
      scopes: ["mcp", "*"],
    }),
  }));

  assert.equal(result.status, 201);
  assert.equal(result.headers.get("cache-control"), "private, no-store");
  assert.deepEqual(await result.json(), {
    data: {
      id: "key-1",
      name: "本地开发",
      prefix: "sk-test",
      project_id: "project-1",
      scopes: ["chat", "responses", "embeddings", "models"],
      status: "active",
      created_at: "2026-08-07T00:00:00Z",
      model_allowlist:[],
    },
    full_key: "sk-test-secret",
  });
  assert.equal(seen.length, 2);
  const createRequest = seen[1]!;
  assert.equal(createRequest.authorization, "Bearer portal-secret");
  assert.equal(createRequest.tenant, "tenant_default");
  assert.deepEqual(JSON.parse(createRequest.body), {
    project_id: "project-1",
    user_id: "employee-1",
    name: "本地开发",
    scopes: ["chat", "responses", "embeddings", "models"],
  });
});

test("self-service key route rejects unauthenticated and invalid requests", async () => {
  const route = (await import("../src/app/api/me/keys/route.js?self-service=validation" as string)) as typeof import("../src/app/api/me/keys/route.js");
  session = null;
  const unauthenticated = await route.POST(new Request("http://portal.test/api/me/keys", {
    method: "POST",
    headers: { "content-type": "application/json",origin:"http://portal.test" },
    body: JSON.stringify({ project_id: "project-1" }),
  }));
  assert.equal(unauthenticated.status, 401);

  session = { user: { id: "employee-1" } };
  const invalidName = await route.POST(new Request("http://portal.test/api/me/keys", {
    method: "POST",
    headers: { "content-type": "application/json",origin:"http://portal.test" },
    body: JSON.stringify({ name: "invalid\nname" }),
  }));
  assert.equal(invalidName.status, 400);
});

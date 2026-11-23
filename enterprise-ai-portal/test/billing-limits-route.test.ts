process.env.PORTAL_PUBLIC_URL='http://portal.test/chat';
import test, { mock } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";

let session: { user: { id: string } } | null = { user: { id: "employee-1" } };
let controlPlaneBaseUrl = "http://127.0.0.1:1";

mock.module("@/auth", {
  namedExports: { auth: async () => session },
});

mock.module("@/lib/gateway-env", {
  namedExports: {
    loadGatewayEnv: () => ({ baseUrl: controlPlaneBaseUrl, portalSecret: "portal-secret" }),
  },
});

mock.module("@/lib/control-plane", {
  namedExports: { PORTAL_DEFAULT_TENANT_ID: "tenant_default" },
});

// W2.3 active-user check is covered by me-routes-active-user.test.ts.
mock.module("@/lib/require-active-user", {
  namedExports: {
    requireActivePortalUser: async (current: { user?: { id?: string } } | null) =>
      current?.user?.id
        ? { user: { id: current.user.id } }
        : Response.json({ error: "unauthorized" }, { status: 401 }),
  },
});

const validLimits = {
  daily_amount_micros: 1_000_000,
  monthly_amount_micros: 2_000_000,
  daily_token_limit: 10_000,
  monthly_token_limit: 20_000,
  rpm_limit: 60,
  concurrency_limit: 3,
};

test("billing limits route binds request caps to the signed-in employee", async (t) => {
  session = { user: { id: "employee-1" } };
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
    response.end(JSON.stringify({ data: { limits: validLimits } }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const address = server.address();
  assert.ok(address && typeof address === "object");
  controlPlaneBaseUrl = `http://127.0.0.1:${address.port}`;

  const route = (await import("../src/app/api/me/billing/limits/route.js?request-caps=success" as string)) as typeof import("../src/app/api/me/billing/limits/route.js");
  const response = await route.PUT(new Request("http://portal.test/api/me/billing/limits", {
    method: "PUT",
    headers: { "content-type": "application/json",origin:"http://portal.test" },
    body: JSON.stringify({ ...validLimits, user_id: "attacker" }),
  }));

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "private, no-store");
  assert.equal(seen.length, 1);
  assert.equal(seen[0]?.path, "/admin/v1/portal-integration/customer-billing/limits");
  assert.equal(seen[0]?.method, "PUT");
  assert.equal(seen[0]?.authorization, "Bearer portal-secret");
  assert.equal(seen[0]?.tenant, "tenant_default");
  assert.deepEqual(JSON.parse(seen[0]?.body ?? "{}"), {
    user_id: "employee-1",
    ...validLimits,
  });
});

test("billing limits route rejects invalid request caps before control-plane access", async () => {
  session = { user: { id: "employee-1" } };
  controlPlaneBaseUrl = "http://127.0.0.1:1";
  const route = (await import("../src/app/api/me/billing/limits/route.js?request-caps=invalid" as string)) as typeof import("../src/app/api/me/billing/limits/route.js");

  for (const limits of [
    { ...validLimits, rpm_limit: -1 },
    { ...validLimits, concurrency_limit: Number.MAX_SAFE_INTEGER + 1 },
  ]) {
    const response = await route.PUT(new Request("http://portal.test/api/me/billing/limits", {
      method: "PUT",
      headers: { "content-type": "application/json",origin:"http://portal.test" },
      body: JSON.stringify(limits),
    }));
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: "invalid_limits" });
  }
});

test("billing limits route rejects unauthenticated employees", async () => {
  session = null;
  const route = (await import("../src/app/api/me/billing/limits/route.js?request-caps=unauthenticated" as string)) as typeof import("../src/app/api/me/billing/limits/route.js");
  const response = await route.PUT(new Request("http://portal.test/api/me/billing/limits", {
    method: "PUT",
    headers: { "content-type": "application/json",origin:"http://portal.test" },
    body: JSON.stringify(validLimits),
  }));
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "unauthorized" });
});

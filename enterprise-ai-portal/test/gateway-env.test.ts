import test from "node:test";
import assert from "node:assert/strict";
import { loadGatewayEnv } from "../src/lib/gateway-env.js";

test("JJD gateway variables take precedence over legacy compatibility values", () => {
  assert.deepEqual(loadGatewayEnv({
    JJD_CP_URL: "http://jjd-control-plane:8081",
    JJD_PORTAL_API_SECRET: "jjd-secret",
    NEWAPI_CP_URL: "http://legacy-canary:8081",
    NEWAPI_PORTAL_API_SECRET: "legacy-secret-canary",
  }), { baseUrl: "http://jjd-control-plane:8081", portalSecret: "jjd-secret" });
});

test("legacy gateway variables remain a compatibility fallback", () => {
  assert.deepEqual(loadGatewayEnv({
    NEWAPI_CP_URL: "http://legacy-control-plane:8081",
    NEWAPI_PORTAL_API_SECRET: "legacy-secret",
  }), { baseUrl: "http://legacy-control-plane:8081", portalSecret: "legacy-secret" });
});

test("blank JJD values fall back and surrounding whitespace is ignored", () => {
  assert.deepEqual(loadGatewayEnv({
    JJD_CP_URL: "   ",
    JJD_PORTAL_API_SECRET: "\t",
    NEWAPI_CP_URL: " http://legacy-control-plane:8081 ",
    NEWAPI_PORTAL_API_SECRET: " legacy-secret ",
  }), { baseUrl: "http://legacy-control-plane:8081", portalSecret: "legacy-secret" });
});

test("missing gateway configuration names variables without leaking values", () => {
  assert.throws(
    () => loadGatewayEnv({ JJD_PORTAL_API_SECRET: "secret-value-canary" }),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.match(error.message, /JJD_CP_URL/);
      assert.doesNotMatch(error.message, /secret-value-canary/);
      return true;
    },
  );
});

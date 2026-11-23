import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  PORTAL_AUTH_BASE_PATH,
  PORTAL_BASE_PATH,
  portalPath,
  stripPortalBasePath,
} from "../src/lib/portal-path.js";

test("portalPath keeps every browser route under /chat", () => {
  assert.equal(PORTAL_BASE_PATH, "/chat");
  assert.equal(PORTAL_AUTH_BASE_PATH, "/chat/api/auth");
  assert.equal(portalPath("/"), "/chat");
  assert.equal(portalPath("/login"), "/chat/login");
  assert.equal(portalPath("/api/chat?stream=1"), "/chat/api/chat?stream=1");
  assert.equal(portalPath("/chat/api/models"), "/chat/api/models");
});

test("stripPortalBasePath normalizes middleware paths without accepting lookalikes", () => {
  assert.equal(stripPortalBasePath("/chat"), "/");
  assert.equal(stripPortalBasePath("/chat/records"), "/records");
  assert.equal(stripPortalBasePath("/chatty"), "/chatty");
  assert.equal(stripPortalBasePath("/records"), "/records");
});

test("Auth.js handler restores the external base path stripped by Next.js", () => {
  const route = readFileSync(
    new URL("../src/app/api/auth/[...nextauth]/route.ts", import.meta.url),
    "utf8",
  );
  assert.match(route, /process\.env\.AUTH_URL \?\? process\.env\.NEXTAUTH_URL/);
  assert.match(route, /url\.hostname = publicUrl\.hostname/);
  assert.match(route, /url\.port = publicUrl\.port/);
  assert.match(route, /url\.pathname = portalPath\(url\.pathname\)/);
  assert.match(route, /handlers\.GET\(restoreExternalBasePath\(request\)\)/);
  assert.match(route, /handlers\.POST\(restoreExternalBasePath\(request\)\)/);
});

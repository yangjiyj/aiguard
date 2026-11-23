import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  assertTrustedLogoutRequest,
  buildFederatedLogoutUrl,
  loadFederatedLogoutConfig,
  loadLogoutRequestConfig,
  resolveFederatedLogoutUrl,
} from "../src/lib/federated-logout.js";

const validEnv = {
  OIDC_ISSUER: "https://sso.example.test/tenant",
  OIDC_CLIENT_ID: "enterprise-ai-portal",
  PORTAL_PUBLIC_URL: "https://ai.example.test/chat",
};

test("登出配置只由固定环境变量生成", () => {
  const requestConfig = loadLogoutRequestConfig({
    PORTAL_PUBLIC_URL: validEnv.PORTAL_PUBLIC_URL,
  });
  assert.equal(requestConfig.postLogoutRedirectUri, validEnv.PORTAL_PUBLIC_URL);

  const config = loadFederatedLogoutConfig(validEnv);
  assert.equal(
    config.discoveryUrl.href,
    "https://sso.example.test/tenant/.well-known/openid-configuration",
  );
  assert.equal(config.postLogoutRedirectUri, validEnv.PORTAL_PUBLIC_URL);
  assert.equal(config.clientId, validEnv.OIDC_CLIENT_ID);
});

test("登出配置拒绝非 HTTP 协议、凭据、查询和片段", () => {
  for (const issuer of [
    "file:///etc/passwd",
    "https://user:pass@sso.example.test/tenant",
    "https://sso.example.test/tenant?next=https://evil.test",
    "https://sso.example.test/tenant#fragment",
  ]) {
    assert.throws(() =>
      loadFederatedLogoutConfig({ ...validEnv, OIDC_ISSUER: issuer }),
    );
  }
  assert.throws(() =>
    loadFederatedLogoutConfig({
      ...validEnv,
      PORTAL_PUBLIC_URL: "https://ai.example.test/chat?next=https://evil.test",
    }),
  );
});

test("联合登出仅接受门户同源 POST", () => {
  const config = loadFederatedLogoutConfig(validEnv);
  assert.doesNotThrow(() =>
    assertTrustedLogoutRequest(
      new Request("https://ai.example.test/api/auth/federated-logout", {
        method: "POST",
        headers: {
          origin: "https://ai.example.test",
          "sec-fetch-site": "same-origin",
        },
      }),
      config,
    ),
  );
  for (const headers of [
    new Headers(),
    new Headers({ origin: "https://evil.example.test" }),
    new Headers({
      origin: "https://ai.example.test",
      "sec-fetch-site": "cross-site",
    }),
  ]) {
    assert.throws(() =>
      assertTrustedLogoutRequest(
        new Request("https://ai.example.test/api/auth/federated-logout", {
          method: "POST",
          headers,
        }),
        config,
      ),
    );
  }
});

test("发现结果生成同源 end-session 地址和精确回跳地址", () => {
  const config = loadFederatedLogoutConfig(validEnv);
  const target = buildFederatedLogoutUrl(config, {
    issuer: validEnv.OIDC_ISSUER,
    end_session_endpoint: "https://sso.example.test/logout",
  });
  assert.equal(target.origin, "https://sso.example.test");
  assert.equal(target.pathname, "/logout");
  assert.equal(
    target.searchParams.get("post_logout_redirect_uri"),
    validEnv.PORTAL_PUBLIC_URL,
  );
  assert.equal(target.searchParams.get("client_id"), validEnv.OIDC_CLIENT_ID);
});

test("发现结果拒绝 issuer 漂移和跨源 end-session 地址", () => {
  const config = loadFederatedLogoutConfig(validEnv);
  assert.throws(() =>
    buildFederatedLogoutUrl(config, {
      issuer: "https://sso.example.test/other",
      end_session_endpoint: "https://sso.example.test/logout",
    }),
  );
  assert.throws(() =>
    buildFederatedLogoutUrl(config, {
      issuer: validEnv.OIDC_ISSUER,
      end_session_endpoint: "https://evil.example.test/logout",
    }),
  );
});

test("发现请求固定、禁重定向并限制响应", async () => {
  const config = loadFederatedLogoutConfig(validEnv);
  let requested = "";
  const target = await resolveFederatedLogoutUrl(config, async (input, init) => {
    requested = String(input);
    assert.equal(init?.redirect, "error");
    assert.equal(init?.cache, "no-store");
    return new Response(
      JSON.stringify({
        issuer: validEnv.OIDC_ISSUER,
        end_session_endpoint: "https://sso.example.test/logout",
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  });
  assert.equal(requested, config.discoveryUrl.href);
  assert.equal(target.pathname, "/logout");

  await assert.rejects(() =>
    resolveFederatedLogoutUrl(config, async () =>
      new Response("x".repeat(65_537), { status: 200 }),
    ),
  );
});

test("声明长度超限时也会取消响应流", async () => {
  const config = loadFederatedLogoutConfig(validEnv);
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({
    cancel() {
      cancelled = true;
    },
  });

  await assert.rejects(() =>
    resolveFederatedLogoutUrl(
      config,
      async () =>
        new Response(body, {
          status: 200,
          headers: { "content-length": "65537" },
        }),
    ),
  );
  assert.equal(cancelled, true);
});

test("分块发现响应超限时立即取消读取", async () => {
  const config = loadFederatedLogoutConfig(validEnv);
  let cancelled = false;
  let pulls = 0;
  const body = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        pulls += 1;
        if (pulls === 1) {
          controller.enqueue(new Uint8Array(65_537));
          return;
        }
        controller.close();
      },
      cancel() {
        cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );

  await assert.rejects(() =>
    resolveFederatedLogoutUrl(
      config,
      async () => new Response(body, { status: 200 }),
    ),
  );
  assert.equal(cancelled, true);
  assert.equal(pulls, 1);
});

test("联合登出路由先清本地会话、不开放 GET 且不读跳转参数", () => {
  const route = readFileSync(
    new URL("../src/app/api/auth/federated-logout/route.ts", import.meta.url),
    "utf8",
  );
  const sidebar = readFileSync(
    new URL("../src/components/sidebar-account.tsx", import.meta.url),
    "utf8",
  );
  assert.match(route, /export async function POST\(request: Request\)/);
  assert.match(route, /assertTrustedLogoutRequest\(request, requestConfig\)/);
  assert.match(route, /signOut\(\{\s*redirect:\s*false\s*\}\)/);
  assert.match(route, /resolveFederatedLogoutUrl/);
  assert.doesNotMatch(route, /function GET|export const GET/);
  assert.doesNotMatch(route, /searchParams|callbackUrl|redirectTo/);
  assert.match(sidebar, /\/api\/auth\/federated-logout/);
  assert.match(sidebar, /form\.method\s*=\s*["']POST["']/);

  const handler = route.slice(route.indexOf("export async function POST"));
  assert.ok(
    handler.indexOf("await signOut") <
      handler.indexOf("loadFederatedLogoutConfig()"),
    "本地会话必须在加载远端 OIDC 配置前清除",
  );
});

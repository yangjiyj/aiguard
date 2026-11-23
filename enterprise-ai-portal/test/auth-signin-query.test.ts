import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  dropSigninAuthorizationQuery,
  isProviderSigninPath,
} from "../src/lib/auth-request.js";

// 背景：@auth/core 在构造授权 URL 时把「发起登录请求」URL 上的 query 并入授权参数，
// 且优先级高于 provider 里服务端固定的 authorization.params
// （lib/actions/signin/authorization-url.js：Object.assign(固定参数, query)）。
// 不加处理时 /signin/enterprise-sso?kc_idp_hint=other&prompt=login 会让请求方改写 IdP 提示、
// 注入强制重新认证参数。这里锁定：登录发起请求的 query 一律丢弃，授权参数只来自服务端配置。

const BASE = "http://portal.test";

test("只有 /signin/<provider> 被识别为登录发起请求", () => {
  assert.equal(isProviderSigninPath("/chat/api/auth/signin/enterprise-sso"), true);
  assert.equal(isProviderSigninPath("/chat/api/auth/signin/account-login/"), true);
  assert.equal(isProviderSigninPath("/chat/api/auth/signin//enterprise-sso"), true);
  // 不带 provider 的 signin 页面重定向要用 callbackUrl，不能误伤
  assert.equal(isProviderSigninPath("/chat/api/auth/signin"), false);
  assert.equal(isProviderSigninPath("/chat/api/auth/callback/enterprise-sso"), false);
  assert.equal(isProviderSigninPath("/chat/api/auth/session"), false);
  assert.equal(isProviderSigninPath("/chat/api/auth/csrf"), false);
  assert.equal(isProviderSigninPath("/chat/api/me"), false);
  assert.equal(isProviderSigninPath("/other/api/auth/signin/enterprise-sso"), false);
});

test("登录发起请求的 query 全部丢弃", () => {
  const url = new URL(
    `${BASE}/chat/api/auth/signin/enterprise-sso?kc_idp_hint=other&prompt=login&max_age=0&callbackUrl=%2Fx`,
  );
  dropSigninAuthorizationQuery(url);
  assert.equal(url.search, "");
});

test("回调、会话、csrf 与不带 provider 的 signin 保持 query 不变", () => {
  for (const path of [
    "/chat/api/auth/callback/enterprise-sso?code=c&state=s",
    "/chat/api/auth/session?update=1",
    "/chat/api/auth/signin?callbackUrl=%2Fchat",
    "/chat/api/auth/signin?callbackUrl=%2Fchat&error=OAuthCallback",
  ]) {
    const url = new URL(BASE + path);
    const before = url.search;
    dropSigninAuthorizationQuery(url);
    assert.equal(url.search, before, path);
  }
});

test("认证路由的 GET 与 POST 共用同一处理，都先丢弃登录发起 query", () => {
  const route = readFileSync(
    new URL("../src/app/api/auth/[...nextauth]/route.ts", import.meta.url),
    "utf8",
  );
  assert.match(route, /dropSigninAuthorizationQuery\(/);
  const helper = route.slice(
    route.indexOf("function restoreExternalBasePath"),
    route.indexOf("export function GET"),
  );
  assert.match(helper, /dropSigninAuthorizationQuery\(url\)/);
  assert.match(route, /handlers\.GET\(restoreExternalBasePath\(request\)\)/);
  assert.match(route, /handlers\.POST\(restoreExternalBasePath\(request\)\)/);
});

// 真实经过 Auth.js：起一个只含 discovery 的本地假 IdP，经 route.ts 发起登录，读取 302 的授权 URL。
const CHILD_SCRIPT = `
import http from "node:http";
const issuerPath = "/realms/jjdguard";
const server = http.createServer((req, res) => {
  const base = "http://127.0.0.1:" + server.address().port + issuerPath;
  if (req.url === issuerPath + "/.well-known/openid-configuration") {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({
      issuer: base,
      authorization_endpoint: base + "/protocol/openid-connect/auth",
      token_endpoint: base + "/protocol/openid-connect/token",
      jwks_uri: base + "/protocol/openid-connect/certs",
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      code_challenge_methods_supported: ["S256"],
    }));
    return;
  }
  res.statusCode = 404;
  res.end();
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
process.env.OIDC_ISSUER = "http://127.0.0.1:" + server.address().port + issuerPath;
const { NextRequest } = await import("next/server");
const route = await import("./src/app/api/auth/[...nextauth]/route.ts");
const { GET, POST } = route.default ?? route;

async function authorize(provider, search) {
  const csrfRes = await GET(new NextRequest("http://portal.test/chat/api/auth/csrf"));
  const { csrfToken } = await csrfRes.json();
  const cookie = csrfRes.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  const body = new URLSearchParams({ csrfToken, callbackUrl: "http://portal.test/chat" });
  const res = await POST(new NextRequest(
    "http://portal.test/chat/api/auth/signin/" + provider + search,
    { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", cookie }, body },
  ));
  const location = res.headers.get("location");
  const params = {};
  if (location) {
    for (const [k, v] of new URL(location).searchParams) {
      params[k] = ["state", "nonce", "code_challenge"].includes(k) ? "<set>" : v;
    }
  }
  return { status: res.status, params };
}

const attack = "?kc_idp_hint=attacker-idp&prompt=login&max_age=0&login_hint=victim&acr_values=x&scope=openid";
const out = {
  accountAttack: await authorize("account-login", attack),
  ssoAttack: await authorize("enterprise-sso", attack),
  ssoPlain: await authorize("enterprise-sso", ""),
};
process.stdout.write(JSON.stringify(out));
server.close();
`;

function runChild(extraEnv: Record<string, string>) {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    AUTH_SECRET: "isolated-signin-query-secret-minimum-32-bytes",
    AUTH_URL: "http://portal.test/chat/api/auth",
    PORTAL_PUBLIC_URL: "http://portal.test/chat",
    OIDC_CLIENT_ID: "enterprise-ai-portal",
    OIDC_CLIENT_SECRET: "isolated-placeholder",
  };
  // 先清掉外部环境里可能存在的提示值，再按用例设置，避免测试结果受运行环境影响
  delete env.OIDC_ENTERPRISE_IDP_HINT;
  Object.assign(env, extraEnv);
  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", "--input-type=module", "-e", CHILD_SCRIPT],
    { env, cwd: process.cwd(), encoding: "utf8", timeout: 90_000 },
  );
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout) as Record<
    "accountAttack" | "ssoAttack" | "ssoPlain",
    { status: number; params: Record<string, string> }
  >;
}

function assertNoForcedReauthentication(params: Record<string, string>) {
  for (const name of ["prompt", "max_age", "login_hint", "acr_values"]) {
    assert.equal(name in params, false, `授权参数不应出现 ${name}`);
  }
  // 认证强度不得因此被削弱：PKCE(S256)、state、nonce 仍在，scope 仍是服务端值
  assert.equal(params.code_challenge_method, "S256");
  assert.equal(params.code_challenge, "<set>");
  assert.equal(params.state, "<set>");
  assert.equal(params.nonce, "<set>");
  assert.equal(params.scope, "openid email profile groups");
  assert.equal(params.response_type, "code");
}

test("经 Auth.js 实测：请求 query 不能改写 kc_idp_hint，也不能注入 prompt/max_age/login_hint", () => {
  const out = runChild({});
  for (const key of ["accountAttack", "ssoAttack", "ssoPlain"] as const) {
    assert.equal(out[key].status, 302, key);
    assertNoForcedReauthentication(out[key].params);
  }
  // 账号登录入口按设计不带 IdP 提示，请求方也不能给它加
  assert.equal("kc_idp_hint" in out.accountAttack.params, false);
  // 企业 SSO 入口固定为服务端值
  assert.equal(out.ssoAttack.params.kc_idp_hint, "enterprise");
  assert.equal(out.ssoPlain.params.kc_idp_hint, "enterprise");
});

test("OIDC_ENTERPRISE_IDP_HINT 仍可由服务端环境变量配置，且同样不被请求覆盖", () => {
  const out = runChild({ OIDC_ENTERPRISE_IDP_HINT: "corp-idp" });
  assert.equal(out.ssoPlain.params.kc_idp_hint, "corp-idp");
  assert.equal(out.ssoAttack.params.kc_idp_hint, "corp-idp");
  assert.equal("kc_idp_hint" in out.accountAttack.params, false);
  for (const key of ["accountAttack", "ssoAttack", "ssoPlain"] as const) {
    assertNoForcedReauthentication(out[key].params);
  }
});

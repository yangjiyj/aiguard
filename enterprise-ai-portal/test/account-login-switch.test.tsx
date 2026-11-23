import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import test from "node:test";

import { LoginOptions } from "../src/components/login-options.js";

// 「企业目录账号登录」(account-login) 不带 kc_idp_hint，落在 Keycloak 自己的账号密码页。
// 只接企业 SSO（例如 Authing）的站点没有这类账号，用户点进去输入企业用户名会得到 user_not_found。
// OIDC_ACCOUNT_LOGIN_ENABLED=false 时不注册该 provider，登录页也不再显示按钮。默认开启，行为不变。

function providersFor(extraEnv: Record<string, string | undefined>) {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    OIDC_ISSUER: "http://127.0.0.1:9/realms/jjdguard",
    OIDC_CLIENT_ID: "enterprise-ai-portal",
    OIDC_CLIENT_SECRET: "isolated-placeholder",
    AUTH_SECRET: "isolated-account-switch-secret-minimum-32-bytes",
    AUTH_URL: "http://portal.test/chat/api/auth",
  };
  delete env.OIDC_ACCOUNT_LOGIN_ENABLED;
  Object.assign(env, extraEnv);
  const script =
    'const {NextRequest}=await import("next/server");' +
    'const module=await import("./src/auth.ts");' +
    "const handlers=module.handlers??module.default.handlers;" +
    'const response=await handlers.GET(new NextRequest("http://portal.test/chat/api/auth/providers"));' +
    "process.stdout.write(JSON.stringify({status:response.status,providers:Object.keys(await response.json())}));";
  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", "--input-type=module", "-e", script],
    { env, cwd: process.cwd(), encoding: "utf8", timeout: 90_000 },
  );
  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(result.stdout) as { status: number; providers: string[] };
  assert.equal(output.status, 200);
  return output.providers;
}

test("默认保留账号登录与企业 SSO 两个 OIDC provider", () => {
  assert.deepEqual(providersFor({}), [
    "employee-local",
    "chat-ticket",
    "account-login",
    "enterprise-sso",
  ]);
});

test("OIDC_ACCOUNT_LOGIN_ENABLED=false 只关闭 account-login，企业 SSO 与本地登录不受影响", () => {
  for (const value of ["false", "FALSE", " false "]) {
    assert.deepEqual(providersFor({ OIDC_ACCOUNT_LOGIN_ENABLED: value }), [
      "employee-local",
      "chat-ticket",
      "enterprise-sso",
    ]);
  }
});

test("其它取值（含空值、true、拼写错误）一律按默认开启处理，不会因误配关掉入口", () => {
  for (const value of ["", "true", "0", "no", "off"]) {
    assert.ok(
      providersFor({ OIDC_ACCOUNT_LOGIN_ENABLED: value }).includes("account-login"),
      `value=${JSON.stringify(value)}`,
    );
  }
});

test("登录页：默认两个企业入口都显示", () => {
  const html = renderToStaticMarkup(createElement(LoginOptions, {}));
  assert.match(html, /企业目录账号登录/);
  assert.match(html, /企业 SSO 登录/);
});

test("登录页：accountLoginAvailable=false 隐藏企业目录账号登录，保留企业 SSO 与本地表单", () => {
  const html = renderToStaticMarkup(
    createElement(LoginOptions, { accountLoginAvailable: false }),
  );
  assert.doesNotMatch(html, /企业目录账号登录/);
  // 关闭目录账号登录后，提示语不能再提「企业目录账号」，否则用户以为下面的按钮能用目录账号登录。
  assert.doesNotMatch(html, /企业目录账号/);
  assert.match(html, /也可以使用企业 SSO 登录/);
  assert.match(html, /企业 SSO 登录/);
  for (const name of ["username", "password", "captcha_code"]) {
    assert.match(html, new RegExp(`name="${name}"`));
  }
});

test("登录页：未配置企业 OIDC 时两个企业入口都不显示（原有行为）", () => {
  const html = renderToStaticMarkup(
    createElement(LoginOptions, { enterpriseLoginAvailable: false }),
  );
  assert.doesNotMatch(html, /企业目录账号登录/);
  assert.doesNotMatch(html, /企业 SSO 登录/);
});

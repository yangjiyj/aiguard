import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { mapPortalIdentityClaims } from "../src/lib/portal-identity.js";

const authSource = readFileSync(new URL("../src/auth.ts", import.meta.url), "utf8");
const loginSource = readFileSync(
  new URL("../src/app/login/page.tsx", import.meta.url),
  "utf8",
);
const optionsSource = readFileSync(
  new URL("../src/components/login-options.tsx", import.meta.url),
  "utf8",
);

const meRouteSource = readFileSync(
  new URL("../src/app/api/me/route.ts", import.meta.url),
  "utf8",
);

test("任务10：Chat 登录提供账号登录与企业 SSO 双 provider 入口", () => {
  // 两个固定 provider：account-login（本地/AD/LDAP 登录页）+ enterprise-sso（固定 kc_idp_hint=enterprise）
  assert.match(authSource, /id:\s*["']account-login["']/);
  assert.match(authSource, /id:\s*["']enterprise-sso["']/);
  // 登录页主入口走 account-login，次入口走 enterprise-sso
  assert.match(optionsSource, /enterpriseSignIn\(["']account-login["']/);
  assert.match(optionsSource, /enterpriseSignIn\(["']enterprise-sso["']/);
});

test("双 provider 配置不硬编码内部 realm/client 名称", () => {
  // 安全意图（继承自旧断言）：不在源码里暴露内部 Keycloak realm/client 标识
  assert.doesNotMatch(
    authSource + loginSource + optionsSource,
    /chat-portal-dev/,
  );
});

test("两个 OIDC provider 都强制 PKCE、state 和 nonce", () => {
  assert.match(authSource, /type:\s*["']oidc["']/);
  assert.match(authSource, /code_challenge_method:\s*["']S256["']/);
  // checks 数组须同时含 pkce/state/nonce（两个 provider 都要有，故用全局匹配计数）
  const checksBlocks = authSource.match(/checks:\s*\[[^\]]*\]/g) ?? [];
  assert.ok(
    checksBlocks.length >= 2,
    `期望至少 2 个 provider 的 checks 块，实际 ${checksBlocks.length}`,
  );
  for (const block of checksBlocks) {
    assert.match(block, /["']pkce["']/);
    assert.match(block, /["']state["']/);
    assert.match(block, /["']nonce["']/);
  }
});

test("两个 OIDC provider 的 scope 都含 groups", () => {
  // 任务10步骤4：scope 加 groups，两个 provider 都要
  const scopeMatches = authSource.match(/scope:\s*["'][^"']*["']/g) ?? [];
  assert.ok(
    scopeMatches.length >= 2,
    `期望至少 2 个 scope 声明，实际 ${scopeMatches.length}`,
  );
  for (const scope of scopeMatches) {
    assert.match(scope, /groups/);
  }
});

test("kc_idp_hint 仅在 enterprise-sso 出现且服务端固定，不从 query 透传", () => {
  // enterprise-sso provider 必须有服务端固定的 kc_idp_hint 字段：绑定服务端常量
  // (ENTERPRISE_IDP_HINT) 或字面量 'enterprise'——两者都算服务端固定。
  assert.match(authSource, /kc_idp_hint:\s*(ENTERPRISE_IDP_HINT|["']enterprise["'])/);
  // 服务端常量默认值固定为 enterprise（环境变量可覆盖，但仍是服务端配置，不经请求）
  assert.match(authSource, /OIDC_ENTERPRISE_IDP_HINT\s*\|\|\s*["']enterprise["']/);
  // account-login provider 不应携带 kc_idp_hint：精确按 "kc_idp_hint: " 字段形式计数应为 1
  const hintFieldCount = (authSource.match(/kc_idp_hint:\s/g) ?? []).length;
  assert.equal(hintFieldCount, 1, `kc_idp_hint 字段应仅在 enterprise-sso 出现 1 次，实际 ${hintFieldCount}`);
  // 安全红线：服务端不接受来自请求的 kc_idp_hint/idp alias
  assert.doesNotMatch(authSource, /searchParams|req\.query|request\.url.*kc_idp/);
});

test("callback 不接受客户端传任意 IdP alias 参数", () => {
  // callback 不得读取 query/body 里的 idp alias 透传给 IdP
  assert.doesNotMatch(
    authSource,
    /kc_idp_hint.*searchParams|idp_alias|idpAlias/,
  );
});

test("员工身份接口显式返回稳定 external_subject", () => {
  assert.match(meRouteSource, /external_subject:\s*session\.user\.id/);
});

test("员工门户不接受上游 role 声明提升权限", () => {
  assert.doesNotMatch(authSource, /\bp\.role\b|profile\.role/);
  assert.match(authSource, /role:\s*PORTAL_EMPLOYEE_ROLE/);
});

test("恶意角色声明不能提升权限，部门声明经过边界清洗", () => {
  assert.deepEqual(
    mapPortalIdentityClaims({
      department: " 信息安全部 ",
      role: "platform_admin",
      groups: ["administrators"],
    }),
    { department: "信息安全部", role: "employee" },
  );
  assert.deepEqual(
    mapPortalIdentityClaims({ department: "安全部\r\nx-forged: true" }),
    { department: null, role: "employee" },
  );
});

test("local ticket provider remains available when the installation has no OIDC configuration", async () => {
 const {spawnSync} = await import("node:child_process");
 const env = {...process.env, OIDC_ISSUER:"", OIDC_CLIENT_ID:"", OIDC_CLIENT_SECRET:"", AUTH_SECRET:"isolated-no-oidc-secret-minimum-32-bytes", AUTH_URL:"http://portal.test/chat/api/auth"};
 const script = 'const {NextRequest}=await import("next/server");const module=await import("./src/auth.ts");const handlers=module.handlers??module.default.handlers;const response=await handlers.GET(new NextRequest("http://portal.test/chat/api/auth/providers"));process.stdout.write(JSON.stringify({status:response.status,providers:Object.keys(await response.json())}));';
 const result = spawnSync(process.execPath,["--import","tsx","--input-type=module","-e",script],{env,cwd:process.cwd(),encoding:"utf8"});
 assert.equal(result.status,0,result.stderr);
 const output=JSON.parse(result.stdout);
 assert.equal(output.status,200);
 assert.deepEqual(output.providers,["employee-local","chat-ticket"]);
});

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// 任务10：Chat 登录页双入口 UI 断言。
// 采用源码文本断言（与现有 auth-provider.test.ts 同栈：node:test + tsx，无 jsdom/RTL 依赖）。
// 规格写 .tsx 后缀，但本仓测试栈不渲染 React，文件用 .test.ts 以保持一致（YAGNI：不引入 vitest）。

const pageSource = readFileSync(
  new URL("../src/app/login/page.tsx", import.meta.url),
  "utf8",
);
const optionsSource = readFileSync(
  new URL("../src/components/login-options.tsx", import.meta.url),
  "utf8",
);
const combined = pageSource + "\n" + optionsSource;

test("登录页提供账号登录主按钮与企业 SSO 次按钮两个入口", () => {
  // 主按钮：账号登录，调 signIn("account-login")
  assert.match(combined, /账号登录/);
  assert.match(optionsSource, /enterpriseSignIn\(["']account-login["']/);
  // 次按钮：企业 SSO 登录，调 signIn("enterprise-sso")
  assert.match(combined, /企业\s*SSO\s*登录/);
  assert.match(optionsSource, /enterpriseSignIn\(["']enterprise-sso["']/);
});

test("登录页说明本地账号与企业目录账号都走账号登录", () => {
  // 说明文字引导用户：本地/AD/LDAP 账号与企业目录账号均通过「账号登录」入口
  assert.match(combined, /本地|企业目录|目录账号/);
});

// 剥除注释和字符串字面量后的代码本体，用于检测真实的注入逻辑（注释里提到关键字不算漏洞）
const stripCommentsAndStrings = (src: string): string =>
  src
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/\/\/.*$/gm, " ")
    .replace(/"[^"]*"/g, '""')
    .replace(/'[^']*'/g, "''")
    .replace(/`[^`]*`/g, "``");

test("登录入口组件不含任何将 query string 透传为 kc_idp_hint 的逻辑", () => {
  // 安全红线：kc_idp_hint 必须服务端固定，客户端组件不得从 searchParams/query 取值透传
  const codeOnly = stripCommentsAndStrings(optionsSource);
  // 代码本体里不得出现把 searchParams/query 取值赋给 hint 类参数的逻辑
  assert.doesNotMatch(
    codeOnly,
    /(searchParams|\.query|params\.)\s*[^;]*kc_idp_hint/,
  );
  // 客户端组件不应直接持有 kc_idp_hint 赋值（服务端固定，客户端不该出现该字段赋值）
  assert.doesNotMatch(codeOnly, /kc_idp_hint\s*:/);
});

test("登录页错误态不泄露上游 token 或内部 provider 配置", () => {
  // 检测代码本体（剥除注释/字符串后），错误展示不得回显上游 token / provider 密钥
  const codeOnly = stripCommentsAndStrings(combined);
  assert.doesNotMatch(
    codeOnly,
    /access_token|id_token|refresh_token|clientSecret|client_secret/,
  );
  // 不得直接把上游 OIDC error_description 回显给用户（应做中性化映射）
  assert.doesNotMatch(codeOnly, /error_description/);
});

test('Chat local account entry uses its own employee form and no console redirect', () => {
 assert.match(optionsSource, /<EmployeeLoginForm/);
 assert.doesNotMatch(combined, /from=chat|takeChatLoginTicket/);
 assert.doesNotMatch(combined, /autoSso|entry ===/);
});

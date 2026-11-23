import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = (path: string) => readFile(new URL(path, import.meta.url), "utf8");

test("chat shell keeps the header and composer focused on conversation", async () => {
  const [panel, composer] = await Promise.all([
    source("../src/components/chat/chat-panel.tsx"),
    source("../src/components/chat/composer.tsx"),
  ]);

  assert.doesNotMatch(panel, /安全网关已启用/);
  assert.doesNotMatch(panel, /aria-label="导出对话"/);
  assert.doesNotMatch(composer, /aria-label="上传图片"/);
  assert.doesNotMatch(composer, /aria-label="上传文件"/);
  assert.match(composer, /onPaste=\{handlePaste\}/);
  assert.match(composer, /可直接粘贴图片或文件/);
  assert.match(panel, /守护中/);
  assert.doesNotMatch(composer, /安全审计已开启/);
  assert.doesNotMatch(composer, /仅文本/);
});

test("customer center remains available without a client runtime flag", async () => {
  const [sidebar, nav, apiKeys, billingPage, dockerfile] = await Promise.all([
    source("../src/components/chat/sidebar.tsx"),
    source("../src/components/portal-nav.tsx"),
    source("../src/components/api-keys-panel.tsx"),
    source("../src/components/billing-page.tsx"),
    source("../Dockerfile"),
  ]);

  assert.doesNotMatch(sidebar, /NEXT_PUBLIC_BILLING_ENABLED/);
  assert.doesNotMatch(sidebar, /企业工具/);
  // 工作台入口在账号菜单里，侧栏只放历史对话。
  assert.match(sidebar, /<SidebarAccount/);
  assert.doesNotMatch(sidebar, /WORKSPACE_NAV|PortalNav/);
  assert.match(nav, /调用记录/);
  const centerLabel = billingPage.match(/<h1[^>]*>([^<]+)<\/h1>/)?.[1];
  assert.ok(centerLabel && nav.includes(centerLabel));
  assert.match(nav, /href: "\/records"/);
  assert.match(nav, /href: "\/billing"/);
  assert.doesNotMatch(nav, /<Link/);
  assert.doesNotMatch(sidebar, /<Link/);
  assert.doesNotMatch(sidebar, /我的记录 · 用量与留痕/);
  assert.doesNotMatch(sidebar, /客户中心 · 余额与 API/);
  assert.match(dockerfile, /ARG NEXT_PUBLIC_BILLING_ENABLED=false/);
  assert.match(apiKeys, /创建 API 密钥/);
  assert.match(apiKeys, /我的 API Key/);
  assert.match(apiKeys, /密钥将自动绑定当前账号/);
  assert.match(apiKeys, /复制完整 Key/);
  assert.match(apiKeys, /\/api\/me\/keys\/\$\{encodeURIComponent\(key\.id\)\}\/reveal/);
  assert.match(apiKeys, /60 秒后自动隐藏/);
  assert.doesNotMatch(apiKeys, /管理员授权/);
  assert.match(billingPage, /每分钟请求上限（RPM）/);
  assert.match(billingPage, /并发请求上限/);
  assert.match(billingPage, /rpm_limit: inputTokens\(rpmLimit\)/);
  assert.match(billingPage, /concurrency_limit: inputTokens\(concurrencyLimit\)/);
	assert.match(await readFile(new URL("../src/components/gateway-config-panel.tsx",import.meta.url),"utf8"), /复制调用地址/);
	assert.match(await readFile(new URL("../src/components/gateway-config-panel.tsx",import.meta.url),"utf8"), /正在读取调用入口，请稍后重试/);
	assert.doesNotMatch(billingPage, /最近成功调用|失败记录/);
	assert.doesNotMatch(billingPage, /GATEWAY_PUBLIC_URL/);
	assert.doesNotMatch(billingPage, /返回对话/);
});

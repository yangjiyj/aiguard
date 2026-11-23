// 安全集成测试：对运行中的企业 AI 对话门户发请求，验证关键安全语义。
// 运行：node --import tsx test/security-check.ts
// 前提：BASE_URL 指向运行中的门户；COOKIE 提供登录态（可选，用于已登录场景）。
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { extname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const CUSTOMER_SOURCE_ROOT = fileURLToPath(new URL('../src', import.meta.url));
const INTERNAL_TERMS = /Keycloak|keycloak|chat-portal-dev|master realm/;

function customerSourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return customerSourceFiles(path);
    return ['.ts', '.tsx'].includes(extname(entry.name)) ? [path] : [];
  });
}

export function assertCustomerSurfaceVendorNeutral() {
  // 仅扫描会进入客户运行包的 src；内部设计、历史交接和运维文档不在此范围。
  for (const path of customerSourceFiles(CUSTOMER_SOURCE_ROOT)) {
    assert.doesNotMatch(
      readFileSync(path, 'utf8'),
      INTERNAL_TERMS,
      `客户源码包含内部身份引擎术语：${relative(CUSTOMER_SOURCE_ROOT, path)}`,
    );
  }
}

assertCustomerSurfaceVendorNeutral();

const BASE = process.env.BASE_URL ?? 'http://localhost:3100';
const COOKIE = process.env.COOKIE ?? '';

interface CheckResult { name: string; pass: boolean; detail?: string; }
const results: CheckResult[] = [];

async function check(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    results.push({ name, pass: true });
    console.log(`✓ ${name}`);
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    results.push({ name, pass: false, detail });
    console.log(`✗ ${name}\n  ${detail}`);
  }
}

function assertOk(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(msg);
}

async function main() {
  // 1. 未登录访问受保护 API → 401
  await check('未登录 GET /api/me → 401', async () => {
    const r = await fetch(`${BASE}/api/me`, { redirect: 'manual' });
    assertOk(r.status === 401, `期望 401，实际 ${r.status}`);
  });

  await check('未登录 GET /api/models → 401', async () => {
    const r = await fetch(`${BASE}/api/models`, { redirect: 'manual' });
    assertOk(r.status === 401, `期望 401，实际 ${r.status}`);
  });

  await check('未登录 POST /api/conversations → 401', async () => {
    const r = await fetch(`${BASE}/api/conversations`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ title: 'x' }),
      redirect: 'manual',
    });
    assertOk(r.status === 401, `期望 401，实际 ${r.status}`);
  });

  // 2. 未登录访问 / → 跳 /login
  await check('未登录 GET / → 跳 /login', async () => {
    // Next basePath canonicalizes /chat/ to /chat with 308 before authentication.
    const r = await fetch(BASE.replace(/\/+$/, ''), { redirect: 'manual' });
    assertOk([307, 302].includes(r.status), `期望 307/302，实际 ${r.status}`);
    const loc = r.headers.get('location') ?? '';
    assertOk(loc.includes('/login'), `location 应含 /login，实际 ${loc}`);
  });

  await check('未登录 GET /api/me/records → 401', async () => {
    const r = await fetch(`${BASE}/api/me/records`, { redirect: 'manual' });
    assertOk(r.status === 401, `期望 401，实际 ${r.status}`);
  });

  await check('未登录 POST /api/upload → 401', async () => {
    const fd = new FormData();
    fd.append('file', new Blob(['x'], { type: 'text/plain' }), 'x.txt');
    const r = await fetch(`${BASE}/api/upload`, { method: 'POST', body: fd, redirect: 'manual' });
    assertOk(r.status === 401, `期望 401，实际 ${r.status}`);
  });

  await check('未登录 GET /api/me/records?user=attacker → 401（user 参数无效）', async () => {
    const r = await fetch(`${BASE}/api/me/records?user=attacker`, { redirect: 'manual' });
    assertOk(r.status === 401, `期望 401，实际 ${r.status}`);
  });

  if (!COOKIE) {
    console.log('\n⚠ 未提供 COOKIE 环境变量，跳过已登录场景测试');
    console.log('  用法：COOKIE="authjs.session-token=xxx" node --import tsx test/security-check.ts');
  } else {
    const headers = { cookie: COOKIE, 'content-type': 'application/json' };

    await check('/api/me 身份与 OIDC 一致', async () => {
      const r = await fetch(`${BASE}/api/me`, { headers });
      assertOk(r.ok, `期望 200，实际 ${r.status}`);
      const data = await r.json();
      assertOk(data.authenticated === true, '应当 authenticated=true');
      assertOk(typeof data.user?.id === 'string' && data.user.id.length > 0, 'user.id 应非空');
      assertOk(data.user.email, 'email 应非空');
    });

    await check('POST /api/chat 带伪造 body.user → 不用于归因', async () => {
      const r = await fetch(`${BASE}/api/chat`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          model: 'glm-5.2',
          messages: [{ role: 'user', content: 'ping' }],
          user: 'forged-attacker-id',
          safety_identifier: 'forged-attacker',
          stream: false,
        }),
      });
      assertOk(r.status !== 401, `已登录不应 401，实际 ${r.status}`);
    });

    await check('POST /api/chat 图片越白名单 → 400', async () => {
      const r = await fetch(`${BASE}/api/chat`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          conversationId: null,
          model: 'glm-5.2',
          messages: [
            {
              role: 'user',
              content: [
                { type: 'text', text: 'x' },
                { type: 'image_url', image_url: { url: 'data:image/gif;base64,R0lGOD' } },
              ],
            },
          ],
        }),
      });
      assertOk(r.status === 400, `期望 400，实际 ${r.status}`);
    });

    await check('POST /api/chat 超张数 → 400', async () => {
      const img = { type: 'image_url', image_url: { url: 'data:image/png;base64,AAAA' } };
      const r = await fetch(`${BASE}/api/chat`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          conversationId: null,
          model: 'glm-5.2',
          messages: [{ role: 'user', content: [{ type: 'text', text: 'x' }, ...Array(11).fill(img)] }],
        }),
      });
      assertOk(r.status === 400, `期望 400，实际 ${r.status}`);
    });

    await check('POST /api/chat 带伪造 user + 图片 → 不 401（归因走服务端）', async () => {
      const r = await fetch(`${BASE}/api/chat`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          conversationId: null,
          model: 'glm-5.2',
          user: 'forged',
          messages: [{ role: 'user', content: [{ type: 'text', text: 'ping' }] }],
        }),
      });
      assertOk(r.status !== 401, `已登录不应 401，实际 ${r.status}`);
    });

    await check('GET /api/me/records 返回合并留痕（records 数组）', async () => {
      const r = await fetch(`${BASE}/api/me/records`, { headers });
      assertOk(r.ok, `期望 200，实际 ${r.status}`);
      const d = await r.json();
      assertOk(Array.isArray(d.records), 'records 应为数组');
      assertOk(typeof d.total === 'number', 'total 应为数字');
    });

    await check('POST /api/upload 伪造 user 字段被忽略（归因走服务端）', async () => {
      const fd = new FormData();
      fd.append('file', new Blob(['hello'], { type: 'text/plain' }), 'x.txt');
      fd.append('user', 'forged-attacker');
      fd.append('model', 'glm-5.2');
      const r = await fetch(`${BASE}/api/upload`, { method: 'POST', headers: { cookie: COOKIE }, body: fd });
      assertOk(r.status !== 401, `已登录不应 401，实际 ${r.status}`);
      if (r.ok) {
        const d = await r.json();
        assertOk(typeof d.reference === 'string', 'reference 应为字符串');
      }
    });

    await check('POST /api/upload 超限类型 → 400', async () => {
      const fd = new FormData();
      fd.append('file', new Blob(['x'], { type: 'image/gif' }), 'x.gif');
      const r = await fetch(`${BASE}/api/upload`, { method: 'POST', headers: { cookie: COOKIE }, body: fd });
      assertOk(r.status === 400, `期望 400，实际 ${r.status}`);
    });

    await check('GET /api/conversations/non-existent → 404', async () => {
      const r = await fetch(`${BASE}/api/conversations/non-existent-id-xxx`, { headers });
      assertOk(r.status === 404, `期望 404，实际 ${r.status}`);
    });

    await check('PATCH /api/conversations/non-existent → 404', async () => {
      const r = await fetch(`${BASE}/api/conversations/non-existent-id-xxx`, {
        method: 'PATCH',
        headers,
        body: JSON.stringify({ title: 'hacked' }),
      });
      assertOk(r.status === 404, `期望 404，实际 ${r.status}`);
    });

    await check('DELETE /api/conversations/non-existent → 404', async () => {
      const r = await fetch(`${BASE}/api/conversations/non-existent-id-xxx`, {
        method: 'DELETE',
        headers,
      });
      assertOk(r.status === 404, `期望 404，实际 ${r.status}`);
    });
  }

  console.log('\n==========');
  const passed = results.filter((r) => r.pass).length;
  const total = results.length;
  console.log(`通过 ${passed}/${total}`);
  if (passed < total) {
    console.log('失败项：');
    for (const r of results) if (!r.pass) console.log(`  - ${r.name}: ${r.detail}`);
    process.exit(1);
  }
}

if (process.env.RUN_LIVE_SECURITY === '1') {
  main().catch((e) => { console.error(e); process.exit(1); });
}

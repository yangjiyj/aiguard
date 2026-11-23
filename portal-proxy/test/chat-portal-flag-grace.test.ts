import assert from 'node:assert/strict';
import test from 'node:test';
import { __resetChatPortalFlagCache, getChatPortalEnabled } from '../src/gateway-flags.js';

const cfg = { gatewayCpUrl: 'http://control-plane.invalid', portalApiSecret: 'synthetic-internal-token', tenantId: 'tenant-test' };

function withClock(t, start: number) {
  const realNow = Date.now;
  let now = start;
  Date.now = () => now;
  t.after(() => { Date.now = realNow; });
  return (ms: number) => { now += ms; };
}

test('控制面短暂读不到开关时沿用最近一次确定值，不把 Chat 整站关掉', async (t) => {
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; __resetChatPortalFlagCache(); });
  __resetChatPortalFlagCache();
  const advance = withClock(t, 1_000_000);
  globalThis.fetch = (async () => new Response(JSON.stringify({ enabled: true }), { status: 200 })) as typeof fetch;
  assert.equal(await getChatPortalEnabled(cfg), true);

  advance(11_000);
  globalThis.fetch = (async () => new Response('{"error":{"code":"chat_portal_status_unavailable"}}', { status: 503 })) as typeof fetch;
  assert.equal(await getChatPortalEnabled(cfg), true, '宽限期内应沿用确定的 enabled=true');

  advance(5 * 60_000);
  assert.equal(await getChatPortalEnabled(cfg), false, '超过宽限期仍读不到必须 fail-closed');
});

test('管理员关闭门户时立即生效，不受宽限期影响', async (t) => {
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; __resetChatPortalFlagCache(); });
  __resetChatPortalFlagCache();
  const advance = withClock(t, 2_000_000);
  globalThis.fetch = (async () => new Response(JSON.stringify({ enabled: true }), { status: 200 })) as typeof fetch;
  assert.equal(await getChatPortalEnabled(cfg), true);
  advance(11_000);
  globalThis.fetch = (async () => new Response(JSON.stringify({ enabled: false }), { status: 200 })) as typeof fetch;
  assert.equal(await getChatPortalEnabled(cfg), false);
  advance(11_000);
  globalThis.fetch = (async () => { throw new Error('outage'); }) as typeof fetch;
  assert.equal(await getChatPortalEnabled(cfg), false, '最近确定值是关闭，读不到时仍保持关闭');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { checkRateLimit, __resetRateLimit } from '../src/lib/rate-limit.js';

test('rate-limit: 首次请求放行', () => {
  __resetRateLimit();
  const r = checkRateLimit('user-a');
  assert.equal(r.allowed, true);
});

test('rate-limit: 突发上限内连续放行（默认容量 5）', () => {
  __resetRateLimit();
  for (let i = 0; i < 5; i++) {
    const r = checkRateLimit('user-b');
    assert.equal(r.allowed, true, `第 ${i + 1} 次应放行`);
  }
});

test('rate-limit: 超过突发上限 → 拒绝并返回 retry-after', () => {
  __resetRateLimit();
  for (let i = 0; i < 5; i++) checkRateLimit('user-c');
  const r = checkRateLimit('user-c');
  assert.equal(r.allowed, false);
  assert.ok(r.retryAfterSec >= 1, `retryAfterSec 应 >=1，实际 ${r.retryAfterSec}`);
});

test('rate-limit: 不同用户互不影响', () => {
  __resetRateLimit();
  for (let i = 0; i < 5; i++) checkRateLimit('user-d');
  assert.equal(checkRateLimit('user-d').allowed, false);
  assert.equal(checkRateLimit('user-e').allowed, true);
});

test('rate-limit: 时间推进后补充令牌恢复放行', async () => {
  __resetRateLimit();
  for (let i = 0; i < 5; i++) checkRateLimit('user-f');
  assert.equal(checkRateLimit('user-f').allowed, false);
  await new Promise((r) => setTimeout(r, 3100));
  assert.equal(checkRateLimit('user-f').allowed, true);
});

// 按用户令牌桶限流：进程内 Map（单实例够用；多实例换 Redis）。
// 默认：每用户容量 5、每 3 秒补充 1 个令牌（≈ 每分钟 20 次 + 突发 5）。
// 命中限流 → 返回 429，带 Retry-After 头。

interface Bucket {
  tokens: number;
  updatedAt: number;
}

const buckets = new Map<string, Bucket>();

const CAPACITY = Number(process.env.RATE_LIMIT_CAPACITY ?? 5);
const REFILL_INTERVAL_MS = Number(process.env.RATE_LIMIT_REFILL_MS ?? 3000);

export interface RateLimitResult {
  allowed: boolean;
  retryAfterSec: number;
}

export function checkRateLimit(userId: string): RateLimitResult {
  const now = Date.now();
  let b = buckets.get(userId);
  if (!b) {
    b = { tokens: CAPACITY, updatedAt: now };
    buckets.set(userId, b);
  }
  // 补充令牌
  const elapsed = now - b.updatedAt;
  const refilled = Math.floor(elapsed / REFILL_INTERVAL_MS);
  if (refilled > 0) {
    b.tokens = Math.min(CAPACITY, b.tokens + refilled);
    b.updatedAt = b.updatedAt + refilled * REFILL_INTERVAL_MS;
  }
  if (b.tokens >= 1) {
    b.tokens -= 1;
    return { allowed: true, retryAfterSec: 0 };
  }
  // 计算下一个令牌到来的时间
  const retryAfterMs = REFILL_INTERVAL_MS - (now - b.updatedAt);
  return { allowed: false, retryAfterSec: Math.max(1, Math.ceil(retryAfterMs / 1000)) };
}

// 测试/重置用
export function __resetRateLimit(): void {
  buckets.clear();
}

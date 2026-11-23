const TTL_MS = 10_000;
const FETCH_TIMEOUT_MS = 3_000;
// 控制面暂时读不到开关（数据库连接打满、磁盘抖动）时，沿用最近一次“确定读到”的值，
// 超过这个时长仍读不到才 fail-closed。管理员真正关闭门户时，控制面能读到 false，立即生效。
const LAST_KNOWN_GRACE_MS = 5 * 60_000;
let cache = null;
let lastKnown = null;
export async function getChatPortalEnabled(cfg) {
    const now = Date.now();
    if (cache && now - cache.at < TTL_MS)
        return cache.value;
    try {
        const res = await fetch(`${cfg.gatewayCpUrl}/admin/v1/portal-integration/system/chat-portal-status`, {
            headers: {
                'X-NewAPI-Internal-Token': cfg.portalApiSecret,
                'X-NewAPI-Tenant-Id': cfg.tenantId,
            },
            signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        });
        if (!res.ok)
            throw new Error(`chat-portal-status ${res.status}`);
        const body = (await res.json()) as { enabled?: unknown };
        const value = body.enabled === true;
        cache = { value, at: now };
        lastKnown = { value, at: now };
        return value;
    }
    catch {
        // 安全优先：从没读到过、或最近一次确定值已超过宽限期，一律按「未启用」处理。
        // 宽限期内沿用确定值，避免控制面一次抖动就把整个 Chat 门户关掉（客户现场 2026-10-22）。
        const value = lastKnown !== null && now - lastKnown.at < LAST_KNOWN_GRACE_MS ? lastKnown.value : false;
        cache = { value, at: now };
        return value;
    }
}
// 仅供测试重置缓存。
export function __resetChatPortalFlagCache() {
    cache = null;
    lastKnown = null;
}

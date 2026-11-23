const TTL_MS = 10_000;
const FETCH_TIMEOUT_MS = 3_000;
let cache = null;
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
        const body = (await res.json());
        cache = { value: body.enabled === true, at: now };
        return cache.value;
    }
    catch {
        // 安全优先 fail-closed：拉取失败一律按「未启用/不暴露」处理，绝不因控制面抖动而把关闭中的门户暴露出去。
        // 缓存 false 并按 TTL 限流，避免每请求都打控制面；控制面恢复后 TTL 内自动回到真值。
        cache = { value: false, at: now };
        return false;
    }
}
// 仅供测试重置缓存。
export function __resetChatPortalFlagCache() {
    cache = null;
}

// 代理面（A 线）：把 LobeHub 打到 portal-proxy 的 OpenAI 兼容请求转发到安全网关。
// 三个端点（/v1/chat/completions、/v1/responses、/v1/embeddings）复用同一条链路：
//   校验内部 token → body.user 换员工网关 key（见 server.ts settleEmployeeKey）→
//   转发 gateway-core 对应端点 → 响应透传。此处只负责“路由白名单 + 目标 path 参数化的转发内核”，
//   换 key/结算逻辑不在此复制，由 server.ts 统一调用。
//
// 响应处理对三端点一视同仁：forwardStream 是纯字节透传，SSE（responses 可能伪流式）逐帧、
// 普通 JSON（embeddings 非流式）原样，都不缓冲不改写——无需按端点分支。
import { forwardStream, pickForwardHeaders } from './sse.js';
/** 代理面开放的端点白名单（网关虽还支持 /v1/models、/v1/messages，但代理面按需只开这三个）。 */
export const PROXY_PATHS = ['/v1/chat/completions', '/v1/responses', '/v1/embeddings'];
/** 转发网关时声明的客户端类型；网关据此只给门户回复加 AI 生成内容标识。 */
export const PORTAL_AGENT_TYPE = 'enterprise-portal';
/**
 * 路由分发：仅 POST + 命中白名单才返回目标 path，否则 null。
 * 调用方拿到 null 即回 404 route_not_found（非白名单路径 / 非 POST 方法一律不转发）。
 */
export function resolveProxyPath(method, pathname) {
    if (method !== 'POST')
        return null;
    return PROXY_PATHS.includes(pathname) ? pathname : null;
}
/** 网关不可达（fetch 抛错）——在 writeHead 之前抛出，调用方据此安全返回 502。 */
export class GatewayUnreachableError extends Error {
    reason;
    constructor(reason) {
        super('gateway unreachable');
        this.reason = reason;
        this.name = 'GatewayUnreachableError';
    }
}
/**
 * 换好 key 后的统一转发内核：以员工 key 转发到 `${gatewayBaseUrl}${targetPath}`，
 * 响应字节流原样透传给 sink（SSE 逐帧 / JSON 原样，同一实现）。
 * - fetch 本身失败 → 抛 GatewayUnreachableError（此时尚未 writeHead，调用方可发 502 JSON）。
 * - fetch 成功后流中途出错 → 直接向上抛（headers 已发出，交顶层兜底），与既有行为一致。
 */
export async function forwardToGateway(target, sink) {
    const doFetch = target.fetchImpl ?? fetch;
    let upstream;
    try {
        upstream = await doFetch(`${target.gatewayBaseUrl}${target.targetPath}`, {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                accept: target.accept,
                authorization: `Bearer ${target.fullKey}`,
                'x-jjdguard-agent-type': PORTAL_AGENT_TYPE,
            },
            body: JSON.stringify(target.forwardBody),
        });
    }
    catch (e) {
        throw new GatewayUnreachableError(e);
    }
    const securityAction = upstream.headers.get('x-security-action');
    const headers = pickForwardHeaders(upstream.headers);
    sink.writeHead(upstream.status, headers);
    let stats = { chunks: 0, bytes: 0 };
    if (upstream.body) {
        stats = await forwardStream(upstream.body, sink);
    }
    else {
        sink.end();
    }
    return { upstreamStatus: upstream.status, securityAction, headers, stats };
}

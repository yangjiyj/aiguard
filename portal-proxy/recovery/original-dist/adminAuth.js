// 管理后台鉴权（浏览器 → portal-proxy /admin/api/* 这一跳）。
// MVP：单一共享令牌 env PORTAL_ADMIN_TOKEN，请求头 X-Portal-Admin-Token 明文携带。
// constant-time：对双方 SHA-256 摘要做 timingSafeEqual，长度差异不泄露时序信息；
// 期望令牌为空（未配置）时一律拒绝——绝不因缺配置变裸奔。
import { createHash, timingSafeEqual } from 'node:crypto';
export function checkAdminToken(presented, expectedToken) {
    if (!expectedToken)
        return false; // 未配置 PORTAL_ADMIN_TOKEN → 后台整体锁死
    if (!presented)
        return false;
    const a = createHash('sha256').update(presented, 'utf8').digest();
    const b = createHash('sha256').update(expectedToken, 'utf8').digest();
    return timingSafeEqual(a, b);
}

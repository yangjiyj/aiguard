// 内部服务 token 校验（LobeHub → portal-proxy 这一跳）。
// constant-time：对双方 SHA-256 摘要做 timingSafeEqual，长度差异不泄露时序信息。
import { createHash, timingSafeEqual } from 'node:crypto';
export function checkInternalToken(authorizationHeader, expectedToken) {
    if (!expectedToken)
        return false; // 配置缺失时绝不放行
    if (!authorizationHeader)
        return false;
    const match = /^Bearer\s+(\S+)$/.exec(authorizationHeader);
    if (!match)
        return false;
    const presented = createHash('sha256').update(match[1], 'utf8').digest();
    const expected = createHash('sha256').update(expectedToken, 'utf8').digest();
    return timingSafeEqual(presented, expected);
}

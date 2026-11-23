// 从 IdP 落库的 id_token（原始 JWT，LobeHub accounts.id_token）里解出 department 声明。
// W9 9.6：旧实现只做 base64 解码不验签，任何能写这一列的人都能伪造部门、换到别的网关 project。
// 现要求签名能被 IdP JWKS 验证、iss 与配置一致；不校验 exp/aud——该列是历史登录时落库的
// 旧 token（aud 是 LobeHub 的 client），只用来读部门，不作为登录凭据。
// 语义：
// - 无 token → null（合法的「无部门」，走 default 组）；
// - 有 token 但结构非法 / 验签失败 / iss 不符 → 抛 DepartmentTokenError，
//   由调用方按「查询失败」处理（保守续用旧 key，绝不按伪造部门换组）；
// - 未配置 JWKS → 抛 DepartmentTokenError（不再信任未验签内容）。
import { compactVerify } from 'jose';
export class DepartmentTokenError extends Error {
    constructor(message) {
        super(message);
        this.name = 'DepartmentTokenError';
    }
}
export async function verifyDepartment(idToken, opts) {
    if (typeof idToken !== 'string' || idToken.length === 0)
        return null;
    if (!opts || !opts.keySet || !opts.issuer)
        throw new DepartmentTokenError('未配置 IdP JWKS，拒绝使用未验签的部门声明');
    let payloadBytes;
    try {
        ({ payload: payloadBytes } = await compactVerify(idToken, opts.keySet));
    }
    catch (e) {
        throw new DepartmentTokenError(`部门 token 验签失败：${e instanceof Error ? e.message : String(e)}`);
    }
    let payload;
    try {
        payload = JSON.parse(Buffer.from(payloadBytes).toString('utf8'));
    }
    catch {
        throw new DepartmentTokenError('部门 token payload 不是合法 JSON');
    }
    if (!payload || typeof payload !== 'object' || payload.iss !== opts.issuer) {
        throw new DepartmentTokenError('部门 token issuer 不符');
    }
    const dept = payload.department;
    return typeof dept === 'string' && dept.length > 0 ? dept : null;
}

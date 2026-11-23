// 直接身份模式（A2 替换 LobeHub 后的唯一归因路径）。
// 新门户后端在 POST /v1/chat/completions 这一跳注入这三个请求头（浏览器永远无法设置），
// portal-proxy 据此跳过 LobeHub PG 库查询，直接用 OIDC 会话身份做 JIT 归因。
// 安全铁律：这三个头只在 portal-proxy 入口被读取，且仅当内部 token（PORTAL_INTERNAL_TOKEN）
// 校验通过后才生效——也就是说只有「持有内部令牌的可信服务」注入的身份才可信。
//
// 兼容性：旧 LobeHub 链路（body.user 模式）已废弃但代码保留；新门户必须走直接身份模式。
// 字段语义：lobeUserId 列实际存的是 OIDC sub（归因主键），向后兼容 schema 不改列名。
const H_SUBJECT = 'x-portal-direct-sso-subject';
const H_EMAIL = 'x-portal-direct-email';
const H_DEPARTMENT = 'x-portal-direct-department';
/**
 * 从请求头解出直接身份。三头都缺失 → 返回 null（调用方据此判定非直接身份模式）。
 * 部分头缺失（有 subject 但无 email）→ 视为非法直接身份，返回 null 并交调用方拒绝。
 * 严格语义：要么三头齐（subject+email 必填，department 可空字符串），要么都无。
 */
export function parseDirectIdentity(headers) {
    const subject = singleHeader(typeof headers.get === 'function' ? headers.get(H_SUBJECT) : headers[H_SUBJECT]);
    const email = singleHeader(typeof headers.get === 'function' ? headers.get(H_EMAIL) : headers[H_EMAIL]);
    if (!subject && !email)
        return null; // 非直接身份模式
    // 有任一头则要求 subject + email 都在；否则视为非法，拒绝
    if (!subject || !email) {
        return null;
    }
    const deptRaw = singleHeader(typeof headers.get === 'function' ? headers.get(H_DEPARTMENT) : headers[H_DEPARTMENT]);
    return {
        ssoSubject: subject,
        email,
        department: typeof deptRaw === 'string' && deptRaw.trim() !== '' ? deptRaw.trim() : null,
    };
}
function singleHeader(v) {
    if (v === undefined)
        return null;
    return Array.isArray(v) ? (v[0] ?? null) : v;
}

// 直接身份模式（A2 替换 LobeHub 后的唯一归因路径）。
// 新门户后端在 POST /v1/chat/completions 这一跳注入这些请求头（浏览器永远无法设置），
// portal-proxy 据此跳过 LobeHub PG 库查询，直接用 OIDC 会话身份做 JIT 归因。
// 安全铁律：这三个头只在 portal-proxy 入口被读取，且仅当内部 token（PORTAL_INTERNAL_TOKEN）
// 校验通过后才生效——也就是说只有「持有内部令牌的可信服务」注入的身份才可信。
//
// 兼容性：旧 LobeHub 链路（body.user 模式）已废弃但代码保留；新门户必须走直接身份模式。
// 字段语义：lobeUserId 列实际存的是 OIDC sub（归因主键），向后兼容 schema 不改列名。
const H_SUBJECT = 'x-portal-direct-sso-subject';
const H_EMAIL = 'x-portal-direct-email';
const H_DEPARTMENT = 'x-portal-direct-department';
const H_GATEWAY_USER_ID = 'x-portal-direct-gateway-user-id';
export type DirectIdentity = {
    ssoSubject: string;
    email: string;
    department: string | null;
    gatewayUserId: string | null;
    localLogin?: boolean;
    localCredentialVersion?: number;
};
/** Only the authenticated internal caller may supply this identity.
 * Local accounts have no required email: the stable gateway user binding is
 * sufficient. Legacy callers still need email when no binding is supplied.
 */
export function parseDirectIdentity(headers: any): DirectIdentity | null {
    const loginMode = singleHeader(typeof headers.get === 'function' ? headers.get('x-portal-direct-login-mode') : headers['x-portal-direct-login-mode']);
    if (loginMode !== null && loginMode !== 'local' && loginMode !== 'oidc') return null;
    const subject = singleHeader(typeof headers.get === 'function' ? headers.get(H_SUBJECT) : headers[H_SUBJECT]);
    const email = singleHeader(typeof headers.get === 'function' ? headers.get(H_EMAIL) : headers[H_EMAIL]);
    const gatewayUserIdRaw = singleHeader(typeof headers.get === 'function' ? headers.get(H_GATEWAY_USER_ID) : headers[H_GATEWAY_USER_ID]);
    const versionRaw=singleHeader(typeof headers.get === 'function' ? headers.get('x-portal-direct-local-credential-version') : headers['x-portal-direct-local-credential-version']);
    const localCredentialVersion=versionRaw&&/^[1-9][0-9]*$/.test(versionRaw)?Number(versionRaw):0;
    if(loginMode==='local'&&(!Number.isSafeInteger(localCredentialVersion)||localCredentialVersion<=0))return null;
    if (loginMode === 'local' && !gatewayUserIdRaw?.trim()) return null;
    if (!subject?.trim() || (!email?.trim() && !gatewayUserIdRaw?.trim())) {
        return null;
    }
    const deptRaw = singleHeader(typeof headers.get === 'function' ? headers.get(H_DEPARTMENT) : headers[H_DEPARTMENT]);
    return {
        ssoSubject: subject,
        ...(loginMode === 'local' ? {localLogin: true,localCredentialVersion} : {}),
        email: email ?? '',
        department: typeof deptRaw === 'string' && deptRaw.trim() !== '' ? deptRaw.trim() : null,
        gatewayUserId: typeof gatewayUserIdRaw === 'string' && gatewayUserIdRaw.trim() !== '' ? gatewayUserIdRaw.trim() : null,
    };
}
function singleHeader(v: string | string[] | null | undefined): string | null {
    if (v === undefined)
        return null;
    return Array.isArray(v) ? (v[0] ?? null) : v;
}

/** Resolve the department project through the gateway, never legacy group rules. */
export async function resolveDirectAssignment(
    direct: DirectIdentity | null,
    resolveUser: () => Promise<{ userId: string; projectId: string; departmentId: string; chatAllowed: boolean }>,
): Promise<{ mappedGroup: string; gatewayProjectId: string } | null> {
    if (!direct?.gatewayUserId) return null;
    const user = await resolveUser();
    if (user.userId !== direct.gatewayUserId || !user.projectId?.trim() || !user.chatAllowed) {
        throw new Error('gateway identity project is not ready');
    }
    return { mappedGroup: user.departmentId || 'default', gatewayProjectId: user.projectId };
}

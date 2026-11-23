// 门户后台独立 OIDC 会话（Phase 3 Track D）——授权码流 + PKCE + JWKS 校验（jose）。
// 无 server session store：id_token 直接存 HttpOnly cookie，每请求 jose 校验（JWKS 缓存）。
// 与 LobeHub 登录同 IdP、不同 client（chat-portal-admin），chat 主链一行不动。
import { createHash, randomBytes } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { extractRoleClaim } from './roles.js';
export class OidcError extends Error {
    constructor(message) {
        super(message);
        this.name = 'OidcError';
    }
}
function base64url(buf) {
    return buf.toString('base64url');
}
/** CSRF state：随机不可猜。 */
export function generateState() {
    return base64url(randomBytes(32));
}
/** PKCE：verifier 随机高熵；challenge = base64url(SHA-256(verifier))。 */
export function generatePkce() {
    const verifier = base64url(randomBytes(48));
    const challenge = base64url(createHash('sha256').update(verifier).digest());
    return { verifier, challenge };
}
/** 构造 Keycloak authorize 重定向 URL（response_type=code + PKCE S256 + state）。 */
export function buildAuthorizeUrl(cfg, input) {
    const u = new URL(cfg.authorizeUrl);
    u.searchParams.set('response_type', 'code');
    u.searchParams.set('client_id', cfg.clientId);
    u.searchParams.set('redirect_uri', cfg.redirectUri);
    u.searchParams.set('scope', cfg.scope || 'openid email profile');
    u.searchParams.set('state', input.state);
    u.searchParams.set('code_challenge', input.codeChallenge);
    u.searchParams.set('code_challenge_method', 'S256');
    return u.toString();
}
/** 用授权码换 token（fetch Keycloak token endpoint，带 client_secret + code_verifier）。返回 id_token。 */
export async function exchangeCode(cfg, input, fetchImpl = fetch) {
    const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code: input.code,
        redirect_uri: cfg.redirectUri,
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
        code_verifier: input.codeVerifier,
    });
    let res;
    try {
        res = await fetchImpl(cfg.tokenUrl, {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
            body: body.toString(),
        });
    }
    catch (e) {
        throw new OidcError(`token endpoint 不可达：${e instanceof Error ? e.message : String(e)}`);
    }
    const text = await res.text();
    if (!res.ok) {
        // 错误文本可能含 IdP 内部信息但不含长期凭据，截断后可安全上抛
        throw new OidcError(`token endpoint ${res.status}: ${text.slice(0, 300)}`);
    }
    let parsed;
    try {
        parsed = JSON.parse(text);
    }
    catch {
        throw new OidcError('token 响应不是合法 JSON');
    }
    if (typeof parsed.id_token !== 'string' || parsed.id_token === '') {
        throw new OidcError('token 响应缺少 id_token');
    }
    return { idToken: parsed.id_token, accessToken: typeof parsed.access_token === 'string' ? parsed.access_token : null };
}
function claimsFromPayload(payload) {
    const rec = payload;
    const sub = typeof payload.sub === 'string' ? payload.sub : '';
    const email = typeof rec.email === 'string' && rec.email !== '' ? rec.email : null;
    const department = typeof rec.department === 'string' && rec.department !== '' ? rec.department : null;
    return { sub, email, department, roleClaim: extractRoleClaim(rec), raw: payload };
}
/**
 * 校验 id_token（jose，JWKS）：签名 + issuer + audience(=clientId) + 过期。
 * keySet 由调用方注入（生产＝createRemoteJWKSet 缓存；测试＝createLocalJWKSet 本地公钥）。
 */
export async function verifyIdToken(idToken, opts) {
    const { payload } = await jwtVerify(idToken, opts.keySet, { issuer: opts.issuer, audience: opts.audience });
    const claims = claimsFromPayload(payload);
    if (!claims.sub)
        throw new OidcError('id_token 缺少 sub');
    return claims;
}
/**
 * 生产用校验器：懒建并缓存 remote JWKS（Keycloak certs 端点），据 issuer/clientId 校验。
 * 校验失败（签名/过期/issuer/aud 不符或无 cookie）由调用方 catch → 视作未认证（401）。
 */
export class OidcVerifier {
    cfg;
    jwks = null;
    constructor(cfg) {
        this.cfg = cfg;
    }
    keySet() {
        if (!this.jwks)
            this.jwks = createRemoteJWKSet(new URL(this.cfg.jwksUri));
        return this.jwks;
    }
    async verify(idToken) {
        return verifyIdToken(idToken, { keySet: this.keySet(), issuer: this.cfg.issuer, audience: this.cfg.clientId });
    }
}

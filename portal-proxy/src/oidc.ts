// 门户后台独立 OIDC 登录（Phase 3 Track D）——授权码流 + PKCE + nonce + JWKS 校验（jose）。
// W9 9.6：id_token 只在回调时校验一次（含 nonce 绑定），随后换成服务端可撤销会话（见 session.ts），
// 浏览器不再持有 id_token；角色只以 EmployeeRole 表为准，不读取 token 里的任何 role 声明。
// 与 LobeHub 登录同 IdP、不同 client（chat-portal-admin），chat 主链一行不动。
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
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
/** OIDC nonce：随机不可猜，绑定本次授权事务，防 id_token 重放/注入。 */
export function generateNonce() {
    return base64url(randomBytes(32));
}
/** PKCE：verifier 随机高熵；challenge = base64url(SHA-256(verifier))。 */
export function generatePkce() {
    const verifier = base64url(randomBytes(48));
    const challenge = base64url(createHash('sha256').update(verifier).digest());
    return { verifier, challenge };
}
/** 构造 Keycloak authorize 重定向 URL（response_type=code + PKCE S256 + state + nonce）。 */
export function buildAuthorizeUrl(cfg, input) {
    if (typeof input.nonce !== 'string' || input.nonce === '') {
        throw new OidcError('authorize 请求缺少 nonce');
    }
    const u = new URL(cfg.authorizeUrl);
    u.searchParams.set('response_type', 'code');
    u.searchParams.set('client_id', cfg.clientId);
    u.searchParams.set('redirect_uri', cfg.redirectUri);
    u.searchParams.set('scope', cfg.scope || 'openid email profile');
    u.searchParams.set('state', input.state);
    u.searchParams.set('nonce', input.nonce);
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
    // sid：IdP 会话标识，供 back-channel logout 按 IdP 会话撤销（W9 9.7）。
    const sid = typeof rec.sid === 'string' && rec.sid !== '' ? rec.sid : null;
    const exp = typeof payload.exp === 'number' ? payload.exp : null;
    return { sub, email, department, sid, exp, raw: payload };
}
function sameString(a, b) {
    const x = Buffer.from(a, 'utf8');
    const y = Buffer.from(b, 'utf8');
    return x.length === y.length && timingSafeEqual(x, y);
}
/**
 * 校验 id_token（jose，JWKS）：签名 + issuer + audience(=clientId) + 过期；
 * 传入 opts.nonce 时 payload.nonce 必须逐字相等（回调路径必传）。
 * keySet 由调用方注入（生产＝createRemoteJWKSet 缓存；测试＝createLocalJWKSet 本地公钥）。
 */
export async function verifyIdToken(idToken, opts) {
    const { payload } = await jwtVerify(idToken, opts.keySet, { issuer: opts.issuer, audience: opts.audience });
    if (opts.nonce !== undefined) {
        const got = payload.nonce;
        if (typeof opts.nonce !== 'string' || opts.nonce === '' || typeof got !== 'string' || !sameString(got, opts.nonce)) {
            throw new OidcError('id_token nonce 不匹配');
        }
    }
    const claims = claimsFromPayload(payload);
    if (!claims.sub)
        throw new OidcError('id_token 缺少 sub');
    return claims;
}
/**
 * 生产用校验器：懒建并缓存 remote JWKS（Keycloak certs 端点），据 issuer/clientId 校验。
 * 校验失败（签名/过期/issuer/aud/nonce 不符）由调用方 catch → 拒绝登录。
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
    async verify(idToken, opts: { nonce?: string } = {}) {
        return verifyIdToken(idToken, { keySet: this.keySet(), issuer: this.cfg.issuer, audience: this.cfg.clientId, nonce: opts.nonce });
    }
    /** W9 9.7：校验 IdP 推送的 back-channel logout_token。 */
    async verifyLogout(logoutToken) {
        return verifyLogoutToken(logoutToken, { keySet: this.keySet(), issuer: this.cfg.issuer, audience: this.cfg.clientId });
    }
}
// ===== W9 9.7：OIDC Back-Channel Logout 1.0 的 logout_token 校验 =====
export const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';
/** logout_token 只接受非对称签名；对称算法意味着任何持有 client_secret 的一方都能伪造登出。 */
const LOGOUT_TOKEN_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'];
/** iat 距今上限（秒）：IdP 推送是即时的，旧 token 不接受。 */
export const LOGOUT_TOKEN_MAX_AGE_SEC = 300;
/**
 * 按规范第 2.6 节校验 logout_token：签名 + iss + aud + iat 新鲜度；必须含 jti 与 backchannel-logout 事件；
 * 必须含 sub 或 sid；禁止含 nonce（防把 id_token 当 logout_token 用）。返回 { sub, sid, jti, exp }。
 */
export async function verifyLogoutToken(token, opts) {
    if (typeof token !== 'string' || token === '' || token.length > 16 * 1024)
        throw new OidcError('logout_token 缺失或过长');
    let payload;
    let header;
    try {
        ({ payload, protectedHeader: header } = await jwtVerify(token, opts.keySet, {
            issuer: opts.issuer,
            audience: opts.audience,
            algorithms: LOGOUT_TOKEN_ALGS,
            maxTokenAge: opts.maxAgeSec ?? LOGOUT_TOKEN_MAX_AGE_SEC,
            currentDate: opts.now ? opts.now() : undefined,
        }));
    }
    catch (e) {
        throw new OidcError(`logout_token 校验失败：${e instanceof Error ? e.message : String(e)}`);
    }
    const typ = typeof header.typ === 'string' ? header.typ.toLowerCase() : '';
    if (typ !== '' && typ !== 'jwt' && typ !== 'logout+jwt' && typ !== 'application/logout+jwt')
        throw new OidcError('logout_token typ 非法');
    const rec = payload;
    if (rec.nonce !== undefined)
        throw new OidcError('logout_token 不得包含 nonce');
    const events = rec.events;
    if (!events || typeof events !== 'object' || Array.isArray(events) ||
        !events[BACKCHANNEL_LOGOUT_EVENT] || typeof events[BACKCHANNEL_LOGOUT_EVENT] !== 'object') {
        throw new OidcError('logout_token 缺少 back-channel logout 事件');
    }
    const jti = typeof payload.jti === 'string' && payload.jti !== '' ? payload.jti : '';
    if (!jti)
        throw new OidcError('logout_token 缺少 jti');
    const sub = typeof payload.sub === 'string' && payload.sub !== '' ? payload.sub : null;
    const sid = typeof rec.sid === 'string' && rec.sid !== '' ? rec.sid : null;
    if (!sub && !sid)
        throw new OidcError('logout_token 必须包含 sub 或 sid');
    const exp = typeof payload.exp === 'number' ? payload.exp : null;
    return { sub, sid, jti, exp, iat: payload.iat };
}

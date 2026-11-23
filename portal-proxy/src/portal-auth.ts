// 门户后台 OIDC 登录 / 会话 / 鉴权（W9 9.6，从 server.ts 抽出以便注入依赖做端到端测试）。
// 流程：
//   /portal/auth/login    生成 state + PKCE + nonce（短时 HttpOnly cookie）→ 302 authorize
//   /portal/auth/callback 校 state → code 换 token → 校 id_token（签名/iss/aud/exp/nonce）
//                         → 服务端签发会话（不透明 ID）→ cookie 只放会话 ID
//   /portal/auth/logout   撤销服务端会话 + 清 cookie（被窃取的 cookie 随之失效）
//   authenticate(req)     会话 ID → 有效会话 → 角色只查 EmployeeRole 表
import { parseCookies, serializeCookie, clearCookie } from './cookies.js';
import { buildAuthorizeUrl, exchangeCode, generateNonce, generatePkce, generateState } from './oidc.js';
import { resolveRole } from './roles.js';
import { SESSION_COOKIE } from './session.js';
export const LEGACY_ID_COOKIE = 'portal_id_token';
export const COOKIE_STATE = 'portal_oidc_state';
export const COOKIE_VERIFIER = 'portal_oidc_verifier';
export const COOKIE_NONCE = 'portal_oidc_nonce';
export const OIDC_TX_TTL = 600; // state/PKCE/nonce 短时 cookie 10 分钟
export const AUTH_COOKIE_PATH = '/portal/auth';
function sendJson(res, status, obj, extraHeaders = {}) {
    if (!res.headersSent)
        res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extraHeaders });
    res.end(JSON.stringify(obj));
}
/**
 * deps：
 *  oidc            OIDC 配置（null＝未启用，仅 break-glass）
 *  verifier        { verify(idToken, { nonce }) }
 *  sessions        SessionStore
 *  roleStore       { findBySubject(sub) }
 *  checkBreakGlass (presentedHeader) => boolean
 *  cookieSecure    boolean
 *  postLoginPath   登录后落地路径
 *  exchange        可选，测试注入换 token 实现（默认 exchangeCode）
 *  log             (level, msg, meta) => void
 */
export function createPortalAuth(deps) {
    const log = deps.log ?? (() => { });
    const exchange = deps.exchange ?? ((cfg, input) => exchangeCode(cfg, input));
    const txOpts = () => ({ httpOnly: true, secure: deps.cookieSecure, sameSite: 'Lax', path: AUTH_COOKIE_PATH, maxAge: OIDC_TX_TTL });
    const clearTx = () => [
        clearCookie(COOKIE_STATE, AUTH_COOKIE_PATH),
        clearCookie(COOKIE_VERIFIER, AUTH_COOKIE_PATH),
        clearCookie(COOKIE_NONCE, AUTH_COOKIE_PATH),
    ];
    function login(res) {
        if (!deps.oidc) {
            sendJson(res, 503, { error: { code: 'oidc_disabled', message: '门户 OIDC 未配置，请使用应急管理令牌登录' } });
            return;
        }
        const state = generateState();
        const nonce = generateNonce();
        const { verifier, challenge } = generatePkce();
        const url = buildAuthorizeUrl(deps.oidc, { state, nonce, codeChallenge: challenge });
        const opts = txOpts();
        res.writeHead(302, {
            location: url,
            'set-cookie': [
                serializeCookie(COOKIE_STATE, state, opts),
                serializeCookie(COOKIE_VERIFIER, verifier, opts),
                serializeCookie(COOKIE_NONCE, nonce, opts),
            ],
            'cache-control': 'no-store',
        });
        res.end();
    }
    async function callback(req, res, url) {
        if (!deps.oidc || !deps.verifier) {
            sendJson(res, 503, { error: { code: 'oidc_disabled', message: '门户 OIDC 未配置' } });
            return;
        }
        const redirectErr = (reason) => {
            log('warn', 'oidc_callback_rejected', { reason });
            res.writeHead(302, { location: `${deps.postLoginPath}?auth_error=${encodeURIComponent(reason)}`, 'set-cookie': clearTx(), 'cache-control': 'no-store' });
            res.end();
        };
        const idpError = url.searchParams.get('error');
        if (idpError)
            return redirectErr(idpError);
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        const cookies = parseCookies(req.headers.cookie);
        const expectState = cookies[COOKIE_STATE];
        const verifier = cookies[COOKIE_VERIFIER];
        const nonce = cookies[COOKIE_NONCE];
        // state 必须与 cookie 一致（CSRF）；缺 code/verifier/nonce 一律拒
        if (!code || !state || !expectState || state !== expectState || !verifier || !nonce) {
            return redirectErr('state_mismatch');
        }
        let claims;
        try {
            const tok = await exchange(deps.oidc, { code, codeVerifier: verifier });
            claims = await deps.verifier.verify(tok.idToken, { nonce });
        }
        catch (e) {
            log('warn', 'oidc_token_exchange_failed', { err: e instanceof Error ? e.message : String(e) });
            return redirectErr('token_exchange_failed');
        }
        let session;
        try {
            session = await deps.sessions.create({ sub: claims.sub, email: claims.email, department: claims.department, sid: claims.sid, exp: claims.exp });
        }
        catch (e) {
            log('error', 'portal_session_create_failed', { err: e instanceof Error ? e.message : String(e) });
            return redirectErr('session_create_failed');
        }
        res.writeHead(302, {
            location: deps.postLoginPath,
            'set-cookie': [
                serializeCookie(SESSION_COOKIE, session.id, { httpOnly: true, secure: deps.cookieSecure, sameSite: 'Lax', path: '/', maxAge: session.maxAgeSec }),
                clearCookie(LEGACY_ID_COOKIE, '/'),
                ...clearTx(),
            ],
            'cache-control': 'no-store',
        });
        res.end();
    }
    async function logout(req, res) {
        const sid = parseCookies(req.headers.cookie)[SESSION_COOKIE];
        if (sid) {
            try {
                await deps.sessions.revoke(sid);
            }
            catch (e) {
                // 撤销失败不能假装成功：返回 500，让前端提示重试
                log('error', 'portal_session_revoke_failed', { err: e instanceof Error ? e.message : String(e) });
                sendJson(res, 500, { error: { code: 'logout_failed', message: '会话撤销失败，请重试' } });
                return;
            }
        }
        sendJson(res, 200, { ok: true }, { 'set-cookie': [clearCookie(SESSION_COOKIE, '/'), clearCookie(LEGACY_ID_COOKIE, '/')] });
    }
    /**
     * 身份三态：
     * (a) 有效服务端会话 → 角色只查 EmployeeRole 表（无记录 employee）+ 会话里的 department；
     * (b) X-Portal-Admin-Token 有效 → break-glass 超管；
     * (c) 都无 → null（调用方 401）。
     * 旧 portal_id_token cookie 一律不再认（升级后需重新登录一次）。
     */
    async function authenticate(req) {
        if (deps.oidc) {
            const sid = parseCookies(req.headers.cookie)[SESSION_COOKIE];
            if (sid) {
                const s = await deps.sessions.resolve(sid);
                if (s) {
                    const assignment = await deps.roleStore.findBySubject(s.subject);
                    return {
                        kind: 'oidc',
                        role: resolveRole(assignment?.role ?? null),
                        sub: s.subject,
                        email: s.email ?? undefined,
                        department: s.department,
                        managedDepartments: assignment?.managedDepartments ?? [],
                    };
                }
                log('info', 'portal_session_invalid', {});
            }
        }
        const hdr = req.headers['x-portal-admin-token'];
        const presented = Array.isArray(hdr) ? hdr[0] : hdr;
        if (deps.checkBreakGlass(presented))
            return { kind: 'breakglass', role: 'admin' };
        return null;
    }
    return { login, callback, logout, authenticate };
}

// OIDC Back-Channel Logout 接收端（W9 9.7）。
// IdP（Keycloak）在用户于 IdP 侧登出、管理员强制下线、会话过期时，直接 POST logout_token 到本端点；
// 本端点校验后按 sid（优先）或 sub 撤销门户后台服务端会话，已发出的会话 cookie 立即失效。
// 约束：
// - 只接受 POST application/x-www-form-urlencoded，body ≤ 16KB；
// - logout_token 由 OidcVerifier.verifyLogout 校验（签名/iss/aud/iat/事件/jti/无 nonce）；
// - jti 在 token 有效窗口内只接受一次（进程内缓存；多副本时由各副本独立判重，撤销本身是幂等的）；
// - 响应不带任何会话/用户信息；日志只记撤销条数，不记 token。
import { OidcError, LOGOUT_TOKEN_MAX_AGE_SEC } from './oidc.js';
export const BACKCHANNEL_LOGOUT_PATH = '/portal/auth/backchannel-logout';
export const MAX_LOGOUT_BODY_BYTES = 16 * 1024;
const MAX_SEEN_JTI = 10000;
function reply(res, status, obj) {
    if (!res.headersSent)
        res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    res.end(obj === undefined ? '' : JSON.stringify(obj));
}
class BodyTooLargeError extends Error {
}
function readLimitedBody(req, limit) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        let done = false;
        req.on('data', (chunk) => {
            if (done)
                return;
            size += chunk.length;
            if (size > limit) {
                done = true;
                reject(new BodyTooLargeError());
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => {
            if (!done) {
                done = true;
                resolve(Buffer.concat(chunks).toString('utf8'));
            }
        });
        req.on('error', (e) => {
            if (!done) {
                done = true;
                reject(e);
            }
        });
    });
}
/**
 * deps：
 *  verifier  { verifyLogout(token) } ；null＝门户 OIDC 未启用
 *  sessions  SessionStore（revokeIdpSession / revokeSubject）
 *  log       (level, msg, meta) => void
 *  now       可选，测试注入时钟
 */
export function createBackchannelLogout(deps) {
    const log = deps.log ?? (() => { });
    const now = deps.now ?? (() => new Date());
    const seen = new Map(); // jti → 过期毫秒
    function sweep(nowMs) {
        for (const [k, until] of seen) {
            if (until <= nowMs)
                seen.delete(k);
        }
    }
    async function handle(req, res) {
        if (req.method !== 'POST') {
            req.resume?.();
            res.writeHead(405, { allow: 'POST', 'cache-control': 'no-store' });
            res.end();
            return;
        }
        if (!deps.verifier || typeof deps.verifier.verifyLogout !== 'function') {
            req.resume?.();
            reply(res, 501, { error: 'backchannel_logout_unsupported' });
            return;
        }
        const ctype = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
        if (ctype !== 'application/x-www-form-urlencoded') {
            req.resume?.();
            reply(res, 400, { error: 'invalid_request' });
            return;
        }
        let body;
        try {
            body = await readLimitedBody(req, MAX_LOGOUT_BODY_BYTES);
        }
        catch (e) {
            reply(res, e instanceof BodyTooLargeError ? 413 : 400, { error: 'invalid_request' });
            return;
        }
        const params = new URLSearchParams(body);
        const tokens = params.getAll('logout_token');
        if (tokens.length !== 1) {
            reply(res, 400, { error: 'invalid_request' });
            return;
        }
        let claims;
        try {
            claims = await deps.verifier.verifyLogout(tokens[0]);
        }
        catch (e) {
            log('warn', 'backchannel_logout_rejected', { reason: e instanceof OidcError ? e.message : 'verify_error' });
            reply(res, 400, { error: 'invalid_request' });
            return;
        }
        const nowMs = now().getTime();
        if (seen.size >= MAX_SEEN_JTI)
            sweep(nowMs);
        const until = seen.get(claims.jti);
        if (until !== undefined && until > nowMs) {
            log('warn', 'backchannel_logout_replayed', {});
            reply(res, 400, { error: 'invalid_request' });
            return;
        }
        let revoked;
        try {
            revoked = claims.sid
                ? await deps.sessions.revokeIdpSession(claims.sid, claims.sub ?? undefined)
                : await deps.sessions.revokeSubject(claims.sub);
        }
        catch (e) {
            // 撤销失败不记 jti：IdP 重试时可再次处理
            log('error', 'backchannel_logout_revoke_failed', { err: e instanceof Error ? e.message : String(e) });
            reply(res, 500, { error: 'server_error' });
            return;
        }
        const expMs = typeof claims.exp === 'number' ? claims.exp * 1000 : nowMs + LOGOUT_TOKEN_MAX_AGE_SEC * 1000;
        if (seen.size < MAX_SEEN_JTI)
            seen.set(claims.jti, Math.max(expMs, nowMs + LOGOUT_TOKEN_MAX_AGE_SEC * 1000));
        log('info', 'backchannel_logout_applied', { revoked, by: claims.sid ? 'sid' : 'sub' });
        reply(res, 200, undefined);
    }
    return { handle };
}

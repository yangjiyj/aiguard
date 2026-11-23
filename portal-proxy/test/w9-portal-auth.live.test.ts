// W9 9.6 live：对真实 Keycloak 跑授权码 + PKCE + nonce 全流程（需 PORTAL_LIVE_KC_URL，未设置则跳过）。
// 前置（由 w9 kc_live.sh 准备）：realm jjdguard 导入生产模板；用户 alice/Alice-pass-123；
// chat-portal-admin 上加了硬编码 role=admin 声明 mapper（模拟客户误配 / 上游透传）。
import assert from 'node:assert/strict';
import test from 'node:test';
import { createRemoteJWKSet, decodeJwt } from 'jose';

import { OidcVerifier } from '../src/oidc.js';
import { verifyDepartment } from '../src/idtoken.js';
import { MemorySessionBackend, SESSION_COOKIE, SessionStore } from '../src/session.js';
import { COOKIE_NONCE, COOKIE_STATE, COOKIE_VERIFIER, createPortalAuth } from '../src/portal-auth.js';

const KC = process.env.PORTAL_LIVE_KC_URL;
const skip = !KC ? 'PORTAL_LIVE_KC_URL 未设置' : false;

function fakeRes() {
  const res = { status: 0, headers: {} as Record<string, unknown>, body: '', headersSent: false,
    writeHead(s, h = {}) { res.status = s; res.headers = h; res.headersSent = true; },
    end(b = '') { res.body = b; } };
  return res;
}
function cookieOf(res, name) {
  const raw = res.headers['set-cookie'];
  for (const c of (Array.isArray(raw) ? raw : [raw])) {
    if (typeof c !== 'string') continue;
    const pair = c.split(';')[0];
    const i = pair.indexOf('=');
    if (pair.slice(0, i) === name) return decodeURIComponent(pair.slice(i + 1));
  }
  return undefined;
}

/** 以 alice 身份在 Keycloak 登录页提交表单，返回回调 URL（含 code/state）。 */
async function browserLogin(authorizeUrl) {
  const jar = new Map();
  const keep = (r) => {
    for (const c of r.headers.getSetCookie()) {
      const pair = c.split(';')[0];
      const i = pair.indexOf('=');
      jar.set(pair.slice(0, i), pair.slice(i + 1));
    }
  };
  const cookieHdr = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  const page = await fetch(authorizeUrl, { redirect: 'manual' });
  keep(page);
  const html = await page.text();
  const m = html.match(/action="([^"]+)"/);
  assert.ok(m, `未找到登录表单：HTTP ${page.status} location=${page.headers.get('location')}`);
  const action = m[1].replace(/&amp;/g, '&');
  const post = await fetch(action, {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHdr() },
    body: new URLSearchParams({ username: 'alice', password: 'Alice-pass-123', credentialId: '' }).toString(),
  });
  assert.equal(post.status, 302, `登录提交应 302：${post.status}`);
  return new URL(post.headers.get('location'));
}

test('live Keycloak：nonce 绑定 + 服务端会话 + 角色以表为准 + 部门验签', { skip }, async () => {
  const issuer = `${KC}/realms/jjdguard`;
  const oidc = {
    issuer,
    authorizeUrl: `${issuer}/protocol/openid-connect/auth`,
    tokenUrl: `${issuer}/protocol/openid-connect/token`,
    jwksUri: `${issuer}/protocol/openid-connect/certs`,
    clientId: 'chat-portal-admin',
    clientSecret: 'admin-secret',
    redirectUri: 'http://127.0.0.1/portal/auth/callback',
    scope: 'openid email profile',
  };
  const verifier = new OidcVerifier(oidc);
  let lastIdToken = '';
  const sessions = new SessionStore(new MemorySessionBackend(), 'tenant_default', 3600);
  const { exchangeCode } = await import('../src/oidc.js');
  const auth = createPortalAuth({
    oidc, verifier, sessions,
    roleStore: { findBySubject: async () => null },
    checkBreakGlass: () => false, cookieSecure: false, postLoginPath: '/admin',
    exchange: async (cfg, input) => { const t = await exchangeCode(cfg, input); lastIdToken = t.idToken; return t; },
  });

  const loginRes = fakeRes();
  auth.login(loginRes);
  const authz = new URL(loginRes.headers.location as string);
  const nonce = cookieOf(loginRes, COOKIE_NONCE);
  assert.equal(authz.searchParams.get('nonce'), nonce);
  const cb = await browserLogin(authz.toString());
  const txCookie = `${COOKIE_STATE}=${cookieOf(loginRes, COOKIE_STATE)}; ${COOKIE_VERIFIER}=${cookieOf(loginRes, COOKIE_VERIFIER)}`;

  // 1) 同一授权码配错 nonce：拒绝（且授权码被消耗前先拒——这里 exchange 已发生，nonce 校验在其后）
  const bad = fakeRes();
  await auth.callback({ headers: { cookie: `${txCookie}; ${COOKIE_NONCE}=not-the-nonce` } }, bad, cb);
  assert.match(bad.headers.location as string, /auth_error=token_exchange_failed/);
  assert.equal(cookieOf(bad, SESSION_COOKIE), undefined);
  const claims = decodeJwt(lastIdToken);
  assert.equal(claims.nonce, nonce, 'Keycloak 应把 nonce 回填进 id_token');
  assert.equal(claims.role, 'admin', '测试前置：mapper 已向 id_token 注入 role=admin');
  assert.equal(typeof claims.sid, 'string');

  // 2) 重新走一次正确流程
  const loginRes2 = fakeRes();
  auth.login(loginRes2);
  const cb2 = await browserLogin(loginRes2.headers.location as string);
  const ok = fakeRes();
  await auth.callback({ headers: { cookie: `${COOKIE_STATE}=${cookieOf(loginRes2, COOKIE_STATE)}; ${COOKIE_VERIFIER}=${cookieOf(loginRes2, COOKIE_VERIFIER)}; ${COOKIE_NONCE}=${cookieOf(loginRes2, COOKIE_NONCE)}` } }, ok, cb2);
  assert.equal(ok.headers.location, '/admin');
  const sid = cookieOf(ok, SESSION_COOKIE);
  assert.ok(sid);
  const cookie = `${SESSION_COOKIE}=${sid}`;
  const id = await auth.authenticate({ headers: { cookie } });
  assert.equal(id.kind, 'oidc');
  assert.equal(id.role, 'employee', 'token 里 role=admin 也不能提权');

  // 3) 登出后同一 cookie 失效
  const out = fakeRes();
  await auth.logout({ headers: { cookie } }, out);
  assert.equal(await auth.authenticate({ headers: { cookie } }), null);

  // 4) 部门验签：真实 id_token 过远端 JWKS；篡改 payload 被拒
  const keySet = createRemoteJWKSet(new URL(oidc.jwksUri));
  assert.equal(await verifyDepartment(lastIdToken, { keySet, issuer }), null);
  const [h, , s] = lastIdToken.split('.');
  const forgedPayload = Buffer.from(JSON.stringify({ ...claims, department: 'security' })).toString('base64url');
  await assert.rejects(verifyDepartment(`${h}.${forgedPayload}.${s}`, { keySet, issuer }));
});

// W9 9.7 live：真实 Keycloak 推送 back-channel logout（需 PORTAL_LIVE_KC_URL 与 PORTAL_LIVE_BCL_LISTEN，未设置则跳过）。
// 前置（由 w9 kc97_live.sh 准备）：realm jjdguard 导入生产模板；用户 alice/Alice-pass-123；
// chat-portal-admin 的 backchannel.logout.url 指向本测试监听的 PORTAL_LIVE_BCL_LISTEN。
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test from 'node:test';

import { OidcVerifier, exchangeCode } from '../src/oidc.js';
import { MemorySessionBackend, SESSION_COOKIE, SessionStore } from '../src/session.js';
import { COOKIE_NONCE, COOKIE_STATE, COOKIE_VERIFIER, createPortalAuth } from '../src/portal-auth.js';
import { BACKCHANNEL_LOGOUT_PATH, createBackchannelLogout } from '../src/backchannel-logout.js';

const KC = process.env.PORTAL_LIVE_KC_URL;
const LISTEN = process.env.PORTAL_LIVE_BCL_LISTEN; // host:port
const skip = !KC || !LISTEN ? 'PORTAL_LIVE_KC_URL / PORTAL_LIVE_BCL_LISTEN 未设置' : false;

function fakeRes() {
  const res = {
    status: 0, headers: {} as Record<string, unknown>, body: '', headersSent: false,
    writeHead(s, h = {}) { res.status = s; res.headers = h; res.headersSent = true; },
    end(b = '') { res.body = b; },
  };
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
async function browserLogin(authorizeUrl) {
  const jar = new Map();
  const keep = (r) => {
    for (const c of r.headers.getSetCookie()) {
      const pair = c.split(';')[0];
      const i = pair.indexOf('=');
      jar.set(pair.slice(0, i), pair.slice(i + 1));
    }
  };
  const page = await fetch(authorizeUrl, { redirect: 'manual' });
  keep(page);
  const m = (await page.text()).match(/action="([^"]+)"/);
  assert.ok(m, `未找到登录表单：HTTP ${page.status}`);
  const post = await fetch(m[1].replace(/&amp;/g, '&'), {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; ') },
    body: new URLSearchParams({ username: 'alice', password: 'Alice-pass-123', credentialId: '' }).toString(),
  });
  assert.equal(post.status, 302, `登录提交应 302：${post.status}`);
  return new URL(post.headers.get('location'));
}
async function kcAdmin(path, init: RequestInit = {}) {
  const tok = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'admin', password: 'admin' }).toString(),
  }).then((r) => r.json());
  return fetch(`${KC}/admin/realms/jjdguard${path}`, { ...init, headers: { authorization: `Bearer ${tok.access_token}`, ...(init.headers ?? {}) } });
}

test('live Keycloak：IdP 侧强制下线经 back-channel 撤销门户会话', { skip }, async () => {
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
  const sessions = new SessionStore(new MemorySessionBackend(), 'tenant_default', 3600);
  const auth = createPortalAuth({
    oidc, verifier, sessions,
    roleStore: { findBySubject: async () => null },
    checkBreakGlass: () => false, cookieSecure: false, postLoginPath: '/admin',
    exchange: (cfg, input) => exchangeCode(cfg, input),
  });
  const events: string[] = [];
  const bcl = createBackchannelLogout({ verifier, sessions, log: (_l, msg) => events.push(msg) });
  const [host, port] = LISTEN.split(':');
  const server = createServer((req, res) => {
    if (req.url === BACKCHANNEL_LOGOUT_PATH) return void bcl.handle(req, res);
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((r) => server.listen(Number(port), host, () => r()));
  try {
    const loginRes = fakeRes();
    auth.login(loginRes);
    const cb = await browserLogin(loginRes.headers.location as string);
    const ok = fakeRes();
    await auth.callback({ headers: { cookie: `${COOKIE_STATE}=${cookieOf(loginRes, COOKIE_STATE)}; ${COOKIE_VERIFIER}=${cookieOf(loginRes, COOKIE_VERIFIER)}; ${COOKIE_NONCE}=${cookieOf(loginRes, COOKIE_NONCE)}` } }, ok, cb);
    assert.equal(ok.headers.location, '/admin');
    const cookie = `${SESSION_COOKIE}=${cookieOf(ok, SESSION_COOKIE)}`;
    assert.ok(await auth.authenticate({ headers: { cookie } }), '登录后会话有效');

    const users = await (await kcAdmin('/users?username=alice&exact=true')).json();
    const out = await kcAdmin(`/users/${users[0].id}/logout`, { method: 'POST' });
    assert.equal(out.status, 204);

    let revoked = false;
    for (let i = 0; i < 50 && !revoked; i++) {
      if ((await auth.authenticate({ headers: { cookie } })) === null) revoked = true;
      else await new Promise((r) => setTimeout(r, 200));
    }
    assert.ok(revoked, `IdP 强制下线后门户会话应失效；events=${events.join(',')}`);
    assert.ok(events.includes('backchannel_logout_applied'), `events=${events.join(',')}`);
  } finally {
    await new Promise((r) => server.close(r));
  }
});

// W9 9.6：门户后台 OIDC 加固的端到端契约测试（本地 JWKS + 内存会话存储，不连外部服务）。
import assert from 'node:assert/strict';
import test from 'node:test';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';

import { buildAuthorizeUrl, verifyIdToken } from '../src/oidc.js';
import { DepartmentTokenError, verifyDepartment } from '../src/idtoken.js';
import { MemorySessionBackend, SESSION_COOKIE, SessionStore, hashSessionId } from '../src/session.js';
import { COOKIE_NONCE, COOKIE_STATE, COOKIE_VERIFIER, LEGACY_ID_COOKIE, createPortalAuth } from '../src/portal-auth.js';

const ISSUER = 'https://idp.example.test/realms/jjdguard';
const CLIENT = 'chat-portal-admin';
const OIDC = {
  issuer: ISSUER,
  authorizeUrl: `${ISSUER}/protocol/openid-connect/auth`,
  tokenUrl: `${ISSUER}/protocol/openid-connect/token`,
  jwksUri: `${ISSUER}/protocol/openid-connect/certs`,
  clientId: CLIENT,
  clientSecret: 'synthetic-client-secret',
  redirectUri: 'https://portal.example.test/portal/auth/callback',
  scope: 'openid email profile',
};

let keySet;
let privateKey;
let attackerKey;

test.before(async () => {
  const kp = await generateKeyPair('RS256');
  privateKey = kp.privateKey;
  const jwk = { ...(await exportJWK(kp.publicKey)), kid: 'k1', alg: 'RS256' };
  keySet = createLocalJWKSet({ keys: [jwk] });
  attackerKey = (await generateKeyPair('RS256')).privateKey;
});

async function sign(claims, opts = {}) {
  const key = opts.key ?? privateKey;
  let jwt = new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
    .setIssuer(opts.issuer ?? ISSUER)
    .setAudience(opts.audience ?? CLIENT)
    .setIssuedAt();
  jwt = jwt.setExpirationTime(opts.exp ?? '5m');
  return jwt.sign(key);
}

function fakeRes() {
  const res = {
    status: 0,
    headers: {},
    body: '',
    headersSent: false,
    writeHead(status, headers = {}) {
      res.status = status;
      res.headers = headers;
      res.headersSent = true;
    },
    end(body = '') {
      res.body = body;
    },
  };
  return res;
}

function setCookies(res) {
  const raw = res.headers['set-cookie'];
  return Array.isArray(raw) ? raw : raw ? [raw] : [];
}

function cookieValue(res, name) {
  for (const c of setCookies(res)) {
    const [pair] = c.split(';');
    const idx = pair.indexOf('=');
    if (pair.slice(0, idx) === name) return decodeURIComponent(pair.slice(idx + 1));
  }
  return undefined;
}

function makeAuth({ roles = {}, idTokenFor } = {}) {
  const backend = new MemorySessionBackend();
  const sessions = new SessionStore(backend, 'tenant_default', 3600);
  const auth = createPortalAuth({
    oidc: OIDC,
    verifier: { verify: (tok, o) => verifyIdToken(tok, { keySet, issuer: ISSUER, audience: CLIENT, nonce: o?.nonce }) },
    sessions,
    roleStore: { findBySubject: async (sub) => (roles[sub] ? { role: roles[sub], managedDepartments: [] } : null) },
    checkBreakGlass: () => false,
    cookieSecure: true,
    postLoginPath: '/admin',
    exchange: async () => ({ idToken: await idTokenFor() }),
  });
  return { auth, sessions, backend };
}

/** 走一遍 login → callback，返回 callback 响应与本次 nonce。 */
async function loginFlow(auth) {
  const loginRes = fakeRes();
  auth.login(loginRes);
  const state = cookieValue(loginRes, COOKIE_STATE);
  const verifier = cookieValue(loginRes, COOKIE_VERIFIER);
  const nonce = cookieValue(loginRes, COOKIE_NONCE);
  const cb = new URL(`https://portal.example.test/portal/auth/callback?code=c1&state=${encodeURIComponent(state)}`);
  const req = { headers: { cookie: `${COOKIE_STATE}=${state}; ${COOKIE_VERIFIER}=${verifier}; ${COOKIE_NONCE}=${nonce}` } };
  const res = fakeRes();
  await auth.callback(req, res, cb);
  return { res, nonce };
}

test('authorize 请求携带随机 nonce，且缺 nonce 时拒绝构造', () => {
  const url = new URL(buildAuthorizeUrl(OIDC, { state: 's', nonce: 'n-123', codeChallenge: 'c' }));
  assert.equal(url.searchParams.get('nonce'), 'n-123');
  assert.throws(() => buildAuthorizeUrl(OIDC, { state: 's', codeChallenge: 'c' }), /nonce/);
});

test('id_token nonce 与本次事务不符时拒绝', async () => {
  const tok = await sign({ sub: 'u1', nonce: 'other' });
  await assert.rejects(verifyIdToken(tok, { keySet, issuer: ISSUER, audience: CLIENT, nonce: 'mine' }), /nonce/);
  const noNonce = await sign({ sub: 'u1' });
  await assert.rejects(verifyIdToken(noNonce, { keySet, issuer: ISSUER, audience: CLIENT, nonce: 'mine' }), /nonce/);
  const ok = await sign({ sub: 'u1', nonce: 'mine' });
  assert.equal((await verifyIdToken(ok, { keySet, issuer: ISSUER, audience: CLIENT, nonce: 'mine' })).sub, 'u1');
});

test('回调注入别的事务的 id_token（nonce 不符）不会建立会话', async () => {
  const { auth, backend } = makeAuth({ idTokenFor: () => sign({ sub: 'victim', nonce: 'replayed-from-elsewhere' }) });
  const { res } = await loginFlow(auth);
  assert.equal(res.status, 302);
  assert.match(res.headers.location, /auth_error=token_exchange_failed/);
  assert.equal(cookieValue(res, SESSION_COOKIE), undefined);
  assert.equal(backend.rows.size, 0);
});

test('登录成功后浏览器只拿到不透明会话 ID，库里只存其摘要', async () => {
  let nonceHolder = { v: '' };
  const { auth, backend } = makeAuth({ idTokenFor: () => sign({ sub: 'u1', email: 'u1@example.test', department: 'rd', sid: 'kc-sid-1', nonce: nonceHolder.v }) });
  const loginRes = fakeRes();
  auth.login(loginRes);
  nonceHolder.v = cookieValue(loginRes, COOKIE_NONCE);
  const state = cookieValue(loginRes, COOKIE_STATE);
  const verifier = cookieValue(loginRes, COOKIE_VERIFIER);
  const res = fakeRes();
  await auth.callback({ headers: { cookie: `${COOKIE_STATE}=${state}; ${COOKIE_VERIFIER}=${verifier}; ${COOKIE_NONCE}=${nonceHolder.v}` } },
    res, new URL(`https://p.example.test/portal/auth/callback?code=c&state=${encodeURIComponent(state)}`));
  assert.equal(res.status, 302);
  assert.equal(res.headers.location, '/admin');
  const sid = cookieValue(res, SESSION_COOKIE);
  assert.ok(sid && sid.length >= 40);
  assert.ok(!sid.includes('.'), '会话 cookie 不能是 JWT');
  assert.equal(cookieValue(res, LEGACY_ID_COOKIE), '');
  const rows = [...backend.rows.values()];
  assert.equal(rows.length, 1);
  assert.equal(rows[0].idHash, hashSessionId(sid));
  assert.notEqual(rows[0].idHash, sid);
  assert.equal(rows[0].idpSid, 'kc-sid-1');
  assert.ok(setCookies(res).find((c) => c.startsWith(`${SESSION_COOKIE}=`)).includes('HttpOnly'));
});

async function establish(roles, claims) {
  const holder = { v: '' };
  const ctx = makeAuth({ roles, idTokenFor: () => sign({ ...claims, nonce: holder.v }) });
  const loginRes = fakeRes();
  ctx.auth.login(loginRes);
  holder.v = cookieValue(loginRes, COOKIE_NONCE);
  const state = cookieValue(loginRes, COOKIE_STATE);
  const verifier = cookieValue(loginRes, COOKIE_VERIFIER);
  const res = fakeRes();
  await ctx.auth.callback({ headers: { cookie: `${COOKIE_STATE}=${state}; ${COOKIE_VERIFIER}=${verifier}; ${COOKIE_NONCE}=${holder.v}` } },
    res, new URL(`https://p.example.test/portal/auth/callback?code=c&state=${encodeURIComponent(state)}`));
  const sid = cookieValue(res, SESSION_COOKIE);
  assert.ok(sid, `登录应成功：${res.headers.location}`);
  return { ...ctx, sid, cookie: `${SESSION_COOKIE}=${sid}` };
}

test('token 里自带 admin 角色声明但角色表是 employee 时，结果是 employee', async () => {
  const { auth, cookie } = await establish({ u1: 'employee' }, { sub: 'u1', role: 'admin', roles: ['admin'], realm_access: { roles: ['admin'] } });
  const id = await auth.authenticate({ headers: { cookie } });
  assert.equal(id.kind, 'oidc');
  assert.equal(id.role, 'employee');
});

test('角色表无记录时即使 token 声明 admin 也只给 employee；表里改成 admin 即时生效', async () => {
  const roles = {};
  const { auth, cookie } = await establish(roles, { sub: 'u2', role: 'admin' });
  assert.equal((await auth.authenticate({ headers: { cookie } })).role, 'employee');
  roles.u2 = 'admin';
  assert.equal((await auth.authenticate({ headers: { cookie } })).role, 'admin');
});

test('登出后原会话 cookie 立即失效（服务端撤销，而不只是清浏览器 cookie）', async () => {
  const { auth, cookie } = await establish({ u1: 'admin' }, { sub: 'u1' });
  assert.equal((await auth.authenticate({ headers: { cookie } })).role, 'admin');
  const res = fakeRes();
  await auth.logout({ headers: { cookie } }, res);
  assert.equal(res.status, 200);
  assert.equal(cookieValue(res, SESSION_COOKIE), '');
  // 攻击者事先复制的同一个 cookie 再来：必须被拒
  assert.equal(await auth.authenticate({ headers: { cookie } }), null);
});

test('按 sub / IdP sid 撤销会话（供 back-channel logout 与管理撤销）', async () => {
  const a = await establish({ u1: 'admin' }, { sub: 'u1', sid: 'kc-1' });
  assert.equal(await a.sessions.revokeIdpSession('kc-other'), 0);
  assert.ok(await a.auth.authenticate({ headers: { cookie: a.cookie } }));
  assert.equal(await a.sessions.revokeIdpSession('kc-1', 'u1'), 1);
  assert.equal(await a.auth.authenticate({ headers: { cookie: a.cookie } }), null);

  const b = await establish({ u3: 'manager' }, { sub: 'u3' });
  assert.equal(await b.sessions.revokeSubject('u3'), 1);
  assert.equal(await b.auth.authenticate({ headers: { cookie: b.cookie } }), null);
});

test('旧版 portal_id_token cookie（有效签名的 id_token）不再被当作登录态', async () => {
  const { auth } = makeAuth({ roles: { u1: 'admin' }, idTokenFor: () => sign({ sub: 'u1' }) });
  const legacy = await sign({ sub: 'u1', role: 'admin' });
  assert.equal(await auth.authenticate({ headers: { cookie: `${LEGACY_ID_COOKIE}=${legacy}` } }), null);
});

test('会话寿命不超过 id_token exp，过期后失效', async () => {
  let now = new Date('2026-09-30T00:00:00Z');
  const sessions = new SessionStore(new MemorySessionBackend(), 'tenant_default', 3600, () => now);
  const exp = Math.floor(now.getTime() / 1000) + 120;
  const s = await sessions.create({ sub: 'u1', exp });
  assert.equal(s.maxAgeSec, 120);
  assert.ok(await sessions.resolve(s.id));
  now = new Date(now.getTime() + 121_000);
  assert.equal(await sessions.resolve(s.id), null);
});

test('会话不跨租户', async () => {
  const backend = new MemorySessionBackend();
  const a = new SessionStore(backend, 'tenant_a', 3600);
  const b = new SessionStore(backend, 'tenant_b', 3600);
  const s = await a.create({ sub: 'u1' });
  assert.ok(await a.resolve(s.id));
  assert.equal(await b.resolve(s.id), null);
});

test('部门声明必须验签：伪造签名 / 错 issuer 拒绝，合法 token 取出部门', async () => {
  const opts = { keySet, issuer: ISSUER };
  const good = await sign({ sub: 'u1', department: 'finance' }, { audience: 'lobehub', exp: '-1h' });
  assert.equal(await verifyDepartment(good, opts), 'finance');
  const forged = await sign({ sub: 'u1', department: 'finance' }, { key: attackerKey });
  await assert.rejects(verifyDepartment(forged, opts), DepartmentTokenError);
  const [h, , s] = good.split('.');
  const tamperedPayload = Buffer.from(JSON.stringify({ iss: ISSUER, sub: 'u1', department: 'security' })).toString('base64url');
  await assert.rejects(verifyDepartment(`${h}.${tamperedPayload}.${s}`, opts), DepartmentTokenError);
  const wrongIss = await sign({ sub: 'u1', department: 'finance' }, { issuer: 'https://evil.example.test' });
  await assert.rejects(verifyDepartment(wrongIss, opts), DepartmentTokenError);
  await assert.rejects(verifyDepartment(good, null), DepartmentTokenError);
  assert.equal(await verifyDepartment(null, opts), null);
  assert.equal(await verifyDepartment('', opts), null);
  const noDept = await sign({ sub: 'u1' });
  assert.equal(await verifyDepartment(noDept, opts), null);
});

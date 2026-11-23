// W9 9.7：OIDC back-channel logout 契约测试（本地 JWKS + 内存会话，不连外部服务）。
import assert from 'node:assert/strict';
import test from 'node:test';
import { Readable } from 'node:stream';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';

import { BACKCHANNEL_LOGOUT_EVENT, verifyLogoutToken } from '../src/oidc.js';
import { BACKCHANNEL_LOGOUT_PATH, createBackchannelLogout } from '../src/backchannel-logout.js';
import { MemorySessionBackend, SessionStore } from '../src/session.js';

const ISSUER = 'https://idp.example.test/realms/jjdguard';
const CLIENT = 'chat-portal-admin';
let keySet;
let privateKey;
let attackerKey;

test.before(async () => {
  const kp = await generateKeyPair('RS256');
  privateKey = kp.privateKey;
  keySet = createLocalJWKSet({ keys: [{ ...(await exportJWK(kp.publicKey)), kid: 'k1', alg: 'RS256' }] });
  attackerKey = (await generateKeyPair('RS256')).privateKey;
});

let jtiSeq = 0;
type TokOpts = { key?: unknown; issuer?: string; audience?: string; iat?: number; alg?: string; hsKey?: Uint8Array };
async function logoutToken(claims: Record<string, unknown> = {}, opts: TokOpts = {}) {
  const body: Record<string, unknown> = { events: { [BACKCHANNEL_LOGOUT_EVENT]: {} }, jti: `jti-${++jtiSeq}`, ...claims };
  for (const k of Object.keys(body)) if (body[k] === undefined) delete body[k];
  const jwt = new SignJWT(body)
    .setProtectedHeader({ alg: opts.alg ?? 'RS256', kid: 'k1', typ: 'logout+jwt' })
    .setIssuer(opts.issuer ?? ISSUER)
    .setAudience(opts.audience ?? CLIENT)
    .setIssuedAt(opts.iat)
    .setExpirationTime('2m');
  return jwt.sign((opts.hsKey ?? opts.key ?? privateKey) as never);
}

const verifier = { verifyLogout: (tok) => verifyLogoutToken(tok, { keySet, issuer: ISSUER, audience: CLIENT }) };

function fakeRes() {
  const res = {
    status: 0, headers: {} as Record<string, unknown>, body: '', headersSent: false,
    writeHead(s, h = {}) { res.status = s; res.headers = h; res.headersSent = true; },
    end(b = '') { res.body = b; },
  };
  return res;
}
function post(body: string, ctype = 'application/x-www-form-urlencoded', method = 'POST') {
  const req = Readable.from([Buffer.from(body)]) as Readable & { method: string; headers: Record<string, string> };
  req.method = method;
  req.headers = { 'content-type': ctype };
  return req;
}
function formBody(tok: string) {
  return new URLSearchParams({ logout_token: tok }).toString();
}

async function withSessions() {
  const sessions = new SessionStore(new MemorySessionBackend(), 'tenant_default', 3600);
  const a1 = await sessions.create({ sub: 'alice', sid: 'kc-sid-1' });
  const a2 = await sessions.create({ sub: 'alice', sid: 'kc-sid-2' });
  const b1 = await sessions.create({ sub: 'bob', sid: 'kc-sid-3' });
  const handler = createBackchannelLogout({ verifier, sessions });
  const alive = async (s) => (await sessions.resolve(s.id)) !== null;
  return { sessions, handler, a1, a2, b1, alive };
}

test('端点路径固定在门户 auth 前缀下', () => {
  assert.equal(BACKCHANNEL_LOGOUT_PATH, '/portal/auth/backchannel-logout');
});

test('带 sid 的 logout_token 只撤销该 IdP 会话派生的门户会话', async () => {
  const { handler, a1, a2, b1, alive } = await withSessions();
  const res = fakeRes();
  await handler.handle(post(formBody(await logoutToken({ sub: 'alice', sid: 'kc-sid-1' }))), res);
  assert.equal(res.status, 200);
  assert.equal(res.headers['cache-control'], 'no-store');
  assert.equal(await alive(a1), false);
  assert.equal(await alive(a2), true, '同一用户的其他 IdP 会话不受影响');
  assert.equal(await alive(b1), true);
});

test('只带 sub 的 logout_token 撤销该用户全部门户会话', async () => {
  const { handler, a1, a2, b1, alive } = await withSessions();
  const res = fakeRes();
  await handler.handle(post(formBody(await logoutToken({ sub: 'alice' }))), res);
  assert.equal(res.status, 200);
  assert.equal(await alive(a1), false);
  assert.equal(await alive(a2), false);
  assert.equal(await alive(b1), true);
});

test('sid 与 sub 不匹配时不撤销别人的会话', async () => {
  const { handler, b1, alive } = await withSessions();
  const res = fakeRes();
  await handler.handle(post(formBody(await logoutToken({ sub: 'alice', sid: 'kc-sid-3' }))), res);
  assert.equal(res.status, 200);
  assert.equal(await alive(b1), true);
});

test('伪造与不合规的 logout_token 一律 400 且不撤销任何会话', async () => {
  const hs = new TextEncoder().encode('synthetic-client-secret-synthetic-client-secret');
  const cases: Array<[string, Promise<string> | string]> = [
    ['攻击者签名', logoutToken({ sub: 'alice' }, { key: attackerKey })],
    ['错 issuer', logoutToken({ sub: 'alice' }, { issuer: 'https://evil.example.test' })],
    ['错 audience', logoutToken({ sub: 'alice' }, { audience: 'other-client' })],
    ['缺事件', logoutToken({ sub: 'alice', events: undefined })],
    ['事件不是对象', logoutToken({ sub: 'alice', events: { [BACKCHANNEL_LOGOUT_EVENT]: true } })],
    ['含 nonce（id_token 冒充）', logoutToken({ sub: 'alice', nonce: 'n' })],
    ['缺 jti', logoutToken({ sub: 'alice', jti: undefined })],
    ['缺 sub 与 sid', logoutToken({})],
    ['过旧 iat', logoutToken({ sub: 'alice' }, { iat: Math.floor(Date.now() / 1000) - 3600 })],
    ['HS256 对称签名', logoutToken({ sub: 'alice' }, { alg: 'HS256', hsKey: hs })],
    ['不是 JWT', 'not-a-jwt'],
  ];
  for (const [name, tokP] of cases) {
    const { handler, a1, a2, alive } = await withSessions();
    const res = fakeRes();
    await handler.handle(post(formBody(await tokP)), res);
    assert.equal(res.status, 400, name);
    assert.equal(res.body.includes('alice'), false, `${name}: 响应不回显身份`);
    assert.equal(await alive(a1), true, name);
    assert.equal(await alive(a2), true, name);
  }
});

test('同一 jti 重放被拒', async () => {
  const { handler } = await withSessions();
  const tok = await logoutToken({ sub: 'alice', sid: 'kc-sid-1' });
  const r1 = fakeRes();
  await handler.handle(post(formBody(tok)), r1);
  assert.equal(r1.status, 200);
  const r2 = fakeRes();
  await handler.handle(post(formBody(tok)), r2);
  assert.equal(r2.status, 400);
});

test('请求形态：非 POST 405、非表单 400、重复参数 400、超大 body 413', async () => {
  const { handler } = await withSessions();
  const tok = await logoutToken({ sub: 'alice' });
  const g = fakeRes();
  await handler.handle(post('', 'application/x-www-form-urlencoded', 'GET'), g);
  assert.equal(g.status, 405);
  const j = fakeRes();
  await handler.handle(post(JSON.stringify({ logout_token: tok }), 'application/json'), j);
  assert.equal(j.status, 400);
  const dup = fakeRes();
  await handler.handle(post(`${formBody(tok)}&${formBody(tok)}`), dup);
  assert.equal(dup.status, 400);
  const big = fakeRes();
  await handler.handle(post(`logout_token=${'a'.repeat(20 * 1024)}`), big);
  assert.equal(big.status, 413);
});

test('门户 OIDC 未启用时返回 501，不撤销', async () => {
  const sessions = new SessionStore(new MemorySessionBackend(), 'tenant_default', 3600);
  const s = await sessions.create({ sub: 'alice', sid: 'kc-sid-1' });
  const handler = createBackchannelLogout({ verifier: null, sessions });
  const res = fakeRes();
  await handler.handle(post(formBody(await logoutToken({ sub: 'alice' }))), res);
  assert.equal(res.status, 501);
  assert.ok(await sessions.resolve(s.id));
});

test('撤销失败返回 500 且不记 jti，IdP 重试可再次处理', async () => {
  const backend = new MemorySessionBackend();
  const sessions = new SessionStore(backend, 'tenant_default', 3600);
  const s = await sessions.create({ sub: 'alice', sid: 'kc-sid-1' });
  const orig = backend.revoke.bind(backend);
  let fail = true;
  backend.revoke = async (w, at) => {
    if (fail) throw new Error('db down');
    return orig(w, at);
  };
  const handler = createBackchannelLogout({ verifier, sessions });
  const tok = await logoutToken({ sub: 'alice', sid: 'kc-sid-1' });
  const r1 = fakeRes();
  await handler.handle(post(formBody(tok)), r1);
  assert.equal(r1.status, 500);
  fail = false;
  const r2 = fakeRes();
  await handler.handle(post(formBody(tok)), r2);
  assert.equal(r2.status, 200);
  assert.equal(await sessions.resolve(s.id), null);
});

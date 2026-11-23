import test, { mock } from 'node:test';
import assert from 'node:assert/strict';

// 员工诊断助手 BFF：身份只取自服务端会话，浏览器传来的 user_id 一律忽略。
let session: { user: { id: string; tenantId?: string } } | null = { user: { id: 'employee-1', tenantId: 'tenant-1' } };
let active = true;
mock.module('@/auth', { namedExports: { auth: async () => session } });
mock.module('@/lib/require-active-user', {
  namedExports: {
    requireActivePortalUser: async () =>
      active ? { user: { id: 'employee-1', modelIds: [] } } : Response.json({ error: 'user_inactive' }, { status: 403 }),
  },
});

const origin = 'http://portal.test';
process.env.PORTAL_PUBLIC_URL = origin;
process.env.JJD_CP_URL = 'http://cp.test';
process.env.JJD_PORTAL_API_SECRET = 'portal-secret';

type Seen = { url: URL; method: string; headers: Headers; body: Record<string, unknown> | null };
const seen: Seen[] = [];
const last = (): Seen => seen[seen.length - 1];
let upstream = (): Response => Response.json({ session_id: 'dgs_1' });
const realFetch = globalThis.fetch;
test.before(() => {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    seen.push({
      url: new URL(String(input)),
      method: init?.method ?? 'GET',
      headers: new Headers(init?.headers),
      body: typeof init?.body === 'string' ? JSON.parse(init.body) : null,
    });
    return upstream();
  }) as typeof fetch;
});
test.after(() => { globalThis.fetch = realFetch; });
test.beforeEach(() => {
  seen.length = 0;
  session = { user: { id: 'employee-1', tenantId: 'tenant-1' } };
  active = true;
  upstream = () => Response.json({ session_id: 'dgs_1' });
});

const post = (path: string, body: unknown, headers: Record<string, string> = { origin }) =>
  new Request(origin + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });

test('创建会话：只转发 question/health，user_id 取自会话而非请求体', async () => {
  const { POST } = await import('../src/app/api/me/diagnostics/sessions/route.js');
  const reply = await POST(post('/api/me/diagnostics/sessions', {
    user_id: 'someone-else', tenant_id: 'other', is_admin: true,
    input: { kind: 'question', text: ' 我的请求为什么失败 ', ref: 'req_x', window_hours: 24 },
  }));
  assert.equal(reply.status, 200);
  assert.deepEqual(await reply.json(), { session_id: 'dgs_1' });
  assert.equal(reply.headers.get('cache-control'), 'private, no-store');
  assert.equal(seen.length, 1);
  const call = seen[0];
  assert.equal(call.url.pathname, '/admin/v1/portal-integration/diagnostics/sessions');
  assert.equal(call.headers.get('x-jjdguard-tenant-id'), 'tenant-1');
  assert.equal(call.headers.get('authorization'), 'Bearer portal-secret');
  assert.deepEqual(call.body, {
    user_id: 'employee-1',
    input: { kind: 'question', text: '我的请求为什么失败', ref: '', window_hours: 1 },
  });
});

test('创建会话：拒绝管理员向的输入种类、空问题与超长文本，且不触达控制面', async () => {
  const { POST } = await import('../src/app/api/me/diagnostics/sessions/route.js');
  for (const input of [
    { kind: 'user', text: 'x', ref: 'victim' },
    { kind: 'request', text: 'req_1' },
    { kind: 'question', text: '   ' },
    { kind: 'question', text: 'a'.repeat(4001) },
    { kind: 'question' },
  ]) {
    const reply = await POST(post('/api/me/diagnostics/sessions', { input }));
    assert.equal(reply.status, 400, JSON.stringify(input));
  }
  assert.equal(seen.length, 0);
  const health = await POST(post('/api/me/diagnostics/sessions', { input: { kind: 'health', text: 'ignored' } }));
  assert.equal(health.status, 200);
  assert.deepEqual(last().body?.input, { kind: 'health', text: '', ref: '', window_hours: 1 });
});

test('读取与列表：user_id 由服务端追加，浏览器的 user_id/all 不下传', async () => {
  const list = await import('../src/app/api/me/diagnostics/sessions/route.js');
  const one = await import('../src/app/api/me/diagnostics/sessions/[id]/route.js');
  upstream = () => Response.json([]);
  const l = await list.GET(new Request(origin + '/api/me/diagnostics/sessions?user_id=victim&all=1'));
  assert.equal(l.status, 200);
  assert.equal(seen[0].url.pathname, '/admin/v1/portal-integration/diagnostics/sessions');
  assert.deepEqual(seen[0].url.searchParams.getAll('user_id'), ['employee-1']);
  assert.equal(seen[0].url.searchParams.has('all'), false);
  upstream = () => Response.json({ status: 'running', steps: [] });
  const g = await one.GET(new Request(origin + '/api/me/diagnostics/sessions/dgs_1?user_id=victim'), { params: Promise.resolve({ id: 'dgs_1' }) });
  assert.equal(g.status, 200);
  assert.equal(seen[1].url.pathname, '/admin/v1/portal-integration/diagnostics/sessions/dgs_1');
  assert.deepEqual(seen[1].url.searchParams.getAll('user_id'), ['employee-1']);
  const bad = await one.GET(new Request(origin + '/x'), { params: Promise.resolve({ id: '../settings' }) });
  assert.equal(bad.status, 400);
  assert.equal(seen.length, 2);
});

test('追问：他人会话的 404 原样返回，错误详情不外泄', async () => {
  const { POST } = await import('../src/app/api/me/diagnostics/sessions/[id]/messages/route.js');
  upstream = () => Response.json({ error: { code: 'not_found', message: '内部细节 secret-detail' } }, { status: 404 });
  const reply = await POST(post('/x', { text: '继续查', user_id: 'victim' }), { params: Promise.resolve({ id: 'dgs_other' }) });
  assert.equal(reply.status, 404);
  assert.deepEqual(await reply.json(), { error: 'not_found' });
  assert.deepEqual(seen[0].body, { text: '继续查', user_id: 'employee-1' });
  upstream = () => Response.json({ error: 'boom' }, { status: 500 });
  const failed = await POST(post('/x', { text: '继续查' }), { params: Promise.resolve({ id: 'dgs_1' }) });
  assert.equal(failed.status, 502);
});

test('未登录 401、停用员工 403、跨站写入 403，均不触达控制面', async () => {
  const { POST } = await import('../src/app/api/me/diagnostics/sessions/route.js');
  const body = { input: { kind: 'health', text: '' } };
  session = null;
  assert.equal((await POST(post('/api/me/diagnostics/sessions', body))).status, 401);
  session = { user: { id: 'employee-1', tenantId: 'tenant-1' } };
  assert.equal((await POST(post('/api/me/diagnostics/sessions', body, { origin: 'https://cross-site.invalid' }))).status, 403);
  active = false;
  assert.equal((await POST(post('/api/me/diagnostics/sessions', body))).status, 403);
  assert.equal(seen.length, 0);
});

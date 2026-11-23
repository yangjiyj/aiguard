// W2.3: every /api/me/* route must re-check the control-plane user status on
// each request. A disabled/deleted employee still holds a valid NextAuth JWT;
// before this change records, call-records, billing, limits and redeem only
// checked session.user.id and kept serving that user.
import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';

type Seen = { path: string; method: string };

let session: { user: { id: string } } | null = { user: { id: 'employee-1' } };
let requestOrigin='http://portal.test';
let chatAllowed = false;
let contextStatus = 200;
const seen: Seen[] = [];

mock.module('@/auth', { namedExports: { auth: async () => session } });
mock.module('@/lib/prisma', {
  namedExports: { prisma: { uploadEvent: { findMany: async () => [] } } },
});

const server = createServer(async (request, response) => {
  for await (const chunk of request) void chunk;
  seen.push({ path: request.url ?? '', method: request.method ?? '' });
  response.setHeader('content-type', 'application/json');
  if (request.url === '/admin/v1/portal-integration/users/employee-1/authorization-context') {
    response.statusCode = contextStatus;
    response.end(JSON.stringify(contextStatus === 200 ? { data: {
      user_id: 'employee-1',
      department_id: 'dept-1',
      department_name: 'R&D',project_id:'project-1',
      department_version: 7,
      chat_allowed: chatAllowed,
      model_ids: ['gpt-5.5'],
    } } : { error: { code: 'not_found' } }));
    return;
  }
  // Every data endpoint answers successfully: a route that skips the active
  // check would therefore return 200 and fail the assertions below.
  if (request.url?.startsWith('/admin/v1/portal-integration/call-records')) {
    response.end(JSON.stringify({ data: [], total: 0, next_cursor: '' }));
    return;
  }
  response.end(JSON.stringify({ data: [], ok: true }));
});

test.before(async () => {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  process.env.PORTAL_PUBLIC_URL='http://portal.test/chat';
  process.env.JJD_CP_URL = `http://127.0.0.1:${address.port}`;
  process.env.JJD_PORTAL_API_SECRET = 'portal-secret';
});
test.after(() => server.close());

type Call = () => Promise<Response>;

async function routes(tag: string): Promise<Array<[string, Call]>> {
  const records = await import(`../src/app/api/me/records/route.js?${tag}`);
  const callRecords = await import(`../src/app/api/me/call-records/route.js?${tag}`);
  const billing = await import(`../src/app/api/me/billing/route.js?${tag}`);
  const limits = await import(`../src/app/api/me/billing/limits/route.js?${tag}`);
  const redeem = await import(`../src/app/api/me/billing/redeem/route.js?${tag}`);
  const keys = await import(`../src/app/api/me/keys/route.js?${tag}`);
  const reveal = await import(`../src/app/api/me/keys/[id]/reveal/route.js?${tag}`);
  const me = await import(`../src/app/api/me/route.js?${tag}`);
  const json = (body: unknown, method = 'POST') => ({
    method,
    headers: { 'content-type': 'application/json',origin:requestOrigin },
    body: JSON.stringify(body),
  });
  return [
    ['GET /api/me', () => me.GET()],
    ['GET /api/me/records', () => records.GET(new Request('http://portal.test/api/me/records'))],
    ['GET /api/me/call-records', () => callRecords.GET(new Request('http://portal.test/api/me/call-records'))],
    ['GET /api/me/billing', () => billing.GET()],
    ['PUT /api/me/billing/limits', () => limits.PUT(new Request('http://portal.test/api/me/billing/limits', json({
      daily_amount_micros: 1, monthly_amount_micros: 1, daily_token_limit: 1,
      monthly_token_limit: 1, rpm_limit: 1, concurrency_limit: 1,
    }, 'PUT')))],
    ['POST /api/me/billing/redeem', () => redeem.POST(new Request('http://portal.test/api/me/billing/redeem', json({ code: 'CARD-1' })))],
    ['POST /api/me/keys', () => keys.POST(new Request('http://portal.test/api/me/keys', json({ project_id: 'project-1' })))],
    ['POST /api/me/keys/:id/reveal', () => reveal.POST(
      new Request('http://portal.test/api/me/keys/key-1/reveal', { method: 'POST',headers:{origin:requestOrigin} }),
      { params: Promise.resolve({ id: 'key-1' }) },
    )],
  ];
}

function dataCalls(): Seen[] {
  return seen.filter((entry) => !entry.path.endsWith('/authorization-context'));
}

test('disabled employee with a valid JWT is rejected by every /api/me route', async () => {
  session = { user: { id: 'employee-1' } };
  chatAllowed = false;
  contextStatus = 200;
  for (const [name, call] of await routes('disabled')) {
    seen.length = 0;
    const response = await call();
    assert.equal(response.status, 403, `${name} must reject a disabled user`);
    assert.deepEqual(await response.json(), { error: 'authorization_denied' }, name);
    assert.deepEqual(dataCalls(), [], `${name} must not reach the data endpoint`);
  }
});

test('deleted employee (control plane 404) is rejected by every /api/me route', async () => {
  session = { user: { id: 'employee-1' } };
  contextStatus = 404;
  for (const [name, call] of await routes('deleted')) {
    seen.length = 0;
    const response = await call();
    assert.equal(response.status, 403, `${name} must reject a deleted user`);
    assert.deepEqual(await response.json(), { error: 'user_inactive' }, name);
    assert.deepEqual(dataCalls(), [], `${name} must not reach the data endpoint`);
  }
});

test('active employee still reaches the data endpoint', async () => {
  session = { user: { id: 'employee-1' } };
  chatAllowed = true;
  contextStatus = 200;
  for (const [name, call] of await routes('active')) {
    seen.length = 0;
    const response = await call();
    assert.notEqual(response.status, 401, name);
    assert.notEqual(response.status, 403, name);
    if (name !== 'GET /api/me') {
      assert.ok(dataCalls().length > 0, `${name} must still reach the data endpoint`);
    }
  }
});

test('unauthenticated requests stay 401 without a control-plane call', async () => {
  session = null;
  for (const [name, call] of await routes('anonymous')) {
    seen.length = 0;
    const response = await call();
    assert.equal(response.status, 401, name);
    assert.deepEqual(seen, [], name);
  }
});

// Auth runs first; valid write payloads then check Origin before querying active status.
// Untrusted origins receive no identity-status oracle and never reach the control plane.
test('write routes reject Origin before active-user lookup',async()=>{
 session={user:{id:'employee-1'}};contextStatus=404;requestOrigin='https://cross-site.invalid';
 try {for(const [name,call] of await routes('origin-order')){
  if(!name.startsWith('POST')&&!name.startsWith('PUT'))continue;
  seen.length=0;const response=await call();
  assert.equal(response.status,403,name);assert.deepEqual(await response.json(),{error:'invalid_origin'},name);assert.deepEqual(seen,[],name);
 }}finally{requestOrigin='http://portal.test'}
});

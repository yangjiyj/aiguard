import test, { mock } from 'node:test';
import assert from 'node:assert/strict';

let session: { user: { id: string } } | null = { user: { id: 'employee-1' } };
class MockControlPlaneError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, status: number, message: string) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

const calls: Array<{
  tenantId: string;
  userId: string;
	query: { limit?: number; cursor?: string; days?: number };
}> = [];
let listError: Error | null = null;

mock.module('@/auth', {
  namedExports: { auth: async () => session },
});

// W2.3: the route checks the user is still active first; that path has its
// own coverage in me-routes-active-user.test.ts, so it is a pass-through here.
mock.module('@/lib/require-active-user', {
  namedExports: {
    requireActivePortalUser: async (current: { user?: { id?: string } } | null) =>
      current?.user?.id
        ? { user: { id: current.user.id } }
        : Response.json({ error: 'unauthorized' }, { status: 401 }),
  },
});

mock.module('@/lib/control-plane', {
  namedExports: {
    ControlPlaneError: MockControlPlaneError,
    PORTAL_DEFAULT_TENANT_ID: 'tenant_default',
    listPortalCallRecords: async (
      tenantId: string,
      userId: string,
		query: { limit?: number; cursor?: string; days?: number },
    ) => {
      calls.push({ tenantId, userId, query });
      if (listError) throw listError;
      return {
        records: [{
          requestId: 'req-1',
          createdAt: '2026-08-16T00:00:00Z',
          model: 'GPT 5.6',
          status: 'success',
          inputTokens: 12,
          outputTokens: 8,
          totalTokens: 20,
          latencyMs: 321,
          agentType: '',
          endpointType: 'chat',
			billingAmountMicros: 0,
			billingCurrency: 'CNY',
			billingState: 'settled',
        }],
        summary: {requests: 100, averageLatencyMs: 321, successRate: 0.98},
        total: 1,
      };
    },
  },
});

test('call records route binds the control-plane query to the signed-in user', async () => {
  session = { user: { id: 'employee-1' } };
  calls.length = 0;
  listError = null;
  const route = (await import('../src/app/api/me/call-records/route.js?bound-user' as string)) as typeof import('../src/app/api/me/call-records/route.js');
  const response = await route.GET(new Request(
		'http://portal.test/api/me/call-records?user=attacker&limit=500&cursor=opaque-page-1&days=180',
  ));

  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'private, no-store');
  assert.deepEqual(calls, [{
    tenantId: 'tenant_default',
    userId: 'employee-1',
		query: { limit: 200, cursor: 'opaque-page-1', days: 90 },
  }]);
  const body = await response.json();
  assert.equal(body.total, 1);
  assert.equal(body.records[0].totalTokens, 20);
	assert.equal(body.records[0].billingAmountMicros, 0);
  assert.equal(JSON.stringify(body).includes('attacker'), false);
  assert.deepEqual(body.summary, {requests: 100, averageLatencyMs: 321, successRate: 0.98});
  assert.doesNotMatch(JSON.stringify(body), /timing|upstream|security/i);
});

test('call records route rejects an unauthenticated request before control-plane access', async () => {
  session = null;
  calls.length = 0;
  listError = null;
  const route = (await import('../src/app/api/me/call-records/route.js?unauthenticated' as string)) as typeof import('../src/app/api/me/call-records/route.js');
  const response = await route.GET(new Request('http://portal.test/api/me/call-records'));

  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: 'unauthorized' });
  assert.equal(calls.length, 0);
});

test('call records route sanitizes control-plane failures', async () => {
  session = { user: { id: 'employee-1' } };
  calls.length = 0;
  listError = new Error('postgres://db.internal/?password=leak-canary');
  const route = (await import('../src/app/api/me/call-records/route.js?failed' as string)) as typeof import('../src/app/api/me/call-records/route.js');
  const response = await route.GET(new Request('http://portal.test/api/me/call-records'));

  assert.equal(response.status, 502);
  const body = JSON.stringify(await response.json());
  assert.match(body, /control_plane_unavailable/);
  assert.doesNotMatch(body, /postgres|leak-canary|db\.internal/i);
});

test('call records route rejects a malformed cursor before control-plane access', async () => {
  session = { user: { id: 'employee-1' } };
  calls.length = 0;
  listError = null;
  const route = (await import('../src/app/api/me/call-records/route.js?invalid-cursor' as string)) as typeof import('../src/app/api/me/call-records/route.js');
  const response = await route.GET(new Request(
    'http://portal.test/api/me/call-records?cursor=bad%20cursor',
  ));

  assert.equal(response.status, 400);
  assert.equal(response.headers.get('cache-control'), 'private, no-store');
  assert.deepEqual(await response.json(), { error: 'invalid_cursor' });
  assert.equal(calls.length, 0);
});

test('call records route preserves an invalid cursor response from control-plane', async () => {
  session = { user: { id: 'employee-1' } };
  calls.length = 0;
  listError = new MockControlPlaneError('invalid_cursor', 400, 'invalid cursor');
  const route = (await import('../src/app/api/me/call-records/route.js?invalid-cursor-response' as string)) as typeof import('../src/app/api/me/call-records/route.js');
  const response = await route.GET(new Request(
    'http://portal.test/api/me/call-records?cursor=not-a-valid-cursor',
  ));

  assert.equal(response.status, 400);
  assert.equal(response.headers.get('cache-control'), 'private, no-store');
  assert.deepEqual(await response.json(), { error: 'invalid_cursor' });
  assert.equal(calls.length, 1);
});

test('call records route passes a valid request_id and rejects malformed ones', async () => {
  session = { user: { id: 'employee-1' } };
  calls.length = 0;
  listError = null;
  const route = (await import('../src/app/api/me/call-records/route.js?request-id' as string)) as typeof import('../src/app/api/me/call-records/route.js');
  const id = 'req_0123abcd-0123-abcd-0123-0123abcd4567';
  const ok = await route.GET(new Request('http://portal.test/api/me/call-records?request_id=' + id));
  assert.equal(ok.status, 200);
  assert.equal(calls[0].userId, 'employee-1');
  assert.equal((calls[0].query as { requestId?: string }).requestId, id);

  calls.length = 0;
  const bad = await route.GET(new Request('http://portal.test/api/me/call-records?request_id=req-1%27'));
  assert.equal(bad.status, 400);
  assert.equal(calls.length, 0);
});

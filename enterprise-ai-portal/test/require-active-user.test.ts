import test from 'node:test';
import assert from 'node:assert/strict';

import { requireActivePortalUser } from '../src/lib/require-active-user.js';

const gateway = { baseUrl: 'http://cp.test', portalSecret: 'portal-secret' };

type Seen = { url: string; authorization: string; tenant: string };

// Mirrors control-plane GetPortalUserAuthorizationContext: chat_allowed is
// user.Status == "active" (and not emergency mode); unknown users are 404.
function controlPlane(
  reply: { status: number; body: unknown } | 'unreachable',
  seen: Seen[] = [],
): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    seen.push({
      url: String(input),
      authorization: headers.get('authorization') ?? '',
      tenant: headers.get('x-jjdguard-tenant-id') ?? '',
    });
    if (reply === 'unreachable') throw new TypeError('fetch failed');
    return new Response(JSON.stringify(reply.body), {
      status: reply.status,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
}

function context(overrides: Record<string, unknown> = {}) {
  return {
    status: 200,
    body: {
      data: {
        user_id: 'user-1',
        department_id: 'dept-1',
        department_name: 'R&D',
        department_version: 3,
        chat_allowed: true,
        model_ids: ['gpt-5.5'],
        ...overrides,
      },
    },
  };
}

async function denied(result: unknown, status: number, error: string) {
  assert.ok(result instanceof Response, 'expected a Response');
  assert.equal(result.status, status);
  assert.equal(result.headers.get('cache-control'), 'private, no-store');
  assert.deepEqual(await result.json(), { error });
}

test('active user: returns authoritative user and asks control plane every call', async () => {
  const seen: Seen[] = [];
  const session = { user: { id: 'user-1', email: 'a@example.test', name: 'A' } };
  const result = await requireActivePortalUser(session, {
    gateway,
    fetchImpl: controlPlane(context(), seen),
  });
  assert.ok(!(result instanceof Response));
  assert.deepEqual(result.user, {
    id: 'user-1',
    email: 'a@example.test',
    name: 'A',
    departmentId: 'dept-1',
    departmentName: 'R&D',
    departmentVersion: 3,
    modelIds: ['gpt-5.5'],
  });
  assert.deepEqual(seen, [{
    url: 'http://cp.test/admin/v1/portal-integration/users/user-1/authorization-context',
    authorization: 'Bearer portal-secret',
    tenant: 'tenant_default',
  }]);
});

test('no session or no user id: 401 without calling control plane', async () => {
  for (const session of [null, undefined, {}, { user: null }, { user: {} }, { user: { id: '  ' } }, { user: { id: 42 } }]) {
    const seen: Seen[] = [];
    const result = await requireActivePortalUser(session as never, {
      gateway,
      fetchImpl: controlPlane(context(), seen),
    });
    await denied(result, 401, 'unauthorized');
    assert.equal(seen.length, 0);
  }
});

test('disabled user with a still-valid JWT: 403 authorization_denied', async () => {
  const result = await requireActivePortalUser({ user: { id: 'user-1' } }, {
    gateway,
    fetchImpl: controlPlane(context({ chat_allowed: false })),
  });
  await denied(result, 403, 'authorization_denied');
});

test('deleted user (control plane 404): 403 user_inactive', async () => {
  const result = await requireActivePortalUser({ user: { id: 'user-1' } }, {
    gateway,
    fetchImpl: controlPlane({ status: 404, body: { error: { code: 'not_found' } } }),
  });
  await denied(result, 403, 'user_inactive');
});

test('control plane down or malformed: fail closed with 502', async () => {
  for (const reply of [
    'unreachable' as const,
    { status: 500, body: { error: 'internal_error' } },
    { status: 200, body: { data: { user_id: 'someone-else' } } },
  ]) {
    const result = await requireActivePortalUser({ user: { id: 'user-1' } }, {
      gateway,
      fetchImpl: controlPlane(reply),
    });
    await denied(result, 502, 'control_plane_unavailable');
  }
});

test('explicit tenant is forwarded', async () => {
  const seen: Seen[] = [];
  await requireActivePortalUser({ user: { id: 'user-1' } }, {
    gateway,
    tenantId: 'tenant_b',
    fetchImpl: controlPlane(context(), seen),
  });
  assert.equal(seen[0]?.tenant, 'tenant_b');
});


test('local credential version must exist and match the current control-plane version',async()=>{
 const current=context({local_login_allowed:true,local_external_subject:'local-subject',local_credential_version:2});
 for(const version of [undefined,0,1,'2',2.5]){
  const response=await requireActivePortalUser({user:{id:'user-1',localLogin:true,externalSubject:'local-subject',localCredentialVersion:version}},
   {gateway,fetchImpl:controlPlane(current)});
  await denied(response,403,'local_identity_revoked');
 }
 const valid=await requireActivePortalUser({user:{id:'user-1',localLogin:true,externalSubject:'local-subject',localCredentialVersion:2}},
  {gateway,fetchImpl:controlPlane(current)});
 assert.ok(!(valid instanceof Response));
});

test('personal portal access survives absent model permission and exposes no models', async () => {
 const result=await requireActivePortalUser({user:{id:'user-1'}},{gateway,fetchImpl:controlPlane(context({portal_allowed:true,chat_allowed:false,model_ids:['must-not-leak']}))});
 assert.ok(!(result instanceof Response));
 assert.deepEqual(result.user.modelIds,[]);
});
test('explicit personal portal revocation wins over cached model permission',async()=>{
 const result=await requireActivePortalUser({user:{id:'user-1'}},{gateway,fetchImpl:controlPlane(context({portal_allowed:false,chat_allowed:true}))});
 await denied(result,403,'authorization_denied');
});

test('signed session tenant and historical owners are preserved for personal routes',async()=>{
 const seen:Seen[]=[];
 const result=await requireActivePortalUser({user:{id:'user-1',tenantId:'tenant_b',externalSubject:'oidc-1'}},{gateway,fetchImpl:controlPlane(context({history_user_ids:['old-user','user-1']}),seen)});
 assert.ok(!(result instanceof Response));
 assert.equal(seen[0]?.tenant,'tenant_b');
 assert.deepEqual(result.user.historyUserIds,['old-user','user-1']);
});

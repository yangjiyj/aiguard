import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
process.env.AUTH_SECRET = 'isolated-test-auth-secret-minimum-32-characters';
process.env.AUTH_URL = 'http://portal.test/chat/api/auth';
process.env.OIDC_ISSUER = 'https://idp.test';
process.env.OIDC_CLIENT_ID = 'portal';
process.env.OIDC_CLIENT_SECRET = 'isolated-test-client-secret';

let localLoginAllowed = true;
let localCredentialVersion=1;
let localExternalSubject = 'trusted-local-subject';
let profileFailure = false;
let transientAuthorizationFailures = 0;
let authorizationCalls = 0;
const actualNow = Date.now;
function expireAuthzCache() { Date.now = () => actualNow() + 6 * 60 * 1000; }
test.afterEach(() => { Date.now = actualNow; });
class MockControlPlaneError extends Error {
  constructor(readonly code: string, readonly status: number, message: string) { super(message); }
}
const ticketCalls: string[] = [];
const profileCalls: unknown[][] = [];
mock.module('@/lib/control-plane', {
 namedExports: {
  PORTAL_DEFAULT_TENANT_ID: 'tenant_default',
  ControlPlaneError: MockControlPlaneError,
  ensurePortalUser: async () => { throw new Error('local ticket must not synthesize OIDC identity'); },
  getCurrentPortalAuthorization: async () => {
   authorizationCalls += 1;
   if (transientAuthorizationFailures > 0) {
    transientAuthorizationFailures -= 1;
    throw new MockControlPlaneError('control_plane_unreachable', 0, 'temporary outage');
   }
   return {
    userId: 'cp-local-user', departmentId: 'dept-a', departmentName: '研发部', departmentVersion: 3,
    localCredentialVersion, chatAllowed: true, modelIds: ['model-a'], localLoginAllowed, localExternalSubject,
   };
  },
  redeemChatLoginTicket: async (ticket: string) => {
   ticketCalls.push(ticket);
   if (ticket !== 'A'.repeat(43)) throw new Error('invalid ticket');
   return {
    userId: 'cp-local-user', tenantId: 'tenant_default', localCredentialVersion, departmentId: 'dept-a',
    departmentName: '研发部', departmentVersion: 3, externalSubject: 'trusted-local-subject',
    chatAllowed: true, email: 'local@example.test', username: '本地员工',
    resolution: 'manual', created: false,
   };
  },
 },
});
mock.module('@/lib/user-service', { namedExports: {
 applyControlPlaneResolution: async (...args: unknown[]) => {if(profileFailure) throw new Error('profile write failed'); profileCalls.push(args);},
}});

let handlers: {
 GET: (request: NextRequest) => Promise<Response>;
 POST: (request: NextRequest) => Promise<Response>;
};
test.before(async () => { ({ handlers } = await import('../src/auth.js')); });

function cookiesOf(response: Response): string {
 return response.headers.getSetCookie().map((cookie) => cookie.split(';')[0]).join('; ');
}

test('Auth.js exposes ticket credentials alongside existing OIDC providers', async () => {
 const response = await handlers.GET(new NextRequest('http://portal.test/chat/api/auth/providers'));
 const providers = await response.json();
 assert.equal(providers['chat-ticket']?.type, 'credentials');
 assert.equal(providers['account-login']?.type, 'oidc');
 assert.equal(providers['enterprise-sso']?.type, 'oidc');
});

test('one control-plane ticket creates an authenticated Chat session without another password', async () => {
 const csrf = await handlers.GET(new NextRequest('http://portal.test/chat/api/auth/csrf'));
 const { csrfToken } = await csrf.json();
 const response = await handlers.POST(new NextRequest('http://portal.test/chat/api/auth/callback/chat-ticket', {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookiesOf(csrf) },
  body: new URLSearchParams({ csrfToken, ticket: 'A'.repeat(43), callbackUrl: 'http://portal.test/chat', user_id: 'forged-user', external_subject: 'forged-subject' }),
 }));
 assert.equal(response.status, 302);
 assert.equal(response.headers.get('location'), 'http://portal.test/chat');
 const session = await handlers.GET(new NextRequest('http://portal.test/chat/api/auth/session', {
  headers: { cookie: cookiesOf(response) },
 }));
 const data = await session.json();
 assert.equal(data.user.id, 'cp-local-user');
 assert.equal(data.user.externalSubject, 'trusted-local-subject');
 assert.equal(data.user.chatAllowed, true);
 assert.deepEqual(ticketCalls, ['A'.repeat(43)]);
 assert.equal((profileCalls[0]?.[4] as {userId: string}).userId, 'cp-local-user');
});

test('ticket callback still requires Auth.js CSRF validation', async () => {
 const before = ticketCalls.length;
 const response = await handlers.POST(new NextRequest('http://portal.test/chat/api/auth/callback/chat-ticket', {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ticket: 'A'.repeat(43)}),
 }));
 assert.ok((response.headers.get('location') ?? '').includes('error=MissingCSRF'));
 assert.equal(ticketCalls.length, before);
});

async function signedInCookie(): Promise<string> {
 const csrf=await handlers.GET(new NextRequest('http://portal.test/chat/api/auth/csrf'));
 const {csrfToken}=await csrf.json();
 const response=await handlers.POST(new NextRequest('http://portal.test/chat/api/auth/callback/chat-ticket',{
  method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',cookie:cookiesOf(csrf)},
  body:new URLSearchParams({csrfToken,ticket:'A'.repeat(43),callbackUrl:'http://portal.test/chat'}),
 }));
 return cookiesOf(response);
}
test('directory takeover or changed trusted binding clears the local Auth.js session', async () => {
 for (const revoked of ['directory','binding']) {
  localLoginAllowed=true;localExternalSubject='trusted-local-subject';
  const cookie=await signedInCookie();
  if(revoked==='directory') localLoginAllowed=false;
  else localExternalSubject='changed-subject';
  expireAuthzCache();
  const response=await handlers.GET(new NextRequest('http://portal.test/chat/api/auth/session',{headers:{cookie}}));
  assert.equal((await response.json())?.user,undefined);
  assert.ok(response.headers.getSetCookie().some((value)=>value.includes('Max-Age=0')));
  Date.now = actualNow;
 }
 localLoginAllowed=true;localExternalSubject='trusted-local-subject';
});
test('a failed profile write cannot create an authorized Chat cookie', async () => {
 profileFailure=true;
 try {
  const cookie=await signedInCookie();
  const response=await handlers.GET(new NextRequest('http://portal.test/chat/api/auth/session',{headers:{cookie}}));
  assert.equal((await response.json())?.user,undefined);
 } finally {profileFailure=false;}
});
test('browser-shaped callback user cannot forge the server-side ticket identity proof', async () => {
 const {signInCallback,jwtCallback}=await import('../src/auth.js');
 const user={id:'forged',email:'forged@example.test',name:'forged'};
 assert.equal(await signInCallback({account:{provider:'chat-ticket'},user}),false);
 const result=await jwtCallback({trigger:'signIn',account:{provider:'chat-ticket'},user,
  token:{controlPlaneUserId:'old-user',chatAllowed:true,departmentId:'old-dept',departmentVersion:9,externalSubject:'old-subject'}});
 assert.equal(result,null);
});

test('local session rechecks the binding on every refresh and transient failures retain identity only', async () => {
 localLoginAllowed = true; localExternalSubject = 'trusted-local-subject';
 const cookie = await signedInCookie();
 const before = authorizationCalls;
 let response = await handlers.GET(new NextRequest('http://portal.test/chat/api/auth/session', { headers: { cookie } }));
 assert.equal((await response.json()).user.id, 'cp-local-user');
 assert.equal(authorizationCalls, before+1);
 expireAuthzCache(); transientAuthorizationFailures = 1;
 response = await handlers.GET(new NextRequest('http://portal.test/chat/api/auth/session', { headers: { cookie } }));
 const session = await response.json();
 assert.equal(session.user.id, 'cp-local-user');
 assert.equal(session.user.localLogin, true);
 assert.ok(!response.headers.getSetCookie().some((value) => value.includes('Max-Age=0')));
});

test('a cached or transiently retained local session cannot authorize a directory takeover or binding change', async () => {
 const { requireActivePortalUser } = await import('../src/lib/require-active-user.js');
 for (const revoked of ['directory', 'binding']) {
  localLoginAllowed = true; localExternalSubject = 'trusted-local-subject';
  const cookie = await signedInCookie();
  if (revoked === 'directory') localLoginAllowed = false;
  else localExternalSubject = 'changed-subject';
  expireAuthzCache(); transientAuthorizationFailures = 1;
  try {
   const response = await handlers.GET(new NextRequest('http://portal.test/chat/api/auth/session', { headers: { cookie } }));
   const session = await response.json();
   assert.equal(session.user.id, 'cp-local-user');
   const active = await requireActivePortalUser(session);
   assert.ok(active instanceof Response);
   assert.equal(active.status, 403);
   assert.deepEqual(await active.json(), {error: 'local_identity_revoked'});
  } finally {
   Date.now = actualNow; transientAuthorizationFailures = 0;
   localLoginAllowed = true; localExternalSubject = 'trusted-local-subject';
  }
 }
});


test('password rotation permanently rejects the previous local cookie even when the account remains active',async()=>{
 localCredentialVersion=1;localLoginAllowed=true;localExternalSubject='trusted-local-subject';
 const oldCookie=await signedInCookie();
 const before=await handlers.GET(new NextRequest('http://portal.test/chat/api/auth/session',{headers:{cookie:oldCookie}}));
 const cached=await before.json();
 assert.equal(cached.user.localCredentialVersion,1);
 localCredentialVersion=2;
 const {requireActivePortalUser}=await import('../src/lib/require-active-user.js');
 const blocked=await requireActivePortalUser(cached);
 assert.ok(blocked instanceof Response);assert.equal(blocked.status,403);
 expireAuthzCache();
 const revoked=await handlers.GET(new NextRequest('http://portal.test/chat/api/auth/session',{headers:{cookie:oldCookie}}));
 assert.equal((await revoked.json())?.user,undefined);
 assert.ok(revoked.headers.getSetCookie().some(value=>value.includes('Max-Age=0')));
 Date.now=actualNow;
 const freshCookie=await signedInCookie();
 const fresh=await handlers.GET(new NextRequest('http://portal.test/chat/api/auth/session',{headers:{cookie:freshCookie}}));
 assert.equal((await fresh.json()).user.localCredentialVersion,2);
 expireAuthzCache();
 const stillRevoked=await handlers.GET(new NextRequest('http://portal.test/chat/api/auth/session',{headers:{cookie:oldCookie}}));
 assert.equal((await stillRevoked.json())?.user,undefined);
 localCredentialVersion=1;
});

test('a legacy local JWT without a signed credential version cannot regain authorization',async()=>{
 const {jwtCallback}=await import('../src/auth.js');
 const result=await jwtCallback({token:{controlPlaneUserId:'cp-local-user',chatAllowed:true,localLogin:true,
   externalSubject:'trusted-local-subject',authTime:Math.floor(actualNow()/1000),authzCheckedAt:Math.floor(actualNow()/1000)}});
 assert.equal(result,null);
});

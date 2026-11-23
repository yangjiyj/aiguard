import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import test, { mock } from 'node:test';
import { NextRequest } from 'next/server';

process.env.AUTH_SECRET = 'employee-login-isolated-fixture-secret-32-bytes';
process.env.AUTH_URL = 'http://portal.test/chat/api/auth';
process.env.OIDC_ISSUER = '';
process.env.OIDC_CLIENT_ID = '';
process.env.OIDC_CLIENT_SECRET = '';
process.env.JJD_PORTAL_API_SECRET = 'fixture-server-portal-secret';
mock.module('@/lib/user-service', { namedExports: { applyControlPlaneResolution: async () => undefined } });

let replyStatus = 200;
let replyError = '';
let nestedErrors = true;
let returnedRole = 'chat_user';
let redeemedUser = 'employee-1';
let redeemedModelsAllowed=true;
let redeemedPortalAllowed:boolean|undefined;
let requests: Array<{ path: string; body: Record<string, unknown>; tenant: string; authorization: string;clientIP:string }> = [];
const server = createServer(async (request, response) => {
  let raw = '';
  for await (const chunk of request) raw += chunk;
  requests.push({ path: request.url ?? '', body: raw ? JSON.parse(raw) : {},
    clientIP:String(request.headers['x-forwarded-for']??''),tenant: String(request.headers['x-jjdguard-tenant-id'] ?? ''), authorization: String(request.headers.authorization ?? '') });
  response.setHeader('content-type', 'application/json');
  if (request.url === '/admin/v1/employee-login') {
    response.statusCode = replyStatus;
    response.end(JSON.stringify(replyStatus === 200 ? {
      user: { id:'employee-1', username:'alice', tenant_id:'tenant_default', role:returnedRole }, chat_ticket:'T'.repeat(43),
    } : nestedErrors ? {error:{code:replyError,message:'must never appear in portal browser',details:{password:'sensitive upstream detail'}}} : {error:replyError,message:'must never appear in portal browser'}));
  } else if (request.url === '/admin/v1/portal-integration/chat-login/redeem') {
    response.end(JSON.stringify({ user_id:redeemedUser, tenant_id:'tenant_default', username:'alice', email:'alice@example.test',
      local_credential_version:1, department_id:'department-1', department_name:'Research', department_version:7, external_subject:'local-subject', chat_allowed:redeemedModelsAllowed, ...(redeemedPortalAllowed===undefined?{}:{portal_allowed:redeemedPortalAllowed}) }));
  } else if (new URL(request.url??'','http://fixture.test').pathname.endsWith('/authorization-context')) {
    const query=new URL(request.url??'','http://fixture.test').searchParams;
    assert.equal(query.get('external_subject'),'local-subject');
    assert.equal(query.get('login_mode'),'local');
    assert.equal(query.get('local_credential_version'),'1');
    response.end(JSON.stringify({data:{user_id:'employee-1',department_id:'department-1',department_name:'Research',department_version:7,chat_allowed:redeemedModelsAllowed,portal_allowed:redeemedPortalAllowed??true,model_ids:[],local_login_allowed:true,local_credential_version:1,local_external_subject:'local-subject'}}));
  } else {
    response.statusCode = 404;
    response.end('{}');
  }
});
let auth: typeof import('../src/auth.js');
test.before(async () => {
  server.listen(0,'127.0.0.1');
  await once(server,'listening');
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  process.env.JJD_CP_URL = 'http://127.0.0.1:'+address.port;
  auth = await import('../src/auth.js');
});
test.after(() => server.close());
test.beforeEach(() => { replyStatus=200; replyError=''; nestedErrors=true; returnedRole='chat_user'; redeemedUser='employee-1'; redeemedModelsAllowed=true; redeemedPortalAllowed=undefined; requests=[]; });

function cookies(response: Response) { return response.headers.getSetCookie().map(value=>value.split(';')[0]).join('; '); }
async function login(extra: Record<string,string> = {}, csrfEnabled = true) {
  const csrf = await auth.handlers.GET(new NextRequest('http://portal.test/chat/api/auth/csrf'));
  const { csrfToken } = await csrf.json();
  return auth.handlers.POST(new NextRequest('http://portal.test/chat/api/auth/callback/employee-local', {
    method:'POST', headers:{'content-type':'application/x-www-form-urlencoded', ...(csrfEnabled ? {cookie:cookies(csrf)} : {})},
    body:new URLSearchParams({ ...(csrfEnabled ? {csrfToken} : {}), username:' alice ', password:'fixture-password',
      captcha_id:'captcha-1', captcha_code:'ABC123', callbackUrl:'http://portal.test/chat', ...extra }),
  }));
}

test('portal exposes employee credentials without OIDC and keeps passwords and tickets server-side', async () => {
  const providers = await auth.handlers.GET(new NextRequest('http://portal.test/chat/api/auth/providers'));
  assert.equal((await providers.json())['employee-local'].type,'credentials');
  const response = await login({tenant_id:'forged',user_id:'forged',role:'platform_admin',external_subject:'forged',scopes:'*'});
  assert.equal(response.status,302);
  assert.equal(response.headers.get('location'),'http://portal.test/chat');
  const session = await auth.handlers.GET(new NextRequest('http://portal.test/chat/api/auth/session',{headers:{cookie:cookies(response)}}));
  const body = await session.json();
  assert.equal(body.user.id,'employee-1');
  assert.equal(body.user.role,'employee');
  assert.equal(body.user.localLogin,true);
  assert.equal(body.user.externalSubject,'local-subject');
  assert.deepEqual(requests.map(item=>new URL(item.path,'http://fixture.test').pathname),['/admin/v1/employee-login','/admin/v1/portal-integration/chat-login/redeem','/admin/v1/portal-integration/users/employee-1/authorization-context']);
  assert.deepEqual(requests[0].body,{username:'alice',password:'fixture-password',captcha_id:'captcha-1',captcha_code:'ABC123',totp_code:''});
  assert.equal(requests[0].tenant,'tenant_default');
  assert.equal(requests[1].authorization,'Bearer fixture-server-portal-secret');
  assert.doesNotMatch(JSON.stringify(body),/fixture-password|chat_ticket|full_key|admin_token/);
});

test('employee password login requires Auth.js CSRF before any control-plane call', async () => {
  const response = await login({},false);
  assert.ok(response.headers.get('location')?.includes('error=MissingCSRF'));
  assert.equal(requests.length,0);
});

test('malformed input is rejected without invoking credential verification', async () => {
  for (const fields of [{username:'\r\nheader'}, {password:'p'.repeat(1025)}, {captcha_id:''}, {captcha_code:''}, {totp_code:'not-a-totp'}] as Array<Record<string,string>>) {
    requests=[];
    const response = await login(fields);
    assert.ok(response.headers.get('location')?.includes('error=CredentialsSignin'));
    assert.equal(requests.length,0);
  }
});

test('actual nested control-plane errors preserve fixed codes without upstream messages or tickets', async () => {
  for (const [status,error,code] of [[400,'invalid_captcha','captcha_invalid'],[423,'account_locked','account_locked'],
    [401,'totp_required','totp_required'],[403,'password_change_required','password_change_required'],
    [400,'password_policy_violation','password_policy_violation'],[400,'password_history_violation','password_history_violation'],
    [400,'password_too_short','password_policy_violation'],[400,'password_too_few_classes','password_policy_violation'],
    [400,'password_contains_username','password_policy_violation'],[400,'password_reused','password_history_violation'],
    [503,'password_updated_session_revoke_failed','password_updated_retry'],
    [503,'password_sync_unavailable','password_sync_unavailable'],[503,'password_identity_sync_failed','password_identity_sync_failed'],
    [503,'password_updated_identity_sync_failed','password_updated_identity_sync_failed'],[409,'password_change_conflict','password_change_conflict'],
    [409,'password_managed_externally','password_managed_externally'],
    [403,'authorization_denied','authorization_denied'],[401,'__proto__','invalid_credentials'],[503,'chat_login_unavailable','login_unavailable']] as const) {
    replyStatus=status; replyError=error; requests=[];
    const response = await login();
    const location = response.headers.get('location') ?? '';
    assert.ok(location.includes('code='+code),location);
    assert.doesNotMatch(location,/must.never|chat_ticket|fixture-password/);
    assert.equal(requests.length,1);
  }
});

test('legacy flat error envelopes remain compatible without exposing messages',async()=>{
  replyStatus=401;replyError='invalid_credentials';nestedErrors=false;
  const response=await login();
  assert.ok(response.headers.get('location')?.includes('code=invalid_credentials'));
  assert.doesNotMatch(response.headers.get('location')??'',/upstream|sensitive|password/);
});

test('mandatory password rotation submits the new password only to the employee contract',async()=>{
  const response=await login({new_password:'fixture-new-password'});
  assert.equal(response.headers.get('location'),'http://portal.test/chat');
  assert.equal(requests[0].body.new_password,'fixture-new-password');
  assert.equal(requests[0].body.password,'fixture-password');
  assert.equal(requests[1].body.new_password,undefined);
  assert.doesNotMatch(response.headers.get('location')??'',/new_password|fixture-new/);
});

test('ticket failures after password rotation tell the browser to retry with the new password',async()=>{
  replyStatus=503;replyError='chat_login_unavailable';
  const response=await login({new_password:'fixture-new-password'});
  assert.ok(response.headers.get('location')?.includes('code=password_updated_retry'));
  assert.doesNotMatch(response.headers.get('location')??'',/fixture-new|upstream/);
});

test('mismatched redeemed subjects cannot create personal portal sessions', async () => {
  returnedRole='platform_admin';
  redeemedUser='another-user';
  const response = await login();
  assert.ok(response.headers.get('location')?.includes('error=CredentialsSignin'));
  assert.equal(response.headers.getSetCookie().some(value=>value.includes('session-token=')),false);
});

test('every human role signs in to the personal portal with employee scope', async () => {
  for (const role of ['chat_user','developer','viewer','dept_manager','security_officer','auditor','platform_admin','tenant_admin','admin','tenant_owner','operator']) {
    returnedRole=role;
    requests=[];
    const response=await login();
    assert.equal(response.headers.get('location'),'http://portal.test/chat',role);
    const session=await auth.handlers.GET(new NextRequest('http://portal.test/chat/api/auth/session',{headers:{cookie:cookies(response)}}));
    const body=await session.json();
    assert.equal(body.user.id,'employee-1',role);
    assert.equal(body.user.role,'employee',role);
    assert.doesNotMatch(JSON.stringify(body),/fixture-password|chat_ticket|admin_token/);
  }
});


test('native identity failures never downgrade a paused account into a retryable completed password update',async()=>{
 for(const code of ['password_identity_sync_failed','password_updated_identity_sync_failed']){
  replyStatus=503;replyError=code;
  const response=await login({new_password:'fixture-new-password'});
  const location=response.headers.get('location')??'';
  assert.ok(location.includes('code='+code));
  assert.doesNotMatch(location,/password_updated_retry|fixture-new|sensitive/);
  assert.equal(response.headers.getSetCookie().some(value=>value.includes('session-token=')),false);
 }
});

test('local personal session remains available without model authorization',async()=>{
 returnedRole='platform_admin';redeemedModelsAllowed=false;redeemedPortalAllowed=true;
 const response=await login();
 assert.equal(response.headers.get('location'),'http://portal.test/chat');
 const session=await auth.handlers.GET(new NextRequest('http://portal.test/chat/api/auth/session',{headers:{cookie:cookies(response)}}));
 const body=await session.json();
 assert.equal(body.user.id,'employee-1');
 assert.equal(body.user.role,'employee');
});

test('employee login forwards the public edge sanitized real IP across internal proxies',async()=>{
 const {authenticateEmployeeCredentials}=await import('../src/lib/employee-login.js');
 await authenticateEmployeeCredentials({username:'alice',password:'fixture-password',captcha_id:'cap',captcha_code:'ABCD'},new Request('http://portal.test/chat',{headers:{'x-real-ip':'198.51.100.29','x-forwarded-for':'203.0.113.66, 172.20.0.5'}}));
 assert.equal(requests[0]?.clientIP,'198.51.100.29');
});

test('employee login does not sign an unsigned inbound forged source IP',async()=>{
 process.env.JJD_LOGIN_IP_FORWARD_SECRET='fixture-ip-secret';
 try{
 const {authenticateEmployeeCredentials}=await import('../src/lib/employee-login.js');
 await authenticateEmployeeCredentials({username:'alice',password:'fixture-password',captcha_id:'cap',captcha_code:'ABCD'},new Request('http://portal.test/chat',{headers:{'x-real-ip':'198.51.100.29','x-forwarded-for':'198.51.100.29'}}));
 assert.equal(requests[0]?.clientIP,'');
 }finally{delete process.env.JJD_LOGIN_IP_FORWARD_SECRET}
});

test('employee login verifies public signature before forwarding signed attribution',async()=>{
 process.env.JJD_LOGIN_IP_FORWARD_SECRET='fixture-ip-secret';
 try{
 const {clientIPHeaders}=await import('../src/lib/signed-client-ip.js');
 const signed=clientIPHeaders('198.51.100.29');
 const {authenticateEmployeeCredentials}=await import('../src/lib/employee-login.js');
 await authenticateEmployeeCredentials({username:'alice',password:'fixture-password',captcha_id:'cap',captcha_code:'ABCD'},new Request('http://portal.test/chat',{headers:{...signed,'x-real-ip':'198.51.100.29'}}));
 assert.equal(requests[0]?.clientIP,'198.51.100.29');
 }finally{delete process.env.JJD_LOGIN_IP_FORWARD_SECRET}
});

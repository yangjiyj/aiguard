import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseDirectIdentity, resolveDirectAssignment } from '../src/direct-identity.js';

test('local identity accepts absent email with a stable gateway binding', () => {
  for (const email of [undefined, '']) {
    const identity = parseDirectIdentity({
      'x-portal-direct-sso-subject': 'subject-local',
      'x-portal-direct-gateway-user-id': 'user-local',
      'x-portal-direct-department': 'team-rd',
      'x-portal-direct-email': email,
    });
    assert.deepEqual(identity, { ssoSubject: 'subject-local', gatewayUserId: 'user-local', department: 'team-rd', email: '' });
  }
});
test('incomplete direct identities remain rejected', () => {
  assert.equal(parseDirectIdentity({ 'x-portal-direct-sso-subject': 'subject' }), null);
  assert.equal(parseDirectIdentity({ 'x-portal-direct-email': 'user@example.test' }), null);
  assert.equal(parseDirectIdentity({ 'x-portal-direct-sso-subject': 'subject', 'x-portal-direct-gateway-user-id': '  ' }), null);
});
test('legacy email identity remains supported', () => {
  assert.equal(parseDirectIdentity({ 'x-portal-direct-sso-subject': 'subject', 'x-portal-direct-email': 'user@example.test' })?.email, 'user@example.test');
});

test('gateway department project is authoritative for an already bound local user', async () => {
  const direct = { ssoSubject: 'subject', gatewayUserId: 'local-user', email: '', department: 'rd' };
  assert.deepEqual(await resolveDirectAssignment(direct, async () => ({ userId: 'local-user', projectId: 'rd-project', departmentId: 'rd', chatAllowed: true })), { mappedGroup: 'rd', gatewayProjectId: 'rd-project' });
  await assert.rejects(resolveDirectAssignment(direct, async () => ({ userId: 'other-user', projectId: 'other-project' })));
  await assert.rejects(resolveDirectAssignment(direct, async () => ({ userId: 'local-user', projectId: '' })));
  await assert.rejects(resolveDirectAssignment(direct, async () => { throw new Error('unavailable'); }));
});


test('bound project assignment ignores a caller department and requires current Chat authorization', async () => {
  const direct = { ssoSubject: 'subject', gatewayUserId: 'bound-user', email: '', department: 'forged-claim' };
  assert.deepEqual(await resolveDirectAssignment(direct, async () => ({ userId:'bound-user', projectId:'current-project', departmentId:'current-department', chatAllowed:true })), { mappedGroup:'current-department', gatewayProjectId:'current-project' });
  await assert.rejects(resolveDirectAssignment(direct, async () => ({ userId:'bound-user', projectId:'current-project', departmentId:'current-department', chatAllowed:false })));
});

test('trusted local mode is explicit and unknown modes cannot supply identity', () => {
 const headers = {'x-portal-direct-sso-subject':'local-subject','x-portal-direct-gateway-user-id':'cp-user'};
 assert.equal(parseDirectIdentity({...headers, 'x-portal-direct-login-mode':'local','x-portal-direct-local-credential-version':'1'})?.localLogin, true);
 assert.equal(parseDirectIdentity({...headers, 'x-portal-direct-login-mode':'oidc'})?.localLogin, undefined);
 assert.equal(parseDirectIdentity({...headers, 'x-portal-direct-login-mode':'forged'}), null);
 assert.equal(parseDirectIdentity({'x-portal-direct-sso-subject':'local-subject','x-portal-direct-email':'local@example.test','x-portal-direct-login-mode':'local'}), null);
});

test('proxy forwards only its verified local mode and never retries a rejected local binding as OIDC', async () => {
 const {getBoundPortalUser} = await import('../src/gateway.js');
 const original = globalThis.fetch;
 const calls: string[] = [];
 const cfg = {gatewayCpUrl:'http://cp.test',portalApiSecret:'isolated-secret',tenantId:'tenant_default'};
 try {
  globalThis.fetch = async (url) => {calls.push(String(url)); return Response.json({data:{user_id:'cp-user',department_id:'dept',chat_allowed:true,project_id:'project',local_credential_version:1}});};
  await getBoundPortalUser(cfg, 'cp-user', 'local-subject', true,1);
  assert.equal(new URL(calls[0]).searchParams.get('login_mode'), 'local');
  await getBoundPortalUser(cfg, 'cp-user', 'sso-subject');
  assert.equal(new URL(calls[1]).searchParams.has('login_mode'), false);
  globalThis.fetch = async (url) => {calls.push(String(url)); return new Response(null,{status:404});};
  await assert.rejects(()=>getBoundPortalUser(cfg,'cp-user','local-subject',true));
  assert.equal(calls.length, 3);
  assert.equal(new URL(calls[2]).searchParams.get('login_mode'), 'local');
 } finally {globalThis.fetch = original;}
});

test('local signed identity requires a safe current credential version', async () => {
 const headers={'x-portal-direct-sso-subject':'local-subject','x-portal-direct-gateway-user-id':'cp-user','x-portal-direct-login-mode':'local'};
 for(const version of [undefined,'0','-1','1.5','9007199254740993','forged']) assert.equal(parseDirectIdentity({...headers,'x-portal-direct-local-credential-version':version}),null);
 assert.equal(parseDirectIdentity({...headers,'x-portal-direct-local-credential-version':'2'})?.localCredentialVersion,2);
 const {getBoundPortalUser}=await import('../src/gateway.js');const original=globalThis.fetch;
 try{
  globalThis.fetch=async()=>Response.json({data:{user_id:'cp-user',department_id:'dept',project_id:'project',chat_allowed:true,local_credential_version:2}});
  await assert.rejects(()=>getBoundPortalUser({gatewayCpUrl:'http://cp.test',portalApiSecret:'synthetic',tenantId:'tenant'},'cp-user','local-subject',true,1));
 }finally{globalThis.fetch=original;}
});

import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn, execFile } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import pg from 'pg';
import { PrismaClient } from '@prisma/client';

const directory = await mkdtemp(join(tmpdir(),'portal-real-gateway-'));
const env = process.env;
const root = new URL('../../',import.meta.url).pathname;
const databaseUrl = `file:${join(directory,'employees.sqlite')}`;
const sql = new pg.Client({connectionString:env.CONTENT_LOGS_TEST_DATABASE_URL});
await sql.connect();
const reservation = http.createServer();
reservation.listen(0,'127.0.0.1');
await once(reservation,'listening');
const port = (reservation.address() as import('node:net').AddressInfo).port;
await new Promise<void>(resolve=>reservation.close(()=>resolve()));
const childEnv = { ...env, DATABASE_URL:databaseUrl, PORT:String(port), PORTAL_INTERNAL_TOKEN:'fixture-internal-token', PORTAL_KEY_ENC_SECRET:'fixture-store-secret', NEWAPI_PORTAL_API_SECRET:'fixture-portal-secret', PORTAL_TENANT_ID:env.TEST_TENANT, GATEWAY_CP_URL:env.TEST_CP_URL, GATEWAY_BASE_URL:env.TEST_GATEWAY_URL, LOBE_DATABASE_URL:'postgres://unused@127.0.0.1:1/unused', PORTAL_GATEWAY_USER_SYNC_ALLOWED:'true' };
await promisify(execFile)(process.execPath,['node_modules/prisma/build/index.js','migrate','deploy'],{cwd:root,env:childEnv});
const prisma=new PrismaClient({datasources:{db:{url:databaseUrl}}});
await prisma.portalSystemConfig.create({data:{tenantId:env.TEST_TENANT!,key:'gateway_user_sync_enabled',value:'true'}});
const child=spawn(process.execPath,['--import','tsx','src/server.ts'],{cwd:root,env:childEnv,stdio:['ignore','pipe','pipe']});
let logs='';
child.stdout!.on('data',chunk=>logs+=String(chunk));
child.stderr!.on('data',chunk=>logs+=String(chunk));
const url=`http://127.0.0.1:${port}`;
try {
  for(let i=0;i<200;i++) {
    try {if((await fetch(url+'/healthz')).ok)break;}catch{}
    if(child.exitCode!==null)throw new Error('isolated proxy exited before readiness');
    if(i===199)throw new Error('isolated proxy readiness timeout');
    await new Promise(resolve=>setTimeout(resolve,25));
  }
  const headers=(user:string,subject:string)=>({authorization:'Bearer fixture-internal-token','x-portal-direct-gateway-user-id':user,'x-portal-direct-sso-subject':subject,'x-portal-direct-department':'forged-caller-department','x-portal-direct-email':''});
  const automaticHeaders=headers(env.TEST_AUTOMATIC_USER!,'engineer-subject');
  const identity=async(user:string)=>(await sql.query('SELECT department_id,department_version,department_assignment_mode FROM users WHERE tenant_id=$1 AND id=$2',[env.TEST_TENANT,user])).rows[0];
  const models=async(h:Record<string,string>)=>{const response=await fetch(url+'/v1/models',{headers:h});assert.equal(response.status,200,await response.clone().text());return await response.json();};
  const chat=async(h:Record<string,string>,model:string)=>fetch(url+'/v1/chat/completions',{method:'POST',headers:{...h,'content-type':'application/json'},body:JSON.stringify({model,messages:[{role:'user',content:'isolated test request'}],stream:false})});
  const machineHeaders={'content-type':'application/json','X-NewAPI-Internal-Token':'fixture-portal-secret','X-JJDGuard-Tenant-Id':env.TEST_TENANT!};
  const ensure=async(user:string,subject:string,local=false)=>{
    const response=await fetch(env.TEST_CP_URL+'/admin/v1/portal-integration/employee-key/ensure',{method:'POST',headers:machineHeaders,body:JSON.stringify({user_id:user,login_mode:local?'local':'oidc',external_subject:subject,...(local?{local_credential_version:1}:{})})});
    assert.equal(response.status,200,'explicit login/bootstrap write provisions a current credential');
  };
  const readonlyBefore=await fetch(env.TEST_CP_URL+'/admin/v1/portal-integration/employee-key/credential?'+new URLSearchParams({user_id:env.TEST_AUTOMATIC_USER!,login_mode:'oidc',external_subject:'engineer-subject'}),{headers:machineHeaders});
  assert.equal(readonlyBefore.status,403,'GET credential does not implicitly create the first Key');
  assert.equal((await sql.query('SELECT count(*) FROM employee_api_keys WHERE tenant_id=$1 AND user_id=$2',[env.TEST_TENANT,env.TEST_AUTOMATIC_USER])).rows[0].count,'0');
  await ensure(env.TEST_AUTOMATIC_USER!,'engineer-subject');
  await ensure(env.TEST_SECOND_USER!,env.TEST_SECOND_USER!+'-subject');
  await ensure(env.TEST_LOCAL_USER!,env.TEST_LOCAL_USER!+'-subject',true);
  const before=await identity(env.TEST_AUTOMATIC_USER!);
  assert.equal(before.department_assignment_mode,'automatic');
  const availableModels=['callable-model','no-endpoint','personal-other','unsupported-protocol'];
  for(let i=0;i<3;i++) {
    const catalog=await models(automaticHeaders);
    assert.deepEqual(catalog.models.map((m:any)=>m.id),availableModels);
    const response=await chat(automaticHeaders,'callable-model');
    assert.equal(response.status,200,await response.text());
    assert.deepEqual(await identity(env.TEST_AUTOMATIC_USER!),before,'reading/sending must not change the real automatic external-group mapping');
  }
  const blockedProtocol=await chat(automaticHeaders,'unsupported-protocol');
  assert.equal(blockedProtocol.status,400,'administrator-disabled protocol remains blocked');
  assert.equal((await blockedProtocol.json()).error.code,'provider_unsupported');
  const employee=(await sql.query('SELECT key_id as "gatewayKeyId",generation FROM employee_api_keys WHERE tenant_id=$1 AND user_id=$2',[env.TEST_TENANT,env.TEST_AUTOMATIC_USER])).rows[0];
  assert.ok(employee,'current employee Key stored in the control plane');
  assert.equal(await prisma.employeeKey.count(),0,'bound employee request never persists a stale proxy Key');
  const firstKey=(await sql.query('SELECT user_id,project_id,status FROM internal_keys WHERE tenant_id=$1 AND id=$2',[env.TEST_TENANT,employee.gatewayKeyId])).rows[0];
  assert.deepEqual(firstKey,{user_id:env.TEST_AUTOMATIC_USER,project_id:env.TEST_PROJECT,status:'active'});
  const secondHeaders=headers(env.TEST_SECOND_USER!,env.TEST_SECOND_USER!+'-subject');
  assert.deepEqual((await models(secondHeaders)).models.map((m:any)=>m.id),['callable-model']);
  assert.equal((await chat(secondHeaders,'personal-other')).status,403);
  await sql.query(`UPDATE user_model_policies SET model_names='[]',version=version+1 WHERE tenant_id=$1 AND user_id=$2`,[env.TEST_TENANT,env.TEST_SECOND_USER]);
  assert.deepEqual((await models(secondHeaders)).models,[]);
  assert.equal((await chat(secondHeaders,'callable-model')).status,403,'same employee key cannot call a personally revoked model');
  const localHeaders={...headers(env.TEST_LOCAL_USER!,env.TEST_LOCAL_USER!+'-subject'),'x-portal-direct-login-mode':'local','x-portal-direct-local-credential-version':'1'};
  assert.deepEqual((await models(localHeaders)).models.map((m:any)=>m.id),availableModels);
  assert.equal((await chat(localHeaders,'callable-model')).status,200,'manual local first use works without email or a prior app membership');
  await sql.query(`UPDATE users SET department_id=$3,department_assignment_mode='manual' WHERE tenant_id=$1 AND id=$2`,[env.TEST_TENANT,env.TEST_AUTOMATIC_USER,env.TEST_NEXT_DEPARTMENT]);
  const moved=await identity(env.TEST_AUTOMATIC_USER!);
  await ensure(env.TEST_AUTOMATIC_USER!,'engineer-subject');
  await models(automaticHeaders);
  assert.equal((await chat(automaticHeaders,'callable-model')).status,200);
  assert.deepEqual(await identity(env.TEST_AUTOMATIC_USER!),moved);
  const switched=(await sql.query('SELECT key_id as "gatewayKeyId",generation FROM employee_api_keys WHERE tenant_id=$1 AND user_id=$2',[env.TEST_TENANT,env.TEST_AUTOMATIC_USER])).rows[0];
  assert.notEqual(switched.gatewayKeyId,employee.gatewayKeyId);
  const currentKey=(await sql.query('SELECT user_id,project_id,status FROM internal_keys WHERE tenant_id=$1 AND id=$2',[env.TEST_TENANT,switched.gatewayKeyId])).rows[0];
  assert.deepEqual(currentKey,{user_id:env.TEST_AUTOMATIC_USER,project_id:env.TEST_NEXT_PROJECT,status:'active'});
  assert.equal((await sql.query('SELECT status FROM internal_keys WHERE tenant_id=$1 AND id=$2',[env.TEST_TENANT,employee.gatewayKeyId])).rows[0].status,'revoked');

  const coordinates={user_id:env.TEST_AUTOMATIC_USER!,login_mode:'oidc',external_subject:'engineer-subject'};
  const originalCredential=await (await fetch(env.TEST_CP_URL+'/admin/v1/portal-integration/employee-key/credential?'+new URLSearchParams(coordinates),{headers:machineHeaders})).json();
  const resetResponse=await fetch(env.TEST_CP_URL+'/admin/v1/portal-integration/employee-key/reset',{method:'POST',headers:machineHeaders,body:JSON.stringify({...coordinates,expected_key_id:switched.gatewayKeyId,expected_generation:Number(switched.generation)})});
  assert.equal(resetResponse.status,200,'managed reset succeeds');
  const rotated=await resetResponse.json();
  assert.ok(rotated.full_key&&rotated.full_key!==originalCredential.credential,'reset changed credential');
  assert.equal((await fetch(env.TEST_GATEWAY_URL+'/v1/models',{headers:{authorization:'Bearer '+originalCredential.credential}})).status,401,'old managed Key immediately rejected by the real gateway');
  assert.equal((await chat(automaticHeaders,'callable-model')).status,200,'same signed Chat identity uses the rotated credential on its next request');
  await sql.query('UPDATE users SET local_credential_version=local_credential_version+1 WHERE tenant_id=$1 AND id=$2',[env.TEST_TENANT,env.TEST_LOCAL_USER]);
  assert.equal((await fetch(url+'/v1/models',{headers:localHeaders})).status,403,'old signed local credential version rejected');
  const forged=await fetch(url+'/v1/models',{headers:headers(env.TEST_AUTOMATIC_USER!,'someone-else')});
  assert.equal(forged.status,403);
  assert.doesNotMatch(logs,/fixture-store-secret|fixture-upstream-key|sk-[a-zA-Z0-9]{24}/);
  console.log('real CP PG -> proxy -> gateway: automatic group preserved across 3 model/chat requests; app deny and missing credential hidden; unverified models listed; administrator protocol override blocked; per-user revocation, local first-use, credential reset and department migration passed');
} finally {
  child.kill('SIGTERM');
  if(child.exitCode===null)await once(child,'exit');
  await prisma.$disconnect();
  await sql.end();
  await rm(directory,{recursive:true,force:true});
}

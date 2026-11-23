import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import test, { mock } from 'node:test';

type Session={user:{id:string;externalSubject:string;localLogin:boolean;localCredentialVersion?:number}};
let session:Session|null={user:{id:'employee-1',externalSubject:'local-subject',localLogin:true,localCredentialVersion:1}};
mock.module('@/auth',{namedExports:{auth:async()=>session}});
let active=true;
let owner='employee-1';
let replyStatus=200;
let replyError='';
let generation=1;
let claimed=false;
let seen:Array<{path:string;method:string;body:Record<string,unknown>;tenant:string;authorization:string}>=[];
const metadata=()=>({id:'managed-key-1',tenant_id:'tenant_default',user_id:owner,project_id:'project-1',prefix:'masked-prefix',
  generation,status:'active',created_at:'2026-10-12T00:00:00Z',first_claim_at:claimed?'2026-10-12T00:01:00Z':null,scopes:['chat','models']});
const server=createServer(async(request,response)=>{
  let raw='';for await(const part of request)raw+=part;
  seen.push({path:request.url??'',method:request.method??'',body:raw?JSON.parse(raw):{},
    tenant:String(request.headers['x-jjdguard-tenant-id']??''),authorization:String(request.headers.authorization??'')});
  response.setHeader('content-type','application/json');
  if(new URL(request.url??'','http://fixture.test').pathname==='/admin/v1/portal-integration/users/employee-1/authorization-context'){
    response.end(JSON.stringify({data:{user_id:'employee-1',department_id:'department-1',department_name:'Authoritative Department',
      department_version:7,chat_allowed:active,model_ids:['model-1'],local_credential_version:1,local_login_allowed:true,local_external_subject:'local-subject'}}));
    return;
  }
  response.statusCode=replyStatus;
  if(replyStatus!==200){response.end(JSON.stringify({error:{code:replyError,message:'sensitive internal value',details:{credential:'must-not-leak'}}}));return;}
  response.end(JSON.stringify({key:metadata(),full_key:'fixture-only-complete-key'}));
});
let service:typeof import('../src/lib/employee-key-service.js');
test.before(async()=>{
  server.listen(0,'127.0.0.1');await once(server,'listening');const address=server.address();assert.ok(address&&typeof address==='object');
  process.env.JJD_CP_URL='http://127.0.0.1:'+address.port;process.env.JJD_PORTAL_API_SECRET='fixture-private-portal-secret';
  process.env.PORTAL_PUBLIC_URL='http://portal.test/chat';
  service=await import('../src/lib/employee-key-service.js');
});
test.after(()=>server.close());
test.beforeEach(()=>{session={user:{id:'employee-1',externalSubject:'local-subject',localLogin:true,localCredentialVersion:1}};active=true;owner='employee-1';
  replyStatus=200;replyError='';generation=1;claimed=false;seen=[];});
function writeRequest(body:Record<string,unknown>={},origin:string|null='http://portal.test'){
  return new Request('http://portal.test/chat/api/me/employee-key/claim',{method:'POST',
    headers:{'content-type':'application/json',...(origin?{origin}:{})},
    body:JSON.stringify({expected_key_id:'managed-key-1',expected_generation:1,...body})});
}

test('metadata uses the signed local binding and never forwards a complete credential',async()=>{
  const response=await service.employeeKeyRequest(new Request('http://portal.test/chat/api/me/employee-key?user_id=attacker'),'metadata');
  assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'private, no-store');
  const payload=await response.json();assert.equal(payload.data.id,'managed-key-1');assert.equal(payload.data.claim_available,true);
  assert.doesNotMatch(JSON.stringify(payload),/fixture-only|full_key|credential|cipher|hash/);
  const url=new URL(seen[1].path,'http://control-plane.test');
  assert.equal(url.pathname,'/admin/v1/portal-integration/employee-key');
  assert.equal(url.searchParams.get('user_id'),'employee-1');assert.equal(url.searchParams.get('login_mode'),'local');
  assert.equal(url.searchParams.get('external_subject'),'local-subject');
});

test('claim forwards only verified identity and compare-and-swap coordinates',async()=>{
  claimed=true;
  const response=await service.employeeKeyRequest(writeRequest({user_id:'attacker',tenant_id:'forged',login_mode:'oidc',external_subject:'forged'}),'claim');
  assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'private, no-store');
  const payload=await response.json();assert.equal(payload.full_key,'fixture-only-complete-key');assert.equal(payload.data.claim_available,false);
  assert.deepEqual(seen[1].body,{user_id:'employee-1',login_mode:'local',external_subject:'local-subject',local_credential_version:1,expected_key_id:'managed-key-1',expected_generation:1});
  assert.equal(seen[1].tenant,'tenant_default');assert.equal(seen[1].authorization,'Bearer fixture-private-portal-secret');
});

test('SSO reset sends the signed OIDC subject and current generation',async()=>{
  session={user:{id:'employee-1',externalSubject:'verified-oidc-subject',localLogin:false}};generation=2;claimed=true;
  const response=await service.employeeKeyRequest(writeRequest(),'reset');
  assert.equal(response.status,200);assert.equal((await response.json()).data.generation,2);
  assert.equal(seen[1].body.login_mode,'oidc');assert.equal(seen[1].body.external_subject,'verified-oidc-subject');
  assert.equal(seen[1].path,'/admin/v1/portal-integration/employee-key/reset');
});

test('missing or foreign Origin and invalid compare-and-swap values cause no upstream side effect',async()=>{
  for(const request of [writeRequest({},null),writeRequest({},'http://attacker.test'),
    writeRequest({expected_generation:0}),writeRequest({expected_key_id:''}),writeRequest({expected_generation:1.5})]){
    seen=[];const response=await service.employeeKeyRequest(request,'claim');assert.ok([400,403].includes(response.status));assert.equal(seen.length,0);
  }
});

test('disabled users and revoked local credentials cannot read or claim keys',async()=>{
  active=false;
  let response=await service.employeeKeyRequest(writeRequest(),'claim');assert.equal(response.status,403);assert.equal(seen.length,1);
  active=true;seen=[];session={user:{id:'employee-1',externalSubject:'revoked-subject',localLogin:true,localCredentialVersion:1}};
  response=await service.employeeKeyRequest(writeRequest(),'reset');assert.equal(response.status,403);assert.equal(seen.length,1);
});

test('another owner metadata is rejected and nested conflicts expose only fixed codes',async()=>{
  owner='another-user';
  let response=await service.employeeKeyRequest(new Request('http://portal.test/chat/api/me/employee-key'),'metadata');
  assert.equal(response.status,502);
  for(const code of ['employee_key_conflict','employee_key_already_claimed']){
    replyStatus=409;replyError=code;
    response=await service.employeeKeyRequest(writeRequest(),'claim');
    assert.equal(response.status,409);assert.deepEqual(await response.json(),{error:code});
  }
});

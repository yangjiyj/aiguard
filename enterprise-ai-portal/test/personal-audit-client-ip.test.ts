import test,{mock} from 'node:test';import assert from 'node:assert/strict';import {clientIPHeaders} from '../src/lib/signed-client-ip.js';
mock.module('@/auth',{namedExports:{auth:async()=>({user:{id:'owner',tenantId:'tenant'}})}});
mock.module('@/lib/require-active-user',{namedExports:{requireActivePortalUser:async()=>({user:{id:'owner'}})}});
test('personal reveal and revoke carry signed real actor IP to audit',async()=>{
 process.env.JJD_CP_URL='http://cp.test';process.env.JJD_PORTAL_API_SECRET='fixture';process.env.PORTAL_PUBLIC_URL='http://portal.test/chat';process.env.JJD_LOGIN_IP_FORWARD_SECRET='fixture-ip-secret';
 const original=globalThis.fetch;
 const calls:Array<{path:string;headers:Headers}>=[];
 globalThis.fetch=async(input,init)=>{
  const path=String(input);calls.push({path,headers:new Headers(init?.headers)});
  if(path.includes('/customer-keys/')&&path.endsWith('/reveal?user_id=owner'))return Response.json({full_key:'fixture-once-secret'});
  if(path.includes('/revoke'))return new Response(null,{status:204});
  return Response.json({data:[{id:'own-key',user_id:'owner',tenant_id:'tenant',name:'fixture',prefix:'masked',project_id:'project',scopes:['chat'],status:'active',created_at:'2026-10-13T00:00:00Z'}]});
 };
 try{
  const request=()=>new Request('http://portal.test/chat/api/me/keys/own-key/revoke',{method:'POST',headers:{origin:'http://portal.test',...clientIPHeaders('198.51.100.41'),'x-real-ip':'198.51.100.41'}});
  const reveal=await import('../src/app/api/me/keys/[id]/reveal/route.js');assert.equal((await reveal.POST(request(),{params:Promise.resolve({id:'own-key'})})).status,200);
  const revoke=await import('../src/app/api/me/keys/[id]/revoke/route.js');assert.equal((await revoke.POST(request(),{params:Promise.resolve({id:'own-key'})})).status,204);
  for(const call of calls.filter(c=>c.path.includes('/reveal')||c.path.includes('/revoke'))){
   assert.equal(call.headers.get('x-forwarded-for'),'198.51.100.41');assert.match(call.headers.get('x-jjd-client-ip-signature')??'',/^[a-f0-9]{64}$/);
  }
 }finally{globalThis.fetch=original;delete process.env.JJD_LOGIN_IP_FORWARD_SECRET}
});

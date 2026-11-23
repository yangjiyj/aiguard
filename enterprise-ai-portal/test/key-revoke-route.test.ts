import test,{mock} from 'node:test';import assert from 'node:assert/strict';
mock.module('@/auth',{namedExports:{auth:async()=>({user:{id:'owner',tenantId:'tenant-test'}})}});
mock.module('@/lib/require-active-user',{namedExports:{requireActivePortalUser:async()=>({user:{id:'owner'}})}});
test('BFF rejects foreign Key without a revoke and supplies only its signed owner',async()=>{
 process.env.PORTAL_PUBLIC_URL='http://portal.test/chat';process.env.JJD_CP_URL='http://cp.test';process.env.JJD_PORTAL_API_SECRET='fixture';
 const {POST}=await import('../src/app/api/me/keys/[id]/revoke/route.js');
 const old=globalThis.fetch;const calls:string[]=[];
 globalThis.fetch=async(input,init)=>{calls.push(String(input));assert.equal(new Headers(init?.headers).get('x-jjdguard-tenant-id'),'tenant-test');return String(input).includes('/revoke')?new Response(null,{status:204}):Response.json({data:[{id:'own-key',user_id:'owner',tenant_id:'tenant-test',name:'test',prefix:'masked',project_id:'project',scopes:['chat'],status:'active',created_at:'2026-10-13T00:00:00Z'}]})};
 try{
  const request=()=>new Request('http://portal.test/chat/api/me/keys/any/revoke',{method:'POST',headers:{origin:'http://portal.test'},body:'{"user_id":"forged"}'});
  assert.equal((await POST(request(),{params:Promise.resolve({id:'foreign-key'})})).status,404);
  assert.equal(calls.some(v=>v.includes('/revoke')),false);
  calls.length=0;
  assert.equal((await POST(request(),{params:Promise.resolve({id:'own-key'})})).status,204);
  assert.equal(new URL(calls[1]).searchParams.get('user_id'),'owner');
 }finally{globalThis.fetch=old}
});

test('personal key metadata retains use and expiry for display',async()=>{
 process.env.JJD_CP_URL='http://cp.test';process.env.JJD_PORTAL_API_SECRET='fixture';
 const old=globalThis.fetch;
 globalThis.fetch=async()=>Response.json({data:[{id:'own-key',user_id:'owner',tenant_id:'tenant-test',prefix:'masked',project_id:'project',scopes:['chat'],status:'active',created_at:'2026-10-13T00:00:00Z',last_used_at:'2026-10-12T08:30:00Z',expires_at:'2027-10-13T00:00:00Z'}]});
 try{
  const {GET}=await import('../src/app/api/me/keys/route.js');
  const response=await GET(new Request('http://portal.test/chat/api/me/keys'));
  const payload=await response.json();assert.equal(payload.data[0].last_used_at,'2026-10-12T08:30:00Z');assert.equal(payload.data[0].expires_at,'2027-10-13T00:00:00Z');
 }finally{globalThis.fetch=old}
});

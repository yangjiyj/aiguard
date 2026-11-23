import test,{mock} from 'node:test';
import assert from 'node:assert/strict';
mock.module('@/auth',{namedExports:{auth:async()=>({user:{id:'user',tenantId:'tenant_default'}})}});
mock.module('@/lib/require-active-user',{namedExports:{requireActivePortalUser:async()=>({user:{id:'user',projectId:'project'}})}});
test('key creation rejects foreign/missing Origin before any control-plane call',async()=>{
 process.env.PORTAL_PUBLIC_URL='http://portal.test/chat';process.env.JJD_CP_URL='http://cp.test';process.env.JJD_PORTAL_API_SECRET='fixture';
 const {POST}=await import('../src/app/api/me/keys/route.js');
 let calls=0;const original=globalThis.fetch;globalThis.fetch=async()=>{calls++;return Response.json({})};
 try{
  for(const origin of [undefined,'http://attacker.test']){
   const response=await POST(new Request('http://portal.test/chat/api/me/keys',{method:'POST',headers:{'content-type':'application/json',...(origin?{origin}:{})},body:'{"name":"test"}'}));
   assert.equal(response.status,403);assert.equal(calls,0);
  }
 }finally{globalThis.fetch=original}
});

test('all sensitive writes reject cross-site Origin before private calls',async()=>{
 process.env.PORTAL_PUBLIC_URL='http://portal.test/chat';process.env.JJD_CP_URL='http://cp.test';process.env.JJD_PORTAL_API_SECRET='fixture';
 const reveal=await import('../src/app/api/me/keys/[id]/reveal/route.js');
 const limits=await import('../src/app/api/me/billing/limits/route.js');
 const redeem=await import('../src/app/api/me/billing/redeem/route.js');
 const old=globalThis.fetch;let calls=0;globalThis.fetch=async()=>{calls++;return Response.json({})};
 try{
  const req=(method:string,body:unknown)=>new Request('http://portal.test/chat/api/me',{method,headers:{origin:'http://evil.test','sec-fetch-site':'cross-site','content-type':'application/json'},body:JSON.stringify(body)});
  assert.equal((await reveal.POST(req('POST',{}),{params:Promise.resolve({id:'key'})})).status,403);
  assert.equal((await limits.PUT(req('PUT',{daily_amount_micros:0,monthly_amount_micros:0,daily_token_limit:0,monthly_token_limit:0,rpm_limit:0,concurrency_limit:0}))).status,403);
  assert.equal((await redeem.POST(req('POST',{code:'synthetic'}))).status,403);
  assert.equal(calls,0);
 }finally{globalThis.fetch=old}
});
test('reveal repeated attempts are limited in the BFF and safely map the control-plane code',async()=>{
 const {__resetRateLimit}=await import('../src/lib/rate-limit.js');__resetRateLimit();
 const {POST}=await import('../src/app/api/me/keys/[id]/reveal/route.js');
 const old=globalThis.fetch;let calls=0;
 globalThis.fetch=async()=>{calls++;return Response.json({full_key:'synthetic-test-only'})};
 try{
  for(let i=0;i<6;i++){
   const r=await POST(new Request('http://portal.test/chat/api/me/keys/k/reveal',{method:'POST',headers:{origin:'http://portal.test'}}),{params:Promise.resolve({id:'key'})});
   assert.equal(r.status,i<5?200:429);
  }
  assert.equal(calls,5);
 }finally{globalThis.fetch=old;__resetRateLimit()}
});

test('跨站写请求即使 JSON 损坏也先返回 Origin 拒绝',async()=>{
 const create=await import('../src/app/api/me/keys/route.js'),redeem=await import('../src/app/api/me/billing/redeem/route.js');
 const request=()=>new Request('https://portal.test/chat/api/me',{method:'POST',headers:{origin:'https://evil.test','content-type':'application/json'},body:'{'});
 assert.equal((await create.POST(request())).status,403);
 assert.equal((await redeem.POST(request())).status,403);
});

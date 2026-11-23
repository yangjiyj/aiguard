import test,{mock} from 'node:test';import assert from 'node:assert/strict';
mock.module('@/auth',{namedExports:{auth:async()=>({user:{id:'owner'}})}});
mock.module('@/lib/require-active-user',{namedExports:{requireActivePortalUser:async()=>({user:{id:'owner'}})}});
test('billing and limits never relay internal error messages',async()=>{
 process.env.JJD_CP_URL='http://cp.test';process.env.JJD_PORTAL_API_SECRET='fixture';process.env.PORTAL_PUBLIC_URL='http://portal.test/chat';
 const original=globalThis.fetch;globalThis.fetch=async()=>Response.json({error:'sensitive database address and internal detail'},{status:500});
 try{
  const billing=await import('../src/app/api/me/billing/route.js');const limits=await import('../src/app/api/me/billing/limits/route.js');
  const responses=[await billing.GET(),await limits.PUT(new Request('http://portal.test/chat/api/me/billing/limits',{method:'PUT',headers:{origin:'http://portal.test','content-type':'application/json'},body:JSON.stringify({daily_amount_micros:0,monthly_amount_micros:0,daily_token_limit:0,monthly_token_limit:0,rpm_limit:0,concurrency_limit:0})}))];
  for(const response of responses){assert.equal(response.status,502);assert.deepEqual(await response.json(),{error:'control_plane_error'})}
 }finally{globalThis.fetch=original}
});

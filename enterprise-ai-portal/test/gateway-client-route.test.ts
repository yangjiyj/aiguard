import test,{mock} from 'node:test';import assert from 'node:assert/strict';
let active=true;
mock.module('@/auth',{namedExports:{auth:async()=>({user:{id:'owner',tenantId:'tenant'}})}});
mock.module('@/lib/require-active-user',{namedExports:{requireActivePortalUser:async()=>active?{user:{id:'owner'}}:Response.json({error:'user_inactive'},{status:403})}});
test('gateway BFF uses safe client config and current identity',async()=>{
 process.env.JJD_CP_URL='http://cp.test';process.env.JJD_PORTAL_API_SECRET='fixture';delete process.env.GATEWAY_PUBLIC_URL;
 const old=globalThis.fetch;let calls=0;globalThis.fetch=async(input,init)=>{calls++;assert.equal(new Headers(init?.headers).get('x-jjdguard-tenant-id'),'tenant');assert.ok(String(input).endsWith('/client-config'));return Response.json({api_url:'https://gateway.test/v1',internal_secret:'never-return'})};
 try{const {GET}=await import('../src/app/api/me/gateway/route.js');const reply=await GET();assert.equal(reply.status,200);const body=await reply.json();assert.equal(body.data.openai,'https://gateway.test/v1');assert.equal(body.data.anthropic,'https://gateway.test');assert.equal(JSON.stringify(body).includes('never-return'),false);
 active=false;assert.equal((await GET()).status,403);assert.equal(calls,1);
 }finally{globalThis.fetch=old;active=true}
});

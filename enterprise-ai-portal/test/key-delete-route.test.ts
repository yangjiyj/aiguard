import test,{mock} from 'node:test';
import assert from 'node:assert/strict';
let signedIn=true;
mock.module('@/auth',{namedExports:{auth:async()=>signedIn?{user:{id:'signed-owner',tenantId:'tenant-test'}}:null}});
mock.module('@/lib/require-active-user',{namedExports:{requireActivePortalUser:async()=>({user:{id:'signed-owner'}})}});
test('personal DELETE binds signed identity, rejects CSRF, and retains no response cache',async()=>{
 process.env.JJD_CP_URL='http://cp.test';process.env.JJD_PORTAL_API_SECRET='fixture';
 const {DELETE}=await import('../src/app/api/me/keys/[id]/route.js');
 const old=globalThis.fetch;const calls:Array<{url:string;init?:RequestInit}>=[];
 let status=204;
 globalThis.fetch=async(input,init)=>{calls.push({url:String(input),init});return status===204?new Response(null,{status}):Response.json({error:'not_found'},{status})};
 const request=(origin='https://portal.test')=>new Request('https://portal.test/chat/api/me/keys/owned?user_id=forged',{method:'DELETE',headers:{origin},body:'{"user_id":"forged"}'});
 const context={params:Promise.resolve({id:'owned'})};
 try{
  signedIn=false;assert.equal((await DELETE(request(),context)).status,401);signedIn=true;
  assert.equal((await DELETE(request('https://evil.test'),context)).status,403);assert.equal(calls.length,0);
  assert.equal((await DELETE(request(),{params:Promise.resolve({id:''})})).status,400);assert.equal(calls.length,0);
  const response=await DELETE(request(),context);assert.equal(response.status,204);assert.match(response.headers.get('cache-control')??'',/no-store/);
  assert.equal(calls[0].init?.method,'DELETE');assert.equal(calls[0].init?.body,undefined);
  assert.equal(new URL(calls[0].url).searchParams.get('user_id'),'signed-owner');assert.equal(new Headers(calls[0].init?.headers).get('x-jjdguard-tenant-id'),'tenant-test');
  status=404;assert.equal((await DELETE(request(),context)).status,404);
  globalThis.fetch=async()=>{throw new Error('private internal URL')};
  const failed=await DELETE(request(),context);assert.equal(failed.status,502);assert.ok(!(await failed.text()).includes('private internal URL'));
 }finally{signedIn=true;globalThis.fetch=old}
});

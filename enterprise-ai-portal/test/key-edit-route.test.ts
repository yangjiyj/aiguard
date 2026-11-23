import test,{mock} from 'node:test';import assert from 'node:assert/strict';
mock.module('@/auth',{namedExports:{auth:async()=>({user:{id:'owner',tenantId:'tenant-test'}})}});
mock.module('@/lib/require-active-user',{namedExports:{requireActivePortalUser:async()=>({user:{id:'owner',modelIds:['approved']}})}});
test('编辑 Key 绑定当前用户，Origin 失败无副作用，模型限制被传给后端复核',async()=>{
 process.env.JJD_CP_URL='http://cp.test';process.env.JJD_PORTAL_API_SECRET='fixture';
 const {PATCH}=await import('../src/app/api/me/keys/[id]/route.js');
 const original=globalThis.fetch;const calls:Array<{url:string;body:unknown}>=[];
 globalThis.fetch=async(input,init)=>{calls.push({url:String(input),body:JSON.parse(String(init?.body??'{}'))});return Response.json({data:{id:'owned-key'}})};
 try{
  const request=(origin:string)=>new Request('https://portal.test/chat/api/me/keys/owned-key',{method:'PATCH',headers:{origin,'content-type':'application/json'},body:JSON.stringify({name:'受限',model_allowlist:['approved'],user_id:'forged'})});
  assert.equal((await PATCH(request('https://evil.test'),{params:Promise.resolve({id:'owned-key'})})).status,403);assert.equal(calls.length,0);
  assert.equal((await PATCH(request('https://portal.test'),{params:Promise.resolve({id:'owned-key'})})).status,200);
  assert.equal(new URL(calls[0].url).searchParams.get('user_id'),'owner');
  assert.deepEqual(calls[0].body,{name:'受限',model_allowlist:['approved']});
 }finally{globalThis.fetch=original}
});

import test,{mock} from 'node:test';import assert from 'node:assert/strict';
let active=true;let modelIds=['m1','m2'];let session:{user:{id:string;tenantId:string}}|null={user:{id:'owner',tenantId:'tenant'}};
mock.module('@/auth',{namedExports:{auth:async()=>session}});
mock.module('@/lib/require-active-user',{namedExports:{requireActivePortalUser:async()=>active?{user:{id:'owner',modelIds}}:Response.json({error:'user_inactive'},{status:403})}});

test('model performance BFF forwards authorised models, window and tenant',async()=>{
 process.env.JJD_CP_URL='http://cp.test';process.env.JJD_PORTAL_API_SECRET='fixture';
 const old=globalThis.fetch;const seen:URL[]=[];
 globalThis.fetch=async(input,init)=>{const url=new URL(String(input));seen.push(url);
  assert.equal(new Headers(init?.headers).get('x-jjdguard-tenant-id'),'tenant');
  return Response.json({data:[{model_name:'m1',samples:3}],window_hours:Number(url.searchParams.get('window_hours')),generated_at:'t',extra:'drop'})};
 try{
  const {GET}=await import('../src/app/api/me/model-performance/route.js');
  const reply=await GET(new Request('http://portal.test/api/me/model-performance?window=24'));
  assert.equal(reply.status,200);assert.equal(reply.headers.get('cache-control'),'private, no-store');
  assert.deepEqual(await reply.json(),{data:[{model_name:'m1',samples:3}],window_hours:24,generated_at:'t'});
  assert.equal(seen[0].pathname,'/admin/v1/portal-integration/model-performance');
  assert.deepEqual(seen[0].searchParams.getAll('model'),['m1','m2']);
  assert.equal(seen[0].searchParams.get('window_hours'),'24');
  await GET(new Request('http://portal.test/api/me/model-performance?window=999'));
  assert.equal(seen[1].searchParams.get('window_hours'),'168');
  modelIds=[];const empty=await GET(new Request('http://portal.test/api/me/model-performance'));
  assert.deepEqual((await empty.json()).data,[]);assert.equal(seen.length,2);
  modelIds=['m1'];globalThis.fetch=async()=>new Response('x',{status:503});
  const failed=await GET(new Request('http://portal.test/api/me/model-performance'));
  assert.equal(failed.status,502);assert.deepEqual(await failed.json(),{error:'model_performance_unavailable'});
  active=false;assert.equal((await GET(new Request('http://portal.test/api/me/model-performance'))).status,403);
  session=null;assert.equal((await GET(new Request('http://portal.test/api/me/model-performance'))).status,401);
 }finally{globalThis.fetch=old;active=true;modelIds=['m1','m2'];session={user:{id:'owner',tenantId:'tenant'}}}
});

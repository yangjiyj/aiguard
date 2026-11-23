import test,{mock} from 'node:test';import assert from 'node:assert/strict';
let active=true;let modelIds=['qwen-max','deepseek-v3'];
mock.module('@/auth',{namedExports:{auth:async()=>({user:{id:'owner',tenantId:'tenant'}})}});
mock.module('@/lib/require-active-user',{namedExports:{requireActivePortalUser:async()=>active?{user:{id:'owner',modelIds}}:Response.json({error:'user_inactive'},{status:403})}});
const qwen={model_name:'qwen-max',currency:'CNY',pricing_mode:'direct',input_per_million_micros:2_400_000,cached_input_per_million_micros:600_000,cache_write_per_million_micros:0,output_per_million_micros:9_600_000,has_cached_input_price:true,has_cache_write_price:false,pricing_extras:{}};
const deepseek={...qwen,model_name:'deepseek-v3',input_per_million_micros:1_000_000,output_per_million_micros:2_000_000,has_cached_input_price:false};

test('model price BFF forwards only authorised models and current tenant',async()=>{
 process.env.JJD_CP_URL='http://cp.test';process.env.JJD_PORTAL_API_SECRET='fixture';
 const old=globalThis.fetch;const seen:string[]=[];
 globalThis.fetch=async(input,init)=>{const url=new URL(String(input));seen.push(url.pathname);
  assert.equal(new Headers(init?.headers).get('x-jjdguard-tenant-id'),'tenant');
  assert.deepEqual(url.searchParams.getAll('model'),['qwen-max','deepseek-v3']);
  return Response.json({data:[qwen],internal:'never-return'})};
 try{
  const {GET}=await import('../src/app/api/me/model-prices/route.js');
  const reply=await GET();assert.equal(reply.status,200);const body=await reply.json();
  assert.deepEqual(body,{data:[qwen]});assert.equal(reply.headers.get('cache-control'),'private, no-store');
  assert.deepEqual(seen,['/admin/v1/portal-integration/model-prices']);
  modelIds=[];const empty=await GET();assert.deepEqual(await empty.json(),{data:[]});assert.equal(seen.length,1);
  active=false;assert.equal((await GET()).status,403);
 }finally{globalThis.fetch=old;active=true;modelIds=['qwen-max','deepseek-v3']}
});

test('model price helpers filter, sort and estimate a typical call',async()=>{
 const {filterModelPrices,priceExtras,typicalCallMicros,isFree}=await import('../src/lib/model-prices.js');
 assert.deepEqual(filterModelPrices([qwen,deepseek],'','all','input').map(p=>p.model_name),['deepseek-v3','qwen-max']);
 assert.deepEqual(filterModelPrices([qwen,deepseek],'千问','all','name').map(p=>p.model_name),['qwen-max']);
 assert.deepEqual(filterModelPrices([qwen,deepseek],'','deepseek','name').map(p=>p.model_name),['deepseek-v3']);
 assert.equal(typicalCallMicros(deepseek),3000);
 assert.deepEqual(priceExtras(qwen).map(e=>e.label),['缓存命中输入']);
 assert.equal(isFree({...qwen,input_per_million_micros:0,output_per_million_micros:0}),true);
 assert.equal(isFree({...qwen,input_per_million_micros:0,output_per_million_micros:0,pricing_extras:{request_per_call_micros:10}}),false);
});

test('usage series fills missing days and model shares aggregate the tail',async()=>{
 const {fillDailySeries,modelShares,compactNumber}=await import('../src/lib/usage-charts.js');
 const series=fillDailySeries([{date:'2026-10-20',requests:1,tokens:10,amount_micros:5}],30,new Date(2026,9,23));
 assert.equal(series.length,30);assert.equal(series.at(-1)!.date,'2026-10-23');assert.equal(series.find(d=>d.date==='2026-10-20')!.amount_micros,5);
 assert.equal(series.filter(d=>d.amount_micros>0).length,1);
 const shares=modelShares(Array.from({length:8},(_,i)=>({model_name:'m'+i,requests:1,tokens:1,amount_micros:8-i})),6);
 assert.equal(shares.length,7);assert.ok(shares[6].model_name.startsWith('其他 2'));
 assert.ok(Math.abs(shares.reduce((s,m)=>s+m.share,0)-1)<1e-9);
 assert.equal(compactNumber(123456),'12.3 万');
});

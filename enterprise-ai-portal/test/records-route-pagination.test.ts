import test,{mock} from 'node:test';import assert from 'node:assert/strict';
mock.module('@/auth',{namedExports:{auth:async()=>({user:{id:'owner',tenantId:'tenant-real'}})}});
mock.module('@/lib/require-active-user',{namedExports:{requireActivePortalUser:async()=>({user:{id:'owner',historyUserIds:['owner']}})}});
let legacyRows:unknown[]=[];
mock.module('@/lib/prisma',{namedExports:{prisma:{uploadEvent:{findMany:async()=>legacyRows}}}});
test('file pages two and three use upstream cursors, real totals and session tenant',async()=>{
 process.env.JJD_CP_URL='http://cp.test';process.env.JJD_PORTAL_API_SECRET='fixture';
 const {GET}=await import('../src/app/api/me/records/route.js');
 const old=globalThis.fetch;globalThis.fetch=async(input,init)=>{
  const url=new URL(String(input));assert.equal(url.searchParams.has('offset'),false);const offset=Number(url.searchParams.get('cursor'));
  assert.equal(new Headers(init?.headers).get('x-jjdguard-tenant-id'),'tenant-real');
  assert.equal(url.searchParams.get('limit'),'2');
  return Response.json({total:6,data:[0,1].map(i=>({id:'event-'+(offset+i),filename:'same.txt',mime_type:'text/plain',size:1,sha256:'same',reference:'r',model:'m',action_taken:'audit',findings:{},created_at:'2026-10-13T00:00:00Z'}))});
 };
 try{for(const offset of [2,4]){
  const response=await GET(new Request('http://portal.test/chat/api/me/records?limit=2&offset='+offset));
  assert.equal(response.headers.get('cache-control'),'private, no-store');
  const body=await response.json();assert.equal(body.total,6);assert.equal(body.records.length,2);assert.ok(body.records.every((r:{id:string})=>Number(r.id.slice(6))>=offset));
 }}finally{globalThis.fetch=old}
});

test('interleaved legacy records use true combined offsets and dedupe only the portal supplement',async()=>{
 const at=(minute:number)=>new Date(Date.UTC(2026,9,13,0,minute));
 legacyRows=[{id:'legacy-mid',filename:'old.png',mime:'image/png',size:1,sha256:'legacy-mid',model:null,kind:'image',createdAt:at(55)},{id:'legacy-old',filename:'old.png',mime:'image/png',size:1,sha256:'legacy-old',model:null,kind:'image',createdAt:at(5)},{id:'duplicate',filename:'same.png',mime:'image/png',size:1,sha256:'same',model:null,kind:'image',createdAt:at(60)}];
 const gateway=[60,50,40,30,20,10].map((minute,i)=>({id:'gateway-'+i,filename:'same.png',mime_type:'image/png',size:1,sha256:'same',reference:'r',model:'m',action_taken:'audit',findings:{},created_at:at(minute).toISOString()}));
 const {GET}=await import('../src/app/api/me/records/route.js');
 const old=globalThis.fetch;globalThis.fetch=async(input,init)=>{
  const url=new URL(String(input));
  if(url.pathname.endsWith('/legacy-index')){
   assert.equal(init?.method,'POST');
   return Response.json({data:[{id:'legacy-mid',matched:false,gateway_before:1},{id:'legacy-old',matched:false,gateway_before:6},{id:'duplicate',matched:true,gateway_before:0}]});
  }
  const offset=Number(url.searchParams.get('cursor')),limit=Number(url.searchParams.get('limit'));
  return Response.json({total:6,data:gateway.slice(offset,offset+limit)});
 };
 try{
  const second=await(await GET(new Request('http://portal.test/chat/api/me/records?limit=2&offset=2'))).json();
  assert.equal(second.total,8);assert.deepEqual(second.records.map((r:{id:string})=>r.id),['gateway-1','gateway-2']);
  const last=await(await GET(new Request('http://portal.test/chat/api/me/records?limit=2&offset=6'))).json();
  assert.equal(last.total,8);assert.deepEqual(last.records.map((r:{id:string})=>r.id),['gateway-5','legacy-old']);
 }finally{globalThis.fetch=old;legacyRows=[]}
});

import {auth} from '@/auth';
import {prisma} from '@/lib/prisma';
import {mergeRecords,type GatewayUploadEvent,type PortalUploadRow,type MergedRecord} from '@/lib/records';
import {loadGatewayEnv} from '@/lib/gateway-env';
import {PORTAL_DEFAULT_TENANT_ID} from '@/lib/control-plane';
import {requireActivePortalUser} from '@/lib/require-active-user';
import {PERSONAL_NO_STORE} from '@/lib/portal-write-security';
function bounded(raw:string|null,fallback:number,min:number,max:number){const n=Number(raw??fallback);return Number.isSafeInteger(n)?Math.max(min,Math.min(max,n)):fallback}
type LegacyPosition={id:string;matched:boolean;gateway_before:number};
export async function GET(request:Request){
 const session=await auth();if(!session?.user?.id)return Response.json({error:'unauthorized'},{status:401,headers:PERSONAL_NO_STORE});
 try{
  const gateway=loadGatewayEnv();const active=await requireActivePortalUser(session,{gateway});if(active instanceof Response)return active;
  const query=new URL(request.url).searchParams;
  const limit=bounded(query.get('limit'),50,1,200),offset=bounded(query.get('offset'),0,0,1000000);
  const headers={authorization:'Bearer '+gateway.portalSecret,'X-JJDGuard-Tenant-Id':session.user.tenantId||PORTAL_DEFAULT_TENANT_ID,'content-type':'application/json'};
  const rows=await prisma.uploadEvent.findMany({where:{userId:active.user.historyUserIds?{in:active.user.historyUserIds}:active.user.id},orderBy:[{createdAt:'desc'},{id:'desc'}]}).catch(()=>[]);
  const portal:PortalUploadRow[]=rows.map(r=>({id:r.id,filename:r.filename,mime:r.mime,size:r.size,sha256:r.sha256,model:r.model,kind:r.kind,createdAt:r.createdAt.toISOString()}));
  const uniqueLegacy=mergeRecords([],portal);
  const positions=new Map<string,LegacyPosition>();
  for(let start=0;start<uniqueLegacy.length;start+=200){
   const chunk=uniqueLegacy.slice(start,start+200);
   const response=await fetch(gateway.baseUrl+'/admin/v1/portal-integration/upload-events/legacy-index',{method:'POST',headers,body:JSON.stringify({user_id:active.user.id,items:chunk.map(r=>({id:r.id,sha256:r.sha256,created_at:r.createdAt}))}),cache:'no-store'});
   const body=await response.json() as {data?:LegacyPosition[]};
   if(!response.ok||!Array.isArray(body.data)||body.data.length!==chunk.length)throw new Error('index_unavailable');
   for(const item of body.data){if(typeof item.id!=='string'||typeof item.matched!=='boolean'||!Number.isSafeInteger(item.gateway_before)||item.gateway_before<0)throw new Error('invalid_index');positions.set(item.id,item)}
  }
  const legacy=uniqueLegacy.filter(r=>positions.get(r.id)?.matched===false);
  let preceding=0;const pageLegacy:MergedRecord[]=[];
  legacy.forEach((r,index)=>{const position=positions.get(r.id)!.gateway_before+index;if(position<offset)preceding++;else if(position<offset+limit)pageLegacy.push(r)});
  const gatewayOffset=Math.max(0,offset-preceding),gatewayLimit=limit-pageLegacy.length;
  const url=gateway.baseUrl+'/admin/v1/portal-integration/upload-events?'+new URLSearchParams({user_id:active.user.id,limit:String(Math.max(1,gatewayLimit)),cursor:String(gatewayOffset)});
  const response=await fetch(url,{headers,cache:'no-store'});
  if(!response.ok)throw new Error('records_unavailable');
  const body=await response.json() as {data?:GatewayUploadEvent[];total?:number};
  if(!Array.isArray(body.data)||!Number.isSafeInteger(body.total)||Number(body.total)<0)throw new Error('invalid_records');
  const records=mergeRecords(gatewayLimit?body.data:[],[]);
  records.push(...pageLegacy);records.sort((a,b)=>Date.parse(b.createdAt)-Date.parse(a.createdAt)||(a.id<b.id?1:a.id>b.id?-1:0));
  return Response.json({records,total:Number(body.total)+legacy.length},{headers:PERSONAL_NO_STORE});
 }catch{return Response.json({error:'records_unavailable'},{status:502,headers:PERSONAL_NO_STORE})}
}

import {auth} from '@/auth';
import {PORTAL_DEFAULT_TENANT_ID} from '@/lib/control-plane';
import {loadGatewayEnv} from '@/lib/gateway-env';
import {requireActivePortalUser} from '@/lib/require-active-user';
import {PERSONAL_NO_STORE} from '@/lib/portal-write-security';

// 模型性能 BFF：只把当前员工的授权模型转给控制面；控制面对空列表同样返回空。
export async function GET(request:Request){
 const session=await auth();
 if(!session?.user?.id)return Response.json({error:'unauthorized'},{status:401,headers:PERSONAL_NO_STORE});
 const window=new URL(request.url).searchParams.get('window')==='24'?'24':'168';
 try{
  const gateway=loadGatewayEnv();
  const active=await requireActivePortalUser(session,{gateway});
  if(active instanceof Response)return active;
  const modelIds=[...new Set(active.user.modelIds.map(id=>id.trim()).filter(Boolean))].slice(0,500);
  if(!modelIds.length)return Response.json({data:[],window_hours:Number(window)},{headers:PERSONAL_NO_STORE});
  const query=new URLSearchParams({window_hours:window});for(const id of modelIds)query.append('model',id);
  const response=await fetch(gateway.baseUrl+'/admin/v1/portal-integration/model-performance?'+query.toString(),{
   headers:{authorization:'Bearer '+gateway.portalSecret,'X-JJDGuard-Tenant-Id':session.user.tenantId||PORTAL_DEFAULT_TENANT_ID},
   cache:'no-store',
  });
  if(!response.ok)throw new Error('unavailable');
  const body=await response.json() as {data?:unknown;window_hours?:unknown;generated_at?:unknown};
  return Response.json({data:Array.isArray(body.data)?body.data:[],window_hours:body.window_hours,generated_at:body.generated_at},{headers:PERSONAL_NO_STORE});
 }catch{return Response.json({error:'model_performance_unavailable'},{status:502,headers:PERSONAL_NO_STORE})}
}

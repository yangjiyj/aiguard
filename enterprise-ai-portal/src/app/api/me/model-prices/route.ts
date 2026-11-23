import {auth} from '@/auth';
import {PORTAL_DEFAULT_TENANT_ID} from '@/lib/control-plane';
import {loadGatewayEnv} from '@/lib/gateway-env';
import {requireActivePortalUser} from '@/lib/require-active-user';
import {PERSONAL_NO_STORE} from '@/lib/portal-write-security';

// Model price market BFF. Only the signed-in employee's authorised models are
// forwarded; the control plane additionally fails closed on an empty list.
export async function GET(){
 const session=await auth();
 if(!session?.user?.id)return Response.json({error:'unauthorized'},{status:401,headers:PERSONAL_NO_STORE});
 try{
  const gateway=loadGatewayEnv();
  const active=await requireActivePortalUser(session,{gateway});
  if(active instanceof Response)return active;
  const modelIds=[...new Set(active.user.modelIds.map(id=>id.trim()).filter(Boolean))].slice(0,500);
  if(!modelIds.length)return Response.json({data:[]},{headers:PERSONAL_NO_STORE});
  const query=new URLSearchParams();for(const id of modelIds)query.append('model',id);
  const response=await fetch(gateway.baseUrl+'/admin/v1/portal-integration/model-prices?'+query.toString(),{
   headers:{authorization:'Bearer '+gateway.portalSecret,'X-JJDGuard-Tenant-Id':session.user.tenantId||PORTAL_DEFAULT_TENANT_ID},
   cache:'no-store',
  });
  if(!response.ok)throw new Error('unavailable');
  const body=await response.json() as {data?:unknown};
  return Response.json({data:Array.isArray(body.data)?body.data:[]},{headers:PERSONAL_NO_STORE});
 }catch{return Response.json({error:'model_prices_unavailable'},{status:502,headers:PERSONAL_NO_STORE})}
}

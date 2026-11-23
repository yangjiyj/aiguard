import type {GatewayAccessSettings} from '@/lib/gateway-access';
import {auth} from '@/auth';import {PORTAL_DEFAULT_TENANT_ID} from '@/lib/control-plane';import {loadGatewayEnv} from '@/lib/gateway-env';import {requireActivePortalUser} from '@/lib/require-active-user';import {resolvePublicGatewayUrl} from '@/lib/public-gateway-url';import {gatewayClientConfig} from '@/lib/gateway-client-config';import {PERSONAL_NO_STORE} from '@/lib/portal-write-security';
export async function GET(){
 const session=await auth();if(!session?.user?.id)return Response.json({error:'unauthorized'},{status:401,headers:PERSONAL_NO_STORE});
 try{
  const gateway=loadGatewayEnv();const active=await requireActivePortalUser(session,{gateway});if(active instanceof Response)return active;
  const configured=resolvePublicGatewayUrl(process.env);
  const response=await fetch(gateway.baseUrl+'/admin/v1/portal-integration/client-config',{headers:{authorization:'Bearer '+gateway.portalSecret,'X-JJDGuard-Tenant-Id':session.user.tenantId||PORTAL_DEFAULT_TENANT_ID,...(configured?{'X-JJDGuard-Gateway-URL':configured}:{})},cache:'no-store'});
  if(!response.ok)throw new Error('unavailable');
  const body=await response.json() as GatewayAccessSettings & {api_url?:unknown};
  return Response.json({data:gatewayClientConfig(typeof body.api_url==='string'?body.api_url:'',process.env.PORTAL_PUBLIC_URL,body)},{headers:PERSONAL_NO_STORE});
 }catch{return Response.json({error:'client_config_unavailable'},{status:502,headers:PERSONAL_NO_STORE})}
}

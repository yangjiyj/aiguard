import {auth} from '@/auth';
import {loadGatewayEnv} from '@/lib/gateway-env';
import {PORTAL_DEFAULT_TENANT_ID} from '@/lib/control-plane';
import {requireActivePortalUser} from '@/lib/require-active-user';
import {PERSONAL_NO_STORE,requirePortalOrigin,limitPersonalAction,withPersonalAction,personalControlPlaneError} from '@/lib/portal-write-security';
export async function POST(request:Request,context:{params:Promise<{id:string}>}){
 return withPersonalAction(request,'key_reset',async()=>{
  const session=await auth();if(!session?.user?.id)return Response.json({error:'unauthorized'},{status:401});
  const denied=requirePortalOrigin(request);if(denied)return denied;
  const limited=limitPersonalAction(session.user.tenantId||PORTAL_DEFAULT_TENANT_ID,session.user.id,'key_reset');if(limited)return limited;
  const {id}=await context.params;if(!id||id.length>128||/[\u0000-\u001f\u007f]/.test(id))return Response.json({error:'invalid_key_id'},{status:400});
  const gateway=loadGatewayEnv(),active=await requireActivePortalUser(session,{gateway});if(active instanceof Response)return active;
  const response=await fetch(gateway.baseUrl+'/admin/v1/portal-integration/customer-keys/'+encodeURIComponent(id)+'/reset?'+new URLSearchParams({user_id:active.user.id}),{method:'POST',headers:{authorization:'Bearer '+gateway.portalSecret,'X-JJDGuard-Tenant-Id':session.user.tenantId||PORTAL_DEFAULT_TENANT_ID},cache:'no-store',signal:AbortSignal.timeout(10000)});
  const payload=await response.json().catch(()=>null);
  if(!response.ok)return Response.json({error:personalControlPlaneError(payload)},{status:[400,401,403,404,409,429].includes(response.status)?response.status:502,headers:PERSONAL_NO_STORE});
  if(typeof payload?.full_key!=='string'||!payload.full_key||payload?.data?.user_id!==active.user.id||payload?.data?.tenant_id!==(session.user.tenantId||PORTAL_DEFAULT_TENANT_ID))return Response.json({error:'invalid_control_plane_response'},{status:502,headers:PERSONAL_NO_STORE});
  const key=payload.data;
  return Response.json({full_key:payload.full_key,data:{id:key.id,name:key.name,prefix:key.prefix,project_id:key.project_id,scopes:key.scopes,status:key.status,created_at:key.created_at,expires_at:key.expires_at,model_allowlist:key.model_allowlist}},{headers:PERSONAL_NO_STORE});
 });
}

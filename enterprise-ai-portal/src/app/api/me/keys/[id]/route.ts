import {auth} from '@/auth';
import {loadGatewayEnv} from '@/lib/gateway-env';
import {PORTAL_DEFAULT_TENANT_ID} from '@/lib/control-plane';
import {requireActivePortalUser} from '@/lib/require-active-user';
import {PERSONAL_NO_STORE,requirePortalOrigin,withPersonalAction,personalControlPlaneError} from '@/lib/portal-write-security';

export async function PATCH(request:Request,context:{params:Promise<{id:string}>}){
 return withPersonalAction(request,'key_update',async()=>{
  const session=await auth();if(!session?.user?.id)return Response.json({error:'unauthorized'},{status:401});
  const denied=requirePortalOrigin(request);if(denied)return denied;
  const {id}=await context.params;
  if(!id||id.length>128||/[\u0000-\u001f\u007f]/.test(id))return Response.json({error:'invalid_key_id'},{status:400});
  const raw:unknown=await request.json().catch(()=>null);
  if(!raw||typeof raw!=='object'||Array.isArray(raw))return Response.json({error:'invalid_request'},{status:400});
  const input=raw as Record<string,unknown>,body:Record<string,unknown>={};
  if(input.name!==undefined){
   if(typeof input.name!=='string'||input.name.length>128||/[\u0000-\u001f\u007f]/.test(input.name))return Response.json({error:'invalid_name'},{status:400});
   body.name=input.name.trim();
  }
  if(input.status!==undefined){if(!['active','disabled'].includes(String(input.status)))return Response.json({error:'invalid_status'},{status:400});body.status=input.status}
  if(input.model_allowlist!==undefined){
   if(!Array.isArray(input.model_allowlist)||input.model_allowlist.length>500||!input.model_allowlist.every(m=>typeof m==='string'&&m.length>0&&m.length<=256))return Response.json({error:'invalid_model_allowlist'},{status:400});
   body.model_allowlist=input.model_allowlist;
  }
  if(!Object.keys(body).length)return Response.json({error:'invalid_request'},{status:400});
  const gateway=loadGatewayEnv(),active=await requireActivePortalUser(session,{gateway});if(active instanceof Response)return active;
  const response=await fetch(gateway.baseUrl+'/admin/v1/portal-integration/customer-keys/'+encodeURIComponent(id)+'?'+new URLSearchParams({user_id:active.user.id}),{
   method:'PATCH',headers:{authorization:'Bearer '+gateway.portalSecret,'X-JJDGuard-Tenant-Id':session.user.tenantId||PORTAL_DEFAULT_TENANT_ID,'content-type':'application/json'},body:JSON.stringify(body),cache:'no-store',signal:AbortSignal.timeout(10000)
  });
  if(!response.ok)return Response.json({error:personalControlPlaneError(await response.json().catch(()=>null))},{status:[400,401,403,404,409,429].includes(response.status)?response.status:502,headers:PERSONAL_NO_STORE});
  return Response.json({data:{id}},{headers:PERSONAL_NO_STORE});
 });
}

export async function DELETE(request:Request,context:{params:Promise<{id:string}>}){
 return withPersonalAction(request,'key_delete',async()=>{
  const session=await auth();
  if(!session?.user?.id)return Response.json({error:'unauthorized'},{status:401,headers:PERSONAL_NO_STORE});
  const denied=requirePortalOrigin(request);if(denied)return denied;
  const {id}=await context.params;
  if(!id||id.length>128||/[\u0000-\u001f\u007f]/.test(id))return Response.json({error:'invalid_key_id'},{status:400,headers:PERSONAL_NO_STORE});
  const gateway=loadGatewayEnv();
  const active=await requireActivePortalUser(session,{gateway});if(active instanceof Response)return active;
  const response=await fetch(gateway.baseUrl+'/admin/v1/portal-integration/customer-keys/'+encodeURIComponent(id)+'?'+new URLSearchParams({user_id:active.user.id}),{
   method:'DELETE',headers:{authorization:'Bearer '+gateway.portalSecret,'X-JJDGuard-Tenant-Id':session.user.tenantId||PORTAL_DEFAULT_TENANT_ID},cache:'no-store',signal:AbortSignal.timeout(10000)
  });
  if(response.status!==204)return Response.json({error:personalControlPlaneError(await response.json().catch(()=>null))},{status:[400,401,403,404,409,429].includes(response.status)?response.status:502,headers:PERSONAL_NO_STORE});
  return new Response(null,{status:204,headers:PERSONAL_NO_STORE});
 });
}

import {withPersonalAction} from '@/lib/portal-write-security';
import {signedClientIP,clientIPHeaders} from './signed-client-ip';
import {auth} from '@/auth';
import {PORTAL_DEFAULT_TENANT_ID} from './control-plane';
import {loadGatewayEnv} from './gateway-env';
import {requireActivePortalUser} from './require-active-user';
import {PERSONAL_NO_STORE,requirePortalOrigin,personalControlPlaneError} from './portal-write-security';

type PersonalKey={id:string;name:string;prefix:string;project_id:string;scopes:string[];status:string;created_at:string;employee_key:boolean;model_allowlist:string[];last_used_at?:string;expires_at?:string};
async function personalKeysRequestImpl(request:Request,keyId?:string):Promise<Response>{
 const session=await auth();
 if(!session?.user?.id)return Response.json({error:'unauthorized'},{status:401,headers:PERSONAL_NO_STORE});
 if(keyId!==undefined){
  const denied=requirePortalOrigin(request);if(denied)return denied;
  if(!keyId||keyId.length>128||/[\u0000-\u001f\u007f]/.test(keyId))return Response.json({error:'invalid_key_id'},{status:400,headers:PERSONAL_NO_STORE});
 }
 try{
  const gateway=loadGatewayEnv();const active=await requireActivePortalUser(session,{gateway});
  if(active instanceof Response)return active;
  const tenant=session.user.tenantId||PORTAL_DEFAULT_TENANT_ID;
  const headers={authorization:'Bearer '+gateway.portalSecret,'X-JJDGuard-Tenant-Id':tenant,...clientIPHeaders(signedClientIP(request.headers))};
  const list=await fetch(gateway.baseUrl+'/admin/v1/portal-integration/customer-keys?user_id='+encodeURIComponent(active.user.id),{headers,cache:'no-store'});
  const body=await list.json().catch(()=>null) as {data?:unknown;error?:unknown}|null;
  if(!list.ok||!Array.isArray(body?.data))return Response.json({error:personalControlPlaneError(body,'keys_unavailable')},{status:502,headers:PERSONAL_NO_STORE});
  const keys:PersonalKey[]=[];
  for(const raw of body.data){
   if(!raw||typeof raw!=='object')throw new Error('invalid_metadata');
   const row=raw as Record<string,unknown>;
   if(row.user_id!==active.user.id||row.tenant_id!==tenant||typeof row.id!=='string'||typeof row.prefix!=='string'||typeof row.project_id!=='string'||!Array.isArray(row.scopes)||!row.scopes.every(s=>typeof s==='string')||typeof row.status!=='string'||typeof row.created_at!=='string')throw new Error('invalid_metadata');
   keys.push({id:row.id,name:typeof row.name==='string'?row.name:'',prefix:row.prefix,project_id:row.project_id,scopes:row.scopes,status:row.status,created_at:row.created_at,employee_key:row.employee_key===true,model_allowlist:Array.isArray(row.model_allowlist)&&row.model_allowlist.every(m=>typeof m==='string')?row.model_allowlist:[],...(typeof row.last_used_at==='string'?{last_used_at:row.last_used_at}:{}),...(typeof row.expires_at==='string'?{expires_at:row.expires_at}:{})});
  }
  if(keyId===undefined)return Response.json({data:keys},{headers:PERSONAL_NO_STORE});
  if(!keys.some(key=>key.id===keyId))return Response.json({error:'not_found'},{status:404,headers:PERSONAL_NO_STORE});
  const response=await fetch(gateway.baseUrl+'/admin/v1/portal-integration/keys/'+encodeURIComponent(keyId)+'/revoke?user_id='+encodeURIComponent(active.user.id),{method:'POST',headers,cache:'no-store'});
  if(response.status!==204)return Response.json({error:personalControlPlaneError(await response.json().catch(()=>null),'key_revoke_failed')},{status:[401,403,404,429].includes(response.status)?response.status:502,headers:PERSONAL_NO_STORE});
  return new Response(null,{status:204,headers:PERSONAL_NO_STORE});
 }catch{return Response.json({error:'keys_unavailable'},{status:502,headers:PERSONAL_NO_STORE});}
}

export async function personalKeysRequest(request:Request,keyId?:string):Promise<Response>{return withPersonalAction(request,keyId?"key_revoke":"key_list",()=>personalKeysRequestImpl(request,keyId));}

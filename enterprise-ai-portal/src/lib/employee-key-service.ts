import {withPersonalAction} from '@/lib/portal-write-security';
import {signedClientIP,clientIPHeaders} from './signed-client-ip';
import {trustedPortalOrigin} from './portal-write-security';
import { auth } from '@/auth';
import { PORTAL_DEFAULT_TENANT_ID } from '@/lib/control-plane';
import { loadGatewayEnv } from '@/lib/gateway-env';
import { requireActivePortalUser } from '@/lib/require-active-user';

const NO_STORE={'cache-control':'private, no-store',pragma:'no-cache'};
type Operation='metadata'|'claim'|'reset'|'ensure';
type KeyData={id:string;prefix:string;generation:number;status:string;created_at:string;claim_available:boolean;model_allowlist:string[]};

function keyMetadata(raw:unknown,userId:string,tenantId:string):KeyData|null {
  if(!raw||typeof raw!=='object')return null;
  const key=raw as Record<string,unknown>;
  if(key.user_id!==userId||key.tenant_id!==tenantId||typeof key.id!=='string'||!key.id||typeof key.prefix!=='string'||!key.prefix||
     typeof key.generation!=='number'||!Number.isSafeInteger(key.generation)||key.generation<=0||
     typeof key.status!=='string'||typeof key.created_at!=='string'||Number.isNaN(Date.parse(key.created_at))||
     !(key.first_claim_at===null||typeof key.first_claim_at==='string'))return null;
  return{id:key.id,prefix:key.prefix,generation:key.generation,status:key.status,created_at:key.created_at,
         claim_available:key.first_claim_at===null&&key.status==='active',model_allowlist:Array.isArray(key.model_allowlist)&&key.model_allowlist.every(m=>typeof m==='string')?key.model_allowlist:[]};
}

async function employeeKeyRequestImpl(request:Request,operation:Operation) {
  const session=await auth();
  if(!session?.user?.id)return Response.json({error:'unauthorized'},{status:401,headers:NO_STORE});
  if(operation!=='metadata'&&!trustedPortalOrigin(request))return Response.json({error:'invalid_origin'},{status:403,headers:NO_STORE});
  let cas:Record<string,unknown>={};
  if(operation!=='metadata'){
    let raw:unknown;
    try{raw=await request.json();}catch{return Response.json({error:'invalid_json'},{status:400,headers:NO_STORE});}
    if(!raw||typeof raw!=='object')return Response.json({error:'invalid_request'},{status:400,headers:NO_STORE});
    const input=raw as Record<string,unknown>;
    if(operation!=='ensure'&&(typeof input.expected_key_id!=='string'||!input.expected_key_id||input.expected_key_id.length>128||
       /[\u0000-\u001f\u007f]/.test(input.expected_key_id)||typeof input.expected_generation!=='number'||
       !Number.isSafeInteger(input.expected_generation)||input.expected_generation<=0)){
      return Response.json({error:'invalid_key_generation'},{status:400,headers:NO_STORE});
    }
    if(operation!=='ensure')cas={expected_key_id:input.expected_key_id,expected_generation:input.expected_generation};
  }
  try{
    const gateway=loadGatewayEnv();
    const active=await requireActivePortalUser(session,{gateway});
    if(active instanceof Response)return active;
    const subject=typeof session.user.externalSubject==='string'?session.user.externalSubject.trim():'';
    if(!subject)return Response.json({error:'identity_not_ready'},{status:403,headers:NO_STORE});
    const binding:Record<string,string>={user_id:active.user.id,login_mode:session.user.localLogin===true?'local':'oidc',external_subject:subject};
    if(session.user.localLogin===true)binding.local_credential_version=String(session.user.localCredentialVersion);
    const base=gateway.baseUrl+'/admin/v1/portal-integration/employee-key';
    const url=operation==='metadata'?base+'?'+new URLSearchParams(binding):base+'/'+operation;
    const response=await fetch(url,{
      method:operation==='metadata'?'GET':'POST',
      headers:{authorization:'Bearer '+gateway.portalSecret,'X-JJDGuard-Tenant-Id':session.user.tenantId||PORTAL_DEFAULT_TENANT_ID,'content-type':'application/json',...clientIPHeaders(signedClientIP(request.headers))},
      ...(operation==='metadata'?{}:{body:JSON.stringify({...binding,...cas,...(session.user.localLogin===true?{local_credential_version:session.user.localCredentialVersion}:{})})}),cache:'no-store',signal:AbortSignal.timeout(10000),
    });
    const payload=await response.json().catch(()=>null) as Record<string,unknown>|null;
    if(!response.ok){
      const field=payload?.error;
      const code=typeof field==='string'?field:field&&typeof field==='object'&&'code'in field&&typeof field.code==='string'?field.code:'';
      const allowed=new Set(['created_before_encryption','employee_key_already_claimed','employee_key_conflict','authorization_denied','employee_key_not_found','unauthorized','rate_limited','control_plane_unreachable']);
      return Response.json({error:allowed.has(code)?code:'employee_key_unavailable'},{status:[403,404,409].includes(response.status)?response.status:502,headers:NO_STORE});
    }
    const raw=payload?.key??payload?.data;
    const metadata=keyMetadata(raw,binding.user_id,session.user.tenantId||PORTAL_DEFAULT_TENANT_ID);
    if(!metadata)return Response.json({error:'invalid_control_plane_response'},{status:502,headers:NO_STORE});
    if(operation==='metadata'||operation==='ensure')return Response.json({data:metadata},{headers:NO_STORE});
    if(typeof payload?.full_key!=='string'||!payload.full_key||payload.full_key.length>1024)return Response.json({error:'invalid_control_plane_response'},{status:502,headers:NO_STORE});
    return Response.json({data:metadata,full_key:payload.full_key},{headers:NO_STORE});
  }catch{
    return Response.json({error:'control_plane_unreachable'},{status:502,headers:NO_STORE});
  }
}

export async function employeeKeyRequest(request:Request,operation:Operation){return withPersonalAction(request,"employee_key_"+operation,()=>employeeKeyRequestImpl(request,operation));}

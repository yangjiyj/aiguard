import {randomUUID} from 'node:crypto';
import {checkRateLimit} from './rate-limit';
export const PERSONAL_NO_STORE={'cache-control':'private, no-store',pragma:'no-cache'};
// Public /chat proxies preserve Host end to end. Forwarded headers are deliberately
// not authentication inputs: Request does not expose a trustworthy socket peer.
export function trustedPortalOrigin(request:Request):boolean {
 const site=request.headers.get('sec-fetch-site');
 if(site&&site!=='same-origin')return false;
 const raw=request.headers.get('origin');
 if(!raw)return false;
 try{
  const origin=new URL(raw);
  if(!['http:','https:'].includes(origin.protocol)||raw!==origin.origin)return false;
  const host=request.headers.get('host')||new URL(request.url).host;
  if(host&&!/[\s,/@?#\\]/.test(host)&&new URL(origin.protocol+'//'+host).host===origin.host)return true;
  const configured=[process.env.PORTAL_PUBLIC_URL,process.env.AUTH_URL,process.env.NEXTAUTH_URL,
   ...(process.env.PORTAL_TRUSTED_ORIGINS||'').split(',')];
  return configured.some(value=>{
   if(!value?.trim())return false;
   try{return new URL(value.trim()).origin===origin.origin}catch{return false}
  });
 }catch{return false}
}
export function requirePortalOrigin(request:Request):Response|null {
 return trustedPortalOrigin(request)?null:Response.json({error:'invalid_origin'},{status:403,headers:PERSONAL_NO_STORE});
}
export function limitPersonalAction(tenant:string,user:string,action:string):Response|null {
 const result=checkRateLimit('personal:'+tenant+':'+user+':'+action);
 return result.allowed?null:Response.json({error:'rate_limited'},{status:429,headers:{...PERSONAL_NO_STORE,'retry-after':String(result.retryAfterSec)}});
}

export function personalControlPlaneError(payload:unknown,fallback='control_plane_error'):string{
 if(!payload||typeof payload!=='object')return fallback;
 const raw=(payload as {error?:unknown}).error;
 const code=typeof raw==='string'?raw:raw&&typeof raw==='object'&&'code' in raw?raw.code:null;
 return typeof code==='string'&&/^[a-z0-9_]{1,80}$/.test(code)?code:fallback;
}

const personalTraceIDs=new WeakMap<Request,string>();
export function personalTraceID(request:Request):string{
 let id=personalTraceIDs.get(request);
 if(!id){id=randomUUID();personalTraceIDs.set(request,id)}
 return id;
}
export async function personalActionResponse(request:Request,action:string,response:Response):Promise<Response>{
 if(response.status<400||response.headers.has('x-trace-id'))return response;
 const trace_id=personalTraceID(request);
 const payload:unknown=await response.clone().json().catch(()=>null);
 const error=personalControlPlaneError(payload,'operation_failed');
 console.warn(JSON.stringify({event:'personal_action_failed',action,status:response.status,error,trace_id}));
 const headers=new Headers(response.headers);headers.set('x-trace-id',trace_id);
 return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
}
export async function withPersonalAction(request:Request,action:string,run:()=>Promise<Response>):Promise<Response>{
 let response:Response;
 try{response=await run()}catch{response=Response.json({error:'control_plane_unreachable'},{status:502,headers:PERSONAL_NO_STORE})}
 return personalActionResponse(request,action,response);
}

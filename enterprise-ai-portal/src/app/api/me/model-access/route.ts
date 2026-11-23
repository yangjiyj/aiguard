import {auth} from '@/auth';
import {requireActivePortalUser} from '@/lib/require-active-user';
import {PERSONAL_NO_STORE} from '@/lib/portal-write-security';
export async function GET(){
 const session=await auth();
 if(!session?.user?.id)return Response.json({error:'unauthorized'},{status:401,headers:PERSONAL_NO_STORE});
 const active=await requireActivePortalUser(session);
 if(active instanceof Response)return active;
 const access=active.user;
 return Response.json({data:{
  modelIds:access.modelIds,modelSources:access.modelSources??{},
  extraGrants:(access.extraGrants??[]).filter(g=>!g.revoked_at).map(g=>({model:g.model,reason:g.reason,expires_at:g.expires_at??null})),
  staleModels:access.staleModels??[],
 }},{headers:PERSONAL_NO_STORE});
}

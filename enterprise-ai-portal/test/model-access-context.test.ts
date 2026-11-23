import test from 'node:test';
import assert from 'node:assert/strict';
import {getCurrentPortalAuthorization} from '../src/lib/control-plane';

test('authorization context preserves personal policy, extras and provenance',async()=>{
 const result=await getCurrentPortalAuthorization('tenant','user',{
  gateway:{baseUrl:'http://cp.test',portalSecret:'fixture'},
  fetchImpl:async()=>Response.json({data:{user_id:'user',department_id:'dept',department_name:'研发部',department_version:1,chat_allowed:true,portal_allowed:true,project_id:'server-project',model_ids:['base','extra'],model_access_mode:'allowlist',department_models:['base'],personal_allowlist:['base','stale'],model_sources:{base:'personal_narrowed',extra:'personal_extra'},stale_models:['stale'],extra_grants:[{id:'g1',model:'extra',reason:'业务',expires_at:null,created_by:'admin',created_at:'2026-10-12T00:00:00Z',revoked_at:null}]}}),
 });
 assert.equal(result.projectId,'server-project');
 assert.equal(result.modelAccessMode,'allowlist');
 assert.deepEqual(result.modelSources,{base:'personal_narrowed',extra:'personal_extra'});
 assert.deepEqual(result.staleModels,['stale']);
 assert.equal(result.extraGrants?.[0]?.reason,'业务');
});


test('OIDC authorization rechecks the signed external subject in each request',async()=>{
 let captured='';
 await getCurrentPortalAuthorization('tenant','user',{
  externalSubject:'subject/one',loginMode:'oidc',
  gateway:{baseUrl:'http://cp.test',portalSecret:'fixture'},
  fetchImpl:async input=>{captured=String(input);return Response.json({data:{user_id:'user',department_id:'dept',department_name:'部门',department_version:1,chat_allowed:true,model_ids:[]}})},
 });
 const url=new URL(captured);
 assert.equal(url.searchParams.get('external_subject'),'subject/one');
 assert.equal(url.searchParams.get('login_mode'),'oidc');
});

test('authorization returns server-owned historical account attribution',async()=>{
 const result=await getCurrentPortalAuthorization('tenant','user',{gateway:{baseUrl:'http://cp.test',portalSecret:'fixture'},fetchImpl:async()=>Response.json({data:{user_id:'user',department_id:'dept',department_name:'部门',department_version:1,chat_allowed:true,model_ids:[],history_user_ids:['source','user']}})});
 assert.deepEqual(result.historyUserIds,['source','user']);
});

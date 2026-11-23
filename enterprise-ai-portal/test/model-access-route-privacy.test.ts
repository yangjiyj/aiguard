import test,{mock} from 'node:test';import assert from 'node:assert/strict';
const access={modelIds:['approved'],modelSources:{approved:'department'},extraGrants:[{model:'extra',reason:'业务需要',expires_at:null,created_by:'internal-admin',id:'grant-id'}],staleModels:['stale'],localCredentialVersion:7,localExternalSubject:'subject',historyUserIds:['old-owner'],departmentId:'internal-dept',projectId:'internal-project'};
let disabled=false;
mock.module('@/auth',{namedExports:{auth:async()=>({user:{id:'owner'}})}});
mock.module('@/lib/control-plane',{namedExports:{PORTAL_DEFAULT_TENANT_ID:'tenant',getCurrentPortalAuthorization:async()=>access}});
mock.module('@/lib/require-active-user',{namedExports:{requireActivePortalUser:async()=>disabled?Response.json({error:'user_inactive'},{status:403}):{user:{id:'owner',...access}}}});
test('model access BFF returns only panel fields and sanitized grants',async()=>{
 const {GET}=await import('../src/app/api/me/model-access/route.js');
 const response=await GET();assert.equal(response.status,200);
 assert.deepEqual(await response.json(),{data:{modelIds:['approved'],modelSources:{approved:'department'},extraGrants:[{model:'extra',reason:'业务需要',expires_at:null}],staleModels:['stale']}});
 assert.equal(response.headers.get('cache-control'),'private, no-store');
});
test('disabled user cannot read model access with a valid session',async()=>{
 disabled=true;try{const {GET}=await import('../src/app/api/me/model-access/route.js');assert.equal((await GET()).status,403)}finally{disabled=false}
});

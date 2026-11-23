import test from 'node:test';import assert from 'node:assert/strict';import {revokePortalKey} from '../src/gateway.js';
const cfg={gatewayCpUrl:'http://cp.test',portalApiSecret:'fixture',tenantId:'tenant'};
test('owned key revocation supplies user ownership',async()=>{
 const original=globalThis.fetch;let seen='';
 globalThis.fetch=async(input)=>{seen=String(input);return new Response(null,{status:204})};
 try{await revokePortalKey(cfg,'owned-key','owner');assert.equal(new URL(seen).searchParams.get('user_id'),'owner')}finally{globalThis.fetch=original}
});
test('revocation 404 is an actionable failure',async()=>{
 const original=globalThis.fetch;globalThis.fetch=async()=>Response.json({error:'not_found'},{status:404});
 try{await assert.rejects(()=>revokePortalKey(cfg,'owned-key','owner'),/404/)}finally{globalThis.fetch=original}
});

import test from 'node:test';import assert from 'node:assert/strict';import React from 'react';import {renderToStaticMarkup} from 'react-dom/server';
test('effective models show three Chinese source groups, expiry and stale narrowing',async()=>{
 const {ModelAccessPanel}=await import('../src/components/model-access-panel.js');
 const html=renderToStaticMarkup(React.createElement(ModelAccessPanel,{models:[{id:'base',displayName:'部门模型'},{id:'extra',displayName:'额外模型'},{id:'narrow',displayName:'保留模型'}],access:{modelSources:{base:'department',extra:'personal_extra',narrow:'personal_narrowed'},extraGrants:[{id:'g',model:'extra',reason:'专项需求',expires_at:'2026-11-13T00:00:00Z',created_by:'admin',created_at:'2026-10-13T00:00:00Z',revoked_at:null}],staleModels:['removed']}}));
 for(const text of ['部门授权','个人额外授权','个人已收窄','专项需求','到期','removed'])assert.ok(html.includes(text));
 assert.equal(html.includes('personal_extra'),false);
});

test('unknown model provenance is explicit',async()=>{
 const {ModelAccessPanel}=await import('../src/components/model-access-panel.js');
 const html=renderToStaticMarkup(React.createElement(ModelAccessPanel,{models:[{id:'unknown-source'}],access:{modelIds:['unknown-source']}}));
 assert.ok(html.includes('授权来源待确认'));
});

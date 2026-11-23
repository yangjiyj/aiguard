import test from 'node:test';import assert from 'node:assert/strict';import React from 'react';import {renderToStaticMarkup} from 'react-dom/server';import {ApiKeysPanel} from '../src/components/api-keys-panel.js';
test('key panel renders last use and expiry',()=>{
 const used='2026-10-12T08:30:00Z',expires='2027-10-13T00:00:00Z';
 const html=renderToStaticMarkup(React.createElement(ApiKeysPanel,{projects:[],initialKeys:[{id:'fixture',name:'Fixture',prefix:'masked',project_id:'private-project',scopes:['chat'],status:'active',created_at:'2026-10-13T00:00:00Z',last_used_at:used,expires_at:expires}]}));
 assert.ok(html.includes(new Date(used).toLocaleString()));assert.ok(html.includes('过期'));assert.ok(html.includes(new Date(expires).toLocaleString()));assert.equal(html.includes('从未'),false);
});

import test from 'node:test';import assert from 'node:assert/strict';
import React from 'react';import {renderToStaticMarkup} from 'react-dom/server';

test('workspace destinations live outside the chat sidebar',async()=>{
 Object.assign(globalThis,{React});
 const {SidebarHeader,WORKSPACE_NAV}=await import('../src/components/portal-nav.js');
 assert.deepEqual(WORKSPACE_NAV.map(i=>i.label),['模型','API 密钥','用量与费用','调用记录']);
 const html=renderToStaticMarkup(React.createElement(SidebarHeader,{}));
 assert.match(html,/新对话/);
 assert.doesNotMatch(html,/aria-label="工作台"/);
 for(const label of ['API 密钥','用量与费用','调用记录'])assert.doesNotMatch(html,new RegExp(label));
});

test('activeFromHash highlights API keys inside the billing page',async()=>{
 const {activeFromHash}=await import('../src/components/portal-nav.js');
 assert.equal(activeFromHash('billing','#api-keys'),'keys');
 assert.equal(activeFromHash('billing','#wallet'),'billing');
 assert.equal(activeFromHash('models','#api-keys'),'models');
});

test('isNewChatShortcut accepts cmd/ctrl+K only',async()=>{
 const {isNewChatShortcut}=await import('../src/components/portal-nav.js');
 assert.equal(isNewChatShortcut({key:'k',metaKey:true,ctrlKey:false,altKey:false,shiftKey:false}),true);
 assert.equal(isNewChatShortcut({key:'K',metaKey:false,ctrlKey:true,altKey:false,shiftKey:false}),true);
 assert.equal(isNewChatShortcut({key:'k',metaKey:false,ctrlKey:false,altKey:false,shiftKey:false}),false);
 assert.equal(isNewChatShortcut({key:'k',metaKey:true,ctrlKey:false,altKey:false,shiftKey:true}),false);
});

test('SidebarAccount renders identity without the chat store',async()=>{
 Object.assign(globalThis,{React});
 const {SidebarAccount}=await import('../src/components/sidebar-account.js');
 const html=renderToStaticMarkup(React.createElement(SidebarAccount,{user:{name:'张三',department:'研发中心',email:'z@example.test',role:'employee'}}));
 assert.match(html,/张三/);assert.match(html,/研发中心/);
});

test('SidebarAccount shows a placeholder, not 未登录, while the identity is loading',async()=>{
 Object.assign(globalThis,{React});
 const {SidebarAccount}=await import('../src/components/sidebar-account.js');
 const html=renderToStaticMarkup(React.createElement(SidebarAccount,{user:null}));
 assert.match(html,/data-loading/);
 assert.doesNotMatch(html,/未登录|企业账号/);
});

test('workspace group: four links, API keys at /keys, one current, collapsible',async()=>{
 Object.assign(globalThis,{React});
 const {WorkspaceNav,WORKSPACE_NAV}=await import('../src/components/portal-nav.js');
 assert.equal(WORKSPACE_NAV.find(i=>i.key==='keys')?.href,'/keys');
 const open=renderToStaticMarkup(React.createElement(WorkspaceNav,{active:'keys',collapsed:false,onToggle:()=>{}}));
 for(const label of ['工作台','模型','API 密钥','用量与费用','调用记录'])assert.match(open,new RegExp(label));
 assert.equal((open.match(/aria-current="page"/g)??[]).length,1);
 assert.match(open,/<a[^>]*href="[^"]*\/keys"[^>]*aria-current="page"/);
 assert.match(open,/aria-expanded="true"/);
 const none=renderToStaticMarkup(React.createElement(WorkspaceNav,{collapsed:false,onToggle:()=>{}}));
 assert.doesNotMatch(none,/aria-current/);
 const closed=renderToStaticMarkup(React.createElement(WorkspaceNav,{active:'keys',collapsed:true,onToggle:()=>{}}));
 assert.match(closed,/aria-expanded="false"/);assert.doesNotMatch(closed,/用量与费用/);
});

test('account menu no longer duplicates the workspace links',async()=>{
 const {readFileSync}=await import('node:fs');
 const src=readFileSync(new URL('../src/components/sidebar-account.tsx',import.meta.url),'utf8');
 assert.doesNotMatch(src,/WORKSPACE_NAV|AccountMenuLinks/);
});

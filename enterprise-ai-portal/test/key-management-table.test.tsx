import test from 'node:test';import assert from 'node:assert/strict';import React from 'react';import {renderToStaticMarkup} from 'react-dom/server';
import {ApiKeysPanel} from '../src/components/api-keys-panel';
const base={prefix:'masked',project_id:'project',scopes:['chat'],status:'active',created_at:'2026-10-13T00:00:00Z'};

test('每个 Key 一张卡片：个人 Key 标「默认」，在线 Key 可复制，次要操作收进菜单',()=>{
 const html=renderToStaticMarkup(React.createElement(ApiKeysPanel,{projects:[],initialKeys:[{...base,id:'managed',name:'默认个人 Key',employee_key:true},{...base,id:'custom',name:'自建 Key'}]}));
 assert.equal((html.match(/<table/g)??[]).length,0);
 assert.equal((html.match(/data-key-card/g)??[]).length,2);
 for(const label of ['默认个人 Key','自建 Key','默认','正常','创建 API 密钥','复制完整 Key','可用模型','最后使用','有效期','编辑','重置 Key','删除'])assert.ok(html.includes(label),label);
 // 个人 Key 也能直接复制；删除已覆盖吊销，不再单独提供吊销
 assert.equal((html.match(/复制完整 Key/g)??[]).length,2);
 assert.ok(!html.includes('>吊销<'));assert.ok(!html.includes('吊销个人 Key'));assert.ok(!html.includes('刷新个人 Key'));
 assert.match(html,/masked••••/);
});

test('已失效的 Key 折叠到下方，只能删除',()=>{
 const html=renderToStaticMarkup(React.createElement(ApiKeysPanel,{projects:[],initialKeys:[{...base,id:'live',name:'在用 Key'},{...base,id:'old',name:'旧 Key',status:'revoked'}]}));
 assert.match(html,/已失效 · 1/);
 const revoked=html.slice(html.indexOf('已失效 · 1'));
 assert.ok(revoked.includes('旧 Key'));assert.ok(revoked.includes('删除'));assert.ok(!revoked.includes('编辑'));
 assert.ok(!html.slice(0,html.indexOf('已失效 · 1')).includes('>旧 Key<'));
});

test('少量 Key 不显示筛选；空列表引导创建',()=>{
 const html=renderToStaticMarkup(React.createElement(ApiKeysPanel,{projects:[],initialKeys:[],customerGroup:'default'}));
 assert.ok(!html.includes('IP 限制'));assert.ok(!html.includes('状态筛选'));
 assert.ok(html.includes('客户组：default'));assert.ok(html.includes('创建第一个 API 密钥'));
});

test('创建时间在名称的悬停提示中可见',()=>{
 const html=renderToStaticMarkup(React.createElement(ApiKeysPanel,{projects:[],initialKeys:[{id:'fixture',name:'测试 Key',prefix:'masked',project_id:'project',scopes:[],status:'active',created_at:'2026-10-15T00:00:00Z'}]}));
 assert.match(html,/title="[^"]*创建时间/);
});

test('八个实际 Key 不因未领取的占位行显示筛选，第九个才显示',()=>{
 const b={name:'历史 Key',prefix:'masked',project_id:'project',scopes:[],status:'revoked',created_at:'2026-10-15T00:00:00Z'};
 const keys=Array.from({length:9},(_,index)=>({...b,id:'fixture-'+index}));
 const render=(count:number)=>renderToStaticMarkup(React.createElement(ApiKeysPanel,{projects:[],initialKeys:keys.slice(0,count)}));
 assert.ok(!render(8).includes('状态筛选'));assert.ok(render(9).includes('状态筛选'));
});

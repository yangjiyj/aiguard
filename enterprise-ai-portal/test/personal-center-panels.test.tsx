import test from 'node:test';import assert from 'node:assert/strict';import React from 'react';import {renderToStaticMarkup} from 'react-dom/server';
import BillingPage from '../src/components/billing-page.js';
test('API 密钥页：账单读取中也显示 Key 卡片和接入信息',()=>{
 const html=renderToStaticMarkup(React.createElement(BillingPage,{view:'keys'}));
 assert.match(html,/<h1[^>]*>API 密钥<\/h1>/);
 assert.ok(html.includes('个人 API Key'));assert.ok(html.includes('模型授权'));assert.ok(html.includes('data-testid="api-key-management"'));
 assert.doesNotMatch(html,/role="tablist"/);assert.doesNotMatch(html,/可用余额/);
 // Key 放在最上面，接入配置在下
 assert.ok(html.indexOf('api-key-management')<html.indexOf('模型授权'));
});
test('personal center uses horizontal tabs and shows one section at a time',()=>{
 const html=renderToStaticMarkup(React.createElement(BillingPage));
 assert.match(html,/role="tablist"/);
 const tabs=[...html.matchAll(/<button[^>]*role="tab"[^>]*>([^<]+)<\/button>/g)].map(m=>m[1]);
 assert.deepEqual(tabs,['用量概览','钱包','限额']);
 assert.doesNotMatch(html,/api-key-management/);
 assert.match(html,/id="center-tab-overview"[^>]*aria-selected="true"/);
 const panels=[...html.matchAll(/<section([^>]*)role="tabpanel"([^>]*)>/g)].map(m=>m[1]+m[2]);
 assert.equal(panels.length,3);
 assert.equal(panels.filter(attrs=>!/hidden=""/.test(attrs)).length,1);
 assert.ok(panels.find(attrs=>!/hidden=""/.test(attrs))?.includes('center-panel-overview'));
});

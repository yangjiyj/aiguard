import test from 'node:test';import assert from 'node:assert/strict';
import React from 'react';import {renderToStaticMarkup} from 'react-dom/server';

test('greeting follows the local hour',async()=>{
 const {greeting}=await import('../src/components/chat/empty-state.js');
 assert.equal(greeting(9,'张三'),'上午好，张三');assert.equal(greeting(14,'张三'),'下午好，张三');assert.equal(greeting(20,''),'晚上好');assert.equal(greeting(3,'李四'),'晚上好，李四');
});

test('message meta shows copy, regenerate, mask chip and timing',async()=>{
 Object.assign(globalThis,{React});
 const {MessageMeta}=await import('../src/components/chat/message-item.js');
 const html=renderToStaticMarkup(React.createElement(MessageMeta,{securityAction:'mask',timing:{ttftMs:3100,tps:42},onCopy:()=>{},onRegenerate:()=>{}}));
 assert.match(html,/复制/);assert.match(html,/重新生成/);assert.match(html,/已脱敏/);assert.match(html,/首字 3\.10s · 42\.0 t\/s/);
 const plain=renderToStaticMarkup(React.createElement(MessageMeta,{securityAction:'audit',timing:{ttftMs:900,tps:null},onCopy:()=>{}}));
 assert.doesNotMatch(plain,/已脱敏|已记录/);assert.doesNotMatch(plain,/重新生成/);assert.match(plain,/首字 900ms/);assert.doesNotMatch(plain,/t\/s/);
});

test('chat surface moves the guard badge to the header and the picker into a slot',async()=>{
 const {readFile}=await import('node:fs/promises');
 const read=(p:string)=>readFile(new URL(p,import.meta.url),'utf8');
 const [panel,composer,empty]=await Promise.all([read('../src/components/chat/chat-panel.tsx'),read('../src/components/chat/composer.tsx'),read('../src/components/chat/empty-state.tsx')]);
 assert.match(panel,/守护中/);assert.doesNotMatch(composer,/智能守护中/);
 assert.match(panel,/<ModelSelector/);assert.doesNotMatch(composer,/<ModelSelector/);assert.match(composer,/modelSlot/);
 // 对话进行中也在输入框里切换模型，头部不再放选择器
 assert.match(panel,/modelSlot=\{modelSelector\}/);assert.doesNotMatch(panel,/!empty && modelSelector/);assert.match(panel,/placement="up"/);
 assert.doesNotMatch(empty,/今天想一起完成什么|企业安全策略已启用|仅显示被允许的模型/);
});

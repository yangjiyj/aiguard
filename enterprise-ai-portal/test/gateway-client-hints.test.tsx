import test from 'node:test';import assert from 'node:assert/strict';import React from 'react';import {renderToStaticMarkup} from 'react-dom/server';
import {gatewayClientConfig} from '../src/lib/gateway-client-config';
import {GatewayConfigPanel} from '../src/components/gateway-config-panel';

// 现场 P3-9：Anthropic 协议客户端（Claude Code）自己拼 /v1/messages，ANTHROPIC_BASE_URL 不能带 /v1；
// OpenAI 协议客户端的 base_url 要带 /v1；https 不要配 8080 这类明文端口。地址来自网关公开地址配置。

test('门户的 Anthropic 地址不带 /v1、OpenAI 地址带一层 /v1，且都来自配置',()=>{
 const config=gatewayClientConfig('https://gateway.customer.test/proxy/v1/v1','https://portal.test');
 assert.equal(config.openai,'https://gateway.customer.test/proxy/v1');
 assert.equal(config.anthropic,'https://gateway.customer.test/proxy');
 assert.ok(config.claudeCode.includes("ANTHROPIC_BASE_URL='https://gateway.customer.test/proxy'"));
 assert.ok(!config.claudeCode.includes('/v1'));
 assert.ok(config.codex.includes('base_url = "https://gateway.customer.test/proxy/v1"'));
 assert.ok(config.curlAnthropic.includes("'https://gateway.customer.test/proxy/v1/messages'"));
 assert.ok(!config.curlAnthropic.includes('/v1/v1'));
});

test('https 配到网关明文端口时给出提示，正常组合没有该提示',()=>{
 for(const port of [8080,8082,3000]){
  const warnings=gatewayClientConfig('https://gw.customer.test:'+port+'/v1','https://portal.test').warnings;
  assert.ok(warnings.some(w=>w.includes('明文 HTTP 端口')&&w.includes(String(port))),'port '+port);
 }
 for(const ok of ['http://gw.customer.test:8080/v1','https://gw.customer.test/v1','https://gw.customer.test:8453/v1','https://gw.customer.test:443/v1']){
  assert.ok(!gatewayClientConfig(ok,'https://portal.test').warnings.some(w=>w.includes('明文 HTTP 端口')),ok);
 }
});

test('接入面板分协议标注写法，并固定展示两条常见错误提示',()=>{
 const config=gatewayClientConfig('https://gateway.customer.test/v1','https://portal.test');
 const html=renderToStaticMarkup(React.createElement(GatewayConfigPanel,{config}));
 assert.ok(html.includes('OpenAI 兼容地址'));assert.ok(html.includes('Anthropic 兼容地址'));
 assert.ok(html.includes('https://gateway.customer.test/v1'));assert.ok(html.includes('https://gateway.customer.test<'));
 assert.match(html,/Anthropic 协议[^<]*不带 \/v1/);
 assert.match(html,/OpenAI 协议[^<]*带一层 \/v1/);
 // 用户要求去掉配置说明提示框，只保留地址和复制。
 assert.doesNotMatch(html,/https[^<]*不要[^<]*明文[^<]*端口/);
 assert.doesNotMatch(html,/\/v1[^<]*不要重复/);
});

test('面板对 https 配明文端口的地址渲染针对性提示',()=>{
 const config=gatewayClientConfig('https://gw.customer.test:8080/v1','https://portal.test');
 const html=renderToStaticMarkup(React.createElement(GatewayConfigPanel,{config}));
 assert.match(html,/端口 8080 通常是网关的明文 HTTP 端口/);
});

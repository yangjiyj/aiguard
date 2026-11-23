import assert from 'node:assert/strict';
import test from 'node:test';

import { forwardToGateway, PORTAL_AGENT_TYPE } from '../src/proxy.js';

// 网关只给企业门户的回复加 AI 生成内容标识，靠这个头识别门户流量。
test('转发网关时声明客户端类型为企业门户', async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchImpl = async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const written: unknown[] = [];
  const sink = {
    writeHead: (_status: number, _headers: unknown) => {},
    write: (chunk: unknown) => {
      written.push(chunk);
    },
    end: () => {},
  };

  await forwardToGateway(
    {
      gatewayBaseUrl: 'http://gateway.test',
      targetPath: '/v1/chat/completions',
      accept: 'text/event-stream',
      fullKey: 'synthetic-employee-key',
      forwardBody: { model: 'm', messages: [] },
      fetchImpl,
    },
    sink,
  );

  assert.equal(PORTAL_AGENT_TYPE, 'enterprise-portal');
  assert.equal(calls.length, 1);
  const headers = calls[0].init.headers as Record<string, string>;
  assert.equal(headers['x-jjdguard-agent-type'], 'enterprise-portal');
  assert.equal(headers.authorization, 'Bearer synthetic-employee-key');
  assert.equal(headers['content-type'], 'application/json');
});

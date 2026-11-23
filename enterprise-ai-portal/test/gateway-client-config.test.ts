import test from 'node:test';import assert from 'node:assert/strict';
test('OpenAI and Anthropic coordinates and placeholder CLI examples use the same configured gateway',async()=>{
 const {gatewayClientConfig}=await import('../src/lib/gateway-client-config.js');
 const config=gatewayClientConfig('https://gateway.test/custom/v1','https://portal.test/chat');
 assert.equal(config.openai,'https://gateway.test/custom/v1');assert.equal(config.anthropic,'https://gateway.test/custom');
 assert.ok(config.curlAnthropic.includes('/v1/messages'));assert.ok(config.curlAnthropic.includes('YOUR_API_KEY'));
 assert.ok(config.codex.includes('wire_api = "responses"'));assert.ok(config.claudeCode.includes('ANTHROPIC_BASE_URL'));
 assert.ok(gatewayClientConfig('http://chat-edge:8180/v1','https://portal.test/chat').warnings.length>=2);
});

test('private IPv4 BaseURLs warn clients about network reachability',async()=>{
 const {gatewayClientConfig}=await import('../src/lib/gateway-client-config.js');
 for(const ip of ['10.0.0.10','172.16.0.1','172.31.255.255','192.168.1.10'])assert.ok(gatewayClientConfig('https://'+ip+'/v1','https://portal.test').warnings.some(w=>w.includes('内网')),ip);
 assert.equal(gatewayClientConfig('https://203.0.113.1/v1','https://portal.test').warnings.length,0);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {personalActionError} from '../src/lib/personal-action-errors';
import {personalActionResponse} from '../src/lib/portal-write-security';
test('关键错误具有准确提示且不会误报兑换码无效',()=>{
 const messages=['invalid_origin','redemption_unavailable','rate_limited','control_plane_unreachable','unauthorized'].map(code=>personalActionError(code));
 assert.equal(new Set(messages).size,5);
 assert.match(messages[0],/来源/);assert.match(messages[1],/兑换码/);assert.match(messages[2],/频繁/);assert.match(messages[3],/服务/);assert.match(messages[4],/登录/);
 assert.equal(personalActionError('unknown_secret_text'),'操作失败，请稍后重试。');
});
test('失败响应带服务端 trace_id，日志不包含兑换码、Key 或上游消息',async()=>{
 const logs:string[]=[];const original=console.warn;console.warn=(value)=>logs.push(String(value));
 try{
  const request=new Request('https://portal.test/chat/api/me/billing/redeem',{method:'POST',body:'do-not-log-request-secret'});
  const response=await personalActionResponse(request,'redeem',Response.json({error:'invalid_origin',message:'do-not-log-upstream-secret'},{status:403}));
  assert.match(response.headers.get('x-trace-id')??'',/^[0-9a-f-]{36}$/);
  assert.equal(logs.length,1);assert.ok(logs[0].includes(response.headers.get('x-trace-id')!));
  assert.doesNotMatch(logs[0],/do-not-log/);
 }finally{console.warn=original}
});

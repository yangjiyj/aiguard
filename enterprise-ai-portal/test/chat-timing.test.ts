import test from 'node:test';import assert from 'node:assert/strict';

test('ChatTimer measures ttft from send to first chunk and tps from first chunk to end',async()=>{
 const {ChatTimer}=await import('../src/lib/chat-timing.js');
 let now=1000;const timer=new ChatTimer(()=>now);
 now=4100;timer.chunk();now=4500;timer.chunk();now=6100;timer.usage(84);
 assert.deepEqual(timer.result(),{ttftMs:3100,tps:42});
});

test('ChatTimer omits tps without usage or with a too-short generation window',async()=>{
 const {ChatTimer}=await import('../src/lib/chat-timing.js');
 let now=0;const a=new ChatTimer(()=>now);now=500;a.chunk();now=3000;
 assert.deepEqual(a.result(),{ttftMs:500,tps:null});
 const b=new ChatTimer(()=>now);now+=100;b.chunk();now+=50;b.usage(10);
 assert.equal(b.result().tps,null);
 const c=new ChatTimer(()=>now);
 assert.deepEqual(c.result(),{ttftMs:null,tps:null});
});

test('parseSSEData emits usage from the final chunk',async()=>{
 const {parseSSEData}=await import('../src/lib/sse.js');
 assert.deepEqual(parseSSEData('{"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":84}}'),[{type:'usage',outputTokens:84}]);
 assert.deepEqual(parseSSEData('{"choices":[{"delta":{"content":"hi"}}]}'),[{type:'delta',content:'hi'}]);
 assert.deepEqual(parseSSEData('{"choices":[{"delta":{"content":"x"}}],"usage":null}'),[{type:'delta',content:'x'}]);
});

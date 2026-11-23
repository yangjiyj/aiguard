import test from 'node:test';import assert from 'node:assert/strict';

test('opening the portal starts a new chat unless ?c= names a known conversation',async()=>{
 const {initialConversationId}=await import('../src/lib/chat-initial.js');
 assert.equal(initialConversationId('?c=a',['a','b']),'a');
 assert.equal(initialConversationId('?c=x',['a','b']),null);
 assert.equal(initialConversationId('',['a']),null);
 assert.equal(initialConversationId('?c=',['a']),null);
 const {readFileSync}=await import('node:fs');
 const store=readFileSync(new URL('../src/components/chat/store.tsx',import.meta.url),'utf8');
 assert.doesNotMatch(store,/list\[0\]\?\.id/);
 assert.match(store,/initialConversationId\(/);
});

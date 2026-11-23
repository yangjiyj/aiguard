import test from 'node:test';
import assert from 'node:assert/strict';
import { takeChatLoginTicket } from '../src/lib/chat-login.js';

test('ticket is removed from browser history before being passed to Auth.js', () => {
 const historyCalls: unknown[][]=[];
 const ticket='A'.repeat(43);
 const result=takeChatLoginTicket({hash:'#chat_ticket='+ticket,pathname:'/chat/login',search:''},{
  replaceState:(...args: unknown[])=>{historyCalls.push(args);},
 });
 assert.equal(result,ticket);
 assert.deepEqual(historyCalls,[[null,'','/chat/login']]);
});
test('malformed fragments are still erased and query parameters cannot supply a login ticket', () => {
 let erased=false;
 assert.throws(()=>takeChatLoginTicket({hash:'#chat_ticket=bad',pathname:'/chat/login',search:''},
  {replaceState:()=>{erased=true;}}),/invalid_chat_ticket/);
 assert.equal(erased,true);
 assert.equal(takeChatLoginTicket({hash:'',pathname:'/chat/login',search:'?chat_ticket='+ 'A'.repeat(43)},
  {replaceState:()=>assert.fail('no fragment to erase')}),null);
});

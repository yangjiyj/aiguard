import test from 'node:test';import assert from 'node:assert/strict';

test('workspace pages share the chat sidebar instead of a back-to-chat bar',async()=>{
 const {readFileSync}=await import('node:fs');
 const read=(p:string)=>readFileSync(new URL(p,import.meta.url),'utf8');
 const shell=read('../src/components/portal-shell.tsx');
 assert.match(shell,/ChatStoreProvider/);assert.match(shell,/<Sidebar/);assert.doesNotMatch(shell,/返回对话|WorkspaceBar/);
 const sidebar=read('../src/components/chat/sidebar.tsx');
 assert.match(sidebar,/<WorkspaceNav/);
 // 工作台页里点历史会话、新对话都回到对话页
 assert.match(sidebar,/portalPath\(`\/\?c=\$\{encodeURIComponent\(/);
 for(const [page,key] of [['models','models'],['billing','billing'],['keys','keys']]){
  assert.match(read(`../src/app/${page}/page.tsx`),new RegExp(`<PortalShell active="${key}"`));
 }
 assert.match(read('../src/app/records/page.tsx'),/<PortalShell active="records"/);
});

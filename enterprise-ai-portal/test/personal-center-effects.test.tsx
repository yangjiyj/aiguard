import test from 'node:test';import assert from 'node:assert/strict';import React,{act} from 'react';import {JSDOM} from 'jsdom';
// Establish a browser surface before loading React DOM and its client components.
const browserBootstrap=new JSDOM('<!doctype html><html><body></body></html>',{url:'https://portal.test'});
Object.assign(globalThis,{window:browserBootstrap.window,document:browserBootstrap.window.document});
let EmployeeKeyPanel:typeof import('../src/components/employee-key-panel.js').EmployeeKeyPanel;
let BillingPage:typeof import('../src/components/billing-page.js').default;
let ApiKeysPanel:typeof import('../src/components/api-keys-panel.js').ApiKeysPanel;
test.before(async()=>{
 ({EmployeeKeyPanel}=await import('../src/components/employee-key-panel.js'));
 ({default:BillingPage}=await import('../src/components/billing-page.js'));
 ({ApiKeysPanel}=await import('../src/components/api-keys-panel.js'));
});
test.after(()=>browserBootstrap.window.close());
const fixture={id:'key-fixture',name:'可用个人密钥',prefix:'masked',project_id:'private-project-id',scopes:['chat'],status:'active',created_at:'2026-10-13T00:00:00Z'};
async function mount(element:React.ReactNode,fetchImpl:typeof fetch,check:(container:HTMLElement)=>Promise<void>){
 const dom=new JSDOM('<!doctype html><div id="root"></div>',{url:'https://portal.test/chat'});
 const originalFetch=globalThis.fetch,originalWindow=globalThis.window,originalDocument=globalThis.document,originalNavigator=Object.getOwnPropertyDescriptor(globalThis,'navigator');
 Object.assign(globalThis,{window:dom.window,document:dom.window.document,IS_REACT_ACT_ENVIRONMENT:true});Object.defineProperty(globalThis,'navigator',{configurable:true,value:dom.window.navigator});globalThis.fetch=fetchImpl;
 const {createRoot}=await import('react-dom/client');
 const container=dom.window.document.getElementById('root')!,root=createRoot(container);
 try{await act(async()=>{root.render(element);await new Promise(resolve=>setTimeout(resolve,0))});await check(container)}
 finally{await act(async()=>root.unmount());globalThis.fetch=originalFetch;Object.assign(globalThis,{window:originalWindow,document:originalDocument});if(originalNavigator)Object.defineProperty(globalThis,'navigator',originalNavigator);dom.window.close()}
}
test('billing failure executes effects and leaves real Key controls usable',async()=>{
 const seen:string[]=[];
 await mount(React.createElement(BillingPage),async(input)=>{
  const path=String(input);seen.push(path);
  if(path.endsWith('/billing'))return Response.json({error:'unavailable'},{status:500});
  if(path.endsWith('/keys'))return Response.json({data:[fixture]});
  if(path.endsWith('/model-access'))return Response.json({data:{modelIds:['approved'],modelSources:{approved:'department'},extraGrants:[],staleModels:[]}});
  if(path.endsWith('/employee-key'))return Response.json({error:'authorization_denied'},{status:403});
  return Response.json({user:{name:'fixture'},data:{openai:'https://gateway.test/v1',anthropic:'https://gateway.test',warnings:[]}});
 },async container=>{
  assert.ok(seen.some(p=>p.endsWith('/billing')));assert.ok(seen.some(p=>p.endsWith('/keys')));
  assert.ok(container.textContent?.includes('账单数据暂不可用'));assert.ok(container.textContent?.includes('可用个人密钥'));assert.ok(container.textContent?.includes('approved'));
  assert.equal(container.textContent?.includes('private-project-id'),false);
  const copy=[...container.querySelectorAll('button')].find(b=>b.textContent==='复制完整 Key');assert.ok(copy);assert.equal(copy.disabled,false);
 });
});
test('revoke dialog owns focus, traps Tab and closes with Escape',async()=>{
 await mount(React.createElement(ApiKeysPanel,{initialKeys:[fixture],projects:[]}),async()=>new Response(null,{status:204}),async container=>{
  const trigger=[...container.querySelectorAll('button')].find(b=>b.textContent==='吊销')!;trigger.focus();
  await act(async()=>trigger.click());
  const dialog=container.querySelector('[role="dialog"]')!;assert.ok(dialog);assert.ok(dialog.contains(document.activeElement));
  const buttons=[...dialog.querySelectorAll('button')];buttons.at(-1)!.focus();
  await act(async()=>document.dispatchEvent(new window.KeyboardEvent('keydown',{key:'Tab',bubbles:true,cancelable:true})));
  assert.ok(document.activeElement===buttons[0]);
  await act(async()=>document.dispatchEvent(new window.KeyboardEvent('keydown',{key:'Escape',bubbles:true})));
  assert.equal(container.querySelector('[role="dialog"]'),null);assert.ok(document.activeElement===trigger);
 });
});

test('employee credential dialog masks content and Escape restores focus',async()=>{
 const metadata={id:'employee-key',prefix:'masked',generation:1,status:'active',created_at:'2026-10-13T00:00:00Z',claim_available:true};
 await mount(React.createElement(EmployeeKeyPanel),async(input)=>String(input).endsWith('/claim')?Response.json({data:{...metadata,claim_available:false},full_key:'fixture-secret-only'}):Response.json({data:metadata}),async container=>{
  const trigger=[...container.querySelectorAll('button')].find(b=>b.textContent==='领取完整 Key')!;assert.ok(trigger);trigger.focus();
  await act(async()=>trigger.click());
  const dialog=container.querySelector('[role="dialog"]')!;assert.ok(dialog);assert.ok(dialog.contains(document.activeElement));
  assert.equal(dialog.querySelector('input')?.getAttribute('type'),'password');
  await act(async()=>document.dispatchEvent(new window.KeyboardEvent('keydown',{key:'Escape',bubbles:true})));
  // The claim button disappears after successful one-time delivery; return to the stable refresh control.
  assert.equal(container.querySelector('[role="dialog"]'),null);assert.equal(document.activeElement?.getAttribute("aria-label"),"刷新个人 Key");
 });
});
test('missing managed Key uses explicit POST ensure and claim',async()=>{
 const metadata={id:'employee-key',prefix:'masked',generation:1,status:'active',created_at:'2026-10-13T00:00:00Z',claim_available:true};
 const calls:Array<{path:string;method:string}>=[];
 await mount(React.createElement(EmployeeKeyPanel),async(input,init)=>{
  const path=String(input);calls.push({path,method:init?.method??'GET'});
  if(path.endsWith('/ensure'))return Response.json({data:metadata});
  if(path.endsWith('/claim'))return Response.json({data:{...metadata,claim_available:false},full_key:'fixture-issued-secret'});
  return Response.json({error:'employee_key_not_found'},{status:404});
 },async container=>{
  assert.deepEqual(calls.map(c=>c.method),['GET']);
  const trigger=[...container.querySelectorAll('button')].find(b=>b.textContent==='领取个人 Key')!;assert.ok(trigger);
  await act(async()=>trigger.click());
  assert.deepEqual(calls.map(c=>c.method),['GET','POST','POST']);
  assert.ok(calls[1].path.endsWith('/ensure'));assert.ok(calls[2].path.endsWith('/claim'));
  assert.ok(container.querySelector('[role="dialog"]'));assert.equal(container.querySelector('input')?.type,'password');
 });
});

test('统一 Key 表创建时仅提供授权模型，提交白名单并脱敏展示新 Key',async()=>{
 const writes:Array<Record<string,unknown>>=[];
 await mount(React.createElement(ApiKeysPanel,{initialKeys:[fixture],projects:[],availableModels:['approved']}),async(input,init)=>{
  if(String(input).endsWith('/employee-key'))return Response.json({error:'authorization_denied'},{status:403});
  writes.push(JSON.parse(String(init?.body??'{}')));
  return Response.json({data:{...fixture,id:'new-restricted-key',model_allowlist:['approved']},full_key:'fixture-created-credential'});
 },async container=>{
  const create=[...container.querySelectorAll('button')].find(button=>button.textContent==='创建 API 密钥')!;await act(async()=>create.click());
  const checkbox=container.querySelector('input[type="checkbox"]')!;await act(async()=>checkbox.dispatchEvent(new window.MouseEvent('click',{bubbles:true})));
  const choices=container.querySelectorAll('input[aria-label="授权模型 approved"]');assert.equal(choices.length,1);
  await act(async()=>(choices[0] as HTMLInputElement).click());
  const form=container.querySelector('form')!;await act(async()=>form.dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true})));
  assert.deepEqual(writes[0].model_allowlist,['approved']);
  assert.equal(container.querySelector('input[aria-label="完整 API Key"]')?.getAttribute('type'),'password');
 });
});
test('旧 Key 重置须确认并显示新密钥，旧行吊销且模型限制保留',async()=>{
 const key={...fixture,model_allowlist:['approved']};const calls:string[]=[];
 await mount(React.createElement(ApiKeysPanel,{initialKeys:[key],projects:[],availableModels:['approved']}),async(input)=>{
  const path=String(input);calls.push(path);
  if(path.endsWith('/employee-key'))return Response.json({error:'authorization_denied'},{status:403});
  assert.ok(path.endsWith('/reset'));
  return Response.json({data:{...key,id:'rotated-key'},full_key:'fixture-rotated-credential'});
 },async container=>{
  const reset=[...container.querySelectorAll('button')].find(button=>button.textContent==='重置 Key')!;
  await act(async()=>reset.click());assert.equal(calls.some(path=>path.endsWith('/reset')),false);
  const confirmation=[...container.querySelectorAll('button')].find(button=>button.textContent==='确认重置 Key')!;await act(async()=>confirmation.click());
  assert.equal(calls.filter(path=>path.endsWith('/reset')).length,1);
  assert.ok(container.textContent?.includes('已吊销'));assert.ok(container.textContent?.includes('approved'));
  assert.equal(container.querySelector('input[aria-label="完整 API Key"]')?.getAttribute('type'),'password');
 });
});
test('个人 Key 重置触发列表更新后完整内容仍可领取，不因换行而消失',async()=>{
 let metadata={id:'managed-old',prefix:'masked-old',generation:1,status:'active',created_at:fixture.created_at,claim_available:false};
 function Wrapper(){
  const [keys,setKeys]=React.useState([{...fixture,id:metadata.id,employee_key:true}]);
  const refresh=React.useCallback(()=>setKeys([{...fixture,id:metadata.id,prefix:metadata.prefix,employee_key:true}]),[]);
  return React.createElement(ApiKeysPanel,{initialKeys:keys,projects:[],onKeysChanged:refresh});
 }
 await mount(React.createElement(Wrapper),async(input)=>{
  if(String(input).endsWith('/reset')){metadata={...metadata,id:'managed-new',generation:2,prefix:'masked-new'};return Response.json({data:metadata,full_key:'fixture-managed-rotated'})}
  return Response.json({data:metadata});
 },async container=>{
  const reset=[...container.querySelectorAll('button')].find(button=>button.textContent==='重置个人 Key')!;await act(async()=>reset.click());
  const confirm=[...container.querySelectorAll('button')].find(button=>button.textContent==='确认重置')!;await act(async()=>confirm.click());
  assert.ok(container.querySelector('input[aria-label="完整个人 API Key"]'));assert.equal(container.querySelector('input[aria-label="完整个人 API Key"]')?.getAttribute('type'),'password');
  assert.ok(container.textContent?.includes('masked-new'));
 });
});

test('复制读取网络错误使用中文提示，绝不裸露 Safari Load failed',async()=>{
 await mount(React.createElement(ApiKeysPanel,{initialKeys:[fixture],projects:[]}),async(input)=>{
  if(String(input).endsWith('/employee-key'))return Response.json({error:'authorization_denied'},{status:403});
  throw new TypeError('Load failed');
 },async container=>{
  const copy=[...container.querySelectorAll('button')].find(b=>b.textContent==='复制完整 Key')!;
  await act(async()=>copy.click());assert.ok(container.textContent?.includes('网络请求失败'));
  assert.ok(!container.textContent?.includes('Load failed'));
 });
});

test('Safari 复制在点击中创建异步 ClipboardItem，并且不再次读取 Key',async()=>{
 const prior=Object.getOwnPropertyDescriptor(globalThis,'ClipboardItem');let requested=0,clipboardEntered=false;
 class Item {constructor(public values:Record<string,Promise<Blob>>) {}}
 Object.defineProperty(globalThis,'ClipboardItem',{configurable:true,value:Item});
 try{await mount(React.createElement(ApiKeysPanel,{initialKeys:[fixture],projects:[]}),async(input)=>{
  if(String(input).endsWith('/employee-key'))return Response.json({error:'authorization_denied'},{status:403});
  requested++;await new Promise(resolve=>setTimeout(resolve,0));assert.ok(clipboardEntered);return Response.json({full_key:'fixture-only-value'});
 },async container=>{
  Object.defineProperty(navigator,'clipboard',{configurable:true,value:{write:async(items:Item[])=>{clipboardEntered=true;const value=await items[0].values['text/plain'];assert.equal(await value.text(),'fixture-only-value')}}});
  const button=[...container.querySelectorAll('button')].find(b=>b.textContent==='复制完整 Key')!;await act(async()=>button.click());assert.equal(requested,1);assert.ok(container.textContent?.includes('已复制完整 Key'));assert.equal(container.querySelector('[role="dialog"]'),null);
 })}finally{if(prior)Object.defineProperty(globalThis,'ClipboardItem',prior);else Reflect.deleteProperty(globalThis,'ClipboardItem')}
});

test('剪贴板被拒绝时打开掩码弹窗，支持明确显示后手动复制并关闭清除',async()=>{
 await mount(React.createElement(ApiKeysPanel,{initialKeys:[fixture],projects:[]}),async(input)=>{
  if(String(input).endsWith('/employee-key'))return Response.json({error:'authorization_denied'},{status:403});
  return Response.json({full_key:'fixture-fallback-value'});
 },async container=>{
  Object.defineProperty(document,'execCommand',{configurable:true,value:()=>false});
  await act(async()=>[...container.querySelectorAll('button')].find(b=>b.textContent==='复制完整 Key')!.click());
  assert.equal(container.querySelector('input[aria-label="完整 API Key"]')?.getAttribute('type'),'password');
  await act(async()=>container.querySelector<HTMLButtonElement>('button[aria-label="显示完整 Key"]')!.click());
  assert.equal(container.querySelector('input[aria-label="完整 API Key"]')?.getAttribute('type'),'text');
  await act(async()=>container.querySelector<HTMLButtonElement>('button[aria-label="关闭"]')!.click());
  assert.equal(container.querySelector('input[aria-label="完整 API Key"]'),null);
 });
});

test('personal Key deletion requires one confirmation and removes only after server success',async()=>{
 const calls:Array<{path:string;method:string}>=[];let fail=true;
 await mount(React.createElement(ApiKeysPanel,{initialKeys:[fixture],projects:[]}),async(input,init)=>{
  const path=String(input);if(path.endsWith('/employee-key'))return Response.json({error:'employee_key_not_found'},{status:404});
  calls.push({path,method:init?.method??'GET'});
  return fail?Response.json({error:'not_found'},{status:404}):new Response(null,{status:204});
 },async container=>{
  const button=()=>[...container.querySelectorAll('button')].find(button=>button.textContent==='删除')!;
  await act(async()=>button().click());assert.equal(calls.length,0);
  const confirm=()=>[...container.querySelectorAll('button')].find(button=>button.textContent==='确认删除')!;
  await act(async()=>confirm().click());assert.ok(container.textContent?.includes(fixture.name));
  fail=false;await act(async()=>confirm().click());
  assert.ok(!container.textContent?.includes(fixture.name));assert.equal(container.querySelector('[role="dialog"]'),null);
  assert.equal(calls.length,2);assert.ok(calls.every(call=>call.method==='DELETE'&&call.path.endsWith('/'+fixture.id)));
 });
});

test('deleting the managed Key clears child metadata and old controls while keeping explicit claim available',async()=>{
 const metadata={id:'employee-to-delete',prefix:'old-managed-prefix',generation:2,status:'active',created_at:fixture.created_at,claim_available:true};
 let exists=true;
 await mount(React.createElement(ApiKeysPanel,{initialKeys:[{...fixture,id:metadata.id,prefix:metadata.prefix,employee_key:true}],projects:[]}),async(input,init)=>{
  if(init?.method==='DELETE'){exists=false;return new Response(null,{status:204});}
  assert.ok(String(input).endsWith('/employee-key'));
  return exists?Response.json({data:metadata}):Response.json({error:'employee_key_not_found'},{status:404});
 },async container=>{
  assert.ok(container.textContent?.includes('重置个人 Key'));
  const trigger=[...container.querySelectorAll('button')].find(button=>button.textContent==='删除')!;
  await act(async()=>trigger.click());
  const confirm=[...container.querySelectorAll('button')].find(button=>button.textContent==='确认删除')!;
  await act(async()=>{confirm.click();await new Promise(resolve=>setTimeout(resolve,0))});
  assert.ok(!container.textContent?.includes(metadata.prefix));assert.ok(!container.textContent?.includes('重置个人 Key'));
  assert.ok(!container.textContent?.includes('吊销个人 Key'));assert.ok(container.textContent?.includes('领取个人 Key'));
 });
});

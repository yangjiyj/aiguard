"use client";
import React from 'react';
import {gatewayClientConfig} from '@/lib/gateway-client-config';
import {gatewayAccessOptions,chooseGatewayEndpoint,inspectGatewayResponse} from '@/lib/gateway-access';
import {copyEmployeeKey} from './employee-key-panel';
const preferenceKey='jjdguard.gateway.endpoint';
export function GatewayConfigPanel({config,error,compact=false}:{compact?:boolean;config?:ReturnType<typeof gatewayClientConfig>|null;error?:string}){
 const [notice,setNotice]=React.useState('');
 const [origin,setOrigin]=React.useState('');
 const [preferred,setPreferred]=React.useState('');
 const [checking,setChecking]=React.useState(false);
 const sequence=React.useRef({current:0,active:true});
 React.useEffect(()=>{
  setOrigin(window.location.origin);
  const update=()=>{try{setPreferred(localStorage.getItem(preferenceKey)||'')}catch{/* Storage can be disabled. */}};
  update();window.addEventListener('storage',update);window.addEventListener('jjdguard-gateway-endpoint-change',update);
  return()=>{window.removeEventListener('storage',update);window.removeEventListener('jjdguard-gateway-endpoint-change',update)};
 },[]);
 const settings=config?.access??{gateway_public_base_url:config?.openai};
 const options=gatewayAccessOptions(settings,origin);
 const selected=chooseGatewayEndpoint(options,settings,preferred);
 const selectedConfig=gatewayClientConfig(selected,origin,settings);
 React.useEffect(()=>{const state={current:0,active:true};sequence.current=state;setNotice('');setChecking(false);return()=>{state.active=false}},[selected]);
 const choose=(url:string)=>{setPreferred(url);try{localStorage.setItem(preferenceKey,url);window.dispatchEvent(new Event('jjdguard-gateway-endpoint-change'))}catch{/* The in-memory selection still works. */}};
 const copy=async(value:string)=>{try{await copyEmployeeKey(value);setNotice('调用地址已复制')}catch{setNotice('复制失败，请手动选择地址')}};
 const check=async()=>{
  const state=sequence.current;const requestSequence=++state.current;setChecking(true);setNotice('');
  try{const response=await fetch(selected+'/models',{credentials:'omit',redirect:'error',cache:'no-store',signal:AbortSignal.timeout(8000)});const result=inspectGatewayResponse(response.status,await response.json().catch(()=>null));if(requestSequence===state.current&&state.active)setNotice(result.message)}
  catch{if(requestSequence===state.current&&state.active)setNotice('当前浏览器无法访问此入口，请检查网络、域名解析、HTTPS 证书及转发路径。')}
  finally{if(requestSequence===state.current&&state.active)setChecking(false)}
 };
 return <section className={compact?"min-w-0":"rounded-xl border bg-card p-5 shadow-sm"}><h2 className="text-base font-semibold">调用地址与客户端配置</h2>
 {error&&<p role="alert" className="mt-3 text-sm text-destructive">{error}</p>}
 {config&&selectedConfig.openai?<div className="mt-4 space-y-4">
 <label className="block text-sm">调用入口<select aria-label="调用入口" className="mt-1 w-full rounded border bg-background p-2 text-sm" value={selected} onChange={event=>choose(event.target.value)}>{options.map(entry=><option key={entry.url} value={entry.url}>{entry.name} · {entry.url}</option>)}</select></label>
 <p className="text-xs text-muted-foreground">按调用客户端所在网络选择入口。HTTPS 证书须被客户端信任。</p>
 {origin&&new URL(selected).origin===origin?<button type="button" disabled={checking} onClick={()=>void check()} className="rounded border px-3 py-1 text-xs">{checking?'检查中…':'检查当前入口'}</button>:<a className="text-xs underline" href={selected+'/models'} target="_blank" rel="noreferrer">打开接口检查</a>}
 {[['OpenAI 兼容地址',selectedConfig.openai,'OpenAI 协议（Codex、Cherry Studio 等）：地址带一层 /v1。'],['Anthropic 兼容地址',selectedConfig.anthropic,'Anthropic 协议（Claude Code 等）：地址不带 /v1，客户端会自己拼接 /v1/messages。'],['Gemini 原生地址',selectedConfig.gemini,'Gemini 原生协议：地址不带 /v1。']].map(([label,value,hint])=><div key={label}><p className="text-xs text-muted-foreground">{label}</p><p className="text-xs text-muted-foreground">{hint}</p><div className="mt-1 flex gap-2"><code data-testid={label.startsWith('OpenAI')?'employee-api-base-url':label.startsWith('Anthropic')?'employee-anthropic-base-url':'employee-gemini-base-url'} className="min-w-0 flex-1 break-all">{value}</code><button type="button" aria-label="复制调用地址" onClick={()=>{void copy(value)}} className="rounded border px-2 text-xs">复制地址</button></div></div>)}
 {selectedConfig.warnings.map(w=><p key={w} className="rounded border px-3 py-2 text-sm">{w}</p>)}
 <details><summary className="cursor-pointer text-sm">curl、Codex、Claude Code 配置示例</summary><p className="mt-2 text-xs text-muted-foreground">将 YOUR_API_KEY 和 YOUR_MODEL 替换为本人 Key 与已授权模型。示例不包含真实凭据。</p>
 {([['OpenAI curl',selectedConfig.curlOpenAI],['Anthropic curl',selectedConfig.curlAnthropic],['Gemini curl',selectedConfig.curlGemini],['Codex 配置',selectedConfig.codex],['Claude Code 配置',selectedConfig.claudeCode]] as const).map(([label,value])=><div key={label} className="mt-3"><h3 className="text-sm font-medium">{label}</h3><pre className="mt-2 overflow-x-auto rounded bg-muted p-3 text-xs">{value}</pre></div>)}</details>
 </div>:<p className="mt-4 text-sm text-muted-foreground">正在读取调用入口，请稍后重试。</p>}
 {notice&&<p role="status" className="mt-3 text-xs">{notice}</p>}
 </section>
}

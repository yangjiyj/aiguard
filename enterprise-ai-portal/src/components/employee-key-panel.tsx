"use client";

import React from "react";
import {PERSONAL_ACTION_ERRORS,personalActionError} from "@/lib/personal-action-errors";
import {useDialogFocus} from "@/lib/use-dialog-focus";
import { Check, Copy, Eye, EyeOff, KeyRound, RefreshCw } from "lucide-react";
import { portalPath } from "@/lib/portal-path";

export type EmployeeKeyMetadata = { id:string; prefix:string; generation:number; status:string; created_at:string; claim_available:boolean;model_allowlist?:string[] };
type KeyResponse = { data:EmployeeKeyMetadata; full_key?:string; error?:string };

export async function copyEmployeeKey(secret: string) {
  try {
    if(navigator.clipboard?.writeText){await navigator.clipboard.writeText(secret);return;}
  }catch{/* Private HTTP installations and restricted browsers use the native selection path. */}
  const textarea=document.createElement("textarea");
  textarea.value=secret;textarea.setAttribute("readonly","");textarea.style.position="fixed";textarea.style.opacity="0";
  document.body.appendChild(textarea);
  try{textarea.select();if(!document.execCommand("copy"))throw new Error("copy_failed");}
  finally{textarea.remove();}
}

export function EmployeeKeyPanel({onMetadata,onMissing,inline=false}:{onMetadata?:(metadata:EmployeeKeyMetadata)=>void;onMissing?:(kind:"missing"|"denied")=>void;inline?:boolean}) {
  const refreshButton=React.useRef<HTMLButtonElement>(null);
  const secretDialog=React.useRef<HTMLDivElement>(null),revokeDialog=React.useRef<HTMLDivElement>(null),resetDialog=React.useRef<HTMLDivElement>(null);
  const [metadata,setMetadata]=React.useState<EmployeeKeyMetadata|null>(null);
  const [error,setError]=React.useState("");
  const [missing,setMissing]=React.useState(false);
  const [busy,setBusy]=React.useState(false);
  const [confirmReset,setConfirmReset]=React.useState(false);
  const [confirmRevoke,setConfirmRevoke]=React.useState(false);
  const [secret,setSecret]=React.useState("");
  const [showSecret,setShowSecret]=React.useState(false);
  const [copied,setCopied]=React.useState(false);
  const load=React.useCallback(async()=>{
    const response=await fetch(portalPath("/api/me/employee-key"),{cache:"no-store"});
    const payload=await response.json() as KeyResponse;
    if((response.status===404&&payload.error==="employee_key_not_found")||(response.status===403&&payload.error==="authorization_denied")){setMetadata(null);setMissing(true);onMissing?.(payload.error==="employee_key_not_found"?"missing":"denied");return;}
    if(!response.ok||!payload.data)throw new Error("key_unavailable");
    setMetadata(payload.data);setMissing(false);
    onMetadata?.(payload.data);
  },[onMetadata,onMissing]);
  React.useEffect(()=>{void Promise.resolve().then(load).catch(()=>setError("个人 API Key 暂不可用，请稍后刷新重试。"));},[load]);
  React.useEffect(()=>{
    if(!secret)return;
    const timer=window.setTimeout(()=>{setSecret("");setShowSecret(false);setCopied(false);},60000);
    return()=>window.clearTimeout(timer);
  },[secret]);
  const close=()=>{setSecret("");setShowSecret(false);setCopied(false);};
  useDialogFocus(secretDialog,Boolean(secret),close,refreshButton);
  useDialogFocus(revokeDialog,confirmRevoke,()=>{if(!busy)setConfirmRevoke(false)});
  useDialogFocus(resetDialog,confirmReset,()=>{if(!busy)setConfirmReset(false)});
  const issue=async(operation:"claim"|"reset")=>{
    if(busy||!metadata)return;
    setBusy(true);setError("");
    try{
      const response=await fetch(portalPath("/api/me/employee-key/"+operation),{
        method:"POST",headers:{"content-type":"application/json"},cache:"no-store",
        body:JSON.stringify({expected_key_id:metadata.id,expected_generation:metadata.generation}),
      });
      const payload=await response.json().catch(()=>null) as KeyResponse|null;
      if(!response.ok||!payload?.data||!payload.full_key){
        const notices:Record<string,string>={...PERSONAL_ACTION_ERRORS,employee_key_already_claimed:"完整 Key 已展示过，请使用已保存的内容，或确认重置。",employee_key_conflict:"个人 Key 已变更，请刷新后重试。",authorization_denied:"当前账号不可管理个人 API Key，请联系管理员。"};
        const notice=notices[payload?.error??""];
        throw new Error(typeof notice==="string"?notice:"个人 API Key 操作失败，请稍后重试。");
      }
      setMetadata(payload.data);setSecret(payload.full_key);setShowSecret(false);setCopied(false);setConfirmReset(false);
      onMetadata?.(payload.data);
    }catch(cause){setError(cause instanceof Error?cause.message:"个人 API Key 操作失败。");}
    finally{setBusy(false);}
  };

  const createAndClaim=async()=>{
   if(busy)return;setBusy(true);setError("");
   try{
    const response=await fetch(portalPath("/api/me/employee-key/ensure"),{method:"POST",headers:{"content-type":"application/json"},body:"{}",cache:"no-store"});
    const made=await response.json() as KeyResponse;if(!response.ok||!made.data)throw new Error(personalActionError(made.error,"个人 Key 创建失败，请联系管理员。"));
    setMetadata(made.data);setMissing(false);
    const claim=await fetch(portalPath("/api/me/employee-key/claim"),{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({expected_key_id:made.data.id,expected_generation:made.data.generation}),cache:"no-store"});
    const payload=await claim.json() as KeyResponse;if(!claim.ok||!payload.data||!payload.full_key)throw new Error(personalActionError(payload.error,"个人 Key 领取失败，请刷新后重试。"));
    setMetadata(payload.data);setSecret(payload.full_key);setShowSecret(false);setCopied(false);onMetadata?.(payload.data);
   }catch(e){setError(e instanceof Error?e.message:"个人 Key 操作失败。")}finally{setBusy(false)}
  };
  const revoke=async()=>{
   if(busy||!metadata)return;setBusy(true);setError('');
   try{
    const r=await fetch(portalPath('/api/me/keys/'+encodeURIComponent(metadata.id)+'/revoke'),{method:'POST',cache:'no-store'});
    if(r.status!==204){const payload=await r.json().catch(()=>null);throw new Error(personalActionError(payload?.error,'吊销失败，请刷新后重试。'));}
    close();setConfirmRevoke(false);await load();
   }catch(e){setError(e instanceof Error?e.message:'吊销失败。')}
   finally{setBusy(false)}
  };
  return <section className={inline?"space-y-2":"rounded-xl border bg-card p-5 shadow-sm"} data-testid="employee-managed-key">
    <div className="flex items-center justify-between gap-3"><h2 className={inline?"sr-only":"flex items-center gap-2 text-base font-semibold"}><KeyRound className="h-4 w-4"/>个人 API Key</h2>{!inline&&<button ref={refreshButton} type="button" onClick={()=>{setError("");void load().catch(()=>setError("个人 API Key 暂不可用，请稍后刷新重试。"));}} disabled={busy} className="flex h-9 w-9 items-center justify-center rounded border hover:bg-accent disabled:opacity-50" aria-label="刷新个人 Key"><RefreshCw className="h-4 w-4"/></button>}</div>
    <p className={inline?"sr-only":"mt-2 text-xs leading-relaxed text-muted-foreground"}>登录后自动配置，始终绑定本人及当前模型权限。每一版完整内容可领取一次；可重置或吊销后重新领取，旧 Key 会立即失效。</p>
    {metadata?<div className={inline?"mt-2 space-y-2":"mt-4 space-y-3"}><div className={inline?"sr-only":"flex flex-wrap items-center justify-between gap-2"}><code className="break-all font-mono text-sm">{metadata.prefix}••••</code><span className="text-xs text-muted-foreground">第 {metadata.generation} 版 · {metadata.status==="active"?"正常":"不可用"}</span></div><p className={inline?"sr-only":"text-xs text-muted-foreground"}>创建时间 {new Date(metadata.created_at).toLocaleString()}</p><div className="flex flex-wrap gap-2">{metadata.status!=="active"&&<button type="button" disabled={busy} onClick={()=>{void createAndClaim()}} className="rounded border px-3 py-2">重新领取个人 Key</button>}{metadata.claim_available&&<button type="button" onClick={()=>{void issue("claim");}} disabled={busy} className="rounded-lg bg-primary px-3 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50">{busy?"处理中…":"领取完整 Key"}</button>}<button type="button" onClick={()=>setConfirmReset(true)} disabled={busy} className={inline?"rounded border px-2 py-1 text-xs disabled:opacity-50":"rounded-lg border px-3 py-2 text-sm hover:bg-accent disabled:opacity-50"}>重置个人 Key</button>{!inline&&<button type="button" disabled={busy} onClick={()=>setConfirmRevoke(true)} className={inline?"rounded border px-2 py-1 text-xs text-destructive":"rounded border px-3 py-2 text-sm text-destructive"}>吊销个人 Key</button>}</div></div>:missing?<button type="button" disabled={busy} onClick={()=>{void createAndClaim()}} className="mt-4 rounded border px-3 py-2">领取个人 Key</button>:<p className="mt-4 text-sm text-muted-foreground">正在读取个人 Key…</p>}
    {error&&<p role="alert" className="mt-4 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</p>}
    {confirmRevoke&&<div ref={revokeDialog} tabIndex={-1} aria-modal="true" role="dialog" className="mt-4 rounded border p-4"><p>确认吊销当前个人 Key？旧 Key 立即失效，之后可以领取新的一版。</p><div className="mt-3 flex gap-2"><button type="button" disabled={busy} onClick={()=>{void revoke()}} className="rounded border px-3 py-2 text-destructive">确认吊销个人 Key</button><button type="button" data-dialog-autofocus disabled={busy} onClick={()=>setConfirmRevoke(false)} className="rounded border px-3 py-2">取消</button></div></div>}
    {confirmReset&&<div ref={resetDialog} role="dialog" aria-modal="true" tabIndex={-1} className="mt-4 rounded-lg border border-amber-300 bg-amber-50 px-3 py-3 text-sm text-amber-900 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-200"><p>重置后，使用旧 Key 的 API 调用将失败。确认继续？</p><div className="mt-3 flex gap-2"><button type="button" onClick={()=>{void issue("reset");}} disabled={busy} className="rounded border border-current px-3 py-1.5 font-medium disabled:opacity-50">{busy?"正在重置…":"确认重置"}</button><button type="button" onClick={()=>setConfirmReset(false)} disabled={busy} className="rounded px-3 py-1.5 hover:bg-black/5">取消</button></div></div>}
    {secret&&<div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/40 p-4"><div ref={secretDialog} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="employee-key-once-title" className="w-full max-w-lg rounded-2xl border bg-background p-6 shadow-xl"><h3 id="employee-key-once-title" className="text-lg font-semibold">请安全保存个人 Key</h3><p className="mt-2 text-sm text-muted-foreground">完整内容只在本次操作中显示，60 秒后自动隐藏。请勿发送给他人或放入截图。</p><div className="mt-4 flex items-center gap-2" data-sensitive="api-key"><input aria-label="完整个人 API Key" type={showSecret?"text":"password"} value={secret} readOnly autoComplete="off" className="h-11 min-w-0 flex-1 rounded-lg border bg-muted/40 px-3 font-mono text-sm"/><button type="button" onClick={()=>setShowSecret(value=>!value)} aria-label={showSecret?"隐藏 Key":"显示 Key"} className="flex h-11 w-11 items-center justify-center rounded border">{showSecret?<EyeOff className="h-4 w-4"/>:<Eye className="h-4 w-4"/>}</button><button type="button" onClick={()=>{void copyEmployeeKey(secret).then(()=>setCopied(true)).catch(()=>setError("复制失败，请检查浏览器剪贴板权限。"));}} aria-label="复制个人 Key" className="flex h-11 w-11 items-center justify-center rounded border">{copied?<Check className="h-4 w-4"/>:<Copy className="h-4 w-4"/>}</button></div><div className="mt-5 flex justify-end"><button type="button" onClick={close} className="rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground">已保存，关闭</button></div></div></div>}
  </section>;
}

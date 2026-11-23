"use client";

import * as React from "react";
import {PERSONAL_ACTION_ERRORS,personalActionError} from "@/lib/personal-action-errors";
import {useDialogFocus} from "@/lib/use-dialog-focus";
import {EmployeeKeyPanel,copyEmployeeKey,type EmployeeKeyMetadata} from "./employee-key-panel";
import { portalPath } from "@/lib/portal-path";

export type PortalApiKey = {
  employee_key?:boolean;
  model_allowlist?:string[];
  id: string;
  name: string;
  prefix: string;
  project_id: string;
  scopes: string[];
  status: string;
  created_at: string;
  last_used_at?: string;
  expires_at?: string;
};

export type PortalProject = { id: string; name: string };

type CreateKeyResponse = { data: PortalApiKey; full_key: string };

const statusLabels: Record<string, string> = {
  active: "正常",
  disabled: "已停用",
  revoked: "已失效",
};

function statusLabel(value: string) {
  return statusLabels[value] || "未知状态";
}

async function copyKey(value: string): Promise<boolean> {
  try { await copyEmployeeKey(value); return true; } catch { return false; }
}

function actionError(cause:unknown,fallback:string) {
  return cause instanceof TypeError ? '网络请求失败，请检查连接后重试。' : cause instanceof Error ? cause.message : fallback;
}

export function ApiKeysPanel({
  initialKeys,
  projects,
  availableModels=[],
  customerGroup,
  onKeysChanged,
}: {
  initialKeys: PortalApiKey[];
  projects: PortalProject[];
  availableModels?:string[];
  customerGroup?:string;
  onKeysChanged?:()=>void;
}) {
  const [keys, setKeys] = React.useState(initialKeys);
  React.useEffect(()=>{void Promise.resolve().then(()=>setKeys(initialKeys));},[initialKeys]);
  const [clockNow,setClockNow]=React.useState(0);
  React.useEffect(()=>{const tick=()=>setClockNow(Date.now());void Promise.resolve().then(tick);const timer=window.setInterval(tick,60000);return()=>window.clearInterval(timer)},[]);
  const [nameFilter,setNameFilter]=React.useState(''),[statusFilter,setStatusFilter]=React.useState('');
  const [employeeAvailability,setEmployeeAvailability]=React.useState<'loading'|'missing'|'denied'>('loading');
  const employeeMissing=React.useCallback((kind:'missing'|'denied')=>setEmployeeAvailability(kind),[]);
  const [employeeEpoch,setEmployeeEpoch]=React.useState(0);
  const deletedEmployeeIds=React.useRef(new Set<string>());
  const [employeeMetadata,setEmployeeMetadata]=React.useState<EmployeeKeyMetadata|null>(null);
  const metadataUpdated=React.useCallback((value:EmployeeKeyMetadata)=>{if(deletedEmployeeIds.current.has(value.id))return;setEmployeeMetadata(value);onKeysChanged?.();},[onKeysChanged]);
  const [editing,setEditing]=React.useState<PortalApiKey|null>(null),[editName,setEditName]=React.useState('');
  const [inheritModels,setInheritModels]=React.useState(true),[selectedModels,setSelectedModels]=React.useState<string[]>([]);
  const [saving,setSaving]=React.useState(false),[editError,setEditError]=React.useState('');
  const editDialog=React.useRef<HTMLDivElement>(null);
  const beginEdit=(key:PortalApiKey)=>{
   setEditing(key);setEditName(key.name);setInheritModels(!key.model_allowlist?.length);
   setSelectedModels((key.model_allowlist??[]).filter(model=>availableModels.includes(model)));setEditError('');
  };
  const update=async(key:PortalApiKey,body:Record<string,unknown>)=>{
   const response=await fetch(portalPath('/api/me/keys/'+encodeURIComponent(key.id)),{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify(body),cache:'no-store'});
   if(!response.ok){const payload=await response.json().catch(()=>null);throw new Error(personalActionError(payload?.error,'API Key 更新失败，请稍后重试。'))}
   setKeys(current=>current.map(row=>row.id===key.id?{...row,...body}:row));
   onKeysChanged?.();
  };
  const saveEdit=async(event:React.FormEvent)=>{
   event.preventDefault();if(!editing||saving)return;
   if(!inheritModels&&!selectedModels.length){setEditError('受限模式至少选择一个当前已授权模型，或明确选择继承全部授权。');return}
   setSaving(true);setEditError('');
   try{await update(editing,{name:editName,model_allowlist:inheritModels?[]:selectedModels});setEditing(null)}
   catch(error){setEditError(error instanceof Error?error.message:'API Key 更新失败。')}
   finally{setSaving(false)}
  };
  const toggle=async(key:PortalApiKey)=>{
   if(saving)return;setSaving(true);setCopyError('');
   try{await update(key,{status:key.status==='active'?'disabled':'active'})}
   catch(error){setCopyError(error instanceof Error?error.message:'状态更新失败。')}
   finally{setSaving(false)}
  };

 const createDialog=React.useRef<HTMLDivElement>(null);
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState("");
  const [createdKey, setCreatedKey] = React.useState("");
  const [showCreated,setShowCreated]=React.useState(false);
  const [copied, setCopied] = React.useState(false);
  const [copyingKeyId, setCopyingKeyId] = React.useState("");
  const [copiedKeyId, setCopiedKeyId] = React.useState("");
  const [copyError, setCopyError] = React.useState("");
  const [resetKey,setResetKey]=React.useState<PortalApiKey|null>(null);
  const resetDialog=React.useRef<HTMLDivElement>(null);
  const [deleteKey,setDeleteKey]=React.useState<PortalApiKey|null>(null);
  const [deleting,setDeleting]=React.useState(false);
  const deleteDialog=React.useRef<HTMLDivElement>(null);

  const projectNames = React.useMemo(
    () => new Map(projects.map((project) => [project.id, project.name])),
    [projects],
  );

  const beginCreate = () => {
    setName("");
    setInheritModels(true);setSelectedModels([]);
    setError("");
    setCreatedKey("");setShowCreated(false);
    setCopied(false);
    setOpen(true);
  };

  React.useEffect(()=>{if(!createdKey)return;const timer=window.setTimeout(()=>{setCreatedKey("");setShowCreated(false);setOpen(false);},60000);return()=>window.clearTimeout(timer)},[createdKey]);

  const close = () => {
    setOpen(false);
    setCreatedKey("");setShowCreated(false);
    setCopied(false);
  };

 useDialogFocus(createDialog,open,close);
 useDialogFocus(resetDialog,Boolean(resetKey),()=>{if(!submitting)setResetKey(null)});
 useDialogFocus(editDialog,Boolean(editing),()=>{if(!saving)setEditing(null)});
  useDialogFocus(deleteDialog,Boolean(deleteKey),()=>{if(!deleting)setDeleteKey(null)});
  const confirmDelete=async()=>{
   if(!deleteKey||deleting)return;setDeleting(true);setCopyError('');
   try{
    const response=await fetch(portalPath('/api/me/keys/'+encodeURIComponent(deleteKey.id)),{method:'DELETE',cache:'no-store'});
    if(response.status!==204){const payload=await response.json().catch(()=>null);throw new Error(personalActionError(payload?.error,'删除失败，请刷新后重试。'))}
    setKeys(current=>current.filter(key=>key.id!==deleteKey.id));
    if(deleteKey.employee_key){deletedEmployeeIds.current.add(deleteKey.id);setEmployeeMetadata(null);setEmployeeAvailability('missing');setEmployeeEpoch(value=>value+1);}
    setDeleteKey(null);onKeysChanged?.();
   }catch(error){setCopyError(actionError(error,'删除失败，请稍后重试。'));}
   finally{setDeleting(false)}
  };
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (submitting) return;
    if(!inheritModels&&!selectedModels.length){setError("受限模式至少选择一个模型。");return;}
    setSubmitting(true);
    setError("");
    try {
      const response = await fetch(portalPath("/api/me/keys"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name,model_allowlist:inheritModels?[]:selectedModels }),
      });
      const payload = (await response.json().catch(() => null)) as (CreateKeyResponse & { error?: string }) | null;
      if (!response.ok || !payload?.data || !payload.full_key) {
        const messages: Record<string, string> = {
          ...PERSONAL_ACTION_ERRORS,
          project_access_denied: "当前账号没有可用于模型调用的默认应用",
          project_unavailable: "当前部门尚未配置默认应用，请联系管理员",
          key_limit_reached: "有效 API Key 已达到数量上限，请联系管理员处理",
          authorization_denied: "当前账号不可创建 API Key",
        };
        throw new Error(messages[payload?.error ?? ""] ?? "API Key 创建失败，请稍后重试");
      }
      setKeys((current) => [payload.data, ...current.filter((key) => key.id !== payload.data.id)]);
      setCreatedKey(payload.full_key);
      onKeysChanged?.();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "API Key 创建失败，请稍后重试");
    } finally {
      setSubmitting(false);
    }
  };

  const copyExistingKey = async (key: PortalApiKey) => {
    if (copyingKeyId || key.status !== "active") return;
    setCopyingKeyId(key.id);
    setCopiedKeyId("");
    setCopyError("");
    try {
      const readKey = async () => {
      const response = await fetch(portalPath(`/api/me/keys/${encodeURIComponent(key.id)}/reveal`), {
        method: "POST",
        cache: "no-store",
      });
      const payload = (await response.json().catch(() => null)) as { full_key?: string; error?: string } | null;
      if (!response.ok || !payload?.full_key) {
        const messages: Record<string, string> = {
          ...PERSONAL_ACTION_ERRORS,
          created_before_encryption: "此 Key 创建时间较早，无法恢复完整内容，请重新创建",
          key_not_active: "此 Key 已停用，无法复制",
          rate_limited:"复制请求过于频繁，请稍后重试。",
          authorization_denied: "当前账号无权复制此 Key",
          not_found: "未找到当前账号的 API Key",
        };
        throw new Error(messages[payload?.error ?? ""] ?? "完整 API Key 读取失败，请稍后重试");
      }
      return payload.full_key;
      };
      const valuePromise=readKey();
      let copiedWithGesture=false;
      if (typeof ClipboardItem!=="undefined" && navigator.clipboard?.write) {
        try { await navigator.clipboard.write([new ClipboardItem({"text/plain":valuePromise.then(value=>new Blob([value],{type:"text/plain"}))})]); copiedWithGesture=true; } catch { /* Fall back to a fresh copy click in a masked dialog. */ }
      }
      const value=await valuePromise;
      if (!copiedWithGesture && !await copyKey(value)) { setOpen(true); setCreatedKey(value); setCopied(false); return; }
      setCopiedKeyId(key.id);
    } catch (cause) {
      setCopyError(actionError(cause,"完整 API Key 复制失败"));
    } finally {
      setCopyingKeyId("");
    }
  };



  const confirmReset=async()=>{
   if(!resetKey||submitting)return;setSubmitting(true);setCopyError('');
   try{
    const response=await fetch(portalPath('/api/me/keys/'+encodeURIComponent(resetKey.id)+'/reset'),{method:'POST',cache:'no-store'});
    const payload=await response.json().catch(()=>null) as (CreateKeyResponse&{error?:string})|null;
    if(!response.ok||!payload?.full_key||!payload.data)throw new Error(personalActionError(payload?.error,'API Key 重置失败，请稍后重试。'));
    setKeys(current=>[payload.data,...current.map(key=>key.id===resetKey.id?{...key,status:'revoked'}:key)]);
    setResetKey(null);setOpen(true);setCreatedKey(payload.full_key);setCopied(false);onKeysChanged?.();
   }catch(error){setCopyError(error instanceof Error?error.message:'重置失败。')}finally{setSubmitting(false)}
  };
  const managed=keys.find(key=>key.employee_key);
  const defaultKey:PortalApiKey=managed??{id:employeeMetadata?.id??'employee-placeholder',name:'个人默认 Key',prefix:employeeMetadata?.prefix??'—',project_id:'',scopes:[],status:employeeMetadata?.status??employeeAvailability,created_at:employeeMetadata?.created_at??'',employee_key:true,model_allowlist:employeeMetadata?.model_allowlist};
  const rows=[defaultKey,...keys.filter(key=>!key.employee_key)];
  const keyCount=keys.length+(!managed&&employeeMetadata?1:0);
  const modelSelector=<fieldset className="space-y-2">
    <legend className="text-sm font-medium">可用模型</legend>
    <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={inheritModels} onChange={event=>setInheritModels(event.target.checked)}/>继承用户全部已授权模型</label>
    {!inheritModels&&<div className="rounded-lg border p-3"><div className="mb-2 flex gap-3 text-xs"><button type="button" onClick={()=>setSelectedModels(availableModels)}>全选</button><button type="button" onClick={()=>setSelectedModels([])}>清空</button></div><div role="group" aria-label="模型白名单" className="max-h-40 space-y-2 overflow-y-auto">{availableModels.map(model=><label key={model} className="flex items-center gap-2 text-sm"><input type="checkbox" aria-label={'授权模型 '+model} checked={selectedModels.includes(model)} onChange={event=>setSelectedModels(current=>event.target.checked?[...current,model]:current.filter(value=>value!==model))}/><span className="break-all">{model}</span></label>)}{!availableModels.length&&<p className="text-xs text-muted-foreground">暂无已授权模型</p>}</div></div>}
    <p className="text-xs text-muted-foreground">仅可选择当前账号已授权的模型。个人默认 Key 的限制在重置后继续保留。</p>
  </fieldset>;
  const effectiveStatus=(key:PortalApiKey)=>key.expires_at&&Date.parse(key.expires_at)<=clockNow?'expired':key.status;
  const matches=(key:PortalApiKey)=>(key.name+' '+key.prefix).toLowerCase().includes(nameFilter.trim().toLowerCase())&&(!statusFilter||effectiveStatus(key)===statusFilter);
  return (
    <section className="min-w-0 rounded-xl border bg-card p-4 sm:p-5" data-testid="api-key-management">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-base font-semibold">我的 API Key</h2>
        <button type="button" onClick={beginCreate} className="rounded-lg bg-primary px-3 py-2 text-xs font-medium text-primary-foreground">创建 API 密钥</button>
      </div>
      {customerGroup&&<p className="mt-1 text-xs text-muted-foreground">客户组：{customerGroup}</p>}
      {keyCount>8&&<div className="mt-4 flex flex-wrap gap-2"><input aria-label="搜索 API Key" placeholder="按名称或密钥后几位搜索" value={nameFilter} onChange={event=>setNameFilter(event.target.value)} className="min-w-0 flex-1 rounded-lg border bg-background px-3 py-2 text-sm"/><select aria-label="状态筛选" value={statusFilter} onChange={event=>setStatusFilter(event.target.value)} className="rounded-lg border bg-background px-3 py-2 text-sm"><option value="">全部状态</option><option value="active">正常</option><option value="disabled">已停用</option><option value="revoked">已失效</option><option value="expired">已过期</option></select></div>}
      {(()=>{
        const live=rows.filter(key=>!['revoked','expired'].includes(effectiveStatus(key)));
        const retired=rows.filter(key=>['revoked','expired'].includes(effectiveStatus(key)));
        const statusText=(key:PortalApiKey)=>effectiveStatus(key)==='expired'?'已过期':key.status==='loading'?'读取中':key.status==='missing'?'未领取':key.status==='denied'?'暂不可用':statusLabel(key.status);
        const fullTime=(value?:string)=>value?new Date(value).toLocaleString():undefined;
        const nameOf=(key:PortalApiKey)=>key.name||(key.employee_key?'个人默认 Key':'未命名 Key');
        const created=(key:PortalApiKey)=>[projectNames.get(key.project_id),key.created_at?"创建时间："+new Date(key.created_at).toLocaleString("zh-CN"):null].filter(Boolean).join(" · ");
        const hideMeta=(key:PortalApiKey)=>Boolean(key.employee_key&&!managed);
        return <>
          <div className="mt-4 space-y-3">
            {live.map(key=><article key={key.employee_key?'employee-default':key.id} data-key-card hidden={!matches(key)} className="rounded-2xl border bg-background px-5 py-4">
              <div className="flex flex-wrap items-center gap-2">
                <span className="min-w-0 break-words text-[15px] font-semibold" title={created(key)}>{nameOf(key)}</span>
                {key.employee_key&&<span className="rounded-full bg-muted px-2 py-px text-[11.5px] text-muted-foreground">默认</span>}
                <span className={"rounded-full px-2 py-px text-[11.5px] "+(key.status==='active'?'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300':'bg-muted text-muted-foreground')}>{statusText(key)}</span>
                <span className="flex-1"/>
                {['active','disabled'].includes(key.status)&&<button type="button" disabled={saving} onClick={()=>void toggle(key)} className="h-8 rounded-lg border px-3 text-[13px] hover:bg-accent">{key.status==='active'?'停用':'启用'}</button>}
                {!key.employee_key&&key.id!=='employee-placeholder'&&<details className="relative">
                  <summary aria-label={'更多操作 '+nameOf(key)} className="flex h-8 w-8 cursor-pointer list-none items-center justify-center rounded-lg border text-muted-foreground hover:bg-accent [&::-webkit-details-marker]:hidden">⋯</summary>
                  <div className="absolute right-0 z-20 mt-1 w-40 rounded-xl border bg-popover p-1 text-[13px] shadow-lg">
                    {['active','disabled'].includes(key.status)&&<button type="button" onClick={()=>beginEdit(key)} className="block w-full rounded-md px-3 py-1.5 text-left hover:bg-accent">编辑</button>}
                    <button type="button" onClick={()=>setResetKey(key)} className="block w-full rounded-md px-3 py-1.5 text-left hover:bg-accent">重置 Key</button>
                    <hr className="my-1"/>
                    <button type="button" onClick={()=>setDeleteKey(key)} disabled={deleting} className="block w-full rounded-md px-3 py-1.5 text-left text-destructive hover:bg-accent">删除</button>
                  </div>
                </details>}
              </div>
              <div className="mt-3 flex flex-wrap items-center gap-3 rounded-xl border border-border/60 bg-muted/30 px-3 py-2.5">
                <code className="min-w-0 flex-1 break-all font-mono text-sm">{key.prefix==='—'?'—':key.prefix+'••••'}</code>
                {key.status==='active'&&key.id!=='employee-placeholder'&&<button type="button" onClick={()=>void copyExistingKey(key)} disabled={Boolean(copyingKeyId)} className="rounded-lg border bg-background px-3 py-1 text-[12.5px] hover:bg-accent">{copyingKeyId===key.id?'读取中…':copiedKeyId===key.id?'已复制完整 Key':'复制完整 Key'}</button>}
              </div>
              <dl className="mt-3 grid grid-cols-1 gap-3 text-[12.5px] sm:grid-cols-3">
                <div className="min-w-0"><dt className="text-muted-foreground">可用模型</dt><dd className="mt-0.5 break-words font-medium">{hideMeta(key)&&!employeeMetadata?'—':key.model_allowlist?.length?key.model_allowlist.join('、'):'继承个人授权'}</dd></div>
                <div><dt className="text-muted-foreground">最后使用</dt><dd title={fullTime(key.last_used_at)} className="mt-0.5 font-medium">{hideMeta(key)?'—':key.last_used_at?fullTime(key.last_used_at):'从未'}</dd></div>
                <div><dt className="text-muted-foreground">{key.expires_at?'过期时间':'有效期'}</dt><dd className="mt-0.5 font-medium">{hideMeta(key)?'—':key.expires_at?fullTime(key.expires_at):'长期有效'}</dd></div>
              </dl>
              {key.employee_key&&<div className="mt-3 border-t pt-3"><EmployeeKeyPanel key={employeeEpoch} inline onMetadata={metadataUpdated} onMissing={employeeMissing}/></div>}
            </article>)}
            {!rows.some(matches)&&<p className="rounded-2xl border border-dashed px-5 py-6 text-sm text-muted-foreground">没有匹配的 API Key</p>}
          </div>
          {retired.length>0&&<details className="mt-5" open={retired.length<=3}>
            <summary className="cursor-pointer select-none text-[12.5px] text-muted-foreground">已失效 · {retired.length}</summary>
            <div className="mt-2 space-y-2">{retired.map(key=><div key={key.id} hidden={!matches(key)} className="flex flex-wrap items-center gap-x-5 gap-y-1 rounded-xl border border-dashed px-4 py-2.5 text-[13px] text-muted-foreground">
              <span className="text-foreground/70" title={created(key)}>{nameOf(key)}</span>
              <code className="font-mono text-xs">{key.prefix+'••••'}</code>
              <span className="min-w-0 truncate">{key.model_allowlist?.length?key.model_allowlist.join('、'):'继承个人授权'}</span>
              <span>{statusText(key)}</span>
              <span className="flex-1"/>
              <button type="button" onClick={()=>setDeleteKey(key)} disabled={deleting} className="text-destructive hover:underline">删除</button>
            </div>)}</div>
          </details>}
        </>;
      })()}
      {keyCount===0&&<div className="mt-3 text-center"><button type="button" onClick={beginCreate} className="rounded-lg border px-3 py-2 text-sm">创建第一个 API 密钥</button></div>}
      {copyError&&<p role="alert" className="mt-3 rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">{copyError}</p>}
      {editing&&<div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/35 p-4"><div ref={editDialog} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="edit-key-title" className="w-full max-w-lg rounded-2xl border bg-background p-6 shadow-xl"><h3 id="edit-key-title" className="text-lg font-semibold">编辑 API 密钥</h3><form onSubmit={saveEdit} className="mt-4 space-y-4"><label className="block text-sm">名称<input aria-label="Key 名称" value={editName} onChange={event=>setEditName(event.target.value)} maxLength={128} className="mt-2 w-full rounded border bg-background p-2"/></label>{modelSelector}{editError&&<p role="alert" className="text-sm text-destructive">{editError}</p>}<div className="flex justify-end gap-2"><button type="button" disabled={saving} onClick={()=>setEditing(null)} className="rounded border px-3 py-2">取消</button><button type="submit" disabled={saving} className="rounded bg-primary px-3 py-2 text-primary-foreground">{saving?'正在保存…':'保存'}</button></div></form></div></div>}
      {resetKey&&<div ref={resetDialog} tabIndex={-1} role="dialog" aria-modal="true" className="mt-4 rounded border p-4"><h3>确认重置 {resetKey.name||"此 Key"}？</h3><p className="mt-2 text-sm">旧 Key 立即失效；新 Key 保留名称、权限范围、过期时间和模型限制。请更新使用此 Key 的客户端。</p><div className="mt-3 flex gap-2"><button type="button" disabled={submitting} onClick={()=>void confirmReset()} className="rounded border px-3 py-2">确认重置 Key</button><button type="button" data-dialog-autofocus disabled={submitting} onClick={()=>setResetKey(null)} className="rounded border px-3 py-2">取消</button></div></div>}
      {deleteKey&&<div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/35 p-4"><div ref={deleteDialog} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="delete-key-title" className="w-full max-w-lg rounded-2xl border bg-background p-6 shadow-xl"><h3 id="delete-key-title" className="text-lg font-semibold">删除 {deleteKey.name||'此 Key'}？</h3><p className="mt-3 text-sm">删除后立即停止此 Key 的新调用，并从密钥列表移除。历史用量和资金流水保留。</p>{copyError&&<p role="alert" className="mt-3 text-sm text-destructive">{copyError}</p>}<div className="mt-4 flex justify-end gap-2"><button type="button" data-dialog-autofocus disabled={deleting} onClick={()=>setDeleteKey(null)} className="rounded border px-3 py-2">取消</button><button type="button" disabled={deleting} onClick={()=>void confirmDelete()} className="rounded border px-3 py-2 text-destructive">{deleting?'正在删除…':'确认删除'}</button></div></div></div>}
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/35 px-4" role="presentation">
          <div ref={createDialog} tabIndex={-1} className="w-full max-w-lg rounded-2xl border bg-background p-6 shadow-2xl" role="dialog" aria-modal="true" aria-labelledby="create-api-key-title">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h3 id="create-api-key-title" className="text-lg font-semibold">{createdKey?"安全保存 API 密钥":"创建 API 密钥"}</h3>
                <p className="mt-1 text-sm text-muted-foreground">密钥将自动绑定当前账号，管理员可在后台统一管理。</p>
              </div>
              <button type="button" onClick={close} className="rounded px-2 py-1 text-muted-foreground hover:bg-muted" aria-label="关闭">×</button>
            </div>

            {createdKey ? (
              <div className="mt-5 space-y-4">
                <div className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-200">
                  请在可信设备上复制。若浏览器限制剪贴板，请再次点击复制或手动选择；60 秒后自动隐藏。
                </div>
                <input type={showCreated?"text":"password"} data-sensitive="api-key" autoComplete="off"
                  value={createdKey}
                  readOnly
                  onFocus={(event) => event.currentTarget.select()}
                  className="h-11 w-full rounded-lg border bg-muted/30 p-3 font-mono text-xs outline-none focus:border-primary"
                  aria-label="完整 API Key"
                />
                <button type="button" aria-label={showCreated?"隐藏完整 Key":"显示完整 Key"} onClick={()=>setShowCreated(value=>!value)} className="text-xs text-muted-foreground">{showCreated?"隐藏":"显示以手动复制"}</button>
                <div className="flex justify-end gap-2">
                  <button type="button" onClick={close} className="rounded-lg border px-4 py-2 text-sm hover:bg-muted">我已保存</button>
                  <button
                    type="button"
                    onClick={async () => setCopied(await copyKey(createdKey))}
                    className="rounded-lg bg-primary px-4 py-2 text-sm text-primary-foreground hover:bg-primary/90"
                  >
                    {copied ? "已复制" : "复制完整 Key"}
                  </button>
                </div>
              </div>
            ) : (
              <form onSubmit={submit} className="mt-5 space-y-4">
                <p className="text-sm text-muted-foreground">所属应用由服务端按当前部门的默认应用确定。</p>
                <label className="block text-sm font-medium">
                  名称（选填）
                  <input
                    value={name}
                    onChange={(event) => setName(event.target.value)}
                    maxLength={128}
                    placeholder="例如：本地开发"
                    className="mt-2 w-full rounded-lg border bg-background px-3 py-2.5 text-sm outline-none focus:border-primary"
                  />
                </label>
                {modelSelector}<p className="text-xs text-muted-foreground">默认获得模型 API 权限，不包含 MCP 工具调用权限。</p>
                {error && <p className="rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</p>}
                <button type="button" aria-label={showCreated?"隐藏完整 Key":"显示完整 Key"} onClick={()=>setShowCreated(value=>!value)} className="text-xs text-muted-foreground">{showCreated?"隐藏":"显示以手动复制"}</button>
                <div className="flex justify-end gap-2">
                  <button type="button" onClick={close} className="rounded-lg border px-4 py-2 text-sm hover:bg-muted">取消</button>
                  <button type="submit" disabled={submitting} className="rounded-lg bg-primary px-4 py-2 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-40">
                    {submitting ? "正在创建…" : "创建"}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

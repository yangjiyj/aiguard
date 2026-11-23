import React from 'react';
import type {PortalAuthorizationContext} from '@/lib/control-plane';
export function ModelAccessPanel({models,access,error,compact=false}:{compact?:boolean;models:{id:string;displayName?:string}[];access?:Partial<PortalAuthorizationContext>|null;error?:string}){
 const groups=[['department','部门授权'],['personal_extra','个人额外授权'],['personal_narrowed','个人已收窄'],['unknown','授权来源待确认']] as const;
 return <section className={compact?"min-w-0":"rounded-xl border bg-card p-5 shadow-sm"}><h2 className="text-base font-semibold">模型授权</h2>
 {error&&<p role="alert" className="mt-3 text-sm text-destructive">{error}</p>}
 {groups.filter(([source])=>!compact||models.some(m=>(access?.modelSources?.[m.id]??'unknown')===source)).map(([source,label])=><div key={source} className="mt-4"><h3 className="text-sm font-medium">{label}</h3><div className="mt-2 flex flex-wrap gap-2">{models.filter(m=>(access?.modelSources?.[m.id]??'unknown')===source).map(m=>{
 const grant=access?.extraGrants?.find(g=>g.model===m.id&&!g.revoked_at);
 return <span className="rounded bg-muted px-2 py-1 text-xs" key={m.id}>{m.displayName||m.id}{source==='personal_extra'&&grant&&<span className="ml-1">（{grant.reason}；{grant.expires_at?'到期 '+new Date(grant.expires_at).toLocaleString('zh-CN'):'长期有效'}）</span>}</span>;
 })}</div></div>)}
 {!models.length&&<p className="mt-4 text-sm text-muted-foreground">当前暂无可调用模型，请联系管理员查看部门和个人授权。</p>}
 {!!access?.staleModels?.length&&<p className="mt-4 rounded border px-3 py-2 text-sm">个人收窄清单中的陈旧项：{access.staleModels.join('、')}。这些基础名单条目已超出部门范围；个人额外授权按其有效期生效。</p>}
 </section>
}

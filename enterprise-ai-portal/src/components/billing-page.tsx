"use client";

import * as React from "react";
import { formatMoneyMicros as money, moneyCurrency, moneyLimitLabel } from "@/lib/money-micros";
import {ModelAccessPanel} from "./model-access-panel";
import {GatewayConfigPanel} from "./gateway-config-panel";
import {gatewayClientConfig} from "@/lib/gateway-client-config";
import type {PortalAuthorizationContext} from "@/lib/control-plane";
import { ApiKeysPanel, type PortalApiKey, type PortalProject } from "@/components/api-keys-panel";
import { portalPath } from "@/lib/portal-path";
import { WalletSummaryPanel } from "@/components/wallet-summary-panel";
import { RedemptionPanel } from "@/components/redemption-panel";
import { latestWalletRefresh, walletAmounts, type MonthlyWalletStatus, type WalletBalance } from "@/lib/wallet-balances";
import { ModelShareChart, UsageTrendChart } from "@/components/usage-charts";
import { compactNumber } from "@/lib/usage-charts";

type BillingData = {
  data: {
    currency?: string;
    wallet: WalletBalance;
    customer_group: string;
    usage: { requests: number; prompt_tokens: number; cached_input_tokens: number; cache_write_input_tokens: number; output_tokens: number; amount_micros: number;currency?: string;unpriced_requests?:number;unpriced_tokens?:number;unpriced_cached_input_tokens?:number;unpriced_cache_write_input_tokens?:number };
    limits: { daily: LimitWindow; monthly: LimitWindow; rpm_limit: number; concurrency_limit: number };
    daily: Array<{ date: string; requests: number; tokens: number; amount_micros: number; currency?: string }>;
    models: Array<{ model_name: string; requests: number; tokens: number; amount_micros: number; currency?: string }>;
    monthly_status?: MonthlyWalletStatus | null;
  };
  keys: PortalApiKey[];
  projects?: PortalProject[];
  api_url: string;
};

type ModelItem = { id: string; displayName: string };
type LimitWindow = {
  amount_limit_micros: number;
  token_limit: number;
  settled_amount_micros: number;
  reserved_amount_micros: number;
  settled_tokens: number;
  reserved_tokens: number;
};


const number = (value: number) => new Intl.NumberFormat("zh-CN").format(value ?? 0);

// 同一套数据加载服务两个页面：/billing（用量与费用）和 /keys（API 密钥）。
export default function BillingPage({view='usage'}:{view?:'usage'|'keys'}) {
 const [billing,setBilling]=React.useState<BillingData|null>(null);
 const [models,setModels]=React.useState<ModelItem[]>([]);
 const [access,setAccess]=React.useState<PortalAuthorizationContext|null>(null);
 const [keys,setKeys]=React.useState<PortalApiKey[]>([]);
 const [clientConfig,setClientConfig]=React.useState<ReturnType<typeof gatewayClientConfig>|null>(null);
 const [billingError,setBillingError]=React.useState('');
 const [modelError,setModelError]=React.useState('');
 const [keyError,setKeyError]=React.useState('');
 const [configError,setConfigError]=React.useState('');
 const [identity,setIdentity]=React.useState<{name?:string;department?:string}|null>(null);
 const refreshBilling=React.useMemo(()=>latestWalletRefresh(async()=>{
  const r=await fetch(portalPath('/api/me/billing'),{cache:'no-store'});
  if(!r.ok)throw new Error('账单数据暂不可用');return await r.json() as BillingData;
 },setBilling),[]);
 const refreshKeys=React.useCallback(async()=>{
  const r=await fetch(portalPath('/api/me/keys'),{cache:'no-store'});if(!r.ok)throw new Error('API Key 列表暂不可用');
  const body=await r.json() as {data:PortalApiKey[]};setKeys(body.data);setKeyError('');
 },[]);
 const keyMetadataUpdated=React.useCallback(()=>{
  void refreshKeys().catch(()=>setKeyError('API Key 列表暂不可用'));
  void refreshBilling().catch(()=>setBillingError('账单数据暂不可用'));
 },[refreshKeys,refreshBilling]);
 React.useEffect(()=>{
  void refreshBilling().catch(()=>setBillingError('账单数据暂不可用，请稍后重试。'));
  void Promise.resolve().then(refreshKeys).catch(()=>setKeyError('API Key 列表暂不可用，请稍后重试。'));
  void fetch(portalPath('/api/me'),{cache:'no-store'}).then(async r=>{if(r.ok)setIdentity((await r.json()).user??null)}).catch(()=>{});
  void fetch(portalPath('/api/me/model-access'),{cache:'no-store'}).then(async r=>{
   if(!r.ok)throw new Error('unavailable');
   const body=await r.json() as {data:PortalAuthorizationContext};setAccess(body.data);
   setModels(body.data.modelIds.map(id=>({id,displayName:id})));
  }).catch(()=>setModelError('模型授权暂不可用，请稍后重试。'));
  void fetch(portalPath('/api/me/gateway'),{cache:'no-store'}).then(async r=>{
   if(!r.ok)throw new Error('unavailable');setClientConfig((await r.json()).data);
  }).catch(()=>setConfigError('调用地址暂不可用，请稍后重试。'));
 },[refreshBilling,refreshKeys]);
 const summary=billing?.data;
 const walletCurrency=moneyCurrency(summary?.wallet.currency,summary?.currency);
 const usageCurrency=moneyCurrency(summary?.usage.currency,summary?.currency);
 const available=summary?walletAmounts(summary.wallet,summary.monthly_status).available:0;
 const totalTokens=summary?summary.usage.prompt_tokens+summary.usage.output_tokens+(summary.usage.unpriced_tokens??0):0;
 const activeKeys=keys.filter(key=>key.status==='active').length;
 const [tab,setTab]=React.useState<CenterTab>('overview');
 React.useEffect(()=>{
  if(view==='usage'&&/^#(api-keys|access)$/.test(window.location.hash)){window.location.replace(portalPath('/keys'));return}
  const sync=()=>{const next=tabFromHash(window.location.hash);if(next)setTab(next)};
  sync();window.addEventListener('hashchange',sync);return()=>window.removeEventListener('hashchange',sync);
 },[view]);
 const selectTab=React.useCallback((next:CenterTab)=>{
  setTab(next);
  try{window.history.replaceState(null,'','#'+next)}catch{}
 },[]);
 const onTabKey=(event:React.KeyboardEvent<HTMLButtonElement>,index:number)=>{
  const step=event.key==='ArrowRight'?1:event.key==='ArrowLeft'?-1:0;if(!step)return;
  event.preventDefault();const next=CENTER_TABS[(index+step+CENTER_TABS.length)%CENTER_TABS.length][0];selectTab(next);
  document.getElementById('center-tab-'+next)?.focus();
 };
 const pending=billingError?<p role="alert" className="rounded-lg border px-4 py-3 text-sm text-destructive">{billingError}</p>:<p className="text-sm text-muted-foreground">正在读取账单…</p>;
 const panel=(id:CenterTab)=>({id:'center-panel-'+id,role:'tabpanel' as const,'aria-labelledby':'center-tab-'+id,hidden:tab!==id});
 if(view==='keys')return <main className="mx-auto min-w-0 max-w-5xl px-4 pb-16 pt-8 sm:px-8">
  <h1 className="text-[22px] font-semibold">API 密钥</h1>
  <p className="mt-1 text-sm text-muted-foreground">{activeKeys} 个可用{summary?.customer_group?' · 客户组 '+summary.customer_group:''}</p>
  <div className="mt-5 min-w-0">{keyError&&<p role="alert" className="mb-3 text-sm text-destructive">{keyError}</p>}<ApiKeysPanel initialKeys={keys} projects={billing?.projects??[]} availableModels={models.map(model=>model.id)} customerGroup={summary?.customer_group} onKeysChanged={keyMetadataUpdated}/></div>
  <div className="mt-5 grid min-w-0 grid-cols-1 gap-4 lg:grid-cols-2"><GatewayConfigPanel compact config={clientConfig} error={configError}/><ModelAccessPanel compact models={models} access={access} error={modelError}/></div>
 </main>;
 return <main className="mx-auto min-w-0 max-w-6xl px-4 pb-16 pt-6 sm:px-6">
  <header className="relative mt-4 overflow-hidden rounded-2xl border bg-gradient-to-br from-primary/15 via-primary/5 to-transparent p-5 sm:p-6">
   <div aria-hidden className="pointer-events-none absolute -right-16 -top-16 h-48 w-48 rounded-full bg-primary/10 blur-2xl"/>
   <div className="relative flex flex-wrap items-center gap-4">
    <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-primary text-lg font-semibold text-primary-foreground">{(identity?.name||'我').slice(0,1)}</span>
    <div className="min-w-0 flex-1"><h1 className="text-2xl font-semibold">用量与费用</h1><p className="mt-0.5 truncate text-sm text-muted-foreground">{identity?(identity.name||'当前账号')+' · '+(identity.department||'未分配部门'):'管理钱包、API Key、模型价格与用量'}</p></div>
   </div>
   <div className="relative mt-5 grid grid-cols-2 gap-3 md:grid-cols-4">
    <Stat label="可用余额" value={summary?money(available,walletCurrency):'—'} tone={summary&&available<=0?'danger':undefined}/>
    <Stat label="近 30 天消费" value={summary?money(summary.usage.amount_micros,usageCurrency):'—'}/>
    <Stat label="近 30 天调用" value={summary?compactNumber(summary.usage.requests+(summary.usage.unpriced_requests??0))+' 次':'—'}/>
    <Stat label="可用模型 / 有效 Key" value={models.length+' / '+activeKeys}/>
   </div>
  </header>
  <div role="tablist" aria-label="个人中心分区" className="sticky top-0 z-30 -mx-4 mt-4 flex gap-1 overflow-x-auto border-b bg-background/95 px-4 backdrop-blur sm:-mx-6 sm:px-6">{CENTER_TABS.map(([id,label],index)=>{const active=tab===id;return <button key={id} id={'center-tab-'+id} type="button" role="tab" aria-selected={active} aria-controls={'center-panel-'+id} tabIndex={active?0:-1} onClick={()=>selectTab(id)} onKeyDown={event=>onTabKey(event,index)} className={"-mb-px whitespace-nowrap border-b-2 px-3 py-2.5 text-sm transition "+(active?"border-primary font-medium text-foreground":"border-transparent text-muted-foreground hover:text-foreground")}>{label}</button>})}</div>
  <div className="mt-5">
  <section {...panel('overview')}>{summary?<>
   <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
    <Card label="近 30 天 Token" value={compactNumber(totalTokens)} note={'输入 '+compactNumber(summary.usage.prompt_tokens)+' · 输出 '+compactNumber(summary.usage.output_tokens)}/>
    <Card label="缓存 Token（已包含在输入中）" value={compactNumber(summary.usage.cached_input_tokens+(summary.usage.unpriced_cached_input_tokens??0))} note={'缓存写入 '+compactNumber(summary.usage.cache_write_input_tokens+(summary.usage.unpriced_cache_write_input_tokens??0))}/>
    <Card label="未定价调用" value={number(summary.usage.unpriced_requests??0)+' 次'} note={number(summary.usage.unpriced_tokens??0)+' Token 未计费'}/>
   </div>
   <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-5">
    <div className="lg:col-span-3"><Panel title="消费趋势（近 30 天）"><UsageTrendChart daily={summary.daily} currency={usageCurrency}/></Panel></div>
    <div className="lg:col-span-2"><Panel title="模型分布"><ModelShareChart models={summary.models} currency={usageCurrency}/></Panel></div>
   </div>
  </>:pending}</section>
  <section {...panel('wallet')}>{summary?<div className="grid grid-cols-1 gap-4 lg:grid-cols-5"><div className="min-w-0 lg:col-span-3"><WalletSummaryPanel wallet={summary.wallet} monthly={summary.monthly_status} dailyAverage={summary.usage.amount_micros/30} tenantCurrency={summary.currency}/></div><div className="min-w-0 lg:col-span-2"><RedemptionPanel currency={walletCurrency} onRedeemed={refreshBilling}/></div></div>:pending}</section>
  <section {...panel('limits')}>{summary?<CallLimits limits={summary.limits} currency={walletCurrency} onSaved={refreshBilling}/>:pending}</section>
  </div>
 </main>;
}

type CenterTab='overview'|'wallet'|'limits';
const CENTER_TABS:[CenterTab,string][]=[['overview','用量概览'],['wallet','钱包'],['limits','限额']];
function tabFromHash(hash:string):CenterTab|null{const id=hash.replace(/^#/,'');return CENTER_TABS.some(([key])=>key===id)?id as CenterTab:null}

function Stat({ label, value, tone }: { label: string; value: string; tone?: 'danger' }) { return <div className="min-w-0 rounded-xl bg-background/70 px-4 py-3 backdrop-blur"><p className="text-xs text-muted-foreground">{label}</p><p className={"mt-1 truncate text-lg font-semibold tabular-nums "+(tone==='danger'?'text-destructive':'')} title={value}>{value}</p></div>; }

function Card({ label, value, note }: { label: string; value: string; note: string }) { return <div className="min-w-0 rounded-xl border bg-card p-4 shadow-sm"><p className="text-xs text-muted-foreground">{label}</p><p className="mt-2 text-xl font-semibold tabular-nums">{value}</p><p className="mt-1 truncate text-xs text-muted-foreground">{note}</p></div>; }
function Panel({ title, children }: { title: string; children: React.ReactNode }) { return <section className="min-w-0 rounded-xl border bg-card p-5 shadow-sm"><h2 className="text-base font-semibold">{title}</h2><div className="mt-4">{children}</div></section>; }


function usedAmount(window: LimitWindow) {
  return window.settled_amount_micros + window.reserved_amount_micros;
}

function usedTokens(window: LimitWindow) {
  return window.settled_tokens + window.reserved_tokens;
}

function inputMicros(value: string) {
  const amount = Number(value || "0");
  if (!Number.isFinite(amount) || amount < 0) throw new Error("金额上限必须为大于或等于 0 的数字");
  const micros = Math.round(amount * 1_000_000);
  if (!Number.isSafeInteger(micros)) throw new Error("金额上限超出可设置范围");
  return micros;
}

function inputTokens(value: string) {
  const tokens = Number(value || "0");
  if (!Number.isSafeInteger(tokens) || tokens < 0) throw new Error("Token 上限必须为大于或等于 0 的整数");
  return tokens;
}

function LimitProgress({ label, used, limit, unit, currency }: { label: string; used: number; limit: number; unit: "money" | "token"; currency: string }) {
  const visible = limit > 0;
  const ratio = visible ? Math.min(100, used / Math.max(1, limit) * 100) : 0;
  const display = unit === "money" ? money(used,currency) : number(used);
  const maximum = unit === "money" ? money(limit,currency) : number(limit);
  return <div className="rounded border px-3 py-2">
    <div className="flex items-center justify-between gap-3 text-xs"><span>{label}</span><span className="tabular-nums text-muted-foreground">{visible ? display + " / " + maximum : "未设置上限"}</span></div>
    <div className="mt-2 h-1.5 overflow-hidden rounded bg-muted"><div className={ratio >= 90 ? "h-full bg-destructive" : "h-full bg-primary"} style={{ width: ratio + "%" }} /></div>
  </div>;
}

function CallLimits({ limits, currency, onSaved }: { limits: BillingData["data"]["limits"]; currency: string; onSaved:()=>Promise<unknown> }) {
  const [dailyAmount, setDailyAmount] = React.useState(String(limits.daily.amount_limit_micros / 1_000_000));
  const [monthlyAmount, setMonthlyAmount] = React.useState(String(limits.monthly.amount_limit_micros / 1_000_000));
  const [dailyTokens, setDailyTokens] = React.useState(String(limits.daily.token_limit));
  const [monthlyTokens, setMonthlyTokens] = React.useState(String(limits.monthly.token_limit));
  const [rpmLimit, setRpmLimit] = React.useState(String(limits.rpm_limit ?? 0));
  const [concurrencyLimit, setConcurrencyLimit] = React.useState(String(limits.concurrency_limit ?? 0));
  const [busy, setBusy] = React.useState<"limits" | "">("");
  const [notice, setNotice] = React.useState("");
  const [expanded,setExpanded]=React.useState(false);

  const saveLimits = async () => {
    setBusy("limits");
    setNotice("");
    try {
      const response = await fetch(portalPath("/api/me/billing/limits"), {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          daily_amount_micros: inputMicros(dailyAmount),
          monthly_amount_micros: inputMicros(monthlyAmount),
          daily_token_limit: inputTokens(dailyTokens),
          monthly_token_limit: inputTokens(monthlyTokens),
          rpm_limit: inputTokens(rpmLimit),
          concurrency_limit: inputTokens(concurrencyLimit),
        }),
      });
      if (!response.ok) throw new Error("保存失败，请检查限额填写后重试");
      setNotice("保存成功，新限额已立即生效");
      await onSaved();
    } catch (cause) {
      setNotice(cause instanceof Error ? cause.message : "限额保存失败，请稍后重试");
    } finally {
      setBusy("");
    }
  };

  return <Panel title="个人自助预算与限额">
    <p className="mb-4 text-sm text-muted-foreground">用于自己控制用量；0 表示取消对应自助限制。调用同时受已配置的部门与应用规则约束。</p>
    <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
      <LimitProgress label="当日金额用量" used={usedAmount(limits.daily)} limit={limits.daily.amount_limit_micros} unit="money" currency={currency} />
      <LimitProgress label="当月金额用量" used={usedAmount(limits.monthly)} limit={limits.monthly.amount_limit_micros} unit="money" currency={currency} />
      <LimitProgress label="当日 Token 用量" used={usedTokens(limits.daily)} limit={limits.daily.token_limit} unit="token" currency={currency} />
      <LimitProgress label="当月 Token 用量" used={usedTokens(limits.monthly)} limit={limits.monthly.token_limit} unit="token" currency={currency} />
    </div>
    <button type="button" aria-expanded={expanded} onClick={()=>setExpanded(value=>!value)} className="mt-4 text-sm text-primary">调整自助限额 {expanded?"⌃":"⌄"}</button>
    {expanded&&<div><div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
      <label className="text-sm">{moneyLimitLabel("当日金额上限",currency)}<input value={dailyAmount} onChange={(event) => setDailyAmount(event.target.value)} type="number" min="0" step="0.000001" className="mt-1 w-full rounded border bg-background px-3 py-2" /></label>
      <label className="text-sm">{moneyLimitLabel("当月金额上限",currency)}<input value={monthlyAmount} onChange={(event) => setMonthlyAmount(event.target.value)} type="number" min="0" step="0.000001" className="mt-1 w-full rounded border bg-background px-3 py-2" /></label>
      <label className="text-sm">当日 Token 上限<input value={dailyTokens} onChange={(event) => setDailyTokens(event.target.value)} type="number" min="0" step="1" className="mt-1 w-full rounded border bg-background px-3 py-2" /></label>
      <label className="text-sm">当月 Token 上限<input value={monthlyTokens} onChange={(event) => setMonthlyTokens(event.target.value)} type="number" min="0" step="1" className="mt-1 w-full rounded border bg-background px-3 py-2" /></label>
      <label className="text-sm">每分钟请求上限（RPM）<input value={rpmLimit} onChange={(event) => setRpmLimit(event.target.value)} type="number" min="0" step="1" className="mt-1 w-full rounded border bg-background px-3 py-2" /></label>
      <label className="text-sm">并发请求上限<input value={concurrencyLimit} onChange={(event) => setConcurrencyLimit(event.target.value)} type="number" min="0" step="1" className="mt-1 w-full rounded border bg-background px-3 py-2" /></label>
    </div>
    <button type="button" disabled={busy !== ""} onClick={saveLimits} className="mt-4 rounded bg-primary px-4 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50">{busy === "limits" ? "正在保存…" : "保存限额"}</button>
    </div>}
    {notice && <p className="mt-4 rounded border px-3 py-2 text-sm">{notice}</p>}
  </Panel>;
}

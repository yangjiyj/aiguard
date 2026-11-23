import React from "react";
import { formatMoneyMicros as money } from "@/lib/money-micros";
import { walletAmounts, type MonthlyWalletStatus, type WalletBalance } from "@/lib/wallet-balances";

export const walletSummaryCopy = {
  title: "我的钱包", total: "总余额", reserved: "请求预占", available: "可用余额",
  monthly: "本月赠送", granted: "本月已到账", monthlyAvailable: "本月赠送可用", expires: "到期时间",
  monthlyUnavailable: "本月赠送信息暂不可用", noMonthlyPolicy: "当前未设置每月赠送",
  permanent: "人工充值和兑换码充值长期有效。", expiryNote: "本月赠送的未用余额在到期时回收。",
};

function periodLabel(value: string, timezone: string) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "—";
  return new Intl.DateTimeFormat("zh-CN", { year: "numeric", month: "long", timeZone: timezone }).format(date);
}
function expiresLabel(value: string | null, timezone: string) {
  if (!value) return "—";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "—";
  return new Intl.DateTimeFormat("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false, timeZone: timezone }).format(date);
}
function AmountCard({label,value,id}:{label:string;value:string;id:string}) {
  return <div className="rounded-lg border bg-muted/20 p-4"><p className="text-xs text-muted-foreground">{label}</p><p data-testid={id} className="mt-2 break-words text-xl font-semibold tabular-nums">{value}</p></div>;
}

export const LOW_BALANCE_DAYS = 3;
export function walletBalanceTone(available:number,dailyAverage:number) {
  return available <= 0 ? 'empty' : dailyAverage > 0 && available <= dailyAverage * LOW_BALANCE_DAYS ? 'low' : 'normal';
}
export function WalletSummaryPanel({wallet,monthly,dailyAverage=0,now,tenantCurrency}:{wallet:WalletBalance;monthly:MonthlyWalletStatus|null|undefined;dailyAverage?:number;now?:number;tenantCurrency?:string}) {
  const [clock,setClock]=React.useState(0);
  React.useEffect(()=>{const tick=()=>setClock(Date.now());void Promise.resolve().then(tick);const timer=window.setInterval(tick,60000);return()=>window.clearInterval(timer)},[]);
  const amounts=walletAmounts(wallet,monthly);
  const tone=walletBalanceTone(amounts.available,dailyAverage);
  const hasGift=monthly && monthly.configured_micros!==null && (monthly.granted_micros>0 || (amounts.monthlyAvailable??0)>0);
  const expiry=monthly?.expires_at?Date.parse(monthly.expires_at):NaN;
  const expiring=expiry>(now??clock) && expiry-(now??clock)<=7*24*60*60*1000;
  return <section className="rounded-xl border bg-card p-5" data-testid="personal-wallet">
    <div className="flex items-center justify-between gap-3"><h2 className="text-base font-semibold">{walletSummaryCopy.title}</h2><details className="relative text-xs text-muted-foreground"><summary aria-label="钱包规则" className="cursor-pointer list-none rounded px-2 py-1">ⓘ 规则</summary><p className="absolute right-0 z-10 mt-2 w-64 rounded-lg border bg-popover p-3 shadow-md">{walletSummaryCopy.permanent}<br/>{walletSummaryCopy.expiryNote}</p></details></div>
    <div className={"mt-4 rounded-lg px-4 py-4 "+(tone==='empty'?'bg-destructive/10 text-destructive':tone==='low'?'bg-amber-500/10 text-amber-700 dark:text-amber-300':'bg-muted/30')}>
      <p className="text-xs">{walletSummaryCopy.available}</p><p data-testid="wallet-available" className="mt-1 break-words text-3xl font-semibold tabular-nums">{money(amounts.available,wallet.currency,tenantCurrency)}</p>
      <p className="mt-2 text-xs text-muted-foreground">总额 <span data-testid="wallet-total">{money(amounts.total,wallet.currency,tenantCurrency)}</span> · 预占 <span data-testid="wallet-reserved">{money(amounts.reserved,wallet.currency,tenantCurrency)}</span></p>
      {tone==='empty'&&<p className="mt-2 text-sm">余额不足，请兑换充值</p>}{tone==='low'&&<p className="mt-2 text-xs">余额不足近三天日均消费，请及时充值</p>}
    </div>
    <div className="mt-4 border-t pt-4" data-testid="monthly-wallet-gift">
      {hasGift?<><div className="flex flex-wrap items-center justify-between gap-2"><h3 className="text-sm font-semibold">本月赠送</h3><span data-testid="wallet-monthly-period" className="text-xs text-muted-foreground">{periodLabel(monthly.month_start,monthly.timezone)}</span></div>
      <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-3"><AmountCard label={walletSummaryCopy.granted} value={money(monthly.granted_micros,monthly.currency,tenantCurrency)} id="wallet-monthly-granted"/><AmountCard label={walletSummaryCopy.monthlyAvailable} value={money(amounts.monthlyAvailable??0,monthly.currency,tenantCurrency)} id="wallet-monthly-available"/><div className={expiring?'rounded-lg border border-amber-300 text-amber-700 dark:text-amber-300':'text-muted-foreground'}><AmountCard label={walletSummaryCopy.expires} value={expiresLabel(monthly.expires_at,monthly.timezone)} id="wallet-monthly-expires"/>{expiring&&<p className="px-4 pb-2 text-xs">赠送额度将在 7 天内到期</p>}</div></div></>:<p className="text-sm text-muted-foreground">{monthly?'本月暂无赠送额度':walletSummaryCopy.monthlyUnavailable}</p>}
    </div>
  </section>;
}

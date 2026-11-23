"use client";

import React from "react";
import {personalActionError} from "@/lib/personal-action-errors";
import {redeemWalletCode,WalletRedemptionError} from "@/lib/wallet-redemption";

export const redemptionCopy={
  title:"兑换码充值", input:"兑换码", placeholder:"请输入兑换码", submit:"确认兑换", busy:"正在兑换…",
  permanent:"兑换充值长期有效，每张兑换码仅可使用一次。",
  invalid:"兑换码无效、已使用、已停用或已过期", unavailable:"兑换失败，请稍后重试",
  success:"兑换成功，账户余额已更新", refreshPending:"兑换已成功，请刷新查看余额",
};

export function RedemptionPanel({currency,onRedeemed}:{currency:string;onRedeemed:()=>Promise<void>}) {
  const [code,setCode]=React.useState("");const [busy,setBusy]=React.useState(false);
  const [notice,setNotice]=React.useState("");const [error,setError]=React.useState("");
  const redeem=async()=>{
    if(busy)return;setBusy(true);setNotice("");setError("");
    try {
      const result=await redeemWalletCode(code,{refresh:onRedeemed});setCode("");
      setNotice(result==="redeemed"?redemptionCopy.success:redemptionCopy.refreshPending);
    } catch(cause) {setError(cause instanceof WalletRedemptionError?personalActionError(cause.code,redemptionCopy.unavailable):redemptionCopy.unavailable);}
    finally {setBusy(false);}
  };
  return <section className="rounded-xl border bg-card p-5 shadow-sm" data-testid="wallet-redemption">
    <h2 className="text-base font-semibold">{redemptionCopy.title}</h2>
    <p className="mt-2 text-xs text-muted-foreground">{currency} · {redemptionCopy.permanent}</p>
    <label className="mt-4 block text-sm" htmlFor="wallet-redemption-code">{redemptionCopy.input}</label>
    <div className="mt-2 flex flex-wrap items-end gap-2"><div data-sensitive className="min-w-0 basis-60 flex-1"><input id="wallet-redemption-code" data-testid="wallet-redemption-code" value={code} onChange={event=>setCode(event.target.value)} disabled={busy} maxLength={128} autoComplete="off" spellCheck={false} autoCapitalize="none" placeholder={redemptionCopy.placeholder} className="w-full rounded border bg-background px-3 py-2 font-mono text-sm" /></div><button type="button" data-testid="wallet-redeem-submit" disabled={busy||!code.trim()} onClick={()=>void redeem()} className="rounded bg-primary px-4 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50">{busy?redemptionCopy.busy:redemptionCopy.submit}</button></div>
    {notice&&<p role="status" className="mt-3 rounded border px-3 py-2 text-sm">{notice}</p>}
    {error&&<p role="alert" className="mt-3 rounded border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive">{error}</p>}
  </section>;
}

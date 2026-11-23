import {portalPath} from "./portal-path";

export type WalletRedemptionErrorCode="invalid_input"|"invalid_origin"|"redemption_unavailable"|"rate_limited"|"control_plane_unreachable"|"unauthorized"|"operation_failed";
export class WalletRedemptionError extends Error {
  constructor(readonly code:WalletRedemptionErrorCode) { super(code); }
}
export async function redeemWalletCode(code:string,options:{fetchImpl?:typeof fetch;refresh:()=>Promise<void>}):Promise<"redeemed"|"redeemed_refresh_pending"> {
  const normalized=code.trim();
  if(!normalized||normalized.length>128)throw new WalletRedemptionError("invalid_input");
  let response:Response;
  try { response=await (options.fetchImpl??fetch)(portalPath("/api/me/billing/redeem"),{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({code:normalized}),cache:"no-store"}); }
  catch { throw new WalletRedemptionError("control_plane_unreachable"); }
  if(!response.ok){
   const payload=await response.json().catch(()=>null) as {error?:unknown}|null;
   const known=new Set(['invalid_origin','redemption_unavailable','rate_limited','control_plane_unreachable','unauthorized','invalid_redemption_code']);
   const code=typeof payload?.error==='string'&&known.has(payload.error)?payload.error:'operation_failed';
   throw new WalletRedemptionError(code==='invalid_redemption_code'?'invalid_input':code as WalletRedemptionErrorCode);
  }
  // A balance-refresh failure must not turn an already committed redemption
  // into a financial retry. The protected BFF and ledger remain unchanged.
  try { await options.refresh();return "redeemed"; }
  catch { return "redeemed_refresh_pending"; }
}

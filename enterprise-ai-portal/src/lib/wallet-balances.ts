export type WalletBalance = {
  currency: string;
  balance_micros: number;
  reserved_micros: number;
  available_micros?: number;
};

export type MonthlyWalletStatus = {
  configured_micros: number | null;
  granted_micros: number;
  remaining_micros: number;
  reserved_micros: number;
  used_micros: number;
  expired_micros: number;
  adjusted_micros: number;
  currency: string;
  timezone: string;
  month_start: string;
  month_end: string;
  expires_at: string | null;
};

export function walletAmounts(wallet: WalletBalance, monthly: MonthlyWalletStatus | null | undefined) {
  return {
    total: wallet.balance_micros,
    reserved: wallet.reserved_micros,
    available: wallet.available_micros ?? wallet.balance_micros - wallet.reserved_micros,
    monthlyAvailable: monthly ? monthly.remaining_micros - monthly.reserved_micros : null,
  };
}

// An earlier metadata refresh must not overwrite the balance returned after
// a committed redemption. Only the latest requested wallet snapshot applies.
export function latestWalletRefresh<T>(load:()=>Promise<T>,apply:(snapshot:T)=>void) {
  let generation=0;
  return async()=>{
    const requested=++generation;
    const snapshot=await load();
    if(requested===generation)apply(snapshot);
  };
}

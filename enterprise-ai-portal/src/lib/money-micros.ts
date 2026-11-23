const microsPerUnit = BigInt(1_000_000);
const zero = BigInt(0);
const formatters = new Map<string, Intl.NumberFormat>();

// 事实币种优先，缺失时跟随租户；未知币种不能被默认标成人民币。
export function moneyCurrency(currency?: string | null, tenantCurrency?: string | null): string {
  return currency?.trim() || tenantCurrency?.trim() || "";
}

// 金额输入框标签的单位：美元显示「美元」，其余（含未知）显示「元」；只换文字，不换算金额。
export function moneyLimitLabel(label: string, currency?: string | null, tenantCurrency?: string | null): string {
  const unit = moneyCurrency(currency, tenantCurrency).toUpperCase() === "USD" ? "美元" : "元";
  return `${label}（${unit}）`;
}

// 先拆分整数微单位，避免接近安全整数边界时损失最后一位精度；不做汇率换算。
export function formatMoneyMicros(amountMicros: number, currency?: string | null, tenantCurrency?: string | null): string {
  currency = moneyCurrency(currency, tenantCurrency);
  if (!/^[A-Z]{3}$/.test(currency)) return "—";
  if (!Number.isSafeInteger(amountMicros)) return "\u2014";
  const value = BigInt(amountMicros);
  const absolute = value < zero ? -value : value;
  const whole = absolute / microsPerUnit;
  const fraction = (absolute % microsPerUnit).toString().padStart(6, "0")
    .replace(/0+$/, "").padEnd(2, "0");
  let formatter = formatters.get(currency);
  if (!formatter) {
    formatter = new Intl.NumberFormat("zh-CN", {
      style: "currency", currency, minimumFractionDigits: 2, maximumFractionDigits: 2,
    });
    formatters.set(currency, formatter);
  }
  const formatted = formatter.formatToParts(whole)
    .map(part => part.type === "fraction" ? fraction : part.value).join("");
  return value < zero ? "-" + formatted : formatted;
}

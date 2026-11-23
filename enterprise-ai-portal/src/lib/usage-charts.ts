import { formatMoneyMicros as money } from "@/lib/money-micros";

export type DailyUsage = { date: string; requests: number; tokens: number; amount_micros: number; currency?: string };
export type ModelUsage = { model_name: string; requests: number; tokens: number; amount_micros: number; currency?: string };

function localDay(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return date.getFullYear() + "-" + pad(date.getMonth() + 1) + "-" + pad(date.getDate());
}

// 把稀疏的日账单补齐为连续 N 天，空白日记 0，图表才不会把相隔多天的柱子挤在一起。
export function fillDailySeries(daily: DailyUsage[], days = 30, today = new Date()): DailyUsage[] {
  const byDate = new Map<string, DailyUsage>();
  for (const item of daily) byDate.set(item.date.slice(0, 10), item);
  const latest = daily.map((d) => d.date.slice(0, 10)).sort().at(-1);
  const end = latest && latest > localDay(today) ? new Date(latest + "T00:00:00") : today;
  const out: DailyUsage[] = [];
  for (let i = days - 1; i >= 0; i--) {
    const day = new Date(end.getFullYear(), end.getMonth(), end.getDate() - i);
    const key = localDay(day);
    out.push(byDate.get(key) ?? { date: key, requests: 0, tokens: 0, amount_micros: 0 });
  }
  return out;
}

export function compactNumber(value: number): string {
  const n = value ?? 0;
  if (Math.abs(n) >= 100_000_000) return (n / 100_000_000).toFixed(2).replace(/\.?0+$/, "") + " 亿";
  if (Math.abs(n) >= 10_000) return (n / 10_000).toFixed(1).replace(/\.0$/, "") + " 万";
  return new Intl.NumberFormat("zh-CN").format(n);
}

export type ModelShare = ModelUsage & { share: number };
export function modelShares(models: ModelUsage[], limit = 6): ModelShare[] {
  const sorted = [...models].sort((a, b) => b.amount_micros - a.amount_micros || b.tokens - a.tokens);
  const byAmount = sorted.some((m) => m.amount_micros > 0);
  const total = sorted.reduce((sum, m) => sum + (byAmount ? m.amount_micros : m.tokens), 0) || 1;
  const head = sorted.slice(0, limit);
  const rest = sorted.slice(limit);
  if (rest.length) head.push(rest.reduce<ModelUsage>((acc, m) => ({
    ...acc, requests: acc.requests + m.requests, tokens: acc.tokens + m.tokens, amount_micros: acc.amount_micros + m.amount_micros,
  }), { model_name: "其他 " + rest.length + " 个模型", requests: 0, tokens: 0, amount_micros: 0, currency: rest[0].currency }));
  return head.map((m) => ({ ...m, share: (byAmount ? m.amount_micros : m.tokens) / total }));
}

export function moneyAxis(max: number, currency: string): string[] {
  return [1, 0.5, 0].map((ratio) => money(Math.round(max * ratio), currency));
}

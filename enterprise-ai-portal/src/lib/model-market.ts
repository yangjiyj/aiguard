import type { PortalModelPrice } from "@/lib/model-prices";
import { vendorName } from "@/lib/model-prices";
import { VENDORS, vendorFromId } from "@/lib/model-catalog";

export type PerfPoint = { at: string; samples: number; success_rate: number | null; ttft_p50_ms: number | null; tps_p50: number | null };
export type ModelPerformance = {
  model_name: string; protocols: string[]; samples: number; success_rate: number | null;
  ttft_p50_ms: number | null; ttft_p95_ms: number | null; tps_p50: number | null;
  latency_p50_ms: number | null; latency_p95_ms: number | null; hourly: PerfPoint[];
};
export type MarketRow = { model: string; price: PortalModelPrice | null; perf: ModelPerformance | null };
export type MarketSortKey = "name" | "ttft" | "tps" | "success" | "price" | "samples";
export type MarketSort = { key: MarketSortKey; dir: "asc" | "desc" };
export type Health = "good" | "warn" | "bad" | "unknown";

// 与控制面一致：样本少于 5 时指标为空，卡片改写「样本不足」。
export const MIN_SAMPLES = 5;

export const PROTOCOL_LABELS: Record<string, string> = { chat: "Chat", responses: "Responses", messages: "Messages" };

// 以授权列表为准：价格或性能里多出来的模型一律丢弃，缺的显示「未定价」「—」。
export function buildMarketRows(models: string[], prices: PortalModelPrice[], perf: ModelPerformance[]): MarketRow[] {
  const priceBy = new Map(prices.map((p) => [p.model_name, p]));
  const perfBy = new Map(perf.map((p) => [p.model_name, p]));
  return [...new Set(models.map((m) => m.trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b))
    .map((model) => ({ model, price: priceBy.get(model) ?? null, perf: perfBy.get(model) ?? null }));
}

export function healthOf(rate: number | null | undefined): Health {
  if (rate == null) return "unknown";
  return rate >= 0.95 ? "good" : rate >= 0.8 ? "warn" : "bad";
}

export const fmtMs = (ms: number | null | undefined) => ms == null ? "—" : ms < 1000 ? `${Math.round(ms)}ms` : `${(ms / 1000).toFixed(ms < 10000 ? 2 : 1)}s`;
export const fmtTps = (v: number | null | undefined) => v == null ? "—" : `${v.toFixed(1)} t/s`;
export const fmtRate = (v: number | null | undefined) => v == null ? "—" : `${(v * 100).toFixed(1)}%`;

const sortValue = (row: MarketRow, key: MarketSortKey): number | null => {
  if (key === "ttft") return row.perf?.ttft_p50_ms ?? null;
  if (key === "tps") return row.perf?.tps_p50 ?? null;
  if (key === "success") return row.perf?.success_rate ?? null;
  if (key === "samples") return row.perf?.samples || null;
  if (key === "price") return row.price ? row.price.input_per_million_micros + row.price.output_per_million_micros : null;
  return null;
};

export function sortRows(rows: MarketRow[], sort: MarketSort): MarketRow[] {
  if (sort.key === "name") return [...rows].sort((a, b) => (sort.dir === "asc" ? 1 : -1) * a.model.localeCompare(b.model));
  return [...rows].sort((a, b) => {
    const x = sortValue(a, sort.key), y = sortValue(b, sort.key);
    if (x == null && y == null) return a.model.localeCompare(b.model);
    if (x == null) return 1;
    if (y == null) return -1;
    return (sort.dir === "asc" ? x - y : y - x) || a.model.localeCompare(b.model);
  });
}

export function filterRows(rows: MarketRow[], query: string, vendor = "all"): MarketRow[] {
  const q = query.trim().toLowerCase();
  return rows.filter((r) => (vendor === "all" || vendorFromId(r.model) === vendor) &&
    (!q || r.model.toLowerCase().includes(q) || vendorName(r.model).toLowerCase().includes(q)));
}

// 只列出授权模型里实际出现的厂商，顺序跟厂商目录一致。
export function vendorFacets(rows: MarketRow[]): { id: string; name: string; count: number }[] {
  return VENDORS.map((v) => ({ id: v.id, name: v.name, count: rows.filter((r) => vendorFromId(r.model) === v.id).length })).filter((v) => v.count > 0);
}

export const SORT_OPTIONS: [MarketSortKey, string][] = [["samples", "常用优先"], ["ttft", "首字最快"], ["tps", "输出最快"], ["success", "成功率最高"], ["name", "名称"]];
export const sortPreset = (key: MarketSortKey): MarketSort => ({ key, dir: key === "ttft" || key === "name" || key === "price" ? "asc" : "desc" });

// 接入示例只用占位变量，不读取、不回显任何密钥。
export function curlExample(baseUrl: string, model: string, protocols: string[]): string {
  if (!baseUrl) return "";
  const base = baseUrl.replace(/\/$/, "");
  const auth = `-H "Authorization: Bearer $JJD_API_KEY" \\\n  -H "Content-Type: application/json" \\\n  `;
  const protocol = protocols.includes("chat") ? "chat" : protocols[0] ?? "chat";
  if (protocol === "messages") return `curl ${base}/messages \\\n  ${auth}-d '{"model":"${model}","max_tokens":256,"messages":[{"role":"user","content":"你好"}]}'`;
  if (protocol === "responses") return `curl ${base}/responses \\\n  ${auth}-d '{"model":"${model}","input":"你好"}'`;
  return `curl ${base}/chat/completions \\\n  ${auth}-d '{"model":"${model}","messages":[{"role":"user","content":"你好"}]}'`;
}

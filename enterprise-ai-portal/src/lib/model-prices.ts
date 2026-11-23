import { VENDORS, vendorFromId } from "@/lib/model-catalog";

// 门户「模型价格超市」展示模型。价格均为已换算的直接价（每百万 Token，微单位），
// 与实际计费使用的 default 客户组同一口径；门户不做任何计费推算。
export type PortalModelPrice = {
  model_name: string;
  currency: string;
  pricing_mode: string;
  input_per_million_micros: number;
  cached_input_per_million_micros: number;
  cache_write_per_million_micros: number;
  output_per_million_micros: number;
  has_cached_input_price: boolean;
  has_cache_write_price: boolean;
  pricing_extras?: {
    image_per_image_micros?: number;
    request_per_call_micros?: number;
    reasoning_per_million_micros?: number | null;
    image_output_per_million_micros?: number | null;
    image_input_per_million_micros?: number | null;
    tool_prices_per_thousand_micros?: Record<string, number> | null;
  } | null;
  effective_at?: string;
};

export type PriceSort = "name" | "input" | "output";

export function vendorName(model: string): string {
  const id = vendorFromId(model);
  return VENDORS.find((vendor) => vendor.id === id)?.name ?? "企业模型";
}

export function priceVendors(prices: PortalModelPrice[]): { id: string; name: string; count: number }[] {
  return VENDORS.map((vendor) => ({ ...vendor, count: prices.filter((p) => vendorFromId(p.model_name) === vendor.id).length }))
    .filter((vendor) => vendor.count > 0);
}

export function filterModelPrices(prices: PortalModelPrice[], query: string, vendor: string, sort: PriceSort): PortalModelPrice[] {
  const q = query.trim().toLowerCase();
  const list = prices.filter((price) =>
    (vendor === "all" || vendorFromId(price.model_name) === vendor) &&
    (!q || price.model_name.toLowerCase().includes(q) || vendorName(price.model_name).toLowerCase().includes(q)));
  const key = sort === "input" ? "input_per_million_micros" : "output_per_million_micros";
  return [...list].sort((a, b) => sort === "name" ? a.model_name.localeCompare(b.model_name) : a[key] - b[key] || a.model_name.localeCompare(b.model_name));
}

// 是否为「仅按次/按张」计价（Token 单价为 0 但有额外计费项）。
export function isFlatPriced(price: PortalModelPrice): boolean {
  const extras = price.pricing_extras ?? {};
  return price.input_per_million_micros === 0 && price.output_per_million_micros === 0 &&
    ((extras.request_per_call_micros ?? 0) > 0 || (extras.image_per_image_micros ?? 0) > 0);
}

export function isFree(price: PortalModelPrice): boolean {
  return price.input_per_million_micros === 0 && price.output_per_million_micros === 0 && !isFlatPriced(price);
}

export type PriceExtra = { label: string; micros: number; unit: string };
export function priceExtras(price: PortalModelPrice): PriceExtra[] {
  const extras = price.pricing_extras ?? {};
  const out: PriceExtra[] = [];
  if (price.has_cached_input_price) out.push({ label: "缓存命中输入", micros: price.cached_input_per_million_micros, unit: "/ 百万 Token" });
  if (price.has_cache_write_price) out.push({ label: "缓存写入", micros: price.cache_write_per_million_micros, unit: "/ 百万 Token" });
  if (extras.reasoning_per_million_micros != null) out.push({ label: "推理输出", micros: extras.reasoning_per_million_micros, unit: "/ 百万 Token" });
  if (extras.image_input_per_million_micros != null) out.push({ label: "图片输入", micros: extras.image_input_per_million_micros, unit: "/ 百万 Token" });
  if (extras.image_output_per_million_micros != null) out.push({ label: "图片输出", micros: extras.image_output_per_million_micros, unit: "/ 百万 Token" });
  if ((extras.image_per_image_micros ?? 0) > 0) out.push({ label: "按张", micros: extras.image_per_image_micros!, unit: "/ 张" });
  if ((extras.request_per_call_micros ?? 0) > 0) out.push({ label: "按次", micros: extras.request_per_call_micros!, unit: "/ 次" });
  for (const [tool, micros] of Object.entries(extras.tool_prices_per_thousand_micros ?? {})) out.push({ label: "工具 " + tool, micros, unit: "/ 千次" });
  return out;
}

// 估算一次典型对话（输入 2000 / 输出 500 Token）的花费，便于直观比较。
export const TYPICAL_CALL = { input: 2000, output: 500 };
export function typicalCallMicros(price: PortalModelPrice): number {
  const extras = price.pricing_extras ?? {};
  return Math.round((price.input_per_million_micros * TYPICAL_CALL.input + price.output_per_million_micros * TYPICAL_CALL.output) / 1_000_000) +
    (extras.request_per_call_micros ?? 0);
}

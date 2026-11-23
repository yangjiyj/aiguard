/**
 * 模型展示元数据层（纯前端）。
 * 模型「有哪些」由后端动态决定（/api/models → useChatStore().models，{id,displayName,capabilities}）；
 * 本文件只负责「怎么展示」——按 id 推断厂商分组，vision 门禁读后端 capabilities.supports_image_input。
 * 不硬编码能力标签（曾因硬编码 glm-5.2 标 vision 但实际不支持，导致用户传图给无视觉模型）。
 */

export type Vendor = { id: string; name: string };

export type EnrichedModel = {
  id: string;
  displayName: string;
  vendorId: string;
  supportsImageInput: boolean; // 从后端 capabilities.supports_image_input 读，默认 false（fail-safe）
};

/** 厂商顺序即下拉分组顺序；other 兜底放最后 */
export const VENDORS: Vendor[] = [
  { id: "zhipu", name: "智谱 AI" },
  { id: "deepseek", name: "DeepSeek" },
  { id: "qwen", name: "通义千问" },
  { id: "anthropic", name: "Anthropic" },
  { id: "openai", name: "OpenAI" },
  { id: "google", name: "Google" },
  { id: "doubao", name: "豆包" },
  { id: "other", name: "企业模型" },
];

export function vendorFromId(id: string): string {
  const s = id.toLowerCase();
  if (s.includes("glm") || s.includes("zhipu")) return "zhipu";
  if (s.includes("deepseek")) return "deepseek";
  if (s.includes("qwen") || s.includes("tongyi")) return "qwen";
  if (s.includes("claude")) return "anthropic";
  if (s.includes("gpt") || s.includes("codex") || s.includes("o1") || s.includes("o3") || s.includes("o4")) return "openai";
  if (s.includes("gemini")) return "google";
  if (s.includes("doubao") || s.includes("seedance")) return "doubao";
  return "other";
}

export function enrichModel(
  m: { id: string; displayName: string; capabilities?: Record<string, unknown> },
): EnrichedModel {
  const caps = m.capabilities ?? {};
  return {
    id: m.id,
    displayName: m.displayName,
    vendorId: vendorFromId(m.id),
    supportsImageInput: caps.supports_image_input === true,
  };
}

export function groupByVendor(
  models: EnrichedModel[],
): { vendor: Vendor; models: EnrichedModel[] }[] {
  return VENDORS.map((vendor) => ({
    vendor,
    models: models.filter((m) => m.vendorId === vendor.id),
  })).filter((g) => g.models.length > 0);
}

export function filterModels(models: EnrichedModel[], query: string): EnrichedModel[] {
  const q = query.trim().toLowerCase();
  if (!q) return models;
  return models.filter((m) => {
    const vendor = VENDORS.find((v) => v.id === m.vendorId);
    return (
      m.displayName.toLowerCase().includes(q) ||
      m.vendorId.toLowerCase().includes(q) ||
      (vendor?.name.toLowerCase().includes(q) ?? false)
    );
  });
}

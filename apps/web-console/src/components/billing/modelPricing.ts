import { useCurrencyStore } from '../../stores/currency'
export const MICROS_PER_YUAN = 1_000_000
export const imageQualityLabel = (value: string) => ({ standard: '标准', hd: '高清', low: '低', medium: '中', high: '高', auto: '自动' }[value] ?? value)

export type PricingMode = 'direct' | 'newapi_ratio'
export interface PriceExtensions {
  image_pricing?: {
    mode: 'token' | 'per_image'
    default_size?: string
    default_quality?: string
    variants?: { size: string; quality: string; price_per_image_micros: number }[]
  }
  image_input_per_million_micros?: number
  image_output_per_million_micros?: number
  cached_image_input_per_million_micros?: number
  newapi_fixed_quantity?: boolean
  image_per_image_micros?: number
  request_per_call_micros?: number
  reasoning_per_million_micros?: number | null
  tool_prices_per_thousand_micros?: Record<string, number>
  source?: string
}

export interface EditablePriceDraft {
  currency: string
  pricingExtras: PriceExtensions
  sourcePriceID: string | null
  mode: PricingMode
  inputPerMillionYuan: number | null
  outputPerMillionYuan: number | null
  cachedInputPerMillionYuan: number | null
  cacheWritePerMillionYuan: number | null
  baseInputPerMillionYuan: number | null
  modelRatio: number | null
  completionRatio: number | null
  cachedInputRatio: number | null
  cacheWriteRatio: number | null
}

export interface ImagePricingTemplate {
  id: string
  model_patterns: string[]
  label: string
  mode: 'token' | 'per_image'
  sizes: string[]
  qualities: string[]
  default_size: string
  default_quality: string
  basis: string
  reference: string
}

export interface PricingCapabilities {
  image_models: ImagePricingTemplate[]
  tools: {
    name: string
    label: string
    unit: string
    evidence: string[]
    support: 'native' | 'usage_counter'
    reference_price_per_thousand_micros?: number
    reference_currency?: 'USD' | 'CNY'
    reference_url?: string
    reference_basis?: string
    reference_key?: string
  }[]
  recognized_model: boolean
  suggested_template_id: string
}

export interface BillingModel {
  model_name: string
  model_label: string
  provider_name: string
  status: string
}

export interface BillingPrice {
  pricing_extras?: PriceExtensions
  id: string
  model_name: string
  version: number
  pricing_mode: PricingMode
  currency: string
  status: string
  effective_at: string
  expires_at?: string | null
  input_per_million_micros?: number
  output_per_million_micros?: number
  cached_input_per_million_micros?: number
  cache_write_per_million_micros?: number
  has_cached_input_price?: boolean
  has_cache_write_price?: boolean
  base_input_per_million_micros?: number
  model_ratio_ppm?: number
  completion_ratio_ppm?: number
  cached_input_ratio_ppm?: number
  cache_write_ratio_ppm?: number
  has_cached_input_ratio?: boolean
  has_cache_write_ratio?: boolean
  created_at?: string
  // 当前生效价接口会带客户组；控制台只写 'default' 组
  customer_group?: string
}

export interface PricingRow {
  key: string
  modelName: string
  modelLabel: string
  providerName: string
  modelStatus: string
  configured: boolean
  current: BillingPrice | null
  history: BillingPrice[]
}

export interface DirectDraft {
  currency?: string
  pricingExtras?: PriceExtensions
  inputPerMillionYuan: number
  outputPerMillionYuan: number
  cachedInputPerMillionYuan: number | null
  cacheWritePerMillionYuan: number | null
}

export interface RatioDraft {
  currency?: string
  pricingExtras?: PriceExtensions
  baseInputPerMillionYuan: number
  modelRatio: number
  completionRatio: number
  cachedInputRatio: number | null
  cacheWriteRatio: number | null
}

// 价格列表接口单次最多返回的行数（历史与当前生效价都按这个上限请求）。
export const PRICE_LIST_LIMIT = 500

// 合并「全部历史」与「当前生效」两份列表：按 id 去重；忽略非 default 客户组的行（控制台只写 default 组）。
export function mergePrices(...lists: BillingPrice[][]): BillingPrice[] {
  const seen = new Set<string>()
  const merged: BillingPrice[] = []
  for (const list of lists) {
    for (const price of list) {
      if (price.customer_group && price.customer_group !== 'default') continue
      if (seen.has(price.id)) continue
      seen.add(price.id)
      merged.push(price)
    }
  }
  return merged
}

const timestamp = (value?: string | null) => {
  if (!value) return Number.NaN
  return Date.parse(value)
}

const currentPrice = (history: BillingPrice[], now: Date) => {
  const nowMillis = now.getTime()
  return history
    .filter((price) => {
      const effectiveAt = timestamp(price.effective_at)
      const expiresAt = timestamp(price.expires_at)
      return price.status === 'active'
        && Number.isFinite(effectiveAt)
        && effectiveAt <= nowMillis
        && (!price.expires_at || (Number.isFinite(expiresAt) && expiresAt > nowMillis))
    })
    .sort((left, right) => {
      const byEffectiveAt = timestamp(right.effective_at) - timestamp(left.effective_at)
      return byEffectiveAt || right.version - left.version
    })[0] ?? null
}

export function buildPricingRows(models: BillingModel[], prices: BillingPrice[], now: Date): PricingRow[] {
  return models.map((model) => {
    const history = prices
      .filter((price) => price.model_name === model.model_name)
      .sort((left, right) => right.version - left.version || timestamp(right.effective_at) - timestamp(left.effective_at))
    const current = currentPrice(history, now)
    return {
      key: model.model_name,
      modelName: model.model_name,
      modelLabel: model.model_label || model.model_name,
      providerName: model.provider_name || '-',
      modelStatus: model.status,
      configured: history.length > 0,
      current,
      history,
    }
  })
}

const toMicros = (value: number, field: string) => {
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${field}必须是非负数`)
  }
  return Math.round(value * MICROS_PER_YUAN)
}

const optionalMicros = (value: number | null, field: string) => (
  value === null ? undefined : toMicros(value, field)
)

export function directPricePayload(
  tenantID: string,
  modelName: string,
  draft: DirectDraft,
): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    tenant_id: tenantID,
    model_name: modelName,
    currency: draft.currency ?? useCurrencyStore.getState().tenantCurrency,
    status: 'active',
    input_per_million_micros: toMicros(draft.inputPerMillionYuan, '输入单价'),
    output_per_million_micros: toMicros(draft.outputPerMillionYuan, '输出单价'),
  }
  if (draft.pricingExtras) payload.pricing_extras = draft.pricingExtras
  const cachedInput = optionalMicros(draft.cachedInputPerMillionYuan, '缓存读取单价')
  const cacheWrite = optionalMicros(draft.cacheWritePerMillionYuan, '缓存写入单价')
  if (cachedInput !== undefined) payload.cached_input_per_million_micros = cachedInput
  if (cacheWrite !== undefined) payload.cache_write_per_million_micros = cacheWrite
  return payload
}

export function ratioPricePayload(
  tenantID: string,
  modelName: string,
  draft: RatioDraft,
): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    tenant_id: tenantID,
    model_name: modelName,
    currency: draft.currency ?? useCurrencyStore.getState().tenantCurrency,
    status: 'active',
    base_input_per_million_micros: toMicros(draft.baseInputPerMillionYuan, '基础输入单价'),
    model_ratio_ppm: toMicros(draft.modelRatio, '模型倍率'),
    completion_ratio_ppm: toMicros(draft.completionRatio, '输出倍率'),
  }
  if (draft.pricingExtras) payload.pricing_extras = draft.pricingExtras
  const cachedInput = optionalMicros(draft.cachedInputRatio, '缓存读取倍率')
  const cacheWrite = optionalMicros(draft.cacheWriteRatio, '缓存写入倍率')
  if (cachedInput !== undefined) payload.cached_input_ratio_ppm = cachedInput
  if (cacheWrite !== undefined) payload.cache_write_ratio_ppm = cacheWrite
  return payload
}

// 跳过原因统一显示中文：后端已给中文就原样展示，英文旧文案做映射，其余给兜底说明，避免露出英文。
const SKIP_REASON_MAP: Record<string, string> = {
  'missing model ratio': '缺少模型倍率',
  'missing per-call price': '缺少按次价格',
  'model not found in source': '官方价目表无此模型，请手工定价',
  'per-call pricing is not supported': '按次计费暂不支持',
  'dynamic billing expression requires manual configuration': '动态计费表达式需人工配置，已跳过以避免误价',
}
export function skipReasonText(reason?: string): string {
  if (!reason) return ''
  if (/[\u4e00-\u9fa5]/.test(reason)) return reason
  return SKIP_REASON_MAP[reason.trim().toLowerCase()] ?? '暂不支持自动导入，请手工定价'
}

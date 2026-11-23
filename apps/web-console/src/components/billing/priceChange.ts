import { formatMicrosDecimal, UNKNOWN_MONEY } from '../../utils/money'
import type { BillingPrice, PricingMode } from './modelPricing'

// 价格变更集：纯函数，不依赖 React。用于写入前向用户展示「旧值 → 新值」，
// 并判断是否把非零价格改成了 0（相当于免费）。金额单位均为 micros（百万分之一货币单位），
// 倍率均为 ppm（百万分之一）。

export type PriceChangeKind = 'to_zero' | 'new' | 'adjust' | 'extras_only' | 'unchanged'

export interface PriceSnapshot {
  mode: PricingMode
  currency: string
  // 直接单价；倍率模式下为 null
  input: number | null
  output: number | null
  // 缓存读/写：null 表示「未设置」，0 表示「设置为 0」
  cacheRead: number | null
  cacheWrite: number | null
  // 倍率模式；直接单价模式下为 null
  baseInput: number | null
  modelRatioPpm: number | null
  completionRatioPpm: number | null
  cachedRatioPpm: number | null
  cacheWriteRatioPpm: number | null
  // 失效时间（毫秒时间戳）；null = 无失效时间。后端把它也算进「条款是否相同」
  expiresAt: number | null
  // 规范化后的 pricing_extras（键排序、忽略 undefined）
  extras: string
}

export type PriceField = Exclude<keyof PriceSnapshot, never>

export interface PriceChange {
  modelName: string
  modelLabel: string
  old: PriceSnapshot | null
  next: PriceSnapshot
  changedFields: PriceField[]
  changed: boolean
  extrasChanged: boolean
  toZero: boolean
  kind: PriceChangeKind
}

const SNAPSHOT_FIELDS: PriceField[] = [
  'mode', 'currency', 'input', 'output', 'cacheRead', 'cacheWrite',
  'baseInput', 'modelRatioPpm', 'completionRatioPpm', 'cachedRatioPpm', 'cacheWriteRatioPpm', 'expiresAt', 'extras',
]

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(item => (item === undefined ? null : canonical(item)))
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    Object.keys(value as Record<string, unknown>).sort().forEach(key => {
      const item = (value as Record<string, unknown>)[key]
      if (item !== undefined) out[key] = canonical(item)
    })
    return out
  }
  return value
}

// 键排序后的规范化 JSON；undefined / 缺失的附加收费等价于空对象。
export function canonicalExtras(extras: unknown): string {
  return JSON.stringify(canonical(extras ?? {}))
}

const num = (value: unknown): number | null => (
  typeof value === 'number' && Number.isFinite(value) ? value : null
)

// 失效时间：字符串按时间解析，数字当作毫秒时间戳，空值和无法解析的都视为「无失效时间」。
function timestampOrNull(value: unknown): number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Date.parse(value)
    return Number.isFinite(parsed) ? parsed : null
  }
  return null
}

const two = (value: number) => String(value).padStart(2, '0')

// 本地时间 YYYY-MM-DD HH:mm；null 显示「无」。
export function formatExpiry(value: number | null): string {
  if (value === null) return '无'
  const date = new Date(value)
  return `${date.getFullYear()}-${two(date.getMonth() + 1)}-${two(date.getDate())} ${two(date.getHours())}:${two(date.getMinutes())}`
}

export function snapshotFromPrice(price: BillingPrice): PriceSnapshot {
  const ratio = price.pricing_mode === 'newapi_ratio'
  return {
    mode: ratio ? 'newapi_ratio' : 'direct',
    currency: price.currency || 'CNY',
    input: ratio ? null : price.input_per_million_micros ?? 0,
    output: ratio ? null : price.output_per_million_micros ?? 0,
    cacheRead: !ratio && price.has_cached_input_price ? price.cached_input_per_million_micros ?? 0 : null,
    cacheWrite: !ratio && price.has_cache_write_price ? price.cache_write_per_million_micros ?? 0 : null,
    baseInput: ratio ? price.base_input_per_million_micros ?? null : null,
    modelRatioPpm: ratio ? price.model_ratio_ppm ?? null : null,
    completionRatioPpm: ratio ? price.completion_ratio_ppm ?? null : null,
    cachedRatioPpm: ratio && price.has_cached_input_ratio ? price.cached_input_ratio_ppm ?? 0 : null,
    cacheWriteRatioPpm: ratio && price.has_cache_write_ratio ? price.cache_write_ratio_ppm ?? 0 : null,
    expiresAt: timestampOrNull(price.expires_at),
    extras: canonicalExtras(price.pricing_extras),
  }
}

// payload 来自 directPricePayload / ratioPricePayload；没带的缓存字段 = 未设置。
export function snapshotFromPayload(payload: Record<string, unknown>): PriceSnapshot {
  const ratio = 'base_input_per_million_micros' in payload || 'model_ratio_ppm' in payload
  return {
    mode: ratio ? 'newapi_ratio' : 'direct',
    currency: typeof payload.currency === 'string' && payload.currency ? payload.currency : 'CNY',
    input: ratio ? null : num(payload.input_per_million_micros),
    output: ratio ? null : num(payload.output_per_million_micros),
    cacheRead: ratio ? null : num(payload.cached_input_per_million_micros),
    cacheWrite: ratio ? null : num(payload.cache_write_per_million_micros),
    baseInput: ratio ? num(payload.base_input_per_million_micros) : null,
    modelRatioPpm: ratio ? num(payload.model_ratio_ppm) : null,
    completionRatioPpm: ratio ? num(payload.completion_ratio_ppm) : null,
    cachedRatioPpm: ratio ? num(payload.cached_input_ratio_ppm) : null,
    cacheWriteRatioPpm: ratio ? num(payload.cache_write_ratio_ppm) : null,
    expiresAt: timestampOrNull(payload.expires_at),
    extras: canonicalExtras(payload.pricing_extras),
  }
}

// 「输入、输出都为 0」：直接单价看输入与输出；倍率模式当且仅当 基础价=0 或 模型倍率=0。
// 倍率行的直接价字段在列表接口里恒为 0，不能拿来判断。
export function isZeroPrice(snapshot: PriceSnapshot): boolean {
  if (snapshot.mode === 'newapi_ratio') return snapshot.baseInput === 0 || snapshot.modelRatioPpm === 0
  return snapshot.input === 0 && snapshot.output === 0
}

export function buildPriceChange(
  modelName: string,
  modelLabel: string,
  current: BillingPrice | null,
  payload: Record<string, unknown>,
): PriceChange {
  const old = current ? snapshotFromPrice(current) : null
  const next = snapshotFromPayload(payload)
  const changedFields = old ? SNAPSHOT_FIELDS.filter(field => old[field] !== next[field]) : [...SNAPSHOT_FIELDS]
  const changed = old === null || changedFields.length > 0
  const extrasChanged = changedFields.includes('extras')
  // 与后端一致：只有「旧价格存在且非零 → 新价格输入输出都为 0」才算改成 0；
  // 首次定价为 0、或旧价格本来就是 0，都不需要确认，也不带 confirm_zero_price。
  const toZero = old !== null && !isZeroPrice(old) && isZeroPrice(next)
  let kind: PriceChangeKind
  if (!changed) kind = 'unchanged'
  else if (toZero) kind = 'to_zero'
  else if (old === null) kind = 'new'
  else if (changedFields.every(field => field === 'extras')) kind = 'extras_only'
  else kind = 'adjust'
  return { modelName, modelLabel, old, next, changedFields, changed, extrasChanged, toZero, kind }
}

// 实际会写入的模型数（不含「无变化」）。
export const writeCount = (changes: PriceChange[]) => changes.filter(change => change.changed).length
export const zeroPriceChanges = (changes: PriceChange[]) => changes.filter(change => change.toZero)

export const currencySymbol = (currency: string) => (currency === 'USD' ? '$' : '¥')
export const currencyName = (currency: string) => (currency === 'USD' ? '美元' : '人民币')

export function formatPriceMicros(value: number | null, currency: string): string {
  if (value === null) return '未设置'
  return `${currencySymbol(currency)}${formatMicrosDecimal(value) ?? UNKNOWN_MONEY}`
}

export function formatRatioPpm(value: number | null): string {
  if (value === null) return '未设置'
  return formatMicrosDecimal(value) ?? UNKNOWN_MONEY
}

export const priceKindLabel: Record<PriceChangeKind, string> = {
  to_zero: '改成 0',
  new: '新增价格',
  adjust: '调整',
  extras_only: '仅附加收费变更',
  unchanged: '无变化',
}

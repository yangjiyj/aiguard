import type { ModelQualityItem } from '../services/modelOperations'

// 真实流量质量的分级阈值：只用于界面着色，不参与任何告警或路由决策。
export type QualityLevel = 'good' | 'warn' | 'bad' | 'unknown'
export const qualityThresholds = {
  firstEventMs: { good: 1500, warn: 4000 },
  tokensPerSec: { good: 30, warn: 12 },
  successRate: { good: 0.99, warn: 0.95 },
  gatewayMs: { good: 150, warn: 500 },
}

export const firstEventLevel = (ms?: number | null): QualityLevel => ms == null ? 'unknown' : ms <= qualityThresholds.firstEventMs.good ? 'good' : ms <= qualityThresholds.firstEventMs.warn ? 'warn' : 'bad'
export const speedLevel = (tps?: number | null): QualityLevel => tps == null ? 'unknown' : tps >= qualityThresholds.tokensPerSec.good ? 'good' : tps >= qualityThresholds.tokensPerSec.warn ? 'warn' : 'bad'
export const successLevel = (rate?: number | null): QualityLevel => rate == null ? 'unknown' : rate >= qualityThresholds.successRate.good ? 'good' : rate >= qualityThresholds.successRate.warn ? 'warn' : 'bad'
export const gatewayLevel = (ms?: number | null): QualityLevel => ms == null ? 'unknown' : ms <= qualityThresholds.gatewayMs.good ? 'good' : ms <= qualityThresholds.gatewayMs.warn ? 'warn' : 'bad'

export const levelColor: Record<QualityLevel, string> = { good: 'var(--status-ok)', warn: 'var(--status-warn)', bad: 'var(--status-danger)', unknown: 'var(--text-tertiary)' }

// 卡片只对可用率下结论：推理模型首字普遍 5–8 秒，用绝对阈值给首字和速度判好坏会让所有模型都「较差」。
export const MIN_QUALITY_SAMPLES = 5
const sampleCount = (item: ModelQualityItem) => item.samples ?? item.total ?? 0
const successOf = (item: ModelQualityItem) => item.success_rate ?? item.availability
export const isThin = (item: ModelQualityItem) => sampleCount(item) < MIN_QUALITY_SAMPLES
export function availabilityFlag(item: ModelQualityItem): string | null {
  const rate = successOf(item)
  const upstream = item.upstream_samples ?? sampleCount(item)
  if (rate == null || upstream < MIN_QUALITY_SAMPLES || rate >= qualityThresholds.successRate.warn) return null
  return `可用率 ${(rate * 100).toFixed(1)}%`
}

// 首字越小越靠前，速度越大越靠前；只在样本充足且有值的模型之间比。
export function rankAmong(items: ModelQualityItem[], item: ModelQualityItem, metric: 'first' | 'speed'): { rank: number; of: number } | null {
  const pick = (x: ModelQualityItem) => metric === 'first' ? x.first_event_p50_ms : x.output_tokens_per_sec_p50
  const value = pick(item)
  if (value == null || isThin(item)) return null
  const pool = items.filter((x) => !isThin(x) && pick(x) != null).map((x) => pick(x) as number)
  const better = pool.filter((v) => metric === 'first' ? v < value : v > value).length
  return { rank: better + 1, of: pool.length }
}

export function splitUnrecognised(items: ModelQualityItem[]) {
  const unknown = items.filter((item) => !item.model_name && !item.model_id)
  return { known: items.filter((item) => item.model_name || item.model_id), unknown }
}

export const qualityLabel = (item: ModelQualityItem) => item.model_name || item.model_id || '未知模型'
export const qualityKey = (item: ModelQualityItem) => `${item.provider_id}:${item.model_id}`

const sampleOf = sampleCount

// 以样本数加权求中位数指标的近似总体值，用于顶部汇总卡片。
function weighted(items: ModelQualityItem[], pick: (item: ModelQualityItem) => number | null | undefined): number | null {
  let sum = 0
  let weight = 0
  for (const item of items) {
    const value = pick(item)
    const samples = sampleOf(item)
    if (value == null || !samples) continue
    sum += value * samples
    weight += samples
  }
  return weight ? sum / weight : null
}

export function qualitySummary(items: ModelQualityItem[]) {
  const samples = items.reduce((sum, item) => sum + sampleOf(item), 0)
  const upstream = items.reduce((sum, item) => sum + (item.upstream_samples ?? 0), 0)
  const upstreamOk = items.reduce((sum, item) => sum + (item.upstream_successes ?? 0), 0)
  return {
    samples,
    successRate: upstream ? upstreamOk / upstream : weighted(items, (item) => item.success_rate ?? item.availability),
    firstEventMs: weighted(items, (item) => item.first_event_p50_ms),
    tokensPerSec: weighted(items, (item) => item.output_tokens_per_sec_p50),
    gatewayMs: weighted(items, (item) => item.pre_upstream_p50_ms),
    rpm: items.reduce((sum, item) => sum + (item.rpm ?? 0), 0),
    tpm: items.reduce((sum, item) => sum + (item.tpm ?? 0), 0),
    errors: items.reduce((sum, item) => sum + (item.http_5xx ?? 0) + (item.http_429 ?? 0) + (item.http_4xx ?? 0), 0),
    attention: items.filter((item) => availabilityFlag(item)).length,
  }
}

export type QualitySort = 'samples' | 'first' | 'speed' | 'success'
export function sortQuality(items: ModelQualityItem[], sort: QualitySort): ModelQualityItem[] {
  const value = (item: ModelQualityItem) => sort === 'first' ? item.first_event_p50_ms ?? Number.POSITIVE_INFINITY
    : sort === 'speed' ? -(item.output_tokens_per_sec_p50 ?? Number.NEGATIVE_INFINITY)
      : sort === 'success' ? (item.success_rate ?? item.availability ?? Number.POSITIVE_INFINITY)
        : -sampleOf(item)
  return [...items].sort((a, b) => value(a) - value(b) || qualityLabel(a).localeCompare(qualityLabel(b)))
}

export const compactCount = (value?: number | null) => {
  if (value == null) return '未知'
  if (Math.abs(value) >= 10_000) return `${(value / 10_000).toFixed(1).replace(/\.0$/, '')} 万`
  return Number.isInteger(value) ? value.toLocaleString('zh-CN') : value.toFixed(1)
}
export const msText = (value?: number | null) => value == null ? '未知' : `${(value / 1000).toFixed(2)} s`

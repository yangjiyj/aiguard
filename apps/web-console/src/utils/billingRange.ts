import { useCurrencyStore } from '../stores/currency'
import dayjs from 'dayjs'
import { billingAnalyticsApi } from '../services/api'
import type { BillingAnalyticsParams, UsageRangeParams } from '../services/api'

/**
 * 计费分析接口（/billing/analytics/*）单次查询硬限 366 天，超过会返回
 * 400 invalid_time_range。为了支持「所有时间」这类长跨度，这里统一做切片：
 * 跨度未超限时只产生 1 片（零额外请求），超限时按 SLICE_DAYS 切片后再合并。
 */
const SLICE_DAYS = 360

export type BillingDimension = 'department' | 'provider' | 'model' | 'project' | 'user' | 'agent'

export function buildBillingSlices(range: UsageRangeParams): UsageRangeParams[] {
  const start = dayjs(range.start_date)
  const end = dayjs(range.end_date)
  if (!start.isValid() || !end.isValid() || end.diff(start, 'day') <= SLICE_DAYS) return [range]
  const slices: UsageRangeParams[] = []
  let cursor = start
  let guard = 0
  while (!cursor.isAfter(end) && guard < 64) {
    const candidate = cursor.add(SLICE_DAYS - 1, 'day')
    const sliceEnd = candidate.isAfter(end) ? end : candidate
    slices.push({ ...range, start_date: cursor.format('YYYY-MM-DD'), end_date: sliceEnd.format('YYYY-MM-DD') })
    cursor = sliceEnd.add(1, 'day')
    guard += 1
  }
  return slices.length > 0 ? slices : [range]
}

// summary 与 breakdown 共用的可加字段。currency 不是数值，单独保留。
const SUM_FIELDS = [
  'requests',
  'priced_requests',
  'unpriced_requests',
  'prompt_tokens',
  'cached_input_tokens',
  'cache_write_input_tokens',
  'output_tokens',
  'reasoning_tokens',
  'total_tokens',
  'image_count',
  'tool_call_count',
  'billable_micros',
  'upstream_cost_micros',
  'upstream_cost_known_requests',
] as const

type BillingRow = Record<string, unknown>

function assertSingleCurrency(rows: BillingRow[]) {
  const currencies = new Set(rows.map(row => row.currency).filter(Boolean))
  if (currencies.size > 1) throw new Error('不同币种的金额不能相加，请按币种分别查询')
}

function addInto(target: BillingRow, source: BillingRow) {
  for (const field of SUM_FIELDS) {
    target[field] = (Number(target[field]) || 0) + (Number(source[field]) || 0)
  }
}

export function mergeBillingSummaries(rows: BillingRow[]): BillingRow {
  assertSingleCurrency(rows)
  const merged: BillingRow = { currency: rows[0]?.currency || useCurrencyStore.getState().tenantCurrency }
  for (const field of SUM_FIELDS) merged[field] = 0
  for (const row of rows) addInto(merged, row)
  merged.other_currencies = [...new Set(rows.flatMap(row => Array.isArray(row.other_currencies) ? row.other_currencies : []))].sort()
  return merged
}

export function mergeBillingBreakdowns(rowsList: BillingRow[][]): BillingRow[] {
  assertSingleCurrency(rowsList.flat())
  const byId = new Map<string, BillingRow>()
  for (const rows of rowsList) {
    for (const row of rows) {
      const key = String(row.id ?? row.name ?? '')
      const existing = byId.get(key)
      if (!existing) {
        byId.set(key, { ...row })
        continue
      }
      addInto(existing, row)
    }
  }
  const merged = Array.from(byId.values())
  // cost_share 是派生值，合并后必须按新的总额重算，不能沿用任一单片的比例。
  const total = merged.reduce((sum, row) => sum + (Number(row.billable_micros) || 0), 0)
  return merged.map((row) => ({
    ...row,
    cost_share: total > 0 ? (Number(row.billable_micros) || 0) / total : 0,
  }))
}

export function mergeBillingSeries(rowsList: BillingRow[][]): BillingRow[] {
  assertSingleCurrency(rowsList.flat())
  const byBucket = new Map<string, BillingRow>()
  for (const rows of rowsList) {
    for (const row of rows) {
      const key = String(row.bucket ?? '')
      const existing = byBucket.get(key)
      if (!existing) {
        byBucket.set(key, { ...row })
        continue
      }
      addInto(existing, row)
    }
  }
  return Array.from(byBucket.values()).sort((a, b) => String(a.bucket).localeCompare(String(b.bucket)))
}

function billingParams(range: UsageRangeParams, extra?: BillingAnalyticsParams): BillingAnalyticsParams {
  return { currency: useCurrencyStore.getState().tenantCurrency, ...range, ...extra }
}

export async function fetchBillingSummaryMerged(range: UsageRangeParams, extra?: BillingAnalyticsParams): Promise<BillingRow> {
  const slices = buildBillingSlices(range)
  const responses = await Promise.all(slices.map((slice) => billingAnalyticsApi.summary(billingParams(slice, extra))))
  const rows = responses.map((response: { data?: BillingRow }) => response.data || {})
  return mergeBillingSummaries(rows)
}

export async function fetchBillingBreakdownMerged(dimension: BillingDimension, range: UsageRangeParams, extra?: BillingAnalyticsParams): Promise<BillingRow[]> {
  const slices = buildBillingSlices(range)
  const responses = await Promise.all(slices.map((slice) => billingAnalyticsApi.breakdown(dimension, billingParams(slice, extra))))
  const rowsList = responses.map((response: { data?: BillingRow[] }) => (Array.isArray(response.data) ? response.data : []))
  // 单维度明细建议按金额倒序，便于直接展示 Top。
  return mergeBillingBreakdowns(rowsList).sort((a, b) => (Number(b.billable_micros) || 0) - (Number(a.billable_micros) || 0))
}

export async function fetchBillingSeriesMerged(range: UsageRangeParams, extra?: BillingAnalyticsParams): Promise<BillingRow[]> {
  const slices = buildBillingSlices(range)
  const responses = await Promise.all(slices.map((slice) => billingAnalyticsApi.series(billingParams(slice, { granularity: 'day', ...extra }))))
  const rowsList = responses.map((response: { data?: BillingRow[] }) => (Array.isArray(response.data) ? response.data : []))
  return mergeBillingSeries(rowsList)
}

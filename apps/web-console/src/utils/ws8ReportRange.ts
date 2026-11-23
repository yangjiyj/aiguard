// W8 统计口径：租户时区、时间范围与报表页眉信息。
// 口径定义见 docs/design/ws8-metrics-definitions.md；改这里之前先改那份文档。
import dayjs from 'dayjs'
import type { Dayjs } from 'dayjs'
import utc from 'dayjs/plugin/utc'
import timezone from 'dayjs/plugin/timezone'
import isoWeek from 'dayjs/plugin/isoWeek'
import { useQuery } from '@tanstack/react-query'
import { statsApi } from '../services/api'
import type { StatsExecutionModeView } from '../services/api'
import { securityModeLabel } from '../services/securityExecutionMode'
import type { SecurityExecutionModeValue } from '../services/securityExecutionMode'

dayjs.extend(utc)
dayjs.extend(timezone)
dayjs.extend(isoWeek)

export const DEFAULT_REPORT_TIMEZONE = 'Asia/Shanghai'

export function normalizeTimezone(name?: string | null): string {
  const value = (name || '').trim()
  if (!value) return DEFAULT_REPORT_TIMEZONE
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: value })
    return value
  } catch {
    return DEFAULT_REPORT_TIMEZONE
  }
}

export type ReportRangeKey =
  | 'today' | '24h' | '7d' | '30d' | '90d' | '180d'
  | 'this_week' | 'last_week' | 'this_month' | 'last_month'
  | 'all' | 'custom'

export const REPORT_RANGE_LABELS: Record<ReportRangeKey, string> = {
  today: '今天',
  '24h': '近24小时',
  '7d': '近7天',
  '30d': '近30天',
  '90d': '近90天',
  '180d': '近180天',
  this_week: '本周',
  last_week: '上周',
  this_month: '本月',
  last_month: '上月',
  all: '所有时间',
  custom: '自定义',
}

// 自定义区间：起止自然日（YYYY-MM-DD），结束日包含在内。
export type CustomDateRange = [string, string]

export interface ResolvedReportRange {
  key: ReportRangeKey
  label: string
  // 左闭右开 [start, end)，均为租户时区下的时刻。
  start: Dayjs
  end: Dayjs
  // 供按自然日取数的接口（usage / billing）：end_date 为包含在内的最后一天。
  dates: { start_date: string; end_date: string }
  // 供按时刻取数的接口（stats / alerts）。
  iso: { start: string; end: string }
  window: { from: string; to: string }
  // 与安全告警页 window_hours 对齐的预设小时数；自然周/月、自定义为 undefined。
  hours?: number
}

const DAY_RANGES: Partial<Record<ReportRangeKey, number>> = { today: 1, '7d': 7, '30d': 30, '90d': 90, '180d': 180 }

export interface ResolveOptions {
  timezone?: string
  dataStart?: string
  custom?: CustomDateRange | null
  now?: Dayjs | Date | string
}

export function resolveReportRange(key: ReportRangeKey, options: ResolveOptions = {}): ResolvedReportRange {
  const tz = normalizeTimezone(options.timezone)
  const now = dayjs(options.now ?? undefined).tz(tz)
  const todayStart = now.startOf('day')
  const tomorrow = todayStart.add(1, 'day')
  let start: Dayjs
  let end: Dayjs
  let label = REPORT_RANGE_LABELS[key]
  let hours: number | undefined

  if (key === '24h') {
    end = now
    start = now.subtract(24, 'hour')
    hours = 24
  } else if (DAY_RANGES[key]) {
    const days = DAY_RANGES[key] as number
    end = tomorrow
    start = tomorrow.subtract(days, 'day')
    hours = days === 1 ? undefined : days * 24
  } else if (key === 'this_week') {
    start = todayStart.isoWeekday(1)
    end = tomorrow
  } else if (key === 'last_week') {
    end = todayStart.isoWeekday(1)
    start = end.subtract(7, 'day')
  } else if (key === 'this_month') {
    start = todayStart.startOf('month')
    end = tomorrow
  } else if (key === 'last_month') {
    end = todayStart.startOf('month')
    start = end.subtract(1, 'month')
  } else if (key === 'custom' && options.custom) {
    const [from, to] = options.custom
    start = dayjs.tz(from, tz).startOf('day')
    end = dayjs.tz(to, tz).startOf('day').add(1, 'day')
    if (!end.isAfter(start)) end = start.add(1, 'day')
    label = `${start.format('YYYY-MM-DD')} 至 ${end.subtract(1, 'day').format('YYYY-MM-DD')}`
  } else if (key === 'all') {
    // 起点取该租户最早有用量数据的自然日；没有数据时回退为今天。
    const parsed = options.dataStart ? dayjs.tz(options.dataStart.slice(0, 10), tz) : null
    start = parsed && parsed.isValid() && parsed.isBefore(tomorrow) ? parsed.startOf('day') : todayStart
    end = tomorrow
  } else {
    // custom 尚未选定起止时按近30天处理，避免发出空窗口请求。
    end = tomorrow
    start = tomorrow.subtract(30, 'day')
  }

  const lastDay = key === '24h' ? end : end.subtract(1, 'millisecond')
  return {
    key,
    label,
    start,
    end,
    dates: { start_date: start.format('YYYY-MM-DD'), end_date: lastDay.format('YYYY-MM-DD') },
    iso: { start: start.toISOString(), end: end.toISOString() },
    window: { from: start.toISOString(), to: end.toISOString() },
    hours,
  }
}

// W8 8.7：审计页起止自然日（YYYY-MM-DD，结束日包含在内），按租户时区换算成 RFC3339 左闭右开窗口；
// 列表与导出传同一组 from/to，保证「看到的」和「导出的」是同一批记录。
export type AuditDateRange = [string, string] | null

export function auditRangeParams(range: AuditDateRange, timezone?: string): { from?: string; to?: string } {
  if (!range) return {}
  return resolveReportRange('custom', { timezone, custom: range }).window
}

export function formatInTimezone(value: string | number | Date | Dayjs | null | undefined, tz?: string, format = 'YYYY-MM-DD HH:mm:ss'): string {
  if (value === null || value === undefined || value === '') return '-'
  const parsed = dayjs(value as any)
  if (!parsed.isValid()) return '-'
  return parsed.tz(normalizeTimezone(tz)).format(format)
}

export function nowInTimezone(tz?: string, format = 'YYYY-MM-DD HH:mm:ss'): string {
  return dayjs().tz(normalizeTimezone(tz)).format(format)
}

export interface ReportContext {
  timezone: string
  dataStart?: string
  executionMode?: StatsExecutionModeView
  modeLabel: string
  modeNote: string
  overview: Record<string, any>
  isLoading: boolean
}

export function executionModeLabel(mode?: StatsExecutionModeView): string {
  const effective = mode?.effective_mode as SecurityExecutionModeValue | undefined
  return securityModeLabel(effective)
}

export function executionModeNote(mode?: StatsExecutionModeView): string {
  if (mode?.effective_mode === 'record') return '当前为观察留痕：命中规则只记录与告警，不阻断，阻断数只统计真实阻断'
  if (mode?.effective_mode === 'protect') return '当前为防护阻断：命中阻断规则的请求被拦截'
  return '执行模式未取到，阻断数请结合系统设置核对'
}

export const METRICS_DEFINITION_NOTE = '窗口左闭右开，按统计时区日界切分；待处置为未处置且未抑制的告警问题'

// 首页与安全运营总览共用 ['stats','overview']：同一个请求同时提供租户时区、数据起点与执行模式。
export function useReportContext(): ReportContext {
  const query = useQuery({ queryKey: ['stats', 'overview'], queryFn: () => statsApi.getOverview(), staleTime: 60_000 })
  const overview: Record<string, any> = (query.data as any)?.data || {}
  const executionMode: StatsExecutionModeView | undefined = overview.execution_mode || undefined
  return {
    timezone: normalizeTimezone(overview.timezone),
    dataStart: overview.data_start || undefined,
    executionMode,
    modeLabel: executionModeLabel(executionMode),
    modeNote: executionModeNote(executionMode),
    overview,
    isLoading: query.isLoading,
  }
}

export function reportMetaItems(ctx: Pick<ReportContext, 'timezone' | 'modeLabel' | 'modeNote'>): { label: string; value: string }[] {
  return [
    { label: '执行模式', value: `${ctx.modeLabel}（${ctx.modeNote}）` },
    { label: '统计时区', value: ctx.timezone },
    { label: '口径定义', value: METRICS_DEFINITION_NOTE },
  ]
}

export { RECORD_MODE_PASS_LABEL } from './ws8ActionLabels'

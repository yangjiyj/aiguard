import { describe, it, expect } from 'vitest'
import { formatInTimezone, normalizeTimezone, resolveReportRange } from '../utils/ws8ReportRange'

// W8 8.5 / 8.6 / 8.9：时间范围按租户时区计算，窗口左闭右开。
describe('W8 report ranges', () => {
  const now = '2026-09-30T02:00:00Z' // Asia/Shanghai 2026-09-30 10:00（周三）

  it('near N days includes today and aligns to tenant midnight', () => {
    const r = resolveReportRange('7d', { timezone: 'Asia/Shanghai', now })
    expect(r.dates).toEqual({ start_date: '2026-09-24', end_date: '2026-09-30' })
    expect(r.iso.start).toBe('2026-09-23T16:00:00.000Z')
    expect(r.iso.end).toBe('2026-09-30T16:00:00.000Z')
    expect(r.hours).toBe(168)
  })

  it('natural week is ISO (Monday start) and last week is the full previous week', () => {
    const tw = resolveReportRange('this_week', { timezone: 'Asia/Shanghai', now })
    expect(tw.dates).toEqual({ start_date: '2026-09-28', end_date: '2026-09-30' })
    const lw = resolveReportRange('last_week', { timezone: 'Asia/Shanghai', now })
    expect(lw.dates).toEqual({ start_date: '2026-09-21', end_date: '2026-09-27' })
    expect(lw.iso.end).toBe('2026-09-27T16:00:00.000Z')
    expect(lw.hours).toBeUndefined()
  })

  it('natural month and last month', () => {
    expect(resolveReportRange('this_month', { timezone: 'Asia/Shanghai', now }).dates).toEqual({ start_date: '2026-09-01', end_date: '2026-09-30' })
    expect(resolveReportRange('last_month', { timezone: 'Asia/Shanghai', now }).dates).toEqual({ start_date: '2026-08-01', end_date: '2026-08-31' })
  })

  it('custom range includes the end day', () => {
    const r = resolveReportRange('custom', { timezone: 'Asia/Shanghai', now, custom: ['2026-09-01', '2026-09-15'] })
    expect(r.dates).toEqual({ start_date: '2026-09-01', end_date: '2026-09-15' })
    expect(r.iso.end).toBe('2026-09-15T16:00:00.000Z')
    expect(r.label).toBe('2026-09-01 至 2026-09-15')
  })

  it('all time starts at data_start, falling back to today without data', () => {
    expect(resolveReportRange('all', { timezone: 'Asia/Shanghai', now, dataStart: '2026-03-05' }).dates.start_date).toBe('2026-03-05')
    expect(resolveReportRange('all', { timezone: 'Asia/Shanghai', now }).dates.start_date).toBe('2026-09-30')
  })

  it('day boundaries follow the tenant timezone, not the browser', () => {
    // 2026-09-30T16:30Z：上海 10-01 00:30，洛杉矶 09-30 09:30
    const late = '2026-09-30T16:30:00Z'
    expect(resolveReportRange('today', { timezone: 'Asia/Shanghai', now: late }).dates.start_date).toBe('2026-10-01')
    expect(resolveReportRange('today', { timezone: 'America/Los_Angeles', now: late }).dates.start_date).toBe('2026-09-30')
    expect(resolveReportRange('today', { timezone: 'Asia/Tokyo', now: late }).dates.start_date).toBe('2026-10-01')
    expect(formatInTimezone('2026-09-01T00:30:00Z', 'Asia/Tokyo')).toBe('2026-09-01 09:30:00')
  })

  it('invalid timezone falls back to Asia/Shanghai', () => {
    expect(normalizeTimezone('Mars/Olympus')).toBe('Asia/Shanghai')
    expect(normalizeTimezone('')).toBe('Asia/Shanghai')
  })
})

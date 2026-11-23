import { describe, expect, it } from 'vitest'
import { billingTrendTheme, toBeijingDateLabel } from '../utils/billingTrendTheme'

describe('费用趋势图统一主题', () => {
  it('金额轴带 ¥ 和千分位，美元带 $，金额统一 3 位小数', () => {
    expect(billingTrendTheme('CNY').amountTick(1234567.8)).toBe('¥1,234,567.800')
    expect(billingTrendTheme('CNY').amountTooltip(1234.5)).toBe('¥1,234.500')
    expect(billingTrendTheme('USD').amountTooltip(-12.3)).toBe('-$12.300')
    expect(billingTrendTheme('CNY').amountTooltipMicros(Number.MAX_SAFE_INTEGER)).toBe('¥9,007,199,254.741')
    expect(billingTrendTheme('CNY').amountTooltipMicros(390)).toBe('¥0.000')
  })
  it('时间轴按北京时间：UTC 16:00 是北京时间次日零点', () => {
    expect(toBeijingDateLabel('2026-10-10T16:00:00Z')).toBe('2026-10-11')
    expect(toBeijingDateLabel('2026-10-10T15:59:59Z')).toBe('2026-10-10')
    expect(toBeijingDateLabel('2026-10-10T16:00:00Z', 'hour')).toBe('2026-10-11 00:00')
  })
  it('悬浮提示为中文：日期带星期，Token 带单位', () => {
    const theme = billingTrendTheme('CNY')
    expect(theme.tooltipLabel('2026-10-11')).toBe('2026年10月11日 周日')
    expect(theme.tokenTooltip(1_234_567)).toBe('123.46 万 Token')
    expect(theme.tokenTooltip(800)).toBe('800 Token')
  })
})

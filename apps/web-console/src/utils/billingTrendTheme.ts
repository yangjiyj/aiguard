import { formatDecimalAmount, formatMicrosDecimal, UNKNOWN_MONEY } from './money'
// ---- 费用趋势统一主题：金额轴 ¥ + 千分位、时间轴按北京时间、悬浮提示中文 ----
const BEIJING_OFFSET_MS = 8 * 3600 * 1000
const WEEKDAYS = ['周日', '周一', '周二', '周三', '周四', '周五', '周六']

// 后端日桶是带时区的时间点；统一换算成北京时间的日期（或小时）标签，不依赖浏览器时区。
export function toBeijingDateLabel(value: string | number | Date, granularity: 'day' | 'hour' = 'day') {
  const ms = new Date(value).getTime()
  if (Number.isNaN(ms)) return String(value)
  const iso = new Date(ms + BEIJING_OFFSET_MS).toISOString()
  return granularity === 'hour' ? `${iso.slice(0, 10)} ${iso.slice(11, 16)}` : iso.slice(0, 10)
}

export function billingTrendTheme(currency: string) {
  const symbol = currency === 'USD' ? '$' : '¥'
  const withSymbol = (amount: string) => amount.startsWith('-') ? `-${symbol}${amount.slice(1)}` : `${symbol}${amount}`
  const money = (value: number) => withSymbol(formatDecimalAmount(value, { grouped: true }) ?? UNKNOWN_MONEY)
  return {
    amountTick: (value: number) => money(value),
    amountTooltip: (value: number) => money(value),
    amountTooltipMicros: (value: unknown) => withSymbol(formatMicrosDecimal(value, { grouped: true }) ?? UNKNOWN_MONEY),
    tokenTick: (value: number) => (Math.abs(value) >= 10_000 ? `${(value / 10_000).toLocaleString('zh-CN', { maximumFractionDigits: 1 })}万` : value.toLocaleString('zh-CN')),
    tokenTooltip: (value: number) => (Math.abs(value) >= 10_000 ? `${(value / 10_000).toFixed(2)} 万 Token` : `${value.toLocaleString('zh-CN')} Token`),
    tooltipLabel: (date: string) => {
      const m = /^(\d{4})-(\d{2})-(\d{2})(?: (\d{2}:\d{2}))?$/.exec(date)
      if (!m) return date
      const weekday = WEEKDAYS[new Date(Date.UTC(+m[1], +m[2] - 1, +m[3])).getUTCDay()]
      return `${m[1]}年${Number(m[2])}月${Number(m[3])}日 ${weekday}${m[4] ? ' ' + m[4] : ''}`
    },
    axisDate: (date: string) => (/^\d{4}-\d{2}-\d{2}/.test(date) ? date.slice(5, 10).replace('-', '/') + (date.length > 10 ? date.slice(10) : '') : date),
  }
}

import { useCurrencyStore } from '../../stores/currency'
import { formatMicrosDecimal, UNKNOWN_MONEY } from '../../utils/money'

// 计费控制台共享的格式化与展示工具：从原 BillingOperations.tsx 原样迁出，行为不变。
export const MICROS_PER_YUAN = 1_000_000

export const toYuan = (value?: number) => formatMicros(value ?? 0, useCurrencyStore.getState().tenantCurrency)
export const toMicros = (value: number) => Math.round(value * MICROS_PER_YUAN)
// 金额按该行自己的币种渲染，绝不默认 ¥：币种缺失显示「未知币种」，
// 金额缺失/非有限数显示「未知」，两者都不冒充 0
export const formatMicros = (micros: unknown, currency?: string) => {
  const amount = formatMicrosDecimal(micros)
  if (amount === null) return UNKNOWN_MONEY
  const code = String(currency || '').trim().toUpperCase()
  if (!code) return `${amount}（未知币种）`
  return code === 'CNY' ? `¥${amount}` : `${code} ${amount}`
}
// 带千分位的金额（¥1,234.56 / -¥450.00）；币种规则与 formatMicros 一致，缺失不冒充 0。
export const formatMoneyMicros = (micros: unknown, currency: string = useCurrencyStore.getState().tenantCurrency) => {
  const amount = formatMicrosDecimal(micros, { grouped: true })
  if (amount === null) return UNKNOWN_MONEY
  const sign = amount.startsWith('-') ? '-' : ''
  const body = sign ? amount.slice(1) : amount
  const code = String(currency || '').trim().toUpperCase()
  if (!code) return `${sign}${body}（未知币种）`
  return code === 'CNY' ? `${sign}¥${body}` : `${sign}${code} ${body}`
}
export const ledgerMoney = (micros: unknown, currency?: string) => formatMicros(micros, currency)
// 账期是 UTC 半开区间。时间戳必须显式按 UTC 渲染：用 toLocaleString 默认会
// 转成浏览器本地时区（东八区偏 8 小时），标签写「UTC」而数字是本地时间，
// 就是把口径标注和实际显示搞成两回事。读不出来时如实显示未知，不猜。
export const formatUTCTime = (value: unknown) => {
  if (!value) return '未知'
  const parsed = new Date(String(value))
  if (Number.isNaN(parsed.getTime())) return '未知'
  const y = parsed.getUTCFullYear()
  const mo = String(parsed.getUTCMonth() + 1).padStart(2, '0')
  const d = String(parsed.getUTCDate()).padStart(2, '0')
  const h = String(parsed.getUTCHours()).padStart(2, '0')
  const mi = String(parsed.getUTCMinutes()).padStart(2, '0')
  const sec = String(parsed.getUTCSeconds()).padStart(2, '0')
  return `${y}-${mo}-${d} ${h}:${mi}:${sec}Z`
}
export const unwrap = (response: any) => response?.data?.data ?? []
export const minuteToTime = (value?: number) => {
  const minute = Number(value || 0)
  return `${String(Math.floor(minute / 60)).padStart(2, '0')}:${String(minute % 60).padStart(2, '0')}`
}
export const tariffBandLabels: Record<string, string> = { peak: '高价时段', flat: '标准时段', valley: '优惠时段', custom: '自定义时段' }
export const eventLabels: Record<string, string> = {
  credit: '充值',
  adjustment: '调账',
  redemption: '兑换充值',
  reserve: '费用预占',
  settle: '费用结算',
  release: '释放预占',
  refund: '退款',
}
export const statusLabels: Record<string, string> = {
  active: '已启用',
  disabled: '已停用',
  redeemed: '已兑换',
  reserved: '预占中',
  settled: '已结算',
  released: '已释放',
  success: '成功',
  failed: '失败',
  unpriced: '未定价',
  usage_unknown: '用量未知',
}
export const exceptionLabel = (kind?: string, status?: string) => {
  if (kind === 'stale_reservation') return '超时调用预占'
  if (kind === 'metering_unpriced') return '计量未定价'
  if (kind === 'metering_failed') return '计量调用失败'
  if (kind === 'usage_unknown') return '用量未知'
  if (kind === 'charge_record' && status === 'unpriced') return '未定价调用'
  if (kind === 'recovered_without_cache') return '对账回补丢缓存'
  if (kind === 'charge_record' && status === 'failed') return '扣费失败'
  return '其他计费异常'
}
export const exceptionExplanation = (row: any) => {
  if (row.kind === 'metering_unpriced') return {
    reason: '调用已有用量记录，但调用准入时没有匹配到该租户、该模型的有效基础价格。',
    action: '在「模型定价」检查模型名称、启用状态及生效时间。未定价调用不扣费；新增价格影响后续调用，不会自动补扣这条历史记录。',
    source: '用量计量记录',
  }
  if (row.kind === 'metering_failed') return {
    reason: '调用用量已留存，但请求结果为失败，未记录可计费金额。',
    action: '按请求 ID 查询调用留痕，检查请求结果与上游错误。',
    source: '用量计量记录',
  }
  if (row.kind === 'usage_unknown') return {
    reason: '模型 API 调用缺少完整 token 用量，需要核查调用结果及估算结算记录。',
    action: '按请求 ID 查询调用留痕，核对已下发 token、预占释放及估算结算，避免重复扣费。',
    source: '用量计量记录',
  }
  if (row.kind === 'stale_reservation') return {
    reason: '调用费用预占超过 15 分钟，仍未结算或释放。',
    action: '按请求 ID 查询调用结果，再核对预占及资金账本，避免重复扣费或释放。',
    source: '调用费用预占记录',
  }
  if (row.kind === 'recovered_without_cache') return {
    reason: '该调用已从请求日志回补结算，但缺少缓存用量明细，且输入与缓存单价不同。',
    action: '核实真实缓存读取、写入数量后，通过「补差」调整。',
    source: '调用扣费记录',
  }
  if (row.kind === 'charge_record' && row.status === 'unpriced') return {
    reason: '扣费记录标记为未定价，未完成正常结算。',
    action: '检查模型定价及请求留痕，核对实际结算状态。',
    source: '调用扣费记录',
  }
  if (row.kind === 'charge_record' && row.status === 'failed') return {
    reason: '扣费记录标记为失败，未完成正常结算。',
    action: '查询调用留痕并核对账本；本列表未提供具体失败错误。',
    source: '调用扣费记录',
  }
  return { reason: '该计费异常类型尚无具体说明，请核查原始记录。', action: '使用完整请求 ID 核查，勿根据列表推断扣费结果。', source: '未识别来源' }
}
export const exceptionRetentionLink = (row: any) => {
  if (!row.request_id) return null
  const params = new URLSearchParams({ request_id: row.request_id })
  const createdAt = Date.parse(row.created_at)
  if (Number.isFinite(createdAt)) {
    params.set('from', new Date(createdAt - 24 * 60 * 60 * 1000).toISOString())
    params.set('to', new Date(createdAt + 24 * 60 * 60 * 1000).toISOString())
  }
  return `/audit/access-retention?${params.toString()}`
}
// 时区按中文显示，不直出 Asia/Shanghai 这类技术 id；不认识的时区保留原值并标注。
export const timezoneLabels: Record<string, string> = {
  'Asia/Shanghai': '北京时间', UTC: '协调世界时', 'Asia/Hong_Kong': '香港时间', 'America/New_York': '纽约时间',
}
export const timezoneLabel = (value?: string) => !value ? '未设置时区' : timezoneLabels[value] || `其他时区（${value}）`
export const displayLabel = (labels: Record<string, string>, value?: string) => labels[value || ''] || value || '-'
export const groupTariffRules = (rules: any[]) => {
  const groups = new Map<string, any[]>()
  for (const rule of Array.isArray(rules) ? rules : []) {
    const modelName = rule.model_name || '未指定模型'
    groups.set(modelName, [...(groups.get(modelName) || []), rule])
  }
  return Array.from(groups.entries())
}

// 预算树金额：读不到返回 null，由调用方显示“读取不到/未设置”，绝不显示成 0。
export const formatMoney = (micros: number | null | undefined, currency: string = useCurrencyStore.getState().tenantCurrency) => {
  if (formatMicrosDecimal(micros) === null) return null
  return formatMicros(micros, currency)
}

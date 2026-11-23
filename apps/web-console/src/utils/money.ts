const SCALE = 1_000_000n
export const UNKNOWN_MONEY = '未知'

function integerMicros(value: unknown): bigint | null {
  if (typeof value === 'bigint') return value
  if (typeof value === 'number') return Number.isSafeInteger(value) ? BigInt(value) : null
  if (typeof value !== 'string' || !/^[+-]?\d+$/.test(value.trim())) return null
  return BigInt(value.trim())
}

// 金额展示统一保留小数点后 3 位：微秒（1e-6）级尾数四舍五入到毫（1e-3），
// 避免各页面 2/4/5 位小数混用；负数四舍五入到 0 时不显示「-0.000」。
function decimalBody(value: bigint, grouped: boolean) {
  const magnitude = value < 0n ? -value : value
  const whole = magnitude / SCALE
  const remainder = magnitude % SCALE
  let frac = remainder / 1000n + ((remainder % 1000n) >= 500n ? 1n : 0n)
  let roundedWhole = whole
  if (frac >= 1000n) { roundedWhole += 1n; frac -= 1000n }
  const nonzero = roundedWhole > 0n || frac > 0n
  const wholeText = grouped ? roundedWhole.toLocaleString('zh-CN') : roundedWhole.toString()
  return `${value < 0n && nonzero ? '-' : ''}${wholeText}.${frac.toString().padStart(3, '0')}`
}

// Split integer micros before formatting so large values never lose their last digit.
export function formatMicrosDecimal(value: unknown, { grouped = false, quantity = 1 }: { grouped?: boolean; quantity?: number } = {}): string | null {
  const micros = integerMicros(value)
  if (micros === null || !Number.isSafeInteger(quantity) || quantity < 1) return null
  return decimalBody(micros * BigInt(quantity), grouped)
}

// Legacy analytics supply amounts in currency units. Parse their decimal text
// without another floating division. Values below one micro remain visibly nonzero.
export function formatDecimalAmount(value: unknown, { grouped = false }: { grouped?: boolean } = {}): string | null {
  if (typeof value !== 'number' && typeof value !== 'string') return null
  if (typeof value === 'number' && !Number.isFinite(value)) return null
  const text = String(value).trim()
  const match = /^([+-]?)(\d+)(?:\.(\d*))?(?:e([+-]?\d+))?$/i.exec(text)
  if (!match) return null
  const fraction = match[3] || ''
  const exponent = Number(match[4] || 0)
  if (!Number.isSafeInteger(exponent) || Math.abs(exponent) > 308 || match[2].length + fraction.length > 512) return null
  const magnitude = BigInt(match[2] + fraction)
  const shift = 6 + exponent - fraction.length
  let micros: bigint
  if (shift >= 0) micros = magnitude * 10n ** BigInt(shift)
  else {
    const divisor = 10n ** BigInt(-shift)
    micros = magnitude / divisor + (magnitude % divisor * 2n >= divisor ? 1n : 0n)
  }
  if (magnitude > 0n && micros === 0n) return `${match[1] === '-' ? '-' : ''}<0.001`
  return decimalBody(match[1] === '-' ? -micros : micros, grouped)
}

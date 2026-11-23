export const MAX_SAFE_QUOTA_INTEGER = 9_007_199_254_740_991
export const MAX_BUDGET_CNY = '9007199254.740991'

export function cnyStringToMicros(value: unknown): number {
  const text = String(value ?? '').trim()
  if (!/^(?:0|[1-9]\d*)(?:\.\d{1,6})?$/.test(text)) {
    throw new Error('金额最多保留 6 位小数')
  }
  const [whole, fraction = ''] = text.split('.')
  const micros = BigInt(whole) * 1_000_000n + BigInt(fraction.padEnd(6, '0'))
  if (micros > BigInt(MAX_SAFE_QUOTA_INTEGER)) {
    throw new Error('金额超过可配置上限')
  }
  return Number(micros)
}

export function microsToCNYString(value: unknown): string {
  if (value === null || value === undefined || value === '') return ''
  const micros = BigInt(String(value))
  const whole = micros / 1_000_000n
  const fraction = (micros % 1_000_000n).toString().padStart(6, '0').replace(/0+$/, '')
  return fraction ? whole.toString() + '.' + fraction : whole.toString()
}

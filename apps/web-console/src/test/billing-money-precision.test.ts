import { describe, expect, it } from 'vitest'
import { formatDecimalAmount, formatMicrosDecimal, UNKNOWN_MONEY } from '../utils/money'
import { formatMicros, formatMoney, formatMoneyMicros, ledgerMoney, toYuan } from '../components/billing/billingFormat'
import formatSource from '../components/billing/billingFormat.ts?raw'

const unknownCurrencySuffix = /if \(!code\) return `\$\{amount\}([^`]+)`/.exec(formatSource)![1]

// 金额展示统一保留小数点后 3 位（毫级）：微秒级尾数四舍五入，不再显示 2/6 位混排。
describe('auditable monetary precision', () => {
  it.each([
    [1, '0.000'], [-1, '0.000'], [390, '0.000'], [-390, '0.000'],
    [10000, '0.010'], [1230000, '1.230'], [1000000, '1.000'], [0, '0.000'], [-0, '0.000'],
    [1234567890123, '1234567.890'], [Number.MAX_SAFE_INTEGER, '9007199254.741'],
    [-Number.MAX_SAFE_INTEGER, '-9007199254.741'], ['9223372036854775807', '9223372036854.776'],
    [1500, '0.002'], [-1500, '-0.002'], [499, '0.000'], [500, '0.001'],
  ])('renders integer micros %s at 3 decimals as %s', (value, body) => {
    expect(formatMicrosDecimal(value)).toBe(body)
    expect(formatMicros(value, 'CNY')).toBe('¥' + body)
    expect(ledgerMoney(value, 'USD')).toBe('USD ' + body)
  })

  it('groups whole units at 3 decimals without applying an exchange rate', () => {
    expect(formatMoneyMicros(Number.MAX_SAFE_INTEGER, 'CNY')).toBe('¥9,007,199,254.741')
    expect(formatMoneyMicros(-1234567890123, 'USD')).toBe('-USD 1,234,567.890')
    expect(formatMicrosDecimal(1, { quantity: 1000 })).toBe('0.001')
    expect(formatMoney(390, 'USD')).toBe('USD 0.000')
  })

  it('keeps true zero at three places and reports missing or unsafe values honestly', () => {
    expect(toYuan()).toBe('¥0.000')
    expect(formatMoney(0)).toBe('¥0.000')
    expect(formatMoney(null)).toBeNull()
    expect(formatMicros(1)).toBe('0.000' + unknownCurrencySuffix)
    for (const invalid of [null, undefined, '', '1.5', NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      expect(formatMicros(invalid, 'CNY')).toBe(UNKNOWN_MONEY)
    }
  })

  it('formats legacy decimal analytics at 3 decimals and bounds sub-milli averages', () => {
    expect(formatDecimalAmount(0.00039)).toBe('0.000')
    expect(formatDecimalAmount(-0.000001)).toBe('0.000')
    expect(formatDecimalAmount(1e-7)).toBe('<0.001')
    expect(formatDecimalAmount(-1e-7)).toBe('-<0.001')
    expect(formatDecimalAmount('9007199254.740991')).toBe('9007199254.741')
    expect(formatDecimalAmount(1234.5, { grouped: true })).toBe('1,234.500')
  })
})

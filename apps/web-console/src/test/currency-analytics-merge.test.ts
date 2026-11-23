import { expect, test } from 'vitest'
import { mergeBillingSummaries, mergeBillingBreakdowns, mergeBillingSeries } from '../utils/billingRange'
test('时间分片不允许将不同币种金额相加', () => {
 const usd = { currency: 'USD', id: 'u', bucket: '2026-10-01', billable_micros: 100 }
 const cny = { ...usd, currency: 'CNY', billable_micros: 200 }
 expect(() => mergeBillingSummaries([usd, cny])).toThrow('不同币种')
 expect(() => mergeBillingBreakdowns([[usd], [cny]])).toThrow('不同币种')
 expect(() => mergeBillingSeries([[usd], [cny]])).toThrow('不同币种')
})
test('合并分片时保留所有未计入的历史币种', () => {
 expect(mergeBillingSummaries([{ currency: 'USD', other_currencies: ['CNY'] }, { currency: 'USD', other_currencies: [] }]).other_currencies).toEqual(['CNY'])
})

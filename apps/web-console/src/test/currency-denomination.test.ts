import { beforeEach, expect, test } from 'vitest'
import { currencies, useCurrencyStore } from '../stores/currency'
beforeEach(() => useCurrencyStore.getState().setCurrency('CNY'))
test('currency selection never applies an exchange rate', () => {
 expect(currencies.map(c => c.code)).toEqual(['USD', 'CNY'])
 expect(useCurrencyStore.getState().convert(100)).toBe(100)
 // 金额展示统一保留 3 位小数（毫级），货币切换只换符号不换算
 expect(useCurrencyStore.getState().formatWithCode(100, 2)).toBe('¥100.000 CNY')
 useCurrencyStore.getState().setCurrency('USD')
 expect(useCurrencyStore.getState().convert(100)).toBe(100)
 expect(useCurrencyStore.getState().formatWithCode(100, 2)).toBe('$100.000 USD')
})

test('amounts display at 3 decimal places while currency selection leaves stored values unchanged', () => {
 const value = 1.234567
 expect(useCurrencyStore.getState().convert(value)).toBe(value)
 // 1.234567 按毫位四舍五入 → 1.235
 expect(useCurrencyStore.getState().format(value, 6)).toBe('¥1.235')
 expect(useCurrencyStore.getState().formatWithCode(value, 4)).toBe('¥1.235 CNY')
})

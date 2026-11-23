import { beforeEach, expect, test } from 'vitest'
import { useCurrencyStore } from '../stores/currency'
beforeEach(() => useCurrencyStore.setState({ manualCurrency: null, currentCurrency: 'CNY', tenantCurrency: 'CNY' }))
test('未手动选择时跟随租户币种且金额不换算', () => {
  useCurrencyStore.getState().setTenantCurrency('USD')
  expect(useCurrencyStore.getState().currentCurrency).toBe('USD')
  expect(useCurrencyStore.getState().format(100)).toBe('$100.000')
  expect(useCurrencyStore.getState().convert(100)).toBe(100)
})
test('手动选择优先，重置后重新跟随租户', () => {
  useCurrencyStore.getState().setCurrency('CNY')
  useCurrencyStore.getState().setTenantCurrency('USD')
  expect(useCurrencyStore.getState().currentCurrency).toBe('CNY')
  useCurrencyStore.getState().followTenant()
  expect(useCurrencyStore.getState().currentCurrency).toBe('USD')
})
test('旧版本默认币种不会继续冒充手动选择', () => {
  const options = useCurrencyStore.persist.getOptions()
  expect(options.version).toBe(2)
  expect(options.migrate?.({ currentCurrency: 'CNY' }, 1)).toEqual({ manualCurrency: null })
  expect(options.partialize?.(useCurrencyStore.getState())).toEqual({ manualCurrency: null })
})

test('默认金额格式化按租户币种，原始事实币种保持独立', async () => {
  const { formatMoney, formatMoneyMicros, formatMicros, toYuan } = await import('../components/billing/billingFormat')
  useCurrencyStore.getState().setTenantCurrency('USD')
  expect(formatMoney(1_000_000)).toContain('USD')
  expect(formatMoneyMicros(1_000_000)).toContain('USD')
  expect(toYuan(1_000_000)).toContain('USD')
  expect(formatMicros(1_000_000, 'CNY')).toBe('¥1.000')
})

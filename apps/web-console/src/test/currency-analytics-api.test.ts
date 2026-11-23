import { afterEach, expect, test, vi } from 'vitest'
import { apiClient, billingAnalyticsApi } from '../services/api'
import { useCurrencyStore } from '../stores/currency'

afterEach(() => vi.restoreAllMocks())
const queries = [
  () => billingAnalyticsApi.breakdown('model', { currency: 'USD' }),
  () => billingAnalyticsApi.series({ currency: 'USD' }),
  () => billingAnalyticsApi.timeProfile({ currency: 'USD' }),
  () => billingAnalyticsApi.departmentProviderMatrix({ currency: 'USD' }),
]
test.each(queries)('统计数组兼容新币种响应包装并将币种补到明细行', async query => {
  vi.spyOn(apiClient, 'get').mockResolvedValue({ data: { data: [{ id: 'm', billable_micros: 1 }], currency: 'USD', other_currencies: ['CNY'] }, status: 200 })
  const response = await query()
  expect(response.data).toEqual([{ id: 'm', billable_micros: 1, currency: 'USD', other_currencies: ['CNY'] }])
  expect(response.currency).toBe('USD')
  expect(response.other_currencies).toEqual(['CNY'])
  expect(response.status).toBe(200)
})
test('旧数组保持兼容，缺失币种使用租户币种，已有事实币种优先', async () => {
  useCurrencyStore.getState().setTenantCurrency('USD')
  vi.spyOn(apiClient, 'get').mockResolvedValue({ data: [{ id: 'old', currency: 'CNY' }, { id: 'missing' }] })
  const response = await billingAnalyticsApi.series()
  expect(response.data.map(row => row.currency)).toEqual(['CNY', 'USD'])
})

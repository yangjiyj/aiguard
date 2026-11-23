import { beforeEach, describe, expect, it } from 'vitest'
import { currencyUnitLabel, currencyUnitSuffix } from '../utils/currencyUnit'
import { formatMoneyQuota } from '../components/ai-permissions/quotaDisplay'
import { ALLOWANCE_CSV_HEADER, allowanceCsvHeader, validateAllowanceRows } from '../components/billing/allowanceCsv'
import { extractApiError } from '../utils/apiError'
import { useCurrencyStore } from '../stores/currency'

// 界面单位跟随系统币种，只换文字，不做汇率换算。
describe('币种单位文案', () => {
  it('美元显示「美元」，人民币显示「元」，未知时按人民币历史口径', () => {
    expect(currencyUnitLabel('USD')).toBe('美元')
    expect(currencyUnitLabel('usd')).toBe('美元')
    expect(currencyUnitLabel('CNY')).toBe('元')
    expect(currencyUnitLabel(undefined)).toBe('元')
    expect(currencyUnitSuffix('USD')).toBe('（美元）')
    expect(currencyUnitSuffix('CNY')).toBe('（元）')
  })
})

describe('配额只读展示跟随币种', () => {
  beforeEach(() => useCurrencyStore.setState({ tenantCurrency: 'CNY', currentCurrency: 'CNY', manualCurrency: null }))
  it('默认按系统币种；也可显式传入', () => {
    const quota = { monthly_budget_micros: 300_000_000 }
    expect(formatMoneyQuota(quota, 'monthly')).toBe('300 元')
    useCurrencyStore.getState().setTenantCurrency('USD')
    expect(formatMoneyQuota(quota, 'monthly')).toBe('300 美元')
    expect(formatMoneyQuota(quota, 'monthly', 'CNY')).toBe('300 元')
    expect(formatMoneyQuota({ monthly_budget_limit: 12 }, 'monthly', 'USD')).toBe('12 美元')
  })
})

describe('员工额度 CSV 表头跟随币种', () => {
  it('美元表头与人民币表头；旧模板（元）在人民币租户下仍可导入，美元租户必须用新表头', () => {
    expect(allowanceCsvHeader('USD')).toEqual(['员工账号', '部门', '月额度（美元）'])
    expect(allowanceCsvHeader('CNY')).toEqual(['员工账号', '部门', '月额度（元）'])
    expect(ALLOWANCE_CSV_HEADER).toEqual(['员工账号', '部门', '月额度（元）'])
    const employees = [{ user_id: 'u1', username: 'alice' }]
    const usd = validateAllowanceRows([['员工账号', '部门', '月额度（美元）'], ['alice', '', '10']], employees, 'USD')
    expect(usd.headerError).toBe('')
    expect(usd.rows[0]).toMatchObject({ ok: true, micros: 10_000_000 })
    const wrong = validateAllowanceRows([['员工账号', '部门', '月额度（元）'], ['alice', '', '10']], employees, 'USD')
    expect(wrong.headerError).toContain('月额度（美元）')
    expect(validateAllowanceRows([['员工账号', '部门', '月额度（元）'], ['alice', '', '10']], employees).headerError).toBe('')
  })
})

describe('新增 409 错误码有中文提示', () => {
  const err = (code: string, message = 'english only') => ({ response: { data: { error: { code, message } } } })
  it.each([
    ['allowance_currency_mismatch', '币种'],
    ['price_currency_mismatch', '价格'],
    ['count_changed', '重新预览'],
    ['currency_switch_in_flight', '预占'],
    ['currency_switch_conflict', '钱包'],
    ['currency_switch_unpriced_confirm_required', '未定价'],
    ['currency_switch_busy', '停流量'],
    ['cost_currency_mismatch', '采购成本'],
  ])('%s', (code, keyword) => {
    const text = extractApiError(err(code))
    expect(text).toBeTruthy()
    expect(text).toContain(keyword)
    expect(text).not.toMatch(/汇率换算[^，。；]*可以/)
  })
})

import { microsToCNYString } from './quotaValues'
import { useCurrencyStore } from '../../stores/currency'
import { currencyUnitLabel } from '../../utils/currencyUnit'

// 配额只读展示：用户详情、部门“模型权限”页共用，统一在“钱包与限流”页修改。
export function formatCountQuota(limit: unknown, blocked: unknown): string | number {
  if (blocked === true) return '禁止'
  if (limit === null || limit === undefined) return '继承上级'
  return Number(limit) === 0 ? '本级不限' : Number(limit)
}

// currency 缺省时跟随系统币种；金额数字原样展示，不做换算。
export function formatMoneyQuota(quota: Record<string, any>, period: 'daily' | 'monthly', currency: string = useCurrencyStore.getState().tenantCurrency): string {
  const unit = currencyUnitLabel(currency)
  if (quota[period + '_budget_blocked'] === true) return '禁止'
  const microsKey = period + '_budget_micros'
  if (Object.prototype.hasOwnProperty.call(quota, microsKey)) {
    const micros = quota[microsKey]
    if (micros === null || micros === undefined) return '继承上级'
    if (Number(micros) === 0) return '本级不限'
    return microsToCNYString(micros) + ' ' + unit
  }
  const legacy = quota[period + '_budget_limit']
  return Number(legacy) > 0 ? String(legacy) + ' ' + unit : '本级不限'
}

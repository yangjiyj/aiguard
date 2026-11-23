import { Select } from 'antd'
import { useCurrencyStore, currencies, CurrencyCode } from '../stores/currency'

export default function CurrencySelector() {
  const { currentCurrency, manualCurrency, setCurrency, followTenant } = useCurrencyStore()

  return (
    <Select
      aria-label="查看币种"
      value={manualCurrency || 'tenant'}
      onChange={(value) => value === 'tenant' ? followTenant() : setCurrency(value as CurrencyCode)}
      style={{ width: 140 }}
      options={[{ value: 'tenant', label: `跟随系统 (${currentCurrency})` }, ...currencies.map(c => ({
        value: c.code,
        label: `${c.name} (${c.symbol})`,
      }))]}
    />
  )
}

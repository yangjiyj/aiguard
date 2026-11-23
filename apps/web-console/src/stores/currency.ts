import { formatDecimalAmount, UNKNOWN_MONEY } from '../utils/money'
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export type CurrencyCode = 'USD' | 'CNY'

export interface Currency {
  code: CurrencyCode
  symbol: string
  name: string
  rate: number // 兼容字段，金额始终不做换算。
}

export const currencies: Currency[] = [
  { code: 'USD', symbol: '$', name: '美元', rate: 1 },
  { code: 'CNY', symbol: '¥', name: '人民币', rate: 1 },
]

export const getCurrencyByCode = (code: CurrencyCode): Currency => {
  return currencies.find(c => c.code === code) || currencies[0]
}

interface CurrencyState {
  currentCurrency: CurrencyCode
  tenantCurrency: CurrencyCode
  manualCurrency: CurrencyCode | null
  setTenantCurrency: (code: string) => void
  followTenant: () => void
  setCurrency: (code: CurrencyCode) => void
  convert: (usdAmount: number) => number
  format: (usdAmount: number, decimals?: number) => string
  formatWithCode: (usdAmount: number, decimals?: number) => string
}

export const useCurrencyStore = create<CurrencyState>()(
  persist(
    (set, get) => ({
      currentCurrency: 'CNY',
      tenantCurrency: 'CNY',
      manualCurrency: null,
      setCurrency: (code) => set({ currentCurrency: code, manualCurrency: code }),
      setTenantCurrency: (code) => {
        if (code !== 'USD' && code !== 'CNY') return
        set({ tenantCurrency: code, currentCurrency: get().manualCurrency || code })
      },
      followTenant: () => set({ manualCurrency: null, currentCurrency: get().tenantCurrency }),
      convert: (usdAmount) => {
        return usdAmount
      },
      format: (usdAmount) => {
        const currency = getCurrencyByCode(get().currentCurrency)
        const converted = usdAmount
        return `${currency.symbol}${formatDecimalAmount(converted) ?? UNKNOWN_MONEY}`
      },
      formatWithCode: (usdAmount) => {
        const currency = getCurrencyByCode(get().currentCurrency)
        const converted = usdAmount
        return `${currency.symbol}${formatDecimalAmount(converted) ?? UNKNOWN_MONEY} ${currency.code}`
      },
    }),
    {
      name: 'currency-storage',
      version: 2,
      partialize: (state) => ({ manualCurrency: state.manualCurrency }),
      migrate: () => ({ manualCurrency: null }),
      merge: (stored, state) => {
        const manual = (stored as { manualCurrency?: CurrencyCode })?.manualCurrency
        return { ...state, manualCurrency: manual === 'USD' || manual === 'CNY' ? manual : null, currentCurrency: manual === 'USD' || manual === 'CNY' ? manual : state.tenantCurrency }
      },
    }
  )
)

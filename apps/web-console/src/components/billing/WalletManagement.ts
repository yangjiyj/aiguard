import type { TabsProps } from 'antd'
import { usePrepaidSection } from './sections/usePrepaidSection'
import type { BillingContext } from './useBillingContext'

export const WALLET_MANAGEMENT_LABELS = {
  accounts: '账户余额',
  groups: '客户组',
  redemptions: '兑换码',
} as const

export type WalletManagementSection = keyof typeof WALLET_MANAGEMENT_LABELS
type WalletItem = NonNullable<TabsProps['items']>[number]

// Wallet operations are available in metering and prepaid mode. The shared
// implementation retains tenant/admin scoping and frozen idempotent requests.
export function useWalletManagement(ctx: BillingContext) {
  const wallet = usePrepaidSection(ctx)
  const item = (key: string, section: WalletManagementSection): WalletItem => {
    const source = wallet.items.find(candidate => candidate.key === key)!
    return { ...source, label: WALLET_MANAGEMENT_LABELS[section] }
  }
  return {
    ...wallet,
    accountsItem: item('customers', 'accounts'),
    groupsItem: item('customer-groups', 'groups'),
    redemptionsItem: item('redemptions', 'redemptions'),
  }
}

import { useWalletManagement } from './WalletManagement'
import type { WalletManagementSection } from './WalletManagement'
import type { BillingContext } from './useBillingContext'

export function WalletManagementPanel({ ctx, section = 'accounts' }: { ctx: BillingContext; section?: WalletManagementSection }) {
  const wallet = useWalletManagement(ctx)
  const selected = { accounts: wallet.accountsItem, groups: wallet.groupsItem, redemptions: wallet.redemptionsItem }[section]
  return <>{selected.children}{wallet.modals}</>
}

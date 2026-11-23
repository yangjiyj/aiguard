import { useState } from 'react'
import { Tabs } from 'antd'
import { useQueryClient } from '@tanstack/react-query'
import { useWalletManagement } from '../components/billing/WalletManagement'
import { useStatementsSection } from '../components/billing/sections/useStatementsSection'
import { invalidateBillingQueries, useBillingContext } from '../components/billing/useBillingContext'
import BillingConsoleHeader from '../components/billing/BillingConsoleHeader'

export function BillingWalletTestHarness() {
  const ctx = useBillingContext()
  const client = useQueryClient()
  const wallet = useWalletManagement(ctx)
  const [activeTab, setActiveTab] = useState('customers')
  return <>
    <BillingConsoleHeader ctx={ctx} title="Wallet" onRefresh={() => void invalidateBillingQueries(client, ctx.tenantID)} />
    <Tabs activeKey={activeTab} onChange={setActiveTab} items={[wallet.accountsItem, wallet.groupsItem, wallet.redemptionsItem]} />
    {wallet.modals}
  </>
}

export function BillingLedgerTestHarness() {
  const ctx = useBillingContext()
  return <Tabs items={useStatementsSection(ctx).items} />
}

import { useState } from 'react'
import { Alert, Tabs } from 'antd'
import { useQueryClient } from '@tanstack/react-query'
import BillingConsoleHeader from '../../components/billing/BillingConsoleHeader'
import MonthlyStatement from '../../components/billing/MonthlyStatement'
import { useStatementsSection } from '../../components/billing/sections/useStatementsSection'
import { invalidateBillingQueries, useBillingContext } from '../../components/billing/useBillingContext'
import '../BillingOperations.css'

export default function BillingStatements() {
  const queryClient = useQueryClient()
  const ctx = useBillingContext()
  const { tenantID, billingRuntime, runtimeQuery } = ctx
  const [activeTab, setActiveTab] = useState('statement')
  const statements = useStatementsSection(ctx)
  const busy = statements.ledgerQuery.isFetching || runtimeQuery.isFetching
  return <div>
    <BillingConsoleHeader ctx={ctx} title="账单" lastUpdated={billingRuntime?.generated_at}
      onRefresh={() => void invalidateBillingQueries(queryClient, tenantID)} refreshing={busy} />
    {statements.ledgerQuery.isError ? <Alert type="error" showIcon style={{ marginBottom: 12 }} message="账本加载失败" /> : null}
    {!tenantID ? <Alert type="info" message="正在加载可管理租户…" showIcon /> : <Tabs activeKey={activeTab} onChange={setActiveTab}
      items={[{ key: 'statement', label: '月度账单', children: <MonthlyStatement tenantID={tenantID} /> }, ...statements.items]} />}
  </div>
}

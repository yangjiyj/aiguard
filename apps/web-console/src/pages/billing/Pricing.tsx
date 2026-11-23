import { useState } from 'react'
import { Alert, Tabs } from 'antd'
import { useQueryClient } from '@tanstack/react-query'
import BillingConsoleHeader from '../../components/billing/BillingConsoleHeader'
import { usePricingSection } from '../../components/billing/sections/usePricingSection'
import { invalidateBillingQueries, useBillingContext } from '../../components/billing/useBillingContext'
import '../BillingOperations.css'

export default function BillingPricing() {
  const queryClient = useQueryClient()
  const ctx = useBillingContext()
  const [activeTab, setActiveTab] = useState('prices')
  const pricing = usePricingSection(ctx)
  const order = ['prices', 'tariffs', 'upstream-costs', 'fixed-costs']
  const items = order.map((key) => pricing.items.find((item: any) => item.key === key)).filter(Boolean) as any[]
  return <div>
    <BillingConsoleHeader ctx={ctx} title="价格与成本"
      onRefresh={() => void invalidateBillingQueries(queryClient, ctx.tenantID)} refreshing={ctx.runtimeQuery.isFetching || ctx.billingModelsQuery.isFetching} />
    {!ctx.tenantID ? <Alert type="info" message="正在加载可管理租户…" showIcon /> : <Tabs activeKey={activeTab} onChange={setActiveTab} items={items} />}
    {pricing.modals}
  </div>
}

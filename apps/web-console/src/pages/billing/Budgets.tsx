import { useEffect, useState } from 'react'
import { Alert, Select, Space, Tabs } from 'antd'
import { useSearchParams } from 'react-router-dom'
import BudgetTree from '../../components/billing/BudgetTree'
import EmployeeAllowancesPanel from '../../components/billing/EmployeeAllowancesPanel'
import { useWalletManagement } from '../../components/billing/WalletManagement'
import { useBillingContext } from '../../components/billing/useBillingContext'
import { BILLING_SECTION_LABELS as labels } from '../../components/billing/sectionLabels'
import { EnterprisePageHeader } from '../../components/EnterpriseUI'
import { useAuthStore } from '../../stores/auth'
import QuotaPolicies from '../QuotaPolicies'

export default function BillingBudgets() {
  const user = useAuthStore((state: any) => state.user)
  const isPlatform = user?.role === 'platform_admin' || user?.role === 'admin'
  const canManage = isPlatform || user?.role === 'tenant_owner' || user?.role === 'tenant_admin'
  const ctx = useBillingContext()
  const tenantID = isPlatform ? ctx.tenantID : user?.tenant_id || ''
  const wallet = useWalletManagement({ ...ctx, tenantID })
  const [searchParams] = useSearchParams()
  const deepLinked = !!searchParams.get('scope_type')
  const [activeTab, setActiveTab] = useState(deepLinked ? 'limits' : 'customers')
  useEffect(() => { if (deepLinked) setActiveTab('limits') }, [deepLinked])
  const tenantReady = (content: React.ReactNode) => tenantID ? content : <Alert type="info" message="正在加载可管理租户…" showIcon />
  const items = [
    ...(canManage ? [
      wallet.accountsItem,
      { key: 'monthly', label: labels.monthly, children: tenantReady(<EmployeeAllowancesPanel tenantID={tenantID} />) },
      wallet.redemptionsItem,
      wallet.groupsItem,
    ] : []),
    { key: 'limits', label: labels.limits, children: <Space direction="vertical" size={16} style={{ width: '100%' }}>
      {tenantID === user?.tenant_id ? <QuotaPolicies embedded /> : <Alert type="info" message="跨租户预算仅查看，请由对应租户管理员配置限流与预算。" showIcon />}
      {canManage ? tenantReady(<BudgetTree tenantID={tenantID} canEditEmployees={false} />) : null}
    </Space> },
  ]
  return <div className="enterprise-page">
    <EnterprisePageHeader title={labels.wallet} />
    {isPlatform && ctx.tenants.length > 1 ? <Select aria-label="选择租户" value={ctx.tenantID} style={{ width: 220, marginBottom: 16 }} options={ctx.tenants.map((tenant: any) => ({ value: tenant.id, label: tenant.name }))} onChange={ctx.setTenantID} /> : null}
    <Tabs activeKey={canManage ? activeTab : 'limits'} onChange={setActiveTab} items={items} />
    {wallet.modals}
  </div>
}

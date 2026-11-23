import type { ReactNode } from 'react'
import { Button, Select, Tooltip, Typography } from 'antd'
import dayjs from 'dayjs'
import './BillingConsoleHeader.css'
import { ReloadOutlined } from '@ant-design/icons'
import type { BillingContext } from './useBillingContext'

export default function BillingConsoleHeader({ ctx, title, lastUpdated, refreshing, onRefresh, extra }: {
  ctx: BillingContext
  title: string
  subtitle?: string
  lastUpdated?: string
  refreshing?: boolean
  onRefresh: () => void
  extra?: ReactNode
}) {
  const { tenantID, setTenantID, tenants, tenantsQuery } = ctx
  const updatedAt = lastUpdated && dayjs(lastUpdated).isValid() ? dayjs(lastUpdated) : null
  return <header className="page-header billing-console-header">
    <div className="billing-console-header-main">
      <Typography.Title level={4} style={{ margin: 0 }}>{title}</Typography.Title>
      {updatedAt ? <Tooltip title={updatedAt.format('YYYY-MM-DD HH:mm:ss')}>
        <Typography.Text className="billing-console-header-updated" type="secondary">更新时间：{updatedAt.format('MM-DD HH:mm')}</Typography.Text>
      </Tooltip> : null}
    </div>
    <div className="billing-console-header-actions">
      {extra}
      <Select className="billing-console-header-tenant" aria-label="选择租户" value={tenantID || undefined} placeholder="选择租户"
        options={tenants.map((item: any) => ({ value: item.id, label: item.name }))} onChange={setTenantID} loading={tenantsQuery.isLoading} />
      <Button icon={<ReloadOutlined />} onClick={onRefresh} loading={refreshing}>刷新</Button>
    </div>
  </header>
}

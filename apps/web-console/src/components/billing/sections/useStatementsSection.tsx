import { Card, Space, Table, Tag, Typography } from 'antd'
import { CURSOR_PAGE_SIZE, useCursorPager } from '../../../hooks/useCursorPager'
import { billingAdminApi } from '../../../services/api'
import type { BillingContext } from '../useBillingContext'
import { displayLabel, eventLabels, formatUTCTime, ledgerMoney } from '../billingFormat'
import { CursorPagerBar, Identifier } from '../BillingWidgets'
import EmployeeIdentity from '../EmployeeIdentity'

const { Text } = Typography
const monthlyWalletEventLabels: Record<string, string> = { grant: '本月充值', expire: '到期回收' }

export function useStatementsSection(ctx: BillingContext) {
  const { tenantID } = ctx
  const ledgerPager = useCursorPager({
    scopeKey: tenantID,
    queryKey: ['billing-ledger', tenantID],
    fetchPage: (cursor?: string) => billingAdminApi.ledger(tenantID, cursor, undefined, CURSOR_PAGE_SIZE),
    enabled: !!tenantID,
  })
  const ledgerQuery = ledgerPager.query
  const ledger = ledgerPager.rows
  const ledgerColumns = [
    // 账本是资金证据，时间戳统一按 UTC 显式渲染：本地时区会让不同时区的
    // 管理员看到不同的入账时刻，事后对账无法对齐
    { title: '时间（UTC）', dataIndex: 'created_at', width: 190, render: (value: string) => value ? formatUTCTime(value) : '-' },
    { title: '员工', dataIndex: 'username', width: 180, render: (_value: string, row: any) => <EmployeeIdentity employee={row} /> },
    { title: '部门', dataIndex: 'department_name', width: 130, ellipsis: true, render: (value?: string) => value || '—' },
    { title: '币种', dataIndex: 'currency', width: 70, render: (value?: string) => value || '—' },
    { title: '事件', dataIndex: 'event_type', width: 150, render: (value: string, row: any) => <Space size={4}><Tag color={value === 'credit' ? 'green' : value === 'adjustment' ? 'orange' : 'blue'}>{monthlyWalletEventLabels[row?.metadata?.monthly_wallet_event] || displayLabel(eventLabels, value)}</Tag>{row?.metadata?.estimated === true ? <Tag color="gold">估算计费</Tag> : null}{row?.metadata?.overdraft === true ? <Tag color="red">透支</Tag> : null}</Space> },
    // 金额按该行钱包币种如实展示；币种缺失时显示「未知币种」而不是默认 ¥
    { title: '余额变动', dataIndex: 'balance_delta_micros', width: 120, align: 'right' as const, render: (value: number, row: any) => <Text type={value < 0 ? 'danger' : undefined}>{value > 0 ? '+' : ''}{ledgerMoney(value, row.currency)}</Text> },
    { title: '预占变动', dataIndex: 'reserved_delta_micros', width: 120, align: 'right' as const, render: (value: number, row: any) => `${value > 0 ? '+' : ''}${ledgerMoney(value, row.currency)}` },
    { title: '变动后账户余额', dataIndex: 'balance_after_micros', width: 160, align: 'right' as const, render: (value: number, row: any) => ledgerMoney(value, row.currency) },
    { title: '请求 ID', dataIndex: 'request_id', width: 170, ellipsis: true, render: (value: string) => value ? <Identifier value={value} /> : '-' },
  ]
  const items = [{ key: 'ledger', label: '计费账本', children: <Card>
    <Table className="billing-operations-table" tableLayout="fixed" scroll={{ x: 1290 }} rowKey="id" columns={ledgerColumns} dataSource={ledger}
      loading={ledgerQuery.isLoading} pagination={false} locale={{ emptyText: '暂无记账流水' }} />
    <CursorPagerBar pager={ledgerPager} unit="条流水" />
  </Card> }]
  return { items, modals: null, ledgerQuery }
}

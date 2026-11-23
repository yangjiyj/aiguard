import { useCurrencyStore } from '../../stores/currency'
import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, Form, Modal, Space, Switch, Table, Tag, Tooltip, Typography, message } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { billingEmployeeApi, policyApi } from '../../services/api'
import { useAuthStore } from '../../stores/auth'
import { extractApiError } from '../../utils/apiError'
import { quotaPayloadWithBudget } from './budgetQuota'
import TwoDecimalInput from './TwoDecimalInput'
import { formatMoney } from './billingFormat'
import { ZhExpandIcon } from './BillingWidgets'

const { Text } = Typography
const FOREIGN_BUDGET_NOTICE = '其他租户预算仅查看，请由该租户管理员配置'

export type BudgetTreeNode = {
  kind: 'organization' | 'department' | 'unassigned' | 'employee'
  id: string
  name: string
  budget_micros: number | null
  used_micros: number | null
  reserved_micros?: number
  remaining_micros: number | null
  status: 'unlimited' | 'normal' | 'warning' | 'exhausted' | 'unknown'
  inherited?: boolean
  currency: string
  personal_budget_micros?: number | null
  personal_used_micros?: number | null
  personal_status?: string
  children?: BudgetTreeNode[]
}

const STATUS: Record<string, { text: string; color: string }> = {
  unlimited: { text: '未设置', color: 'default' },
  normal: { text: '正常', color: 'green' },
  warning: { text: '80% 预警', color: 'orange' },
  exhausted: { text: '预算用尽', color: 'red' },
  unknown: { text: '用量待确认', color: 'gold' },
}
const KIND_LABEL: Record<string, string> = { organization: '组织', department: '部门', unassigned: '未分配部门', employee: '员工' }


const visibleBudgetNode = (node?: BudgetTreeNode): BudgetTreeNode | undefined => {
  if (!node || (node.kind !== 'organization' && node.kind !== 'department')) return undefined
  const children = (node.children || []).map(visibleBudgetNode).filter((child): child is BudgetTreeNode => !!child)
  return { ...node, children: children.length ? children : undefined }
}

export default function BudgetTree({ tenantID }: { tenantID: string; canEditEmployees?: boolean }) {
  const queryClient = useQueryClient()
  const authenticatedTenantID = useAuthStore((state) => state.user?.tenant_id || '')
  const canEdit = !!tenantID && tenantID === authenticatedTenantID
  const [editing, setEditing] = useState<BudgetTreeNode | null>(null)
  const [amount, setAmount] = useState<number | null>(null)
  const [clear, setClear] = useState(false)
  const [error, setError] = useState('')
  const treeQuery = useQuery({ queryKey: ['billing-budget-tree', tenantID], queryFn: () => billingEmployeeApi.budgetTree(tenantID), enabled: !!tenantID, refetchInterval: 5000 })
  const rawRoot: BudgetTreeNode | undefined = treeQuery.data?.data?.data
  const root = useMemo(() => visibleBudgetNode(rawRoot), [rawRoot])
  const refresh = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['billing-budget-tree', tenantID] }),
      queryClient.invalidateQueries({ queryKey: ['quota-policy'] }),
    ])
  }
  const save = useMutation({
    mutationFn: async ({ node, micros, targetTenantID }: { node: BudgetTreeNode; micros: number | null; targetTenantID: string }) => {
      if (targetTenantID !== tenantID || targetTenantID !== useAuthStore.getState().user?.tenant_id) throw new Error(FOREIGN_BUDGET_NOTICE)
      const scopeType = node.kind === 'organization' ? 'tenant' : 'team'
      const scopeId = node.kind === 'organization' ? '' : node.id
      // 先读原策略，回写时只替换月预算，限流、执行模式、时区保持不变。
      const loaded = await policyApi.getQuota({ scope_type: scopeType, scope_id: scopeId })
      const body = loaded?.data?.data ?? loaded?.data ?? {}
      if (targetTenantID !== useAuthStore.getState().user?.tenant_id) throw new Error(FOREIGN_BUDGET_NOTICE)
      return policyApi.setQuota(quotaPayloadWithBudget(body, scopeType, scopeId, { monthlyMicros: micros }) as any)
    },
    onSuccess: async () => { message.success('已保存，新请求按新额度判定'); setEditing(null); await refresh() },
    onError: (e: any) => setError(extractApiError(e) || '保存失败，请稍后重试'),
  })
  useEffect(() => { setEditing(null); setError('') }, [tenantID, authenticatedTenantID])
  const open = (node: BudgetTreeNode) => {
    if (!canEdit) return
    setEditing(node)
    setError('')
    setClear(node.budget_micros === null)
    setAmount(node.budget_micros === null ? null : Number(node.budget_micros) / 1_000_000)
  }
  const submit = () => {
    if (!editing || !canEdit) return
    if (!clear && (amount === null || !Number.isFinite(amount) || amount < 0)) { setError('请输入有效金额；0 表示停止调用'); return }
    save.mutate({ node: editing, targetTenantID: tenantID, micros: clear ? null : Math.round(Number(amount) * 1_000_000) })
  }
  const rowKey = (node: BudgetTreeNode) => node.kind + ':' + node.id
  // 数据异步到达，defaultExpandAllRows 只在首次挂载生效；这里在数据到达后默认展开组织和部门两层。
  const [expanded, setExpanded] = useState<React.Key[]>([])
  useEffect(() => {
    const keys: string[] = []
    const walk = (n?: BudgetTreeNode) => { if (!n || n.kind === 'employee') return; if (n.children?.length) keys.push(rowKey(n)); n.children?.forEach(walk) }
    walk(root)
    setExpanded(keys)
  }, [root])
  const columns = [
    { title: '组织 / 部门', dataIndex: 'name', render: (value: string, node: BudgetTreeNode) => <Space size={6}><Text strong>{value || '未命名'}</Text><Tag bordered={false}>{KIND_LABEL[node.kind]}</Tag></Space> },
    { title: '月预算', dataIndex: 'budget_micros', width: 170, render: (_: unknown, node: BudgetTreeNode) => formatMoney(node.budget_micros, node.currency) ?? <Text type="secondary">未设置</Text> },
    { title: '本月已用', dataIndex: 'used_micros', width: 140, render: (_: unknown, node: BudgetTreeNode) => (formatMoney(node.used_micros, node.currency) ?? (node.budget_micros === null ? <Text type="secondary">—</Text> : <Tooltip title="预算用量暂时读取不到，不会当作 0 处理"><Text type="warning">读取不到</Text></Tooltip>)) },
    { title: '剩余', dataIndex: 'remaining_micros', width: 140, render: (_: unknown, node: BudgetTreeNode) => formatMoney(node.remaining_micros, node.currency) ?? <Text type="secondary">—</Text> },
    { title: '状态', dataIndex: 'status', width: 120, render: (_: unknown, node: BudgetTreeNode) => {
      const status = STATUS[node.status] || STATUS.unknown
      return <Tag color={status.color}>{status.text}</Tag>
    } },
    ...(canEdit ? [{ title: '操作', key: 'action', width: 110, render: (_: unknown, node: BudgetTreeNode) => <Button type="link" size="small" onClick={() => open(node)}>编辑预算</Button> }] : []),
  ]

  return <Space direction="vertical" size={12} style={{ width: '100%' }}>
    {!canEdit && tenantID ? <Text type="secondary">{FOREIGN_BUDGET_NOTICE}</Text> : null}
    {treeQuery.isError ? <Alert type="error" showIcon message="预算树读取失败" action={<Button onClick={() => void treeQuery.refetch()}>重试</Button>} /> : null}
    <section aria-label="预算树"><Table rowKey={rowKey} columns={columns as any} dataSource={root ? [root] : []} loading={treeQuery.isLoading}
      pagination={false} size="middle" expandable={{ expandedRowKeys: expanded, onExpandedRowsChange: (keys) => setExpanded([...keys]), expandIcon: ZhExpandIcon }} locale={{ emptyText: '暂无组织或部门' }} scroll={{ x: 900 }} /></section>
    {editing ? <Modal open title={`设置月预算：${editing.name}`} okText="保存" cancelText="取消"
      onCancel={() => setEditing(null)} onOk={submit} confirmLoading={save.isPending}>
      <Form layout="vertical">
        <Form.Item label="不设置预算"><Switch aria-label="不设置预算" checked={clear} onChange={setClear} /></Form.Item>
        <Form.Item label="每月金额"><TwoDecimalInput aria-label="每月金额" prefix={editing.currency || root?.currency || useCurrencyStore.getState().tenantCurrency} min={0} max={1000000000} value={amount} onChange={setAmount} disabled={clear} style={{ width: '100%' }} /></Form.Item>
        {error ? <Alert type="error" showIcon message={error} /> : null}
      </Form>
    </Modal> : null}
  </Space>
}

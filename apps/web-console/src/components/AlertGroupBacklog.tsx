import { CORE_SEVERITY_LABELS, SEVERITY_LABELS } from '../utils/risk'
import { useState } from 'react'
import { Alert, Button, Card, Input, Modal, Segmented, Select, Space, Table, Tag, Typography, message } from 'antd'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { alertGroupApi } from '../services/api'
import type { AlertGroupBatchResult, AlertGroupBatchStatus, AlertGroupItem } from '../services/api'
import { AuditDateRangeFilter } from './AuditExportControls'
import type { AuditDateRange } from './AuditExportControls'
import { auditRangeParams, formatInTimezone } from '../utils/ws8ReportRange'
import { useAuthStore } from '../stores/auth'

const { Text } = Typography

// 告警组积压处置：对 alert_groups 按类型 / 规则 / 最近发生时间筛选后人工勾选，批量确认、关闭或标记误报。
// 只处置勾选出的组（服务端单次最多 500 个），不提供"按条件一键全关"。

const BATCH_MAX = 500
const PAGE_SIZE = 50

// 能处置告警的角色与后端 roles.CanHandleAlerts / SoD alert_handle 一致；其它角色只读。
const ALERT_HANDLER_ROLES = new Set(['platform_admin', 'admin', 'security_officer', 'tenant_admin', 'tenant_owner'])

const SEVERITY: Record<string, { color: string; label: string }> = {
  critical: { color: 'red', label: CORE_SEVERITY_LABELS.critical },
  high: { color: 'orange', label: CORE_SEVERITY_LABELS.high },
  medium: { color: 'gold', label: CORE_SEVERITY_LABELS.medium },
  low: { color: 'blue', label: CORE_SEVERITY_LABELS.low },
}

// alert_groups.alert_type 的中文名（与后端 alertTypeForSecurityEvent 取值一一对应）。
const ALERT_GROUP_TYPE_LABELS: Record<string, string> = {
  security_event: '安全事件',
  runtime_fault: '运行故障',
  access_governance: '访问治理',
  tool_execution_risk: '工具执行风险',
  tool_attempt_blocked: '工具尝试已阻断',
  agent_endpoint_risk: '终端智能体风险',
}

const STATUS_LABELS: Record<string, { color: string; label: string }> = {
  open: { color: 'processing', label: '待处置' },
  acknowledged: { color: 'blue', label: '已确认' },
  resolved: { color: 'default', label: '已关闭' },
  false_positive: { color: 'default', label: '误报' },
}

const BATCH_ACTIONS: { status: AlertGroupBatchStatus; label: string; danger?: boolean }[] = [
  { status: 'acknowledged', label: '确认' },
  { status: 'resolved', label: '关闭' },
  { status: 'false_positive', label: '标记误报', danger: true },
]

const FAILURE_LABELS: Record<string, string> = {
  not_open: '状态已变化（已被处置或不处于待处置）',
  not_found: '不存在或无权处置',
}

function typeLabel(t?: string) {
  return (t && ALERT_GROUP_TYPE_LABELS[t]) || '其它类型'
}

export default function AlertGroupBacklog({ timezone }: { timezone?: string }) {
  const qc = useQueryClient()
  const role = useAuthStore((s) => s.user?.role)
  const canHandle = ALERT_HANDLER_ROLES.has(role || '')
  const [status, setStatus] = useState<'open' | 'acknowledged'>('open')
  const [alertType, setAlertType] = useState<string | undefined>()
  const [ruleInput, setRuleInput] = useState('')
  const [rule, setRule] = useState('')
  const [range, setRange] = useState<AuditDateRange>(null)
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<string[]>([])
  const [pending, setPending] = useState<AlertGroupBatchStatus | null>(null)
  const [note, setNote] = useState('')
  const [lastResult, setLastResult] = useState<{ label: string; result: AlertGroupBatchResult } | null>(null)

  const rangeWindow = auditRangeParams(range, timezone)
  const filters = {
    status,
    ...(alertType ? { type: alertType } : {}),
    ...(rule ? { rule } : {}),
    ...rangeWindow,
  }
  const resetSelection = () => { setPage(1); setSelected([]) }

  const listQ = useQuery({
    queryKey: ['alert-group-backlog', filters, page],
    queryFn: () => alertGroupApi.list({ ...filters, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE }),
    placeholderData: keepPreviousData,
  })
  const items: AlertGroupItem[] = listQ.data?.data?.items ?? []
  const total = Number(listQ.data?.data?.total) || 0

  const batchM = useMutation({
    mutationFn: (s: AlertGroupBatchStatus) => alertGroupApi.batchStatus({
      ids: selected,
      status: s,
      note: note.trim() || undefined,
      filters: { status, type: alertType, rule: rule || undefined, from: rangeWindow.from, to: rangeWindow.to },
    }),
    onSuccess: (res, s) => {
      const result = res.data
      const label = BATCH_ACTIONS.find((a) => a.status === s)?.label || '处置'
      setLastResult({ label, result })
      const failed = result.failed?.length || 0
      if (failed > 0) message.warning(`${label}：成功 ${result.updated} 个，失败 ${failed} 个`)
      else message.success(`${label}：成功 ${result.updated} 个`)
      setSelected([])
      setPending(null)
      setNote('')
      qc.invalidateQueries({ queryKey: ['alert-group-backlog'] })
    },
    onError: () => message.error('批量处置失败，请稍后重试'),
  })

  const tooMany = selected.length > BATCH_MAX
  const pendingLabel = BATCH_ACTIONS.find((a) => a.status === pending)?.label || ''

  const failureSummary = lastResult
    ? Object.entries((lastResult.result.failed || []).reduce<Record<string, number>>((acc, f) => {
      const key = FAILURE_LABELS[f.reason] ? f.reason : 'not_found'
      acc[key] = (acc[key] || 0) + 1
      return acc
    }, {}))
    : []

  const columns = [
    {
      title: '严重度', dataIndex: 'severity', key: 'severity', width: 90,
      render: (_: unknown, r: AlertGroupItem) => {
        const severityKey = (r.effective_severity || r.severity || '').toLowerCase()
        const cfg = SEVERITY[severityKey] || { color: 'default', label: SEVERITY_LABELS[severityKey] || '未分级' }
        return <Tag color={cfg.color}>{cfg.label}</Tag>
      },
    },
    { title: '告警', dataIndex: 'title', key: 'title', ellipsis: true, render: (v?: string) => v || '-' },
    { title: '类型', dataIndex: 'type', key: 'type', width: 120, render: (v?: string) => <Tag>{typeLabel(v)}</Tag> },
    { title: '规则', dataIndex: 'rule_name', key: 'rule_name', width: 160, ellipsis: true, render: (v?: string) => v || '-' },
    { title: '发生次数', dataIndex: 'occurrence_count', key: 'occurrence_count', width: 90 },
    { title: '最近发生', dataIndex: 'last_seen_at', key: 'last_seen_at', width: 165, render: (v: string) => formatInTimezone(v, timezone) },
    {
      title: '状态', dataIndex: 'status', key: 'status', width: 90,
      render: (v: string) => { const cfg = STATUS_LABELS[v] || STATUS_LABELS.open; return <Tag color={cfg.color}>{cfg.label}</Tag> },
    },
  ]

  return (
    <Card title="告警组积压处置" style={{ marginTop: 16 }} aria-label="告警组积压处置">
      <Text type="secondary" style={{ display: 'block', marginBottom: 12 }}>
        按类型、规则和最近发生时间筛选同类告警组，勾选后批量确认、关闭或标记误报。只处置勾选的告警组，单次最多 {BATCH_MAX} 个；安全事件原始记录与审计证据不受影响。
      </Text>
      <Space wrap style={{ marginBottom: 12 }}>
        <Segmented
          aria-label="按处置状态筛选"
          value={status}
          onChange={(v) => { setStatus(v as 'open' | 'acknowledged'); resetSelection() }}
          options={[{ value: 'open', label: '待处置' }, { value: 'acknowledged', label: '已确认' }]}
        />
        <Select
          allowClear
          aria-label="按告警类型筛选"
          placeholder="全部类型"
          style={{ width: 160 }}
          value={alertType}
          onChange={(v) => { setAlertType(v); resetSelection() }}
          options={Object.entries(ALERT_GROUP_TYPE_LABELS).map(([value, label]) => ({ value, label }))}
        />
        <Input.Search
          allowClear
          aria-label="按规则筛选"
          placeholder="规则名称"
          style={{ width: 200 }}
          value={ruleInput}
          onChange={(e) => { setRuleInput(e.target.value); if (!e.target.value) { setRule(''); resetSelection() } }}
          onSearch={(v) => { setRule(v.trim()); resetSelection() }}
        />
        <Text type="secondary">最近发生</Text>
        <AuditDateRangeFilter value={range} onChange={(next) => { setRange(next); resetSelection() }} timezone={timezone} />
        <Text type="secondary" style={{ fontSize: 12 }}>共 {total} 个告警组</Text>
      </Space>
      {canHandle && (
        <Space wrap style={{ marginBottom: 12 }} aria-label="批量处置">
          <Text>已选 {selected.length} 个</Text>
          {BATCH_ACTIONS.map((a) => (
            <Button key={a.status} danger={a.danger} disabled={selected.length === 0 || tooMany} onClick={() => setPending(a.status)}>
              批量{a.label}
            </Button>
          ))}
          {selected.length > 0 && <Button type="link" onClick={() => setSelected([])}>清空选择</Button>}
          {tooMany && <Text type="danger">单次最多处置 {BATCH_MAX} 个，请减少勾选</Text>}
        </Space>
      )}
      {lastResult && (
        <Alert
          style={{ marginBottom: 12 }}
          type={lastResult.result.failed?.length ? 'warning' : 'success'}
          showIcon
          closable
          onClose={() => setLastResult(null)}
          message={`批量${lastResult.label}完成：成功 ${lastResult.result.updated} 个，失败 ${lastResult.result.failed?.length || 0} 个`}
          description={failureSummary.length ? failureSummary.map(([k, n]) => `${FAILURE_LABELS[k]}：${n} 个`).join('；') : undefined}
        />
      )}
      <Table
        size="small"
        rowKey="id"
        dataSource={items}
        columns={columns}
        loading={listQ.isLoading}
        rowSelection={canHandle ? {
          selectedRowKeys: selected,
          preserveSelectedRowKeys: true,
          onChange: (keys) => setSelected(keys.map(String)),
        } : undefined}
        pagination={{ current: page, pageSize: PAGE_SIZE, total, showSizeChanger: false, onChange: (p) => setPage(p) }}
        locale={{ emptyText: '没有符合条件的告警组' }}
      />
      <Modal
        open={pending !== null}
        title={`确认批量${pendingLabel}`}
        okText={`确认${pendingLabel} ${selected.length} 个`}
        cancelText="取消"
        okButtonProps={{ danger: pending === 'false_positive', loading: batchM.isPending }}
        onOk={() => pending && batchM.mutate(pending)}
        onCancel={() => { setPending(null); setNote('') }}
        destroyOnClose
      >
        <p>将对选中的 <b>{selected.length}</b> 个告警组执行「{pendingLabel}」。</p>
        {pending === 'false_positive' && <p>标记误报后，同类告警在静默期内不再进入消息中心，安全事件仍照常留存。</p>}
        <Input.TextArea
          aria-label="处置说明"
          placeholder="处置说明（可选，写入操作审计）"
          maxLength={500}
          value={note}
          onChange={(e) => setNote(e.target.value)}
          autoSize={{ minRows: 2, maxRows: 4 }}
        />
      </Modal>
    </Card>
  )
}

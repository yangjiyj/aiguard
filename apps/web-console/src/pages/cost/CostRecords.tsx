import { useCurrencyStore } from '../../stores/currency'
import { useSearchParams } from 'react-router-dom'
import { useMemo, useState } from 'react'
import { Alert, Button, Card, Checkbox, DatePicker, Drawer, Input, Select, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { useQuery } from '@tanstack/react-query'
import dayjs, { type Dayjs } from 'dayjs'
import RequestTimingCard from '../../components/RequestTimingCard'
import { formatLatencySeconds } from '../../utils/modelProbe'
import { billingStateLabel } from './billingStateLabels'
import {
  getUsageRecords,
  keyApi,
  modelApi,
  projectApi,
  providerApi,
  userApi,
  FAILURE_CATEGORY_LABELS,
  type UsageRecord,
  type UsageRecordsParams,
} from '../../services/api'

const { RangePicker } = DatePicker
const { Text, Title } = Typography

type FilterState = {
  user_id: string
  client_id: string
  project_id: string
  model_id: string
  provider_id: string
  request_status: string
  billing_state: string
  source_ip: string
  failure_category: string
  error_keyword: string
  http_status: string
  fallback: string
}

const DEFAULT_FILTERS: FilterState = {
  user_id: '', client_id: '', project_id: '', model_id: '', provider_id: '',
  request_status: '', billing_state: '', fallback: '', source_ip: '', failure_category: '', error_keyword: '', http_status: '',
}

const statusOptions = [
  { label: '全部状态', value: '' }, { label: '成功', value: 'success' },
  { label: '失败', value: 'failed' }, { label: '已阻断', value: 'blocked' },
]
const billingOptions = [
  { label: '全部账单状态', value: '' }, { label: '已结算', value: 'settled' },
  { label: '待结算', value: 'reserved' }, { label: '已释放', value: 'released' },
  { label: '未定价', value: 'unpriced' }, { label: '计费失败', value: 'failed' },
  { label: '异常待核对', value: 'exception' }, { label: '无计费事实', value: 'not_billed' },
  { label: '预算用尽被拒', value: 'budget_exhausted' }, { label: '未定价被拒', value: 'budget_unpriced' },
  { label: '计费不可用被拒', value: 'budget_unavailable' },
]
const billingDisplay = (record: UsageRecord) => {
  if (record.billing_state === 'settled') {
    if (record.billing_mode === 'metering') return { label: '已计量', color: 'success' }
    if (record.billing_mode === 'prepaid') return { label: '已扣费', color: 'success' }
  }
  return billingStateLabel(record.billing_state)
}

const requestMeta: Record<string, { label: string; color: string }> = {
  success: { label: '成功', color: 'success' }, failed: { label: '失败', color: 'error' },
  blocked: { label: '已阻断', color: 'volcano' },
}

const rows = (response: any): any[] => {
  const payload = response?.data
  return Array.isArray(payload?.data) ? payload.data : Array.isArray(payload) ? payload : []
}
const formatTokens = (value?: number) => (value || 0).toLocaleString()
const formatTime = (value?: string) => (value ? dayjs(value).format('YYYY-MM-DD HH:mm:ss') : '-')
const formatBillingAmount = (value?: number | null, currency: string = useCurrencyStore.getState().tenantCurrency) => {
  if (value == null) return '-'
  const amount = value / 1_000_000
  const displayed = `${currency} ${amount.toLocaleString('zh-CN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
  const minimum = `${currency} 0.01`
  return amount !== 0 && Math.abs(amount) < 0.01 ? `< ${minimum}` : displayed
}
const businessName = (value: string | undefined, empty: string) => value || empty

// 历史记录没有中文解释时，仅按已留存的响应错误匹配，不推测丢失的原文。
// 历史错误翻译函数供现有测试复用，不包含组件状态。
// eslint-disable-next-line react-refresh/only-export-components
export function usageErrorHint(record: UsageRecord): string {
  if (record.error_hint) return record.error_hint
  const text = `${record.error_message || ''} ${record.upstream_error_code || ''}`
  if (/prompt is too long|context_length_exceeded|maximum context length|tokens?\s*>\s*[\d,]+\s+maximum/i.test(text)) {
    const counts = text.match(/([\d,]+)\s*tokens?\s*>\s*([\d,]+)\s+maximum/i)
    return counts
      ? `对话上下文超过模型上限（本次 ${counts[1].replace(/,/g, '')} token，上限 ${counts[2].replace(/,/g, '')}），请压缩上下文或新开对话`
      : '对话上下文超过模型上限，请压缩上下文或新开对话'
  }
  if (/insufficient_quota|balance|credit|billing|余额|额度|欠费|充值/i.test(text) || record.upstream_status_code === 402) return '上游账号额度不足，请联系管理员'
  if (/rate[_ -]?limit|限流/i.test(text) || record.upstream_status_code === 429) return '上游请求过于频繁，请稍后重试'
  return ''
}

function CostRecords() {
  const [searchParams] = useSearchParams()
  const requestId = searchParams.get('request_id') || ''
  const [range, setRange] = useState<[Dayjs, Dayjs]>(() => [dayjs().subtract(7, 'day'), dayjs()])
  const [filters, setFilters] = useState<FilterState>(DEFAULT_FILTERS)
  const [page, setPage] = useState(1)
  const [selectedRecord, setSelectedRecord] = useState<UsageRecord | null>(null)
  const pageSize = 50

  const usersQ = useQuery({ queryKey: ['usage-directory', 'users'], queryFn: userApi.list })
  const keysQ = useQuery({ queryKey: ['usage-directory', 'keys'], queryFn: () => keyApi.list() })
  const projectsQ = useQuery({ queryKey: ['usage-directory', 'projects'], queryFn: projectApi.list })
  const providersQ = useQuery({ queryKey: ['usage-directory', 'providers'], queryFn: providerApi.list })
  const modelsQ = useQuery({ queryKey: ['usage-directory', 'models'], queryFn: () => modelApi.list() })

  const providerNames = useMemo(() => new Map(rows(providersQ.data).map((item) => [item.id, item.name])), [providersQ.data])
  const userOptions = useMemo(() => rows(usersQ.data).filter((item) => item.id && (item.username || item.name)).map((item) => ({ value: item.id, label: item.username || item.name })), [usersQ.data])
  const keyOptions = useMemo(() => rows(keysQ.data).filter((item) => item.id && (item.name || item.key_prefix)).map((item) => ({ value: item.id, label: item.name ? `${item.name}${item.key_prefix ? ` · ${item.key_prefix}` : ''}` : item.key_prefix })), [keysQ.data])
  const projectOptions = useMemo(() => rows(projectsQ.data).filter((item) => item.id && item.name).map((item) => ({ value: item.id, label: item.name })), [projectsQ.data])
  const providerOptions = useMemo(() => rows(providersQ.data).filter((item) => item.id && item.name).map((item) => ({ value: item.id, label: item.name })), [providersQ.data])
  const modelOptions = useMemo(() => rows(modelsQ.data).filter((item) => item.id && (item.model_label || item.model_name)).map((item) => {
    const name = item.model_label || item.model_name
    const provider = providerNames.get(item.provider_id)
    return { value: item.id, label: provider ? `${name}（${provider}）` : name }
  }), [modelsQ.data, providerNames])

  const baseParams = useMemo<UsageRecordsParams>(() => {
    const params: UsageRecordsParams = { request_id: requestId || undefined, start: range[0].toISOString(), end: range[1].toISOString() }
    Object.entries(filters).forEach(([key, value]) => { if (value) params[key] = value })
    return params
  }, [filters, range, requestId])
  const listParams = useMemo<UsageRecordsParams>(() => ({ ...baseParams, limit: pageSize, offset: (page - 1) * pageSize }), [baseParams, page])
  const recordsQ = useQuery({ queryKey: ['usage-records', 'list', listParams], queryFn: () => getUsageRecords(listParams) })

  const records = recordsQ.data?.data.records || []
  const total = recordsQ.data?.data.total || 0
  const updateFilter = (key: keyof FilterState, value?: string) => { setFilters((prev) => ({ ...prev, [key]: value || '' })); setPage(1) }
  const directoryProps = (query: any) => ({
    disabled: query.isLoading || query.isError,
    notFoundContent: query.isError ? <Button type="link" onClick={() => query.refetch()}>重新加载目录</Button> : '无可选业务对象',
  })

  // 列宽自适应：只有窄列给固定宽，长文本列（用户/Key/应用、模型/供应商、错误详情）保持弹性，
  // 由 antd 按容器宽度分配，表格随浏览器缩放，不再靠横向滚动条看全。
  const columns = useMemo<ColumnsType<UsageRecord>>(() => [
    { title: '时间', dataIndex: 'created_at', width: 150, render: formatTime },
    { title: '用户 / Key / 应用', render: (_, record) => <Space direction="vertical" size={2}><Text strong ellipsis>{businessName(record.user_name, '已删除或不可见用户')}</Text><Text type="secondary" ellipsis>{businessName(record.key_name, '已删除或不可见 Key')}{record.key_prefix ? ` · ${record.key_prefix}` : ''}</Text><Text type="secondary" ellipsis>{businessName(record.project_name, '已删除或未归属应用')}</Text></Space> },
    { title: '源 IP', dataIndex: 'source_ip', width: 135, render: (value: string) => value ? <Text copyable style={{ fontSize: 12 }}>{value}</Text> : <Text type="secondary">未记录</Text> },
    { title: '模型 / 供应商', render: (_, record) => <Space direction="vertical" size={2}><Text strong ellipsis>{businessName(record.model_name, '已删除或不可见模型')}</Text><Text type="secondary" ellipsis>{businessName(record.provider_name, '已删除或不可见供应商')}</Text></Space> },
    { title: '请求状态', dataIndex: 'request_status', width: 92, render: (value: string) => <Tag color={(requestMeta[value] || { color: 'default' }).color}>{(requestMeta[value] || { label: '未知' }).label}</Tag> },
    { title: '错误详情', render: (_, record) => record.request_status === 'success' ? '—' : <Space direction="vertical" size={2}><Text type="danger">{FAILURE_CATEGORY_LABELS[record.failure_category || 'unknown'] || '其他原因'}{record.upstream_status_code ? ` · HTTP ${record.upstream_status_code}` : ''}</Text><Text ellipsis style={{ maxWidth: '100%' }} title={record.error_message || record.raw_status}>{usageErrorHint(record) || record.error_message || record.raw_status || '未留存错误原文'}</Text></Space> },
    { title: '账单状态', dataIndex: 'billing_state', width: 92, render: (_value: string, record) => { const meta = billingDisplay(record); return <Tag color={meta.color}>{meta.label}</Tag> } },
    { title: '结算金额', key: 'billing_amount', align: 'right', width: 110, render: (_, record) => record.billing_state === 'settled' ? <strong>{formatBillingAmount(record.billing_amount_micros, record.billing_currency)}</strong> : '-' },
    { title: '总 Token', dataIndex: 'total_tokens', align: 'right', width: 90, render: formatTokens },
    { title: '总耗时', dataIndex: 'latency_ms', align: 'right', width: 85, render: (value: number) => formatLatencySeconds(value || 0) },
    { title: '操作', key: 'detail', width: 70, render: (_, record) => <Button type="link" size="small" onClick={(event) => { event.stopPropagation(); setSelectedRecord(record) }}>详情</Button> },
  ], [])

  return (
    <div>
      <div className="page-header">
        <Title level={4} style={{ margin: 0, fontSize: 20, fontWeight: 600 }}>调用明细</Title>
        <Text type="secondary">按时间、用户、应用、模型和账单状态核对每一笔调用；汇总分析请进入“费用总览”。</Text>
      </div>
      {recordsQ.isError ? (
        <Alert type="error" showIcon message="调用明细加载失败" description="暂时无法读取计费明细，请检查网络后重试。" action={<Button onClick={() => void recordsQ.refetch()}>重试</Button>} style={{ marginBottom: 16 }} />
      ) : null}
      <Card style={{ marginBottom: 16 }}>
        <Space size={[8, 8]} wrap>
          <RangePicker allowClear={false} showTime value={range} onChange={(value) => { if (value?.[0] && value?.[1]) { setRange([value[0], value[1]]); setPage(1) } }} />
          <Select aria-label="用户筛选" placeholder="选择用户" allowClear showSearch optionFilterProp="label" value={filters.user_id || undefined} options={userOptions} onChange={(value) => updateFilter('user_id', value)} style={{ width: 160 }} {...directoryProps(usersQ)} />
          <Select aria-label="Key 筛选" placeholder="选择 Key" allowClear showSearch optionFilterProp="label" value={filters.client_id || undefined} options={keyOptions} onChange={(value) => updateFilter('client_id', value)} style={{ width: 180 }} {...directoryProps(keysQ)} />
          <Select aria-label="应用筛选" placeholder="选择应用" allowClear showSearch optionFilterProp="label" value={filters.project_id || undefined} options={projectOptions} onChange={(value) => updateFilter('project_id', value)} style={{ width: 160 }} {...directoryProps(projectsQ)} />
          <Select aria-label="模型筛选" placeholder="选择模型" allowClear showSearch optionFilterProp="label" value={filters.model_id || undefined} options={modelOptions} onChange={(value) => updateFilter('model_id', value)} style={{ width: 190 }} {...directoryProps(modelsQ)} />
          <Select aria-label="供应商筛选" placeholder="选择供应商" allowClear showSearch optionFilterProp="label" value={filters.provider_id || undefined} options={providerOptions} onChange={(value) => updateFilter('provider_id', value)} style={{ width: 170 }} {...directoryProps(providersQ)} />
          <Select aria-label="请求状态筛选" value={filters.request_status} options={statusOptions} onChange={(value) => updateFilter('request_status', value)} style={{ width: 120 }} />
          <Select aria-label="账单状态筛选" value={filters.billing_state} options={billingOptions} onChange={(value) => updateFilter('billing_state', value)} style={{ width: 135 }} />
          <Input.Search aria-label="源 IP 筛选" placeholder="源 IP（精确匹配）" allowClear onSearch={(value) => updateFilter('source_ip', value.trim())} onChange={(event) => { if (!event.target.value) updateFilter('source_ip', '') }} style={{ width: 210 }} />
          <Select aria-label="错误类型筛选" placeholder="全部错误类型" allowClear value={filters.failure_category || undefined} options={Object.entries(FAILURE_CATEGORY_LABELS).map(([value, label]) => ({ value, label }))} onChange={(value) => updateFilter('failure_category', value)} style={{ width: 160 }} />
          <Input.Search aria-label="错误详情筛选" placeholder="搜索错误原文 / 错误码" allowClear onSearch={(value) => updateFilter('error_keyword', value.trim())} onChange={(event) => { if (!event.target.value) updateFilter('error_keyword', '') }} style={{ width: 250 }} />
          <Input.Search aria-label="HTTP 状态码筛选" placeholder="HTTP 状态码，如 429" allowClear onSearch={(value) => updateFilter('http_status', value.trim())} onChange={(event) => { if (!event.target.value) updateFilter('http_status', '') }} style={{ width: 210 }} />
          <Checkbox checked={filters.fallback === '1'} onChange={(event) => updateFilter('fallback', event.target.checked ? '1' : '')}>仅看自动切换</Checkbox>
        </Space>
      </Card>
      <Card>
        <Table rowKey="id" columns={columns} dataSource={records} loading={recordsQ.isLoading} scroll={{ x: 'max-content' }} pagination={{ current: page, pageSize, total, showSizeChanger: false, showTotal: (count) => `共 ${count} 条`, onChange: setPage }} onRow={(record) => ({ onClick: () => setSelectedRecord(record), style: { cursor: 'pointer' } })} />
      </Card>
      <Drawer title={selectedRecord ? `请求详情: ${selectedRecord.request_id?.slice(0, 12)}…` : '请求详情'} open={Boolean(selectedRecord)} onClose={() => setSelectedRecord(null)} width={520}>
        {selectedRecord && <Space direction="vertical" size={14} style={{ width: '100%' }}>
          <Card size="small" title="业务归属"><p>请求 ID：<Text copyable>{selectedRecord.request_id}</Text></p><p>源 IP：{selectedRecord.source_ip ? <Text copyable>{selectedRecord.source_ip}</Text> : '未记录'}</p><p>用户：{businessName(selectedRecord.user_name, '已删除或不可见用户')}</p><p>Key：{businessName(selectedRecord.key_name, '已删除或不可见 Key')}{selectedRecord.key_prefix ? ` · ${selectedRecord.key_prefix}` : ''}</p><p>应用：{businessName(selectedRecord.project_name, '已删除或未归属应用')}</p><p>模型：{businessName(selectedRecord.model_name, '已删除或不可见模型')}（{businessName(selectedRecord.provider_name, '已删除或不可见供应商')}）</p></Card>
          {(selectedRecord.request_status === 'failed' || selectedRecord.request_status === 'blocked') && <Card size="small" title="失败归因"><Space direction="vertical" style={{ width: '100%' }}><Tag color="error">{FAILURE_CATEGORY_LABELS[selectedRecord.failure_category || 'unknown'] || '其他原因'}</Tag><Text>HTTP 状态码：{selectedRecord.upstream_status_code || '未收到上游响应'}</Text><Text>原始状态：{selectedRecord.raw_status || selectedRecord.request_status}</Text>{usageErrorHint(selectedRecord) && <Text>{usageErrorHint(selectedRecord)}</Text>}{selectedRecord.upstream_error_code && <Text>上游错误码：{selectedRecord.upstream_error_code}</Text>}<Text>上游错误原文：</Text><Typography.Paragraph copyable={!!selectedRecord.error_message} style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{selectedRecord.error_message || '此记录未留存错误原文，可用请求 ID 关联服务日志。'}</Typography.Paragraph>{selectedRecord.attempts?.map((attempt, index) => <div key={index}>尝试 {index + 1}：{attempt.route?.provider_name || '上游线路'} · {FAILURE_CATEGORY_LABELS[attempt.failure_category || ''] || attempt.result || '状态未知'} · {attempt.status_code_category || '无状态码'} · {formatLatencySeconds(attempt.latency_ms || 0)}</div>)}</Space></Card>}
          <RequestTimingCard record={selectedRecord} />
          <Card size="small" title="账单"><p>状态：<Tag color={billingStateLabel(selectedRecord.billing_state).color}>{billingStateLabel(selectedRecord.billing_state).label}</Tag></p><p>结算金额：{selectedRecord.billing_state === 'settled' ? formatBillingAmount(selectedRecord.billing_amount_micros, selectedRecord.billing_currency) : '—'}</p><p>Token：输入 {formatTokens(selectedRecord.input_tokens)} / 输出 {formatTokens(selectedRecord.output_tokens)}</p></Card>
        </Space>}
      </Drawer>
    </div>
  )
}

export default CostRecords

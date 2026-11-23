import { useDiagnosisContext } from '../stores/diagnosisContext'
import RequestTimingCard from './RequestTimingCard'
import { useState } from 'react'
import { Alert, Button, Descriptions, Drawer, Space, Table, Tag, Typography } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { FAILURE_CATEGORY_LABELS, getUsageRecords, type UsageRecord } from '../services/api'
import { modelOperationError, probeLatency } from '../utils/modelProbe'
import { useAuthStore } from '../stores/auth'

const { Text } = Typography
export default function ModelRequestDiagnostics({ target, windowHours, onClose }: {
  target: { model_id: string; provider_id: string; model_name?: string } | null
  windowHours: number
  onClose: () => void
}) {
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<UsageRecord | null>(null)
  const [end] = useState(() => new Date().toISOString())
  const { user } = useAuthStore()
  const principal = `${user?.tenant_id || 'unknown'}:${user?.id || 'unknown'}`
  const start = new Date(new Date(end).getTime() - windowHours * 3600_000).toISOString()
  const params = { model_id: target?.model_id, provider_id: target?.provider_id, start, end, limit: 20, offset: (page - 1) * 20 }
  const query = useQuery({ queryKey: ['model-operation-diagnostics', principal, params], queryFn: () => getUsageRecords(params), enabled: target !== null })
  const records = query.data?.data.records || []
  const total = query.data?.data.total
  const statusMeta: Record<string, { label: string; color: string }> = { success: { label: '成功', color: 'green' }, failed: { label: '失败', color: 'red' }, blocked: { label: '已阻断', color: 'orange' }, cancelled: { label: '已取消', color: 'default' }, canceled: { label: '已取消', color: 'default' }, pending: { label: '待完成', color: 'blue' }, running: { label: '执行中', color: 'blue' }, reserved: { label: '待完成', color: 'blue' } }
  const columns = [
    { title: '时间 / 请求', key: 'id', width: 220, render: (_: unknown, record: UsageRecord) => <Space direction="vertical" size={0}><Text>{new Date(record.created_at).toLocaleString('zh-CN')}</Text><Text className="modelops-small" code>{record.request_id}</Text></Space> },
    { title: '结果', key: 'status', width: 140, render: (_: unknown, record: UsageRecord) => { const meta = record.failure_category === 'client_canceled' ? statusMeta.cancelled : statusMeta[record.request_status] || { label: '未知', color: 'default' }; return <Space direction="vertical" size={0}><Tag color={meta.color}>{meta.label}</Tag><Text>HTTP {record.upstream_status_code || '未收到'}</Text></Space> } },
    { title: '故障类别', dataIndex: 'failure_category', width: 150, render: (value?: string) => value ? FAILURE_CATEGORY_LABELS[value] || value : '—' },
    { title: '总耗时 / 首事件', key: 'latency', width: 180, render: (_: unknown, record: UsageRecord) => `${probeLatency(record.latency_ms)} / ${probeLatency(record.upstream_ttft_ms)}` },
    { title: '备用线路', dataIndex: 'fallback_used', width: 100, render: (value?: boolean) => value === undefined ? '未知' : value ? '已使用' : '未使用' },
    { title: '诊断', key: 'detail', width: 100, render: (_: unknown, record: UsageRecord) => <Button type="link" size="small" onClick={() => { setSelected(record); useDiagnosisContext.getState().setContext({ requestId: record.request_id }) }}>查看</Button> },
  ]
  return <Drawer title={target ? `请求诊断 · ${target.model_name || '模型'}` : '请求诊断'} width={1060} open={target !== null} onClose={onClose} destroyOnClose>
    {query.isError ? <Alert type="error" showIcon message={modelOperationError(query.error, '请求诊断读取失败')} /> : <>
      {!query.isLoading && (typeof total !== 'number' || total < 0) && <Alert type="warning" showIcon message="请求总数未知，分页暂不可用" />}
      <Table size="small" columns={columns} dataSource={records} rowKey="id" loading={query.isLoading} scroll={{ x: 890 }} pagination={typeof total === 'number' && total >= 0 ? { current: page, pageSize: 20, total, showSizeChanger: false, onChange: (value) => { setPage(value); setSelected(null) }, showTotal: (count) => `共 ${count} 个请求` } : false} locale={{ emptyText: query.isLoading ? '读取中' : '所选窗口暂无真实请求' }} />
    </>}
    {selected && <section style={{ borderTop: '1px solid var(--border-color)', paddingTop: 16, marginTop: 16 }}>
      <Descriptions size="small" column={2} items={[
        { key: 'request', label: '请求 ID', children: <Text code>{selected.request_id}</Text>, span: 2 },
        { key: 'planned', label: '计划线路', children: selected.planned_route_name || '未记录' },
        { key: 'actual', label: '实际线路', children: selected.actual_route_name || '未记录' },
        { key: 'first', label: '首事件', children: probeLatency(selected.upstream_ttft_ms) },
        { key: 'total', label: '总耗时', children: probeLatency(selected.latency_ms) },
      ]} />
      <RequestTimingCard record={selected} />
      <Table size="small" pagination={false} rowKey={(_, index) => String(index)} dataSource={selected.attempts || []} locale={{ emptyText: '未记录线路尝试' }} columns={[
        { title: '尝试线路', key: 'route', render: (_, attempt) => attempt.route?.provider_name || attempt.route?.route_ref || '未记录' },
        { title: '结果', dataIndex: 'result' },
        { title: 'HTTP 类别', dataIndex: 'status_code_category' },
        { title: '耗时', dataIndex: 'latency_ms', render: probeLatency },
        { title: '故障类别', dataIndex: 'failure_category', render: (value?: string) => value ? FAILURE_CATEGORY_LABELS[value] || value : '—' },
      ]} />
    </section>}
  </Drawer>
}

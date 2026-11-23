import { useState } from 'react'
import { Alert, Button, DatePicker, Empty, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { DownloadOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts'
import dayjs from 'dayjs'
import { modelOperationsApi, type ModelSLAMetrics, type ModelSLAMonth, type ModelSLAFilter } from '../services/modelOperations'
import { useAuthStore } from '../stores/auth'
import { modelOperationError, probeLatency } from '../utils/modelProbe'

const { Text } = Typography
const rate = (value?: number | null) => value === undefined || value === null ? '未知' : `${(value * 100).toFixed(2)}%`
const count = (value?: number | null) => value === undefined || value === null ? '未知' : value.toLocaleString('zh-CN')
const duration = (metrics: ModelSLAMetrics) => `${probeLatency(metrics.p50_ms)} / ${probeLatency(metrics.p95_ms)}`
const firstEvent = (metrics: ModelSLAMetrics) => `${probeLatency(metrics.first_event_p50_ms)} / ${probeLatency(metrics.first_event_p95_ms)}`

export default function ModelSLAMonthly({ providerId, modelId }: { providerId?: string; modelId?: string }) {
  const { user } = useAuthStore()
  const [month, setMonth] = useState(() => dayjs().format('YYYY-MM'))
  const [timezone, setTimezone] = useState('Asia/Shanghai')
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState('')
  const filters: ModelSLAFilter = { month, timezone, provider_id: providerId, model_id: modelId }
  const principal = `${user?.tenant_id || 'unknown'}:${user?.id || 'unknown'}`
  const query = useQuery({ queryKey: ['model-operations', 'sla', principal, filters], queryFn: () => modelOperationsApi.sla(filters).then((response) => response.data.data) })
  const report = query.data
  const exportCsv = async () => {
    if (exporting) return
    setExporting(true); setExportError('')
    try {
      const response = await modelOperationsApi.exportSla(filters)
      if (!(response.data instanceof Blob) || !response.data.size || !response.data.type.includes('text/csv')) throw new Error('invalid csv response')
      const url = URL.createObjectURL(response.data)
      const link = document.createElement('a')
      link.href = url
      link.download = `model-sla-${month}-${timezone.replace('/', '-')}.csv`
      link.click()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (error) { setExportError(modelOperationError(error, '月报导出失败')) }
    finally { setExporting(false) }
  }
  const metricColumns = [
    { title: '业务请求', dataIndex: 'requests', width: 100, render: count },
    { title: '可判定请求', dataIndex: 'eligible_requests', width: 110, render: count },
    { title: '请求可用率', dataIndex: 'availability', width: 110, render: rate },
    { title: '上游 / 平台失败', dataIndex: 'platform_failures', width: 140, render: count },
    { title: '其他上游 4xx', dataIndex: 'client_errors', width: 110, render: count },
    { title: '上游凭据失败', dataIndex: 'auth_failures', width: 110, render: count },
    { title: '取消 / 阻断 / 未知', key: 'excluded', width: 160, render: (_: unknown, item: ModelSLAMetrics) => `${count(item.cancelled)} / ${count(item.blocked)} / ${count(item.unknown)}` },
    { title: '总耗时 P50 / P95', key: 'latency', width: 200, render: (_: unknown, item: ModelSLAMetrics) => duration(item) },
    { title: '首事件 P50 / P95', key: 'first', width: 200, render: (_: unknown, item: ModelSLAMetrics) => firstEvent(item) },
    { title: '首事件样本', dataIndex: 'first_event_samples', width: 110, render: count },
    { title: '观测分钟 / 故障分钟', key: 'minutes', width: 170, render: (_: unknown, item: ModelSLAMetrics) => `${count(item.active_minutes)} / ${count(item.down_minutes)}` },
    { title: '观测分钟可用率', dataIndex: 'minute_availability', width: 140, render: rate },
  ]
  const modelColumns = [{ title: '模型 / 上游', key: 'identity', width: 220, render: (_: unknown, item: ModelSLAMonth['models'][number]) => <Space direction="vertical" size={0}><Text>{item.model_name || item.model_id || '未知模型'}</Text><Text type="secondary" className="modelops-small">{item.provider_name || item.provider_id || '未知上游'}</Text></Space> }, ...metricColumns]
  return <section aria-label="自然月 SLA" className="modelops-monthly">
    <div className="modelops-table-heading"><Space wrap><DatePicker aria-label="SLA 月份" picker="month" allowClear={false} value={dayjs(`${month}-01`)} onChange={(value) => { if (value) { setMonth(value.format('YYYY-MM')); setExportError('') } }} /><Select aria-label="SLA 时区" value={timezone} onChange={(value) => { setTimezone(value); setExportError('') }} style={{ width: 180 }} options={[{ label: 'Asia/Shanghai', value: 'Asia/Shanghai' }, { label: 'UTC', value: 'UTC' }]} /></Space><Tooltip title="导出当前月报 CSV"><Button aria-label="导出当前月报 CSV" icon={<DownloadOutlined />} loading={exporting} disabled={query.isLoading || query.isError || !report} onClick={exportCsv} /></Tooltip></div>
    {exportError && <Alert type="error" showIcon message={exportError} />}
    {query.isError ? <Alert type="error" showIcon message={modelOperationError(query.error, '月度 SLA 读取失败')} /> : query.isLoading ? <div role="status">正在读取月报</div> : report ? <>
      <div className="modelops-table-heading"><Space wrap><Tag color={report.in_progress ? 'blue' : 'default'}>{report.in_progress ? '本月进行中' : '完整自然月'}</Tag><Text type="secondary">截至 {new Date(report.observed_until).toLocaleString('zh-CN', { timeZone: timezone })}</Text></Space></div>
      <div className="modelops-sla-totals" aria-label="月度统计">
        <div><Text type="secondary">业务请求 / 可判定</Text><strong>{count(report.totals.requests)} / {count(report.totals.eligible_requests)}</strong></div>
        <div><Text type="secondary">请求可用率</Text><strong>{rate(report.totals.availability)}</strong></div>
        <div><Text type="secondary">观测分钟 / 故障分钟</Text><strong>{count(report.totals.active_minutes)} / {count(report.totals.down_minutes)}</strong></div>
        <div><Text type="secondary">观测分钟可用率</Text><strong>{rate(report.totals.minute_availability)}</strong></div>
      </div>
      <Alert type="info" showIcon message="分母为可判定请求；沉默分钟不算健康。观测结果不代表合同 SLA。" />
      <details style={{ marginBottom: 12 }}>
        <summary style={{ cursor: 'pointer' }}>统计口径</summary>
        <Text type="secondary" style={{ display: 'block', marginTop: 8 }}>可用率按业务 HTTP 与传输证据统计，上游 5xx、429、凭据和传输失败计为不可用；其他上游 4xx 独立列示。安全阻断、取消及缺失证据不充作健康样本，沉默分钟未观测。首事件含文本、推理及工具事件。此处为观测统计，不代表完整生成验证或合同 SLA 承诺。</Text>
      </details>
      {!report.available && <Alert type="warning" showIcon message="本月暂无可判定证据" />}
      {report.days.some((day) => day.availability !== null) ? <div className="modelops-chart"><ResponsiveContainer width="100%" height={260}><LineChart data={report.days.map((day) => ({ ...day, available_percent: day.availability === null ? null : day.availability * 100 }))}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="day" minTickGap={32} tickFormatter={(value: string) => value.slice(5)} /><YAxis domain={[0, 100]} unit="%" /><ChartTooltip /><Line name="请求可用率" dataKey="available_percent" stroke="var(--chart-1)" strokeWidth={2} dot={false} connectNulls={false} /></LineChart></ResponsiveContainer></div> : <Empty description="暂无日可用率样本" />}
      <Table size="small" rowKey={(item) => `${item.provider_id}:${item.model_id}`} dataSource={report.models} columns={modelColumns} loading={query.isFetching} scroll={{ x: 1780 }} pagination={{ pageSize: 20, showSizeChanger: false, showTotal: (total) => `共 ${total} 个模型上游` }} locale={{ emptyText: '暂无模型月度证据' }} />
      <details className="modelops-day-details"><summary>逐日记录</summary><Table size="small" rowKey="day" dataSource={report.days} columns={[{ title: '日期', dataIndex: 'day', width: 120 }, ...metricColumns]} scroll={{ x: 1650 }} pagination={{ pageSize: 15, showSizeChanger: false }} /></details>
    </> : <Alert type="warning" showIcon message="未收到月报数据" />}
  </section>
}

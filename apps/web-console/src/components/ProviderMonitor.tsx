import { useState } from 'react'
import { Alert, Button, Empty, Table, Tooltip, Typography } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts'
import { modelOperationsApi, type ModelOperationFilters, type ProviderMonitorItem } from '../services/modelOperations'
import { levelColor, successLevel } from '../utils/modelQuality'
import { modelOperationError, formatLatencySeconds } from '../utils/modelProbe'

const { Text } = Typography
const ERRORS = [
  { key: 'http_5xx', label: '5xx', color: 'var(--status-danger)' },
  { key: 'rate_limited', label: '429 限流', color: 'var(--status-warn)' },
  { key: 'rejected', label: '上游拒绝', color: 'var(--chart-2)' },
  { key: 'network', label: '网络 / 超时', color: 'var(--chart-6)' },
  { key: 'other', label: '其他', color: 'var(--chart-other)' },
] as const
const rate = (value: number | null | undefined) => value == null ? '—' : `${(value * 100).toFixed(1)}%`
const ms = (value: number | null | undefined) => value == null ? '—' : formatLatencySeconds(value)
const rowKey = (item: ProviderMonitorItem) => item.provider_id || `name:${item.provider_name}`

function ErrorBar({ item }: { item: ProviderMonitorItem }) {
  const parts = ERRORS.map((e) => ({ ...e, count: item.errors[e.key] })).filter((e) => e.count > 0)
  const total = parts.reduce((sum, e) => sum + e.count, 0)
  if (!total) return <Text type="secondary">—</Text>
  const label = `错误分布：${parts.map((e) => `${e.label} ${e.count}`).join('，')}`
  return <Tooltip title={label}><div className="provider-errorbar" aria-label={label}>{parts.map((e) => <i key={e.key} style={{ width: `${(e.count / total) * 100}%`, background: e.color }} />)}</div></Tooltip>
}

export default function ProviderMonitor({ filters, principal }: { filters: ModelOperationFilters; principal: string }) {
  const [selected, setSelected] = useState<string | null>(null)
  const query = useQuery({ queryKey: ['model-operations', 'providers', principal, filters], queryFn: () => modelOperationsApi.providers(filters).then((r) => r.data), refetchInterval: 30_000 })
  if (query.isError) return <Alert type="error" showIcon message={modelOperationError(query.error, '渠道监控数据读取失败')} action={<Button size="small" onClick={() => query.refetch()}>重试</Button>} />
  const data = query.data
  const items = data?.items ?? []
  const current = items.find((item) => rowKey(item) === selected) ?? null
  const columns = [
    { title: '渠道', key: 'provider', render: (_: unknown, item: ProviderMonitorItem) => <div><Text strong>{item.provider_name || '未知渠道'}</Text><div className="modelops-small">{item.model_count} 个模型</div></div> },
    { title: '尝试', dataIndex: 'attempts', width: 90, render: (v: number) => v.toLocaleString('zh-CN') },
    { title: '成功率', key: 'rate', width: 150, render: (_: unknown, item: ProviderMonitorItem) => <span className="provider-rate"><span>{rate(item.success_rate)}</span>{item.success_rate != null && <span className="provider-rate-track"><i style={{ width: `${item.success_rate * 100}%`, background: levelColor[successLevel(item.success_rate)] }} /></span>}</span> },
    { title: '延迟 P50 / P95', key: 'latency', width: 150, render: (_: unknown, item: ProviderMonitorItem) => item.latency_p50_ms == null ? '—' : `${ms(item.latency_p50_ms)} / ${ms(item.latency_p95_ms)}` },
    { title: '首字 P50', dataIndex: 'ttft_p50_ms', width: 100, render: ms },
    { title: '错误分布', key: 'errors', width: 170, render: (_: unknown, item: ProviderMonitorItem) => <ErrorBar item={item} /> },
    { title: '回退 出 / 入', key: 'fallback', width: 110, render: (_: unknown, item: ProviderMonitorItem) => `${item.fallback_out} / ${item.fallback_in}` },
  ]
  const trend = current?.hourly.map((p) => ({ label: new Date(p.at).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }), success: p.success_rate == null ? null : p.success_rate * 100, p95: p.latency_p95_ms == null ? null : p.latency_p95_ms / 1000 })) ?? []
  return <div className="provider-monitor">
    <div className="provider-totals" data-testid="provider-totals">
      <div><span>尝试次数</span><strong>{data ? data.totals.attempts.toLocaleString('zh-CN') : '—'}</strong></div>
      <div><span>整体成功率</span><strong>{rate(data?.totals.success_rate)}</strong></div>
      <div><span>回退次数</span><strong>{data ? data.totals.fallbacks.toLocaleString('zh-CN') : '—'}</strong></div>
      <div><span>首字 P50</span><strong>{ms(data?.totals.ttft_p50_ms)}</strong></div>
    </div>
    <Table size="small" rowKey={rowKey} dataSource={items} columns={columns} pagination={false} loading={query.isLoading} locale={{ emptyText: '所选窗口内没有渠道流量' }}
      onRow={(item) => ({ onClick: () => setSelected(rowKey(item)), className: rowKey(item) === selected ? 'provider-row-selected' : 'provider-row' })} />
    <div className="provider-legend">{ERRORS.map((e) => <span key={e.key}><i style={{ background: e.color }} />{e.label}</span>)}</div>
    {current && <div className="provider-detail" data-testid="provider-detail">
      <div className="provider-detail-chart">
        <Text strong>{current.provider_name} · 成功率与 P95 延迟</Text>
        {current.hourly.some((p) => p.attempts > 0) ? <ResponsiveContainer width="100%" height={240}><LineChart data={trend}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="label" minTickGap={40} /><YAxis yAxisId="rate" domain={[0, 100]} unit="%" /><YAxis yAxisId="lat" orientation="right" unit="s" /><ChartTooltip /><Legend /><Line yAxisId="rate" name="成功率" dataKey="success" stroke="var(--chart-1)" strokeWidth={2} dot={false} connectNulls={false} /><Line yAxisId="lat" name="P95 延迟" dataKey="p95" stroke="var(--chart-3)" strokeDasharray="4 3" dot={false} connectNulls={false} /></LineChart></ResponsiveContainer> : <Empty description="暂无趋势样本" />}
      </div>
      <div className="provider-detail-models">
        <Text strong>按模型</Text>
        <table><tbody>{current.models.map((m) => <tr key={m.model_id}><td>{m.model_name || m.model_id}</td><td>{m.attempts}</td><td style={{ color: levelColor[successLevel(m.success_rate)] }}>{rate(m.success_rate)}</td></tr>)}</tbody></table>
      </div>
    </div>}
  </div>
}

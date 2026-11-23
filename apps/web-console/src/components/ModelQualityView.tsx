import { useMemo, useState } from 'react'
import { Empty, Segmented, Space, Spin, Table, Tooltip, Typography } from 'antd'
import { AppstoreOutlined, BarChartOutlined, UnorderedListOutlined } from '@ant-design/icons'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts'
import type { ModelQualityItem } from '../services/modelOperations'
import { KpiCard, QualityCard, ThinCard, UnrecognisedRow } from './ModelQualityCard'
import { compactCount, isThin, msText, qualityKey, qualityLabel, qualitySummary, qualityThresholds, rankAmong, sortQuality, splitUnrecognised, type QualitySort } from '../utils/modelQuality'

const { Text } = Typography
type View = 'cards' | 'chart' | 'table'
const WINDOW_LABEL: Record<number, string> = { 6: '近 6 小时', 24: '近 24 小时', 72: '近 3 天', 168: '近 7 天' }
const BAR = 'var(--chart-1)'

export default function ModelQualityView({ items, loading, columns, onDiagnose, windowHours = 24 }: { items: ModelQualityItem[]; loading: boolean; columns: any[]; onDiagnose: (item: ModelQualityItem) => void; windowHours?: number }) {
  const [view, setView] = useState<View>('cards')
  const [sort, setSort] = useState<QualitySort>('samples')
  const windowLabel = WINDOW_LABEL[windowHours] ?? `近 ${windowHours} 小时`
  const { known, unknown } = useMemo(() => splitUnrecognised(items), [items])
  const sorted = useMemo(() => sortQuality(known, sort), [known, sort])
  const cards = useMemo(() => [...sorted.filter((item) => !isThin(item)), ...sorted.filter(isThin)], [sorted])
  const summary = useMemo(() => qualitySummary(items), [items])
  const chartData = sorted.slice(0, 20).map((item) => ({ key: qualityKey(item), name: qualityLabel(item), first: item.first_event_p50_ms ?? null, speed: item.output_tokens_per_sec_p50 ?? null }))
  const chartHeight = Math.max(160, chartData.length * 34 + 40)
  return <section className="mq-root" aria-label="真实流量质量">
    <div className="mq-kpis">
      <KpiCard label="真实请求" value={compactCount(summary.samples)} hint={summary.attention ? `可用率偏低 ${summary.attention} 个` : undefined} alert={summary.attention > 0} />
      <KpiCard label="上游可用率" value={summary.successRate == null ? '—' : `${(summary.successRate * 100).toFixed(2)}%`} hint={summary.errors ? `错误响应 ${compactCount(summary.errors)}` : undefined} alert={summary.successRate != null && summary.successRate < qualityThresholds.successRate.warn} />
      <KpiCard label="首字 P50（加权）" value={msText(summary.firstEventMs)} />
      <KpiCard label="输出速度（加权）" value={summary.tokensPerSec == null ? '—' : `${summary.tokensPerSec.toFixed(1)} t/s`} />
      <KpiCard label="每分钟请求 / 词元" value={`${compactCount(summary.rpm)} / ${compactCount(summary.tpm)}`} />
      <KpiCard label="网关处理 P50" value={msText(summary.gatewayMs)} />
    </div>
    <div className="mq-toolbar">
      <Space wrap>
        <Segmented<View> value={view} onChange={setView} options={[{ value: 'cards', label: '卡片', icon: <AppstoreOutlined /> }, { value: 'chart', label: '对比图', icon: <BarChartOutlined /> }, { value: 'table', label: '明细表', icon: <UnorderedListOutlined /> }]} />
        {view !== 'table' && <Segmented<QualitySort> value={sort} onChange={setSort} options={[{ value: 'samples', label: '按流量' }, { value: 'first', label: '首字最快' }, { value: 'speed', label: '输出最快' }, { value: 'success', label: '可用率最低' }]} />}
      </Space>
      <Space size={14} className="mq-legend"><span>{windowLabel} · {known.length} 个模型</span><Tooltip title="首字计时以首个文本、推理或工具事件为准；网关处理为发出上游前的耗时（含输入检测）；安全检测为输入与输出累计。每分钟请求数、词元数按所选完整窗口分钟数求均值（含空闲分钟）。"><Text type="secondary" className="mq-help">口径说明</Text></Tooltip></Space>
    </div>
    {loading && !items.length ? <div className="mq-empty"><Spin /></div> : !items.length ? <Empty className="mq-empty" description="所选窗口暂无真实流量证据" /> : <>
      {view === 'cards' && <>
        <div className="mq-grid">{cards.map((item) => isThin(item)
          ? <ThinCard key={qualityKey(item)} item={item} windowLabel={windowLabel} onDiagnose={onDiagnose} />
          : <QualityCard key={qualityKey(item)} item={item} firstRank={rankAmong(known, item, 'first')} speedRank={rankAmong(known, item, 'speed')} onDiagnose={onDiagnose} />)}</div>
        {unknown.length > 0 && <UnrecognisedRow items={unknown} />}
      </>}
      {view === 'chart' && <div className="mq-charts">
        <div className="mq-chart-box"><div className="mq-chart-title">首字 P50（秒，越短越好）</div><ResponsiveContainer width="100%" height={chartHeight}><BarChart layout="vertical" data={chartData} margin={{ left: 8, right: 24 }}><CartesianGrid strokeDasharray="3 3" horizontal={false} /><XAxis type="number" /><YAxis type="category" dataKey="name" width={150} tick={{ fontSize: 12 }} /><ChartTooltip formatter={(value) => msText(Number(value))} /><Bar dataKey="first" name="首字 P50" radius={[0, 4, 4, 0]}>{chartData.map((row) => <Cell key={row.key} fill={BAR} />)}</Bar></BarChart></ResponsiveContainer></div>
        <div className="mq-chart-box"><div className="mq-chart-title">输出速度（词元/秒，越长越好）</div><ResponsiveContainer width="100%" height={chartHeight}><BarChart layout="vertical" data={chartData} margin={{ left: 8, right: 24 }}><CartesianGrid strokeDasharray="3 3" horizontal={false} /><XAxis type="number" /><YAxis type="category" dataKey="name" width={150} tick={{ fontSize: 12 }} /><ChartTooltip formatter={(value) => `${Number(value).toFixed(1)} t/s`} /><Bar dataKey="speed" name="输出速度" radius={[0, 4, 4, 0]}>{chartData.map((row) => <Cell key={row.key} fill={BAR} />)}</Bar></BarChart></ResponsiveContainer></div>
      </div>}
      {view === 'table' && <Table size="small" rowKey={qualityKey} dataSource={items} columns={columns} pagination={{ pageSize: 25, showTotal: (total) => `共 ${total} 个模型上游`, showSizeChanger: false }} loading={loading} scroll={{ x: 2350 }} />}
    </>}
  </section>
}

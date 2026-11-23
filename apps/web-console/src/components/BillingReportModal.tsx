import { useCurrencyStore } from '../stores/currency'
import { formatMicrosDecimal, formatDecimalAmount, UNKNOWN_MONEY } from '../utils/money'
import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, DatePicker, Empty, Modal, Select, Space, Spin, Tag, message } from 'antd'
import { DownloadOutlined, FilePdfOutlined, FilterOutlined, ReloadOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import dayjs from 'dayjs'
import { billingAnalyticsApi } from '../services/api'
import { BillingReportFilters as ReportFilters, buildBillingReportParams } from '../utils/billingReport'

const { RangePicker } = DatePicker

type BillingSummary = {
  requests: number
  priced_requests: number
  unpriced_requests: number
  prompt_tokens: number
  cached_input_tokens: number
  cache_write_input_tokens: number
  output_tokens: number
  reasoning_tokens: number
  total_tokens: number
  billable_micros: number
  upstream_cost_micros: number
  upstream_cost_known_requests: number
  currency: string
}

type BillingBreakdown = BillingSummary & {
  id: string
  name: string
  secondary?: string
  cost_share: number
}

type BillingSeriesPoint = {
  bucket: string
  requests: number
  total_tokens: number
  billable_micros: number
  upstream_cost_micros: number
}

type DimensionKey = 'department' | 'project' | 'user' | 'model' | 'provider' | 'agent'

const emptySummary: BillingSummary = {
  requests: 0,
  priced_requests: 0,
  unpriced_requests: 0,
  prompt_tokens: 0,
  cached_input_tokens: 0,
  cache_write_input_tokens: 0,
  output_tokens: 0,
  reasoning_tokens: 0,
  total_tokens: 0,
  billable_micros: 0,
  upstream_cost_micros: 0,
  upstream_cost_known_requests: 0,
  currency: '',
}

const dimensionLabels: Record<DimensionKey, string> = {
  department: '部门费用',
  project: '应用费用',
  user: '个人费用',
  model: '模型费用',
  provider: '渠道费用',
  agent: '智能体费用',
}

function initialFilters(range: [dayjs.Dayjs, dayjs.Dayjs]): ReportFilters {
  return {
    range: [range[0], range[1]],
    departmentIds: [],
    projectIds: [],
    userIds: [],
    modelIds: [],
    providerIds: [],
    agentTypes: [],
  }
}

function compact(value: number) {
  return new Intl.NumberFormat('zh-CN', { notation: 'compact', maximumFractionDigits: 2 }).format(value || 0)
}

function percent(value: number) {
  return `${Math.max(0, Math.min(100, value)).toFixed(1)}%`
}

function money(micros: number, currency: string = useCurrencyStore.getState().tenantCurrency) {
  const amount = Number.isInteger(micros)
    ? formatMicrosDecimal(micros, { grouped: true })
    : formatDecimalAmount(micros / 1_000_000, { grouped: true })
  const symbol = currency === 'USD' ? '$' : '¥'
  return amount?.startsWith('-') ? `-${symbol}${amount.slice(1)}` : `${symbol}${amount ?? UNKNOWN_MONEY}`
}

function filterOptions(rows: BillingBreakdown[] = []) {
  return rows.filter((row) => row.id).map((row) => ({
    value: row.id,
    label: row.secondary ? `${row.name} · ${row.secondary}` : row.name,
  }))
}

function CostTrendChart({ data, currency }: { data: BillingSeriesPoint[]; currency: string }) {
  if (!data.length) return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无趋势数据" />
  const width = 820
  const height = 238
  const chartTop = 24
  const chartBottom = 190
  const max = Math.max(1, ...data.map((point) => point.billable_micros || 0))
  const step = data.length === 1 ? 0 : (width - 72) / (data.length - 1)
  const x = (index: number) => data.length === 1 ? width / 2 : 52 + index * step
  const y = (value: number) => chartBottom - (value / max) * (chartBottom - chartTop)
  const line = data.map((point, index) => `${x(index)},${y(point.billable_micros)}`).join(' ')
  const area = `${x(0)},${chartBottom} ${line} ${x(data.length - 1)},${chartBottom}`
  const labelEvery = Math.max(1, Math.ceil(data.length / 6))
  return (
    <svg className="billing-report-trend" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="计费金额趋势">
      {[0, .25, .5, .75, 1].map((ratio) => {
        const lineY = chartBottom - ratio * (chartBottom - chartTop)
        return <g key={ratio}><line x1="52" x2={width - 20} y1={lineY} y2={lineY} className="billing-report-grid-line" /><text x="46" y={lineY + 4} textAnchor="end">{money(max * ratio, currency)}</text></g>
      })}
      <polygon points={area} className="billing-report-trend-area" />
      <polyline points={line} className="billing-report-trend-line" />
      {data.map((point, index) => <circle key={point.bucket} cx={x(index)} cy={y(point.billable_micros)} r="3.5" className="billing-report-trend-dot"><title>{dayjs(point.bucket).format('YYYY-MM-DD')} · {money(point.billable_micros, currency)}</title></circle>)}
      {data.map((point, index) => index % labelEvery === 0 || index === data.length - 1 ? <text key={`label-${point.bucket}`} x={x(index)} y="218" textAnchor="middle">{dayjs(point.bucket).format('MM-DD')}</text> : null)}
    </svg>
  )
}

function TokenComposition({ summary }: { summary: BillingSummary }) {
  const items = [
    { label: '普通输入', value: Math.max(0, summary.prompt_tokens - summary.cached_input_tokens - summary.cache_write_input_tokens), color: 'var(--chart-6)' },
    { label: '缓存命中', value: summary.cached_input_tokens, color: 'var(--chart-1)' },
    { label: '缓存写入', value: summary.cache_write_input_tokens, color: 'var(--chart-2)' },
    { label: '普通输出', value: Math.max(0, summary.output_tokens - summary.reasoning_tokens), color: 'var(--chart-5)' },
    { label: '推理 Token', value: summary.reasoning_tokens, color: 'var(--chart-3)' },
  ]
  const total = Math.max(1, items.reduce((sum, item) => sum + item.value, 0))
  return <div className="billing-report-token-composition">
    <div className="billing-report-token-bar">{items.map((item) => item.value > 0 ? <span key={item.label} style={{ width: `${item.value / total * 100}%`, background: item.color }} title={`${item.label} ${compact(item.value)}`} /> : null)}</div>
    <div className="billing-report-token-legend">{items.map((item) => <div key={item.label}><i style={{ background: item.color }} /><span>{item.label}</span><strong>{compact(item.value)}</strong><small>{percent(item.value / total * 100)}</small></div>)}</div>
  </div>
}

function RankCard({ dimension, rows, summary, currency }: { dimension: DimensionKey; rows: BillingBreakdown[]; summary: BillingSummary; currency: string }) {
  const topRows = rows.slice(0, 5)
  const max = Math.max(1, ...topRows.map((row) => row.billable_micros || 0))
  return <section className="billing-report-rank-card">
    <div className="billing-report-rank-heading"><h4>{dimensionLabels[dimension]}</h4><span>TOP {topRows.length || 0}</span></div>
    {topRows.length ? <div className="billing-report-rank-list">{topRows.map((row, index) => {
      const share = summary.billable_micros > 0 ? row.billable_micros / summary.billable_micros * 100 : 0
      return <div className="billing-report-rank-row" key={`${dimension}-${row.id || index}`}>
        <span className="billing-report-rank-index">{index + 1}</span>
        <div className="billing-report-rank-main"><div><strong title={row.name}>{row.name}</strong><span>{money(row.billable_micros, currency)}</span></div><div className="billing-report-rank-bar"><i style={{ width: `${row.billable_micros / max * 100}%` }} /></div><small>{compact(row.total_tokens)} Token · {percent(share)}</small></div>
      </div>
    })}</div> : <div className="billing-report-rank-empty">{dimension === 'agent' ? '暂无可识别智能体调用；普通 API 调用不会被强行归类。' : '暂无数据'}</div>}
  </section>
}

function Kpi({ label, value, note, tone = 'blue' }: { label: string; value: string; note: string; tone?: 'blue' | 'orange' | 'green' | 'purple' }) {
  return <div className={`billing-report-kpi tone-${tone}`}><span>{label}</span><strong>{value}</strong><small>{note}</small></div>
}

export function BillingReportModal({ open, initialRange, onClose }: {
  open: boolean
  initialRange: [dayjs.Dayjs, dayjs.Dayjs]
  onClose: () => void
}) {
  const currentCurrency = useCurrencyStore(state => state.currentCurrency)
  const [draft, setDraft] = useState<ReportFilters>(() => initialFilters(initialRange))
  const [applied, setApplied] = useState<ReportFilters>(() => initialFilters(initialRange))
  const [exportingCsv, setExportingCsv] = useState(false)
  const initialStart = initialRange[0].format('YYYY-MM-DD')
  const initialEnd = initialRange[1].format('YYYY-MM-DD')

  useEffect(() => {
    if (!open) return
    const next = initialFilters([dayjs(initialStart), dayjs(initialEnd)])
    setDraft(next)
    setApplied(next)
  }, [open, initialStart, initialEnd])

  const params = useMemo(() => ({ ...buildBillingReportParams(applied), currency: currentCurrency, limit: 20 }), [applied, currentCurrency])
  const optionParams = useMemo(() => ({ start_date: draft.range[0].format('YYYY-MM-DD'), end_date: draft.range[1].format('YYYY-MM-DD'), currency: currentCurrency, limit: 100 }), [draft.range, currentCurrency])
  const summaryQ = useQuery({ queryKey: ['billing-report', 'summary', params], queryFn: () => billingAnalyticsApi.summary(params), enabled: open })
  const seriesQ = useQuery({ queryKey: ['billing-report', 'series', params], queryFn: () => billingAnalyticsApi.series({ ...params, granularity: 'day' }), enabled: open })
  const departmentQ = useQuery({ queryKey: ['billing-report', 'department', params], queryFn: () => billingAnalyticsApi.breakdown('department', params), enabled: open })
  const projectQ = useQuery({ queryKey: ['billing-report', 'project', params], queryFn: () => billingAnalyticsApi.breakdown('project', params), enabled: open })
  const userQ = useQuery({ queryKey: ['billing-report', 'user', params], queryFn: () => billingAnalyticsApi.breakdown('user', params), enabled: open })
  const modelQ = useQuery({ queryKey: ['billing-report', 'model', params], queryFn: () => billingAnalyticsApi.breakdown('model', params), enabled: open })
  const providerQ = useQuery({ queryKey: ['billing-report', 'provider', params], queryFn: () => billingAnalyticsApi.breakdown('provider', params), enabled: open })
  const agentQ = useQuery({ queryKey: ['billing-report', 'agent', params], queryFn: () => billingAnalyticsApi.breakdown('agent', params), enabled: open })

  const optionDepartmentQ = useQuery({ queryKey: ['billing-report-options', 'department', optionParams], queryFn: () => billingAnalyticsApi.breakdown('department', optionParams), enabled: open })
  const optionProjectQ = useQuery({ queryKey: ['billing-report-options', 'project', optionParams], queryFn: () => billingAnalyticsApi.breakdown('project', optionParams), enabled: open })
  const optionUserQ = useQuery({ queryKey: ['billing-report-options', 'user', optionParams], queryFn: () => billingAnalyticsApi.breakdown('user', optionParams), enabled: open })
  const optionModelQ = useQuery({ queryKey: ['billing-report-options', 'model', optionParams], queryFn: () => billingAnalyticsApi.breakdown('model', optionParams), enabled: open })
  const optionProviderQ = useQuery({ queryKey: ['billing-report-options', 'provider', optionParams], queryFn: () => billingAnalyticsApi.breakdown('provider', optionParams), enabled: open })
  const optionAgentQ = useQuery({ queryKey: ['billing-report-options', 'agent', optionParams], queryFn: () => billingAnalyticsApi.breakdown('agent', optionParams), enabled: open })

  const queries = [summaryQ, seriesQ, departmentQ, projectQ, userQ, modelQ, providerQ, agentQ]
  const loading = queries.some((query) => query.isLoading || query.isFetching)
  const failed = queries.some((query) => query.isError)
  const summary: BillingSummary = { ...emptySummary, currency: currentCurrency, ...(summaryQ.data?.data || {}) }
  const series: BillingSeriesPoint[] = seriesQ.data?.data || []
  const dimensions: Record<DimensionKey, BillingBreakdown[]> = {
    department: departmentQ.data?.data || [],
    project: projectQ.data?.data || [],
    user: userQ.data?.data || [],
    model: modelQ.data?.data || [],
    provider: providerQ.data?.data || [],
    agent: agentQ.data?.data || [],
  }
  const currency = summary.currency || useCurrencyStore.getState().tenantCurrency
  const pricedCoverage = summary.requests > 0 ? summary.priced_requests / summary.requests * 100 : 0
  // 缓存命中率：缓存命中是 prompt_tokens 的子集，可直接相除。
  const cacheHitRate = summary.prompt_tokens > 0 ? summary.cached_input_tokens / summary.prompt_tokens * 100 : 0
  const topProject = dimensions.project[0]
  const topModel = dimensions.model[0]
  const topAgent = dimensions.agent.find((row) => row.id !== 'non-agent')
  const peak = series.reduce<BillingSeriesPoint | undefined>((top, point) => !top || point.billable_micros > top.billable_micros ? point : top, undefined)

  const labels = useMemo(() => {
    const collect = (rows: BillingBreakdown[] = []) => new Map(rows.map((row) => [row.id, row.name]))
    return {
      department: collect(optionDepartmentQ.data?.data), project: collect(optionProjectQ.data?.data),
      user: collect(optionUserQ.data?.data), model: collect(optionModelQ.data?.data),
      provider: collect(optionProviderQ.data?.data), agent: collect(optionAgentQ.data?.data),
    }
  }, [optionDepartmentQ.data, optionProjectQ.data, optionUserQ.data, optionModelQ.data, optionProviderQ.data, optionAgentQ.data])

  const activeFilterTags = [
    ...applied.departmentIds.map((id) => `部门：${labels.department.get(id) || id}`),
    ...applied.userIds.map((id) => `个人：${labels.user.get(id) || id}`),
    ...applied.projectIds.map((id) => `应用：${labels.project.get(id) || id}`),
    ...applied.modelIds.map((id) => `模型：${labels.model.get(id) || id}`),
    ...applied.providerIds.map((id) => `渠道：${labels.provider.get(id) || id}`),
    ...applied.agentTypes.map((id) => `智能体：${labels.agent.get(id) || id}`),
  ]

  const update = <K extends keyof ReportFilters>(key: K, value: ReportFilters[K]) => setDraft((current) => ({ ...current, [key]: value }))
  const reset = () => {
    const next = initialFilters(initialRange)
    setDraft(next)
    setApplied(next)
  }

  const exportCsv = async () => {
    setExportingCsv(true)
    try {
      const response = await billingAnalyticsApi.report(buildBillingReportParams(applied))
      const url = URL.createObjectURL(response.data)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `billing-report-detail-${applied.range[0].format('YYYYMMDD')}-${applied.range[1].format('YYYYMMDD')}.csv`
      anchor.click()
      URL.revokeObjectURL(url)
      message.success('计费明细 CSV 已导出')
    } catch {
      message.error('计费明细导出失败')
    } finally {
      setExportingCsv(false)
    }
  }

  const exportPdf = () => {
    const previousTitle = document.title
    document.title = `AI计费分析报告-${applied.range[0].format('YYYYMMDD')}-${applied.range[1].format('YYYYMMDD')}`
    window.print()
    document.title = previousTitle
  }

  return <Modal
    className="billing-report-modal"
    width={1180}
    open={open}
    onCancel={onClose}
    title={<span>AI 计费分析报告</span>}
    footer={<Space wrap>
      <Button onClick={onClose}>关闭</Button>
      <Button icon={<DownloadOutlined />} loading={exportingCsv} onClick={exportCsv}>下载明细 CSV</Button>
      <Button type="primary" icon={<FilePdfOutlined />} disabled={loading || failed} onClick={exportPdf}>导出 PDF</Button>
    </Space>}
  >
    <div className="billing-report-filter-panel">
      <div className="billing-report-filter-title"><div><FilterOutlined /><strong>报告筛选</strong><span>筛选条件会写入 PDF 抬头，并同步作用于全部图表与附表。</span></div><Button size="small" icon={<ReloadOutlined />} onClick={reset}>重置</Button></div>
      <div className="billing-report-filter-grid">
        <label className="range"><span>统计周期</span><RangePicker value={draft.range} allowClear={false} onChange={(range) => { if (range?.[0] && range?.[1]) update('range', [range[0], range[1]]) }} /></label>
        <label><span>部门</span><Select mode="multiple" allowClear maxTagCount="responsive" placeholder="全部部门" options={filterOptions(optionDepartmentQ.data?.data)} value={draft.departmentIds} onChange={(value) => update('departmentIds', value)} /></label>
        <label><span>个人</span><Select mode="multiple" allowClear maxTagCount="responsive" placeholder="全部个人" options={filterOptions(optionUserQ.data?.data)} value={draft.userIds} onChange={(value) => update('userIds', value)} /></label>
        <label><span>应用</span><Select mode="multiple" allowClear maxTagCount="responsive" placeholder="全部应用" options={filterOptions(optionProjectQ.data?.data)} value={draft.projectIds} onChange={(value) => update('projectIds', value)} /></label>
        <label><span>模型</span><Select mode="multiple" allowClear maxTagCount="responsive" placeholder="全部模型" options={filterOptions(optionModelQ.data?.data)} value={draft.modelIds} onChange={(value) => update('modelIds', value)} /></label>
        <label><span>渠道</span><Select mode="multiple" allowClear maxTagCount="responsive" placeholder="全部渠道" options={filterOptions(optionProviderQ.data?.data)} value={draft.providerIds} onChange={(value) => update('providerIds', value)} /></label>
        <label><span>智能体</span><Select mode="multiple" allowClear maxTagCount="responsive" placeholder="全部智能体" options={filterOptions(optionAgentQ.data?.data)} value={draft.agentTypes} onChange={(value) => update('agentTypes', value)} /></label>
        <Button type="primary" icon={<FilterOutlined />} onClick={() => setApplied({ ...draft, range: [draft.range[0], draft.range[1]] })}>应用筛选</Button>
      </div>
    </div>

    <Spin spinning={loading} tip="正在生成计费分析报告…">
      {failed ? <Alert type="error" showIcon message="报告数据加载失败" description="没有把查询失败伪装成 0 元。请重试或缩小筛选范围。" /> : <article className="billing-report-print-root">
        <header className="billing-report-cover">
          <div className="billing-report-brand"><span>AI</span><div><strong>AI 算力安全网关</strong><small>FINOPS · BILLING INTELLIGENCE</small></div></div>
          <div className="billing-report-cover-main"><span className="billing-report-kicker">企业 AI 成本经营报告</span><h1>AI 计费分析报告</h1><p>{applied.range[0].format('YYYY年MM月DD日')} — {applied.range[1].format('YYYY年MM月DD日')}</p></div>
          <div className="billing-report-cover-meta"><span>生成时间：{dayjs().format('YYYY-MM-DD HH:mm')}</span><span>币种：{currency}</span><span>口径：平台实际计费事实</span></div>
          <div className="billing-report-cover-filters">{activeFilterTags.length ? activeFilterTags.map((label) => <Tag key={label}>{label}</Tag>) : <Tag>全部组织与业务维度</Tag>}</div>
        </header>

        <section className="billing-report-section">
          <div className="billing-report-section-title"><div><span>01</span><div><h2>经营摘要</h2><p>先回答花了多少、用了多少、计费是否完整，再定位主要消耗来源。</p></div></div></div>
          <div className="billing-report-kpi-grid">
            <Kpi label="内部结算金额" value={money(summary.billable_micros, currency)} note={`平均单次 ${money(summary.requests ? summary.billable_micros / summary.requests : 0, currency)}`} tone="orange" />
            <Kpi label="计费 Token" value={compact(summary.total_tokens)} note={`输入 ${compact(summary.prompt_tokens)} · 输出 ${compact(summary.output_tokens)}`} tone="purple" />
            <Kpi label="调用请求" value={compact(summary.requests)} note={`${compact(summary.priced_requests)} 次已计费`} tone="blue" />
            <Kpi label="价格覆盖率" value={percent(pricedCoverage)} note={summary.unpriced_requests ? `${compact(summary.unpriced_requests)} 次调用未计费` : '计费价格覆盖完整'} tone={summary.unpriced_requests ? 'orange' : 'green'} />
            {/* 上游渠道成本恒空（upstream_cost_micros 无任何写入方），改为展示真实可用的缓存指标 */}
            <Kpi label="缓存命中 Token" value={compact(summary.cached_input_tokens)} note={summary.prompt_tokens ? `占输入 ${percent(cacheHitRate)}` : '暂无输入 Token'} tone={summary.cached_input_tokens ? 'green' : 'blue'} />
            <Kpi label="缓存写入 Token" value={compact(summary.cache_write_input_tokens)} note={summary.reasoning_tokens ? `推理 Token ${compact(summary.reasoning_tokens)}` : '首次写入缓存的输入'} tone="purple" />
          </div>
          <div className="billing-report-observations">
            <div><span>最高费用日</span><strong>{peak ? dayjs(peak.bucket).format('MM月DD日') : '-'}</strong><small>{peak ? money(peak.billable_micros, currency) : '暂无趋势'}</small></div>
            <div><span>最烧钱应用</span><strong>{topProject?.name || '-'}</strong><small>{topProject ? money(topProject.billable_micros, currency) : '暂无应用归属'}</small></div>
            <div><span>最烧钱模型</span><strong>{topModel?.name || '-'}</strong><small>{topModel ? money(topModel.billable_micros, currency) : '暂无模型归属'}</small></div>
            <div><span>主要智能体</span><strong>{topAgent?.name || '非智能体为主'}</strong><small>{topAgent ? money(topAgent.billable_micros, currency) : '未识别到智能体费用'}</small></div>
          </div>
          {summary.unpriced_requests > 0 && <div className="billing-report-attention"><strong>本期关注</strong><div><span>有 {compact(summary.unpriced_requests)} 次调用缺少价格，费用总额可能偏低。</span></div></div>}
        </section>

        <section className="billing-report-section billing-report-page-break">
          <div className="billing-report-section-title"><div><span>02</span><div><h2>费用与 Token 结构</h2><p>费用趋势用于识别突增日期，Token 构成用于判断缓存、输入、输出和推理消耗。</p></div></div></div>
          <div className="billing-report-analysis-grid">
            <div className="billing-report-panel wide"><div className="billing-report-panel-heading"><h3>计费金额趋势</h3><span>按日 · {currency}</span></div><CostTrendChart data={series} currency={currency} /></div>
            <div className="billing-report-panel"><div className="billing-report-panel-heading"><h3>Token 构成</h3><span>总计 {compact(summary.total_tokens)}</span></div><TokenComposition summary={summary} /></div>
          </div>
        </section>

        <section className="billing-report-section billing-report-page-break">
          <div className="billing-report-section-title"><div><span>03</span><div><h2>六维费用排行</h2><p>从组织、人员、业务、模型、渠道和智能体六个维度定位成本归属。</p></div></div></div>
          <div className="billing-report-rank-grid">{(Object.keys(dimensionLabels) as DimensionKey[]).map((dimension) => <RankCard key={dimension} dimension={dimension} rows={dimensions[dimension]} summary={summary} currency={currency} />)}</div>
        </section>

        <section className="billing-report-section billing-report-page-break">
          <div className="billing-report-section-title"><div><span>04</span><div><h2>模型计费明细</h2><p>列出本期费用最高的模型，核对请求、Token、计费覆盖与采购成本。</p></div></div></div>
          <div className="billing-report-table-wrap"><table><thead><tr><th>模型</th><th>渠道</th><th>请求</th><th>已计费</th><th>输入</th><th>缓存命中</th><th>输出</th><th>平台计费</th><th>费用占比</th></tr></thead><tbody>{dimensions.model.slice(0, 10).map((row) => <tr key={row.id}><td><strong>{row.name}</strong></td><td>{row.secondary || '-'}</td><td>{compact(row.requests)}</td><td>{compact(row.priced_requests)}</td><td>{compact(row.prompt_tokens)}</td><td>{row.prompt_tokens > 0 ? `${compact(row.cached_input_tokens)}（${percent(row.cached_input_tokens / row.prompt_tokens * 100)}）` : '-'}</td><td>{compact(row.output_tokens)}</td><td>{money(row.billable_micros, currency)}</td><td>{percent(summary.billable_micros ? row.billable_micros / summary.billable_micros * 100 : 0)}</td></tr>)}</tbody></table>{!dimensions.model.length && <div className="billing-report-rank-empty">暂无模型计费明细</div>}</div>
          <div className="billing-report-methodology"><h3>计费口径说明</h3><div><p><strong>金额：</strong>“平台计费金额”来自逐请求计费事实；未配置价格的调用不计入金额，并单独披露。</p><p><strong>Token：</strong>总 Token = 提示 Token + 输出 Token；缓存命中/写入属于提示 Token，推理 Token 属于输出 Token，结构图已去重展示。</p><p><strong>组织归属：</strong>部门、人员、应用、模型和实际落地渠道采用调用发生时快照，避免组织调整导致历史漂移。</p><p><strong>智能体：</strong>按同一请求审计记录中的 agent_type 关联；识别不到的调用归入“非智能体调用”，不做猜测。</p></div></div>
        </section>
        <footer className="billing-report-footer"><span>AI 算力安全网关 · 费用治理中心</span><span>筛选条件与生成时间已固化在报告中</span></footer>
      </article>}
    </Spin>
  </Modal>
}

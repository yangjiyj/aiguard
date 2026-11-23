import { formatMicrosDecimal, UNKNOWN_MONEY } from '../utils/money'
import { useMemo, useState } from 'react'
import { Alert, Button, DatePicker, Progress, Space, Table, Tabs, Tag, Typography, message } from 'antd'
import { FileExcelOutlined, FilePdfOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { useQuery } from '@tanstack/react-query'
import dayjs from 'dayjs'
import { billingAnalyticsApi, billingReportXlsxApi, usageApi, UsageRangeParams } from '../services/api'
import { formatLatencySeconds } from '../utils/modelProbe'
import { getCurrencyByCode, useCurrencyStore } from '../stores/currency'
import CurrencySelector from '../components/CurrencySelector'
import { CompactNumber, EnterprisePageHeader, MetricCard, SectionPanel, StatusPill } from '../components/EnterpriseUI'
import { BillingTrendChart, DistributionPie } from '../components/Charts'
import { toBeijingDateLabel } from '../utils/billingTrendTheme'
import { UserDetailDrawer } from '../components/UserDetailDrawer'
import { Col, Row } from 'antd'
import { compactNumber, percentValue, ratioToPercentText } from '../utils/format'
import { BillingReportModal } from '../components/BillingReportModal'
import ModelCostDistribution from '../components/billing/ModelCostDistribution'
import ModelIdentity from '../components/billing/ModelIdentity'
import { modelDisplayLabel } from '../components/billing/modelDisplay'

const { Text } = Typography
const { RangePicker } = DatePicker

type Summary = { requests: number; input_tokens: number; output_tokens: number; total_cost: number; data_fresh_until?: string }
type DimensionRow = {
  id: string
  name?: string
  provider_name?: string
  provider_type?: string
  model_id?: string
  project_id?: string
  project_name?: string
  user_id?: string
  username?: string
  key_prefix?: string
  requests: number
  input_tokens: number
  output_tokens: number
  total_tokens?: number
  total_cost: number
  billable_micros?: number
  cost_percent?: number
  average_cost?: number
  success_rate?: number
  budget_usage_rate?: number
  average_latency_ms?: number
  model_count?: number
  last_called_at?: string
  abnormal_growth?: boolean
}
type BillingBreakdownRow = { id: string; name: string; model_name?: string; model_label?: string; secondary?: string; requests: number; priced_requests: number; prompt_tokens?: number; cached_input_tokens?: number; cache_write_input_tokens?: number; output_tokens?: number; reasoning_tokens?: number; total_tokens: number; billable_micros: number; upstream_cost_micros: number; cost_share: number }
type BillingTimeProfileRow = { weekday: number; minute_of_day: number; tariff_band: string; requests: number; total_tokens: number; billable_micros: number }
type BillingMatrixRow = { department_id: string; department_name: string; provider_id: string; provider_name: string; requests: number; total_tokens: number; billable_micros: number }

const emptySummary: Summary = { requests: 0, input_tokens: 0, output_tokens: 0, total_cost: 0 }

type DashboardView = 'trend' | 'tokens' | 'organization' | 'time'

const DASHBOARD_VIEWS: Array<{ key: DashboardView; label: string }> = [
  { key: 'trend', label: '趋势与分布' },
  { key: 'tokens', label: 'Token 用量' },
  { key: 'organization', label: '部门与渠道' },
  { key: 'time', label: '时段分析' },
]

function Usage() {
  const [dateRange, setDateRange] = useState<[dayjs.Dayjs, dayjs.Dayjs]>([dayjs().subtract(30, 'days'), dayjs()])
  const { format, currentCurrency } = useCurrencyStore()
  const [usageDrawerUserId, setUsageDrawerUserId] = useState<string | null>(null)
  const [usageDrawerOpen, setUsageDrawerOpen] = useState(false)
  const [dashboardView, setDashboardView] = useState<DashboardView>('trend')
  const [reportOpen, setReportOpen] = useState(false)
  const [exportingXlsx, setExportingXlsx] = useState(false)

  const rangeParams = useMemo<UsageRangeParams>(() => ({ start_date: dateRange[0].format('YYYY-MM-DD'), end_date: dateRange[1].format('YYYY-MM-DD'), currency: currentCurrency }), [dateRange, currentCurrency])
  const exportXlsx = async () => {
    setExportingXlsx(true)
    try {
      const response = await billingReportXlsxApi.report(rangeParams)
      const url = URL.createObjectURL(response.data)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `billing-report-detail-${dateRange[0].format('YYYYMMDD')}-${dateRange[1].format('YYYYMMDD')}.xlsx`
      anchor.click()
      URL.revokeObjectURL(url)
      message.success('计费明细 XLSX 已导出')
    } catch {
      message.error('计费明细导出失败')
    } finally {
      setExportingXlsx(false)
    }
  }
  const summaryQ = useQuery({ queryKey: ['usage-summary', rangeParams], queryFn: () => usageApi.summary(rangeParams) })
  const byProjectQ = useQuery({ queryKey: ['usage-by-project', rangeParams], queryFn: () => usageApi.byProject(rangeParams) })
  const byModelQ = useQuery({ queryKey: ['usage-by-model', rangeParams], queryFn: () => usageApi.byModel(rangeParams) })
  const byUserQ = useQuery({ queryKey: ['usage-by-user', rangeParams], queryFn: () => usageApi.byUser(rangeParams) })
  const byKeyQ = useQuery({ queryKey: ['usage-by-key', rangeParams], queryFn: () => usageApi.byKey(rangeParams) })
  const byProviderQ = useQuery({ queryKey: ['usage-by-provider', rangeParams], queryFn: () => usageApi.byProvider(rangeParams) })
  const billingSummaryQ = useQuery({ queryKey: ['billing-analytics-summary', rangeParams], queryFn: () => billingAnalyticsApi.summary(rangeParams) })
  const billingDepartmentQ = useQuery({ queryKey: ['billing-analytics-department', rangeParams], queryFn: () => billingAnalyticsApi.breakdown('department', rangeParams) })
  const billingProviderQ = useQuery({ queryKey: ['billing-analytics-provider', rangeParams], queryFn: () => billingAnalyticsApi.breakdown('provider', rangeParams) })
  const billingBandQ = useQuery({ queryKey: ['billing-analytics-band', rangeParams], queryFn: () => billingAnalyticsApi.breakdown('tariff_band', rangeParams) })
  // 模型维度用于 Token 分项明细表(breakdown 与 summary 字段同构,已含缓存/推理分项)。
  const billingModelQ = useQuery({ queryKey: ['billing-analytics-model', rangeParams], queryFn: () => billingAnalyticsApi.breakdown('model', rangeParams) })
  const billingSeriesQ = useQuery({ queryKey: ['billing-analytics-series', rangeParams], queryFn: () => billingAnalyticsApi.series({ ...rangeParams, granularity: 'day' }) })
  const billingTimeProfileQ = useQuery({ queryKey: ['billing-analytics-time-profile', rangeParams], queryFn: () => billingAnalyticsApi.timeProfile({ ...rangeParams, timezone: 'Asia/Shanghai', interval_minutes: 60 }) })
  const billingMatrixQ = useQuery({ queryKey: ['billing-analytics-matrix', rangeParams], queryFn: () => billingAnalyticsApi.departmentProviderMatrix(rangeParams) })
  const billingAnalyticsQueries = [billingSummaryQ, billingDepartmentQ, billingProviderQ, billingBandQ, billingModelQ, billingSeriesQ, billingTimeProfileQ, billingMatrixQ]
  const billingAnalyticsError = billingAnalyticsQueries.some((query) => query.isError)
  const retryBillingAnalytics = () => billingAnalyticsQueries.forEach((query) => { if (query.isError) void query.refetch() })

  const summary: Summary = { ...emptySummary, ...(summaryQ.data?.data || {}) }
  const projectData: DimensionRow[] = byProjectQ.data?.data || []
  const modelData: DimensionRow[] = byModelQ.data?.data || []
  const userData: DimensionRow[] = byUserQ.data?.data || []
  const keyData: DimensionRow[] = byKeyQ.data?.data || []
  const providerData: DimensionRow[] = byProviderQ.data?.data || []
  const billingSummary = billingSummaryQ.data?.data || { requests: 0, priced_requests: 0, unpriced_requests: 0, prompt_tokens: 0, cached_input_tokens: 0, cache_write_input_tokens: 0, output_tokens: 0, reasoning_tokens: 0, total_tokens: 0, billable_micros: 0, upstream_cost_micros: 0, upstream_cost_known_requests: 0, currency: currentCurrency }
  const billingDepartments: BillingBreakdownRow[] = billingDepartmentQ.data?.data || []
  const billingProviders: BillingBreakdownRow[] = billingProviderQ.data?.data || []
  const billingBands: BillingBreakdownRow[] = billingBandQ.data?.data || []
  const billingModels: BillingBreakdownRow[] = billingModelQ.data?.data || []
  const billingTimeProfile: BillingTimeProfileRow[] = billingTimeProfileQ.data?.data || []
  const billingMatrix: BillingMatrixRow[] = billingMatrixQ.data?.data || []
  // 部门维度来自不可变计费事实，不再混用节省额口径。
  const teamData: DimensionRow[] = billingDepartments.map((r) => ({ id: r.id, name: r.name, requests: r.requests, input_tokens: r.total_tokens, output_tokens: 0, total_tokens: r.total_tokens, billable_micros: r.billable_micros, total_cost: r.billable_micros / 1_000_000 }))
  const billingProviderData: DimensionRow[] = billingProviders.map((r) => ({ id: r.id, name: r.name, provider_name: r.name, provider_type: r.secondary, requests: r.requests, input_tokens: r.total_tokens, output_tokens: 0, total_tokens: r.total_tokens, billable_micros: r.billable_micros, total_cost: r.billable_micros / 1_000_000, cost_percent: r.cost_share }))
  const billingSeriesData = (billingSeriesQ.data?.data || []).map((r: any) => ({ date: toBeijingDateLabel(r.bucket), cost: (r.billable_micros || 0) / 1_000_000, cost_micros: r.billable_micros || 0, tokens: r.total_tokens || 0 }))
  const departmentCostPie = billingDepartments.map((r) => ({ name: r.name, amount_micros: r.billable_micros, value: r.billable_micros / 1_000_000 })).filter((r) => r.value > 0).slice(0, 10)
  const providerCostPie = billingProviders.map((r) => ({ name: r.name, amount_micros: r.billable_micros, value: r.billable_micros / 1_000_000 })).filter((r) => r.value > 0).slice(0, 10)
  const bandNames: Record<string, string> = { peak: '高价时段', flat: '标准时段', valley: '优惠时段', custom: '自定义时段' }
  const bandCostPie = billingBands.map((r) => ({ name: bandNames[r.id] || r.name, amount_micros: r.billable_micros, value: r.billable_micros / 1_000_000 })).filter((r) => r.value > 0)
  const timeProfileMap = new Map<string, BillingTimeProfileRow>()
  billingTimeProfile.forEach((row) => {
    const key = `${row.weekday}-${row.minute_of_day}`
    const existing = timeProfileMap.get(key)
    timeProfileMap.set(key, existing ? { ...existing, requests: existing.requests + row.requests, total_tokens: existing.total_tokens + row.total_tokens, billable_micros: existing.billable_micros + row.billable_micros } : row)
  })
  const maxHeatCost = Math.max(1, ...Array.from(timeProfileMap.values()).map((row) => row.billable_micros))


  const billingRequests = Number(billingSummary.requests) || 0
  const billingPricedRequests = Number(billingSummary.priced_requests) || 0

  const promptTokens = Number(billingSummary.prompt_tokens) || 0
  const cachedInputTokens = Number(billingSummary.cached_input_tokens) || 0
  const cacheWriteInputTokens = Number(billingSummary.cache_write_input_tokens) || 0
  const outputTokens = Number(billingSummary.output_tokens) || 0
  const reasoningTokens = Number(billingSummary.reasoning_tokens) || 0
  const plainInputTokens = Math.max(0, promptTokens - cachedInputTokens - cacheWriteInputTokens)
  const plainOutputTokens = Math.max(0, outputTokens - reasoningTokens)
  const cacheHitRate = promptTokens > 0 ? (cachedInputTokens / promptTokens) * 100 : 0
  const tokenCompositionData = [
    { name: '普通输入', value: plainInputTokens },
    { name: '缓存命中输入', value: cachedInputTokens },
    { name: '缓存写入输入', value: cacheWriteInputTokens },
    { name: '普通输出', value: plainOutputTokens },
    { name: '推理输出', value: reasoningTokens },
  ].filter((item) => item.value > 0)
  const tokenRender = (v?: number) => <CompactNumber value={v} />
  const rangePresets: { label: string; value: [dayjs.Dayjs, dayjs.Dayjs] }[] = [
    { label: '今日', value: [dayjs().startOf('day'), dayjs()] },
    { label: '近 15 天', value: [dayjs().subtract(15, 'day'), dayjs()] },
    { label: '近 7 天', value: [dayjs().subtract(7, 'day'), dayjs()] },
    { label: '近 30 天', value: [dayjs().subtract(30, 'day'), dayjs()] },
    { label: '本月', value: [dayjs().startOf('month'), dayjs()] },
    { label: '上月', value: [dayjs().subtract(1, 'month').startOf('month'), dayjs().subtract(1, 'month').endOf('month')] },
  ]
  const trendEmpty = <span>暂无计费数据</span>
  const billAmount = (micros: unknown) => `${getCurrencyByCode(billingSummary.currency || currentCurrency).symbol}${formatMicrosDecimal(micros ?? 0) ?? UNKNOWN_MONEY}`
  const costRender = (v?: number) => <Text strong style={{ color: 'var(--brand-orange)' }}>{format(v || 0, 2)}</Text>
  const totalCostRender = (v: number, row: DimensionRow) => row.billable_micros != null ? <Text strong style={{ color: 'var(--brand-orange)' }}>{billAmount(row.billable_micros)}</Text> : costRender(v)
  // success_rate / cost_percent 来自 usage_governance.go（纯除法，是 0~1 的比率）。
  const percentRender = (v?: number) => ratioToPercentText(v)
  const freshUntilText = summary.data_fresh_until ? dayjs(summary.data_fresh_until).format('YYYY-MM-DD HH:mm') : ''

  const projectColumns: ColumnsType<DimensionRow> = [
    { title: '应用', dataIndex: 'name', key: 'name', ellipsis: true, render: (_: string, r) => r.name || r.project_name || r.project_id || '-' },
    { title: '请求数', dataIndex: 'requests', key: 'requests', render: tokenRender },
    { title: 'Token', dataIndex: 'total_tokens', key: 'total_tokens', render: (_: number, r) => tokenRender(r.total_tokens || r.input_tokens + r.output_tokens) },
    { title: '费用', dataIndex: 'total_cost', key: 'total_cost', render: totalCostRender },
    { title: '成功率', dataIndex: 'success_rate', key: 'success_rate', render: percentRender },
    // budget_usage_rate 来自 usage_governance.go（纯除法，是 0~1 的比率），需先乘 100 再截位。
    { title: '预算使用率', dataIndex: 'budget_usage_rate', key: 'budget_usage_rate', render: (v?: number) => <Progress percent={percentValue((v || 0) * 100)} size="small" /> },
  ]
  const modelColumns: ColumnsType<DimensionRow> = [
    { title: '模型', dataIndex: 'name', key: 'name', ellipsis: true }, { title: '供应商', dataIndex: 'provider_name', key: 'provider_name', ellipsis: true }, { title: '请求数', dataIndex: 'requests', key: 'requests', render: tokenRender }, { title: '输入 Token', dataIndex: 'input_tokens', key: 'input_tokens', render: tokenRender }, { title: '输出 Token', dataIndex: 'output_tokens', key: 'output_tokens', render: tokenRender }, { title: '费用', dataIndex: 'total_cost', key: 'total_cost', render: totalCostRender }, { title: '费用占比', dataIndex: 'cost_percent', key: 'cost_percent', render: percentRender }, { title: '平均单次成本', dataIndex: 'average_cost', key: 'average_cost', render: costRender },
  ]
  const userColumns: ColumnsType<DimensionRow> = [
    { title: '用户', dataIndex: 'username', key: 'username', ellipsis: true, render: (_: string, r) => r.username || r.name || r.user_id || '-' }, { title: '请求数', dataIndex: 'requests', key: 'requests', render: tokenRender }, { title: 'Token', dataIndex: 'total_tokens', key: 'total_tokens', render: (_: number, r) => tokenRender(r.total_tokens || r.input_tokens + r.output_tokens) }, { title: '费用', dataIndex: 'total_cost', key: 'total_cost', render: totalCostRender }, { title: '异常增长', dataIndex: 'abnormal_growth', key: 'abnormal_growth', render: (v?: boolean) => v ? <Tag color="orange">需关注</Tag> : <Tag>正常</Tag> },
  ]
  const keyColumns: ColumnsType<DimensionRow> = [
    { title: 'Key 前缀', dataIndex: 'key_prefix', key: 'key_prefix', ellipsis: true }, { title: '所属应用', dataIndex: 'project_name', key: 'project_name', ellipsis: true }, { title: '所属用户', dataIndex: 'username', key: 'username', ellipsis: true }, { title: '请求数', dataIndex: 'requests', key: 'requests', render: tokenRender }, { title: 'Token', dataIndex: 'total_tokens', key: 'total_tokens', render: (_: number, r) => tokenRender(r.total_tokens || r.input_tokens + r.output_tokens) }, { title: '费用', dataIndex: 'total_cost', key: 'total_cost', render: totalCostRender }, { title: '最后调用时间', dataIndex: 'last_called_at', key: 'last_called_at', render: (v?: string) => v ? dayjs(v).format('YYYY-MM-DD HH:mm') : '-' },
  ]
  const providerColumns: ColumnsType<DimensionRow> = [
    { title: '供应商', dataIndex: 'name', key: 'name', ellipsis: true }, { title: '模型数', dataIndex: 'model_count', key: 'model_count', render: tokenRender }, { title: '请求数', dataIndex: 'requests', key: 'requests', render: tokenRender }, { title: '费用', dataIndex: 'total_cost', key: 'total_cost', render: totalCostRender }, { title: '成功率', dataIndex: 'success_rate', key: 'success_rate', render: percentRender }, { title: '平均延迟', dataIndex: 'average_latency_ms', key: 'average_latency_ms', render: (v?: number) => formatLatencySeconds(v || 0) },
  ]
  const teamColumns: ColumnsType<DimensionRow> = [
    { title: '部门', dataIndex: 'name', key: 'name', ellipsis: true }, { title: '请求数', dataIndex: 'requests', key: 'requests', render: tokenRender }, { title: 'Token', dataIndex: 'total_tokens', key: 'total_tokens', render: (_: number, r) => tokenRender(r.total_tokens || r.input_tokens + r.output_tokens) }, { title: '费用', dataIndex: 'total_cost', key: 'total_cost', render: totalCostRender },
  ]
  const matrixColumns: ColumnsType<BillingMatrixRow> = [
    { title: '部门', dataIndex: 'department_name', key: 'department_name', ellipsis: true },
    { title: '渠道', dataIndex: 'provider_name', key: 'provider_name', ellipsis: true },
    { title: '请求数', dataIndex: 'requests', key: 'requests', render: tokenRender },
    { title: 'Token', dataIndex: 'total_tokens', key: 'total_tokens', render: tokenRender },
    { title: '计费金额', dataIndex: 'billable_micros', key: 'billable_micros', render: (v: number) => <Text strong>{billAmount(v || 0)}</Text> },
  ]
  const tokenBreakdownColumns: ColumnsType<BillingBreakdownRow> = [
    { title: '模型', dataIndex: 'name', key: 'name', ellipsis: true, render: (v: string, r) => {
      const modelName = r.model_name || v || r.id
      return <ModelIdentity modelName={modelName} label={modelDisplayLabel(modelName, [{ ...r, model_name: modelName }])} strong />
    } },
    { title: '调用', dataIndex: 'requests', key: 'requests', width: 90, align: 'right', render: tokenRender },
    { title: '输入(含缓存)', dataIndex: 'prompt_tokens', key: 'prompt_tokens', width: 120, align: 'right', render: tokenRender },
    { title: '缓存命中', dataIndex: 'cached_input_tokens', key: 'cached_input_tokens', width: 110, align: 'right', render: tokenRender },
    { title: '缓存写入', dataIndex: 'cache_write_input_tokens', key: 'cache_write_input_tokens', width: 110, align: 'right', render: tokenRender },
    { title: '输出', dataIndex: 'output_tokens', key: 'output_tokens', width: 100, align: 'right', render: tokenRender },
    { title: '图片数', dataIndex: 'image_count', key: 'image_count', width: 90, align: 'right', render: tokenRender },
    { title: '工具调用数', dataIndex: 'tool_call_count', key: 'tool_call_count', width: 110, align: 'right', render: tokenRender },
    { title: '推理', dataIndex: 'reasoning_tokens', key: 'reasoning_tokens', width: 90, align: 'right', render: tokenRender },
    {
      title: '缓存命中率', key: 'cache_rate', width: 110, align: 'right',
      render: (_: unknown, r) => {
        const prompt = Number(r.prompt_tokens) || 0
        if (prompt <= 0) return <Text type="secondary">-</Text>
        return <Tag color={(Number(r.cached_input_tokens) || 0) > 0 ? 'green' : 'default'}>{(((Number(r.cached_input_tokens) || 0) / prompt) * 100).toFixed(1)}%</Tag>
      },
    },
    { title: '计费金额', key: 'billable', width: 130, align: 'right', render: (_: unknown, r) => costRender((Number(r.billable_micros) || 0) / 1_000_000) },
  ]
  const tableProps = { size: 'middle' as const, pagination: { defaultPageSize: 10, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` } }

  return (
    <div className="enterprise-page">
      {billingSummary.other_currencies?.length > 0 && <Alert type="info" showIcon message={`本时间段还有 ${billingSummary.other_currencies.join('、')} 计价的历史用量，未计入；可切换币种查看`} style={{ marginBottom: 16 }} />}
      <EnterprisePageHeader
        eyebrow="模型费用治理中心"
        title="费用总览"
        actions={<Space size={8} wrap>
          <Button type="primary" icon={<FilePdfOutlined />} onClick={() => setReportOpen(true)}>生成计费报告</Button>
          <Button icon={<FileExcelOutlined />} loading={exportingXlsx} onClick={exportXlsx}>下载明细 XLSX</Button>
          <CurrencySelector />
          <RangePicker value={dateRange} onChange={(d) => { if (d?.[0] && d?.[1]) setDateRange([d[0], d[1]]) }} size="small" allowClear={false} presets={rangePresets} />
        </Space>}
        meta={<Space size={8} wrap><StatusPill tone={cacheHitRate > 0 ? 'green' : 'blue'}>缓存命中 {promptTokens > 0 ? cacheHitRate.toFixed(1) + '%' : '—'}</StatusPill>{freshUntilText ? <StatusPill tone="blue">数据更新至 {freshUntilText}</StatusPill> : null}</Space>}
      />
      {billingAnalyticsError ? (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 16 }}
          message="计费统计加载失败"
          description="计费事实或维度分析暂时不可用，不会把查询失败计作零费用。请检查服务状态后重试。"
          action={<Button onClick={retryBillingAnalytics}>重试</Button>}
        />
      ) : null}
      {!billingAnalyticsError ? <SectionPanel title="本期费用">
        <div className="enterprise-metric-grid four">
          <MetricCard label="本期计费金额" value={billAmount(billingSummary.billable_micros || 0)} tone="orange" />
          <MetricCard label="调用请求" valueNumber={billingSummary.requests || 0} tone="blue" />
          <MetricCard label="调用 Token" valueNumber={billingSummary.total_tokens || 0} tone="purple" hint={`输入 ${compactNumber(promptTokens)} · 输出 ${compactNumber(outputTokens)}`} />
          <MetricCard label="缓存命中 Token" valueNumber={cachedInputTokens} tone={cacheHitRate > 0 ? 'green' : 'blue'} hint={promptTokens > 0 ? `占输入 ${cacheHitRate.toFixed(1)}%` : '暂无输入 Token'} />
        </div>
        <div className="billing-dashboard-switcher" role="tablist" aria-label="计费分析视图">
          {DASHBOARD_VIEWS.map((item) => (
            <button
              key={item.key}
              type="button"
              role="tab"
              aria-selected={dashboardView === item.key}
              className={dashboardView === item.key ? 'is-active' : ''}
              onClick={() => setDashboardView(item.key)}
            >
              <strong>{item.label}</strong>
            </button>
          ))}
        </div>

        <div className="billing-dashboard-content">
          {dashboardView === 'trend' ? (
              <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
                <Col xs={24} xl={16}>
                  <SectionPanel title="计费金额趋势">
                    <BillingTrendChart data={billingSeriesData} currency={billingSummary.currency || currentCurrency} empty={trendEmpty} />
                  </SectionPanel>
                </Col>
                <Col xs={24} xl={8}>
                  <SectionPanel title="模型成本分布"><ModelCostDistribution data={billingModels} currency={billingSummary.currency || currentCurrency} /></SectionPanel>
                </Col>
              </Row>
          ) : dashboardView === 'tokens' ? (
              <SectionPanel title="Token 构成与计费用量">
                <div className="enterprise-metric-grid six">
                  <MetricCard label="输入 Token（含缓存）" valueNumber={promptTokens} tone="blue" hint={`普通输入 ${compactNumber(plainInputTokens)}`} />
                  <MetricCard label="缓存命中 Token" valueNumber={cachedInputTokens} tone={cachedInputTokens > 0 ? 'green' : 'blue'} hint={promptTokens > 0 ? `占输入 ${cacheHitRate.toFixed(1)}%` : '暂无输入'} />
                  <MetricCard label="缓存写入 Token" valueNumber={cacheWriteInputTokens} tone="purple" hint="首次写入缓存的输入" />
                  <MetricCard label="输出 Token" valueNumber={outputTokens} tone="orange" hint={`普通输出 ${compactNumber(plainOutputTokens)}`} />
                  <MetricCard label="推理 Token" valueNumber={reasoningTokens} tone="purple" hint="属于输出子集；独立推理价优先，未配置时使用输出价" />
                  <MetricCard label="计费调用" valueNumber={billingPricedRequests} unit="次" tone="green" hint={`共 ${compactNumber(billingRequests)} 次调用`} />
                </div>
                <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
                  <Col xs={24} xl={9}>
                    <SectionPanel title="Token 构成占比">
                      {tokenCompositionData.length > 0
                        ? <DistributionPie data={tokenCompositionData} unit="tok" />
                        : <div style={{ height: 220, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)', fontSize: 13 }}>当前范围暂无 Token 用量</div>}
                    </SectionPanel>
                  </Col>
                  <Col xs={24} xl={15}>
                    <SectionPanel title="按模型的 Token 与计费明细">
                      <Table
                        {...tableProps}
                        className="enterprise-table-tight"
                        columns={tokenBreakdownColumns}
                        dataSource={billingModels}
                        rowKey={(r) => r.id || r.name}
                        loading={billingModelQ.isLoading}
                      />
                    </SectionPanel>
                  </Col>
                </Row>
              </SectionPanel>
          ) : dashboardView === 'organization' ? (
            <Tabs className="billing-overview-tabs" defaultActiveKey="share" items={[
              { key: 'share', label: '费用占比', forceRender: true, children: (
              <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
                <Col xs={24} md={12}>
                  <SectionPanel title="部门费用占比"><DistributionPie data={departmentCostPie} unit={currentCurrency === 'USD' ? '美元' : '元'} /></SectionPanel>
                </Col>
                <Col xs={24} md={12}>
                  <SectionPanel title="渠道费用占比"><DistributionPie data={providerCostPie} unit={currentCurrency === 'USD' ? '美元' : '元'} /></SectionPanel>
                </Col>
              </Row>
              ) },
              { key: 'matrix', label: '部门 × 渠道', forceRender: true, children: (
              <SectionPanel title="部门 × 渠道费用明细">
                <Table {...tableProps} className="enterprise-table-tight" columns={matrixColumns} dataSource={billingMatrix} rowKey={(r) => r.department_id + ':' + r.provider_id} loading={billingMatrixQ.isLoading} />
              </SectionPanel>
              ) },
              { key: 'dimensions', label: '多维下钻', forceRender: true, children: (
              <SectionPanel title="多维成本">
                <Tabs items={[
                  { key: 'project', label: '按应用', children: <Table {...tableProps} className="enterprise-table-tight" columns={projectColumns} dataSource={projectData} rowKey={(r) => r.id || r.project_id || ''} loading={byProjectQ.isLoading} /> },
                  { key: 'model', label: '按模型', children: <Table {...tableProps} className="enterprise-table-tight" columns={modelColumns} dataSource={modelData} rowKey={(r) => r.id || r.model_id || ''} loading={byModelQ.isLoading} /> },
                  { key: 'user', label: '按用户', children: (
                    <Table
                      {...tableProps}
                      className="enterprise-table-tight"
                      columns={userColumns}
                      dataSource={userData}
                      rowKey={(r) => r.id || r.user_id || ''}
                      loading={byUserQ.isLoading}
                      onRow={(r: DimensionRow) => ({
                        onClick: () => {
                          const uid = r.user_id || r.id
                          if (uid) {
                            setUsageDrawerUserId(uid)
                            setUsageDrawerOpen(true)
                          }
                        },
                        style: { cursor: 'pointer' },
                      })}
                    />
                  ) },
                  { key: 'key', label: '按 API Key', children: <Table {...tableProps} className="enterprise-table-tight" columns={keyColumns} dataSource={keyData} rowKey={(r) => r.id || r.key_prefix || ''} loading={byKeyQ.isLoading} /> },
                  { key: 'provider', label: '按供应商', children: <Table {...tableProps} className="enterprise-table-tight" columns={providerColumns} dataSource={billingProviderData.length ? billingProviderData : providerData} rowKey={(r) => r.id || r.name || ''} loading={billingProviderQ.isLoading || byProviderQ.isLoading} /> },
                  { key: 'team', label: '按部门', children: <Table {...tableProps} className="enterprise-table-tight" columns={teamColumns} dataSource={teamData} rowKey={(r) => r.id || ''} loading={billingDepartmentQ.isLoading} /> },
                ]} />
              </SectionPanel>
              ) },
            ]} />
          ) : (
            <>
              <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
                <Col xs={24} lg={16}>
                  <SectionPanel title="调用时段热力图">
                    <div style={{ overflowX: 'auto' }}>
                      <div style={{ minWidth: 920, display: 'grid', gridTemplateColumns: '64px repeat(24, minmax(30px, 1fr))', gap: 3, alignItems: 'center' }}>
                        <div />
                        {Array.from({ length: 24 }, (_, hour) => <Text key={'h-' + hour} type="secondary" style={{ fontSize: 11, textAlign: 'center' }}>{hour % 3 === 0 ? hour + ':00' : ''}</Text>)}
                        {['周一', '周二', '周三', '周四', '周五', '周六', '周日'].flatMap((weekdayName, weekdayIndex) => [
                          <Text key={'d-' + weekdayIndex} type="secondary">{weekdayName}</Text>,
                          ...Array.from({ length: 24 }, (_, hour) => {
                            const point = timeProfileMap.get((weekdayIndex + 1) + '-' + (hour * 60))
                            const ratio = (point?.billable_micros || 0) / maxHeatCost
                            return <div key={'c-' + weekdayIndex + '-' + hour} title={weekdayName + ' ' + hour + ':00 · ' + billAmount(point?.billable_micros || 0) + ' · ' + (point?.requests || 0) + ' 次'} style={{ height: 28, borderRadius: 5, background: 'rgba(22,119,255,' + (0.06 + ratio * 0.88) + ')', border: '1px solid rgba(22,119,255,.12)' }} />
                          }),
                        ])}
                      </div>
                    </div>
                  </SectionPanel>
                </Col>
                <Col xs={24} lg={8}>
                  <SectionPanel title="时段计费占比"><DistributionPie data={bandCostPie} unit={currentCurrency === 'USD' ? '美元' : '元'} /></SectionPanel>
                </Col>
              </Row>
              <SectionPanel title="计费金额趋势">
                <BillingTrendChart data={billingSeriesData} currency={billingSummary.currency || currentCurrency} empty={trendEmpty} />
              </SectionPanel>
            </>
          )}
        </div>
      </SectionPanel> : null}

      <UserDetailDrawer
        open={usageDrawerOpen}
        userId={usageDrawerUserId}
        initialTab="7"
        onClose={() => setUsageDrawerOpen(false)}
      />
      <BillingReportModal open={reportOpen} initialRange={dateRange} onClose={() => setReportOpen(false)} />
    </div>
  )
}

export default Usage

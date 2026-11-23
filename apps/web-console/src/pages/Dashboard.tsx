import { useMemo, useState } from 'react'
import { Alert, Button, Col, Progress, Row, Segmented, Space, Spin, Table, Tabs, Tag, Typography, message } from 'antd'
import { ApartmentOutlined, ApiOutlined, BarChartOutlined, DashboardOutlined, DownloadOutlined, FundOutlined, KeyOutlined, ProjectOutlined, TeamOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { accessRetentionApi, boundedTimeWindowParams, budgetApi, keyApi, projectApi, statsApi, usageApi, ws8StatsApi } from '../services/api'
import { alertOccurrencesApi } from '../services/alertOccurrences'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import { useAuthStore } from '../stores/auth'
import { useCurrencyStore } from '../stores/currency'
import { CompactNumber, EnterprisePageHeader, MetricCard, SectionPanel } from '../components/EnterpriseUI'
import { DistributionPie, ModelShareRadial, RankedList, TrendArea } from '../components/Charts'
import AgentStats from './AgentStats'
import { getRiskCategoryLabel } from '../utils/risk'
import { fetchBillingBreakdownMerged, fetchBillingSeriesMerged, fetchBillingSummaryMerged } from '../utils/billingRange'
import type { BillingDimension } from '../utils/billingRange'
import { buildReportDocx, downloadBlob, safeFilename } from '../utils/reportExport'
import type { ReportBlock } from '../utils/reportExport'
import { compactNumber, percentValue, ratioToPercentText } from '../utils/format'
import ReportRangeSelector from '../components/ReportRangeSelector'
import { METRICS_DEFINITION_NOTE, formatInTimezone, nowInTimezone, reportMetaItems, resolveReportRange, useReportContext } from '../utils/ws8ReportRange'
import type { CustomDateRange, ReportRangeKey } from '../utils/ws8ReportRange'
import { productCopy, resolveProductIdentity } from '../product/profiles'
import type { ProductIdentity } from '../product/profiles'
import { productApi } from '../services/api'

const { Text } = Typography

const ORG_STATS_ROLES = new Set(['platform_admin', 'tenant_owner', 'tenant_admin', 'admin', 'team_owner', 'auditor'])
const canViewOrgStatsRole = (role?: string) => !!role && ORG_STATS_ROLES.has(role)

// 「用量与费用」和各维度统计共用的时间范围选项（W8：补自然周/月与自定义起止）。
// 计费分析接口单次查询硬限 366 天，长跨度切片逻辑统一在 utils/billingRange.ts。
// 「所有时间」的起点取 /stats/overview 下发的 data_start（最早有用量数据的自然日），不再写死。
// 用量接口按自然日取数，因此最短档是「今天」而不是滚动 24 小时，标题与数据保持一致。
const OVERVIEW_RANGE_KEYS: ReportRangeKey[] = ['today', '7d', '30d', '90d', 'this_week', 'last_week', 'this_month', 'last_month', 'all', 'custom']

const BILLING_DIMENSIONS: { key: BillingDimension; label: string }[] = [
  { key: 'department', label: '部门' },
  { key: 'user', label: '人员' },
  { key: 'model', label: '模型' },
  { key: 'project', label: '应用' },
  { key: 'provider', label: '渠道' },
]

function GatewayDashboard({ product }: { product: ProductIdentity }) {
  const [activeTab, setActiveTab] = useState('overview')
  const { user } = useAuthStore()
  const copy = productCopy[product.profile]
  const navigate = useNavigate()
  const canViewOrgStats = canViewOrgStatsRole(user?.role)
  // W8：统计时区、数据起点与执行模式统一来自 /stats/overview（租户时区，缺省 Asia/Shanghai）。
  const reportCtx = useReportContext()
  const reportTz = reportCtx.timezone
  // 系统概览维持既有口径：实时快照 + 近30天面板 + 近24小时告警。刻意不在这里加时间范围切换，
  // 避免改变客户已经熟悉的首页数字；时间范围只在「用量与费用」及各统计 Tab 内生效。
  // 日界按租户时区切分，与后端 usage/stats 接口一致。
  const dashboardUsageRange = useMemo(() => {
    const range = resolveReportRange('30d', { timezone: reportTz })
    return { access: range.window, usage: range.dates }
  }, [reportTz])
  const securityAlertWindow = useMemo(() => boundedTimeWindowParams(24), [])

  // 「用量与费用」Tab 自带时间范围，包含自然周/月、自定义起止与“所有时间”。
  const [billingRangeKey, setBillingRangeKey] = useState<ReportRangeKey>('30d')
  const [billingCustom, setBillingCustom] = useState<CustomDateRange | null>(null)
  const billingResolved = useMemo(
    () => resolveReportRange(billingRangeKey, { timezone: reportTz, dataStart: reportCtx.dataStart, custom: billingCustom }),
    [billingRangeKey, billingCustom, reportTz, reportCtx.dataStart],
  )
  const billingRangeLabel = billingResolved.label
  const selectedCurrency = useCurrencyStore(state => state.currentCurrency)
  const billingRange = useMemo(() => ({ ...billingResolved.dates, currency: selectedCurrency }), [billingResolved.dates, selectedCurrency])

  // 密钥、用户、应用、模型和智能体统计共用同一时间范围，避免各 Tab 口径不一致。
  const [statisticsRangeKey, setStatisticsRangeKey] = useState<ReportRangeKey>('30d')
  const [statisticsCustom, setStatisticsCustom] = useState<CustomDateRange | null>(null)
  const statisticsResolved = useMemo(
    () => resolveReportRange(statisticsRangeKey, { timezone: reportTz, dataStart: reportCtx.dataStart, custom: statisticsCustom }),
    [statisticsRangeKey, statisticsCustom, reportTz, reportCtx.dataStart],
  )
  const statisticsRangeLabel = statisticsResolved.label
  const statisticsRange = useMemo(
    () => ({ usage: statisticsResolved.dates, stats: statisticsResolved.iso }),
    [statisticsResolved],
  )

  // W8 8.12：首屏只发「系统概览」需要的请求，其余 Tab 在首次切到时才取数。
  const onOverview = activeTab === 'overview'
  const onUsers = activeTab === 'users'
  const onKeys = activeTab === 'keys'
  const onApps = activeTab === 'apps'
  const onModels = activeTab === 'models'
  const onOrg = activeTab === 'org'

  const overviewQ = { isLoading: reportCtx.isLoading }
  // 8.1：排行与占比分母来自同一次请求、同一窗口（with_totals），分母是窗口内已归属用户的合计。
  const userTokenQ = useQuery({ queryKey: ['stats', 'users', 'tokens', 'with-totals', statisticsRange.stats], queryFn: () => ws8StatsApi.getUserStatsWithTotals('tokens', 10, statisticsRange.stats), enabled: onUsers })
  const userReqQ = useQuery({ queryKey: ['stats', 'users', 'requests', 'with-totals', statisticsRange.stats], queryFn: () => ws8StatsApi.getUserStatsWithTotals('requests', 10, statisticsRange.stats), enabled: onUsers })
  // 应用用量同时服务首页「应用调用 TOP」与应用统计 Tab，两处共用统计范围（8.4：标题随范围变化）。
  const appQ = useQuery({ queryKey: ['usage', 'by-project', statisticsRange.usage], queryFn: () => usageApi.byProject(statisticsRange.usage), enabled: onOverview || onApps })
  const keyListQ = useQuery({ queryKey: ['keys', 'current'], queryFn: () => keyApi.list(), enabled: onKeys })
  const projectListQ = useQuery({ queryKey: ['projects', 'current'], queryFn: () => projectApi.list(), enabled: onOverview || onApps })
  const modelQ = useQuery({ queryKey: ['stats', 'models', statisticsRange.stats], queryFn: () => statsApi.getModelStats(10, statisticsRange.stats), enabled: onModels })
  const orgStatsQ = useQuery({ queryKey: ['stats', 'org'], queryFn: () => statsApi.getOrgStats(), enabled: canViewOrgStats && onOrg })
  const byKeyQ = useQuery({ queryKey: ['usage', 'by-key', statisticsRange.usage], queryFn: () => usageApi.byKey(statisticsRange.usage), enabled: onKeys })
  const usageQ = useQuery({ queryKey: ['usage-summary', dashboardUsageRange.usage], queryFn: () => usageApi.summary(dashboardUsageRange.usage), enabled: onOverview })
  const trafficSummaryQ = useQuery({
    queryKey: ['dashboard-traffic-summary', dashboardUsageRange.access],
    queryFn: () => accessRetentionApi.getSummary({ ...dashboardUsageRange.access, access_type: 'all', summary_detail: 'counts' }),
    enabled: onOverview,
  })
  const snapshotQ = useQuery({
    queryKey: ['budget-snapshot-dashboard'],
    queryFn: () => budgetApi.snapshot({ scope_type: 'tenant' }),
    refetchInterval: onOverview ? 30000 : false,
    staleTime: 30000,
    enabled: onOverview,
  })
  const trendQ = useQuery({ queryKey: ['usage-trend', dashboardUsageRange.usage], queryFn: () => usageApi.trend(dashboardUsageRange.usage), enabled: onOverview })
  const modelDistQ = useQuery({ queryKey: ['usage', 'by-model', dashboardUsageRange.usage], queryFn: () => usageApi.byModel(dashboardUsageRange.usage), enabled: onOverview })
  const alertIdentity = useAuditQueryIdentity()
  const securityAlertsQ = useQuery({
    queryKey: ['alert-case-summary', alertIdentity, securityAlertWindow],
    queryFn: ({signal}) => alertOccurrencesApi.summary({
      grouping: 'cases', disposition: 'pending', start_time: securityAlertWindow.from,
      end_time: securityAlertWindow.to, signal,
    }),
    staleTime: 15000,
    retry: false,
    enabled: onOverview,
  })
  const alertLink = (category?: string) => '/security/alerts?' + new URLSearchParams({
    window_hours: '24', start_time: securityAlertWindow.from, end_time: securityAlertWindow.to,
    ...(category ? {risk_category: category} : {}),
  }).toString()

  const [billingDimension, setBillingDimension] = useState<BillingDimension>('department')
  // 只在切到「用量与费用」时才发计费请求：首页首屏不该为它多打三组计费分析接口。
  const billingEnabled = activeTab === 'billing'
  const billingSummaryQ = useQuery({
    queryKey: ['dashboard-billing-summary', billingRange],
    queryFn: () => fetchBillingSummaryMerged(billingRange),
    enabled: billingEnabled,
  })
  const billingBreakdownQ = useQuery({
    queryKey: ['dashboard-billing-breakdown', billingDimension, billingRange],
    queryFn: () => fetchBillingBreakdownMerged(billingDimension, billingRange),
    enabled: billingEnabled,
  })
  const billingSeriesQ = useQuery({
    queryKey: ['dashboard-billing-series', billingRange],
    queryFn: () => fetchBillingSeriesMerged(billingRange),
    enabled: billingEnabled,
  })
  const formatCurrency = useCurrencyStore((state) => state.format)

  const overview: any = reportCtx.overview
  // 今日数据优先用 Redis 实时快照（跟用量监控同源），不再用 rollup 延迟数据
  const snapRaw = snapshotQ.data?.data
  const snapObj = (snapRaw?.data && typeof snapRaw.data === 'object') ? snapRaw.data : snapRaw
  const snap = Array.isArray(snapObj) ? (snapObj[0] || {}) : (snapObj || {})
  // 今日请求/Token: 取 Redis 实时快照与 DB 口径的较大值。
  // 原因: Redis 计数在 gateway-core 重启后从 0 重新累加(内存计数不持久化),
  // 会用一个偏小的值盖住 DB 里真实的大值。取 max 保证重启后不回退显示。
  const snapReq = Number(snap.day_requests) || 0
  const snapTok = Number(snap.day_tokens) || 0
  const dbReq = Number(overview.today_requests) || 0
  const dbTok = Number(overview.today_tokens) || 0
  const todayRequests = Math.max(snapReq, dbReq)
  const todayTokens = Math.max(snapTok, dbTok)
  const userTokens: any[] = userTokenQ.data?.data?.data || []
  const userRequests: any[] = userReqQ.data?.data?.data || []
  const userTokenDenominator = Number(userTokenQ.data?.data?.totals?.total_tokens) || 0
  const userRequestDenominator = Number(userReqQ.data?.data?.totals?.total_requests) || 0
  const keyListResponse: any = keyListQ.data?.data
  const projectListResponse: any = projectListQ.data?.data
  const currentKeys: any[] = Array.isArray(keyListResponse?.data) ? keyListResponse.data : Array.isArray(keyListResponse) ? keyListResponse : []
  const currentProjects: any[] = Array.isArray(projectListResponse?.data) ? projectListResponse.data : Array.isArray(projectListResponse) ? projectListResponse : []
  const currentKeyIDs = new Set(currentKeys.map((item: any) => item.id).filter(Boolean))
  const currentKeyPrefixes = new Set(currentKeys.map((item: any) => item.key_prefix).filter(Boolean))
  const currentProjectIDs = new Set(currentProjects.filter((item: any) => item.status !== 'deleted').map((item: any) => item.id).filter(Boolean))
  const appResponse: any = appQ.data?.data
  const appUsageRows: any[] = Array.isArray(appResponse?.data) ? appResponse.data : Array.isArray(appResponse) ? appResponse : []
  const apps = appUsageRows.filter((item: any) => currentProjectIDs.has(item.project_id || item.id))
  const models = modelQ.data?.data || []
  const trendData = (trendQ.data?.data?.data || []).map((d: any) => ({ date: d.date, tokens: (d.input_tokens || 0) + (d.output_tokens || 0), requests: d.requests || 0 }))
  // Merge the same public model across providers before ranking. Keep the tail
  // in the chart so its total and percentages cover every attributed call.
  const modelCalls = new Map<string, number>()
  for (const m of (modelDistQ.data?.data?.data || modelDistQ.data?.data || [])) {
    const name = m.name || m.model_name || '未识别模型'
    const value = Number(m.requests)
    if (Number.isFinite(value) && value > 0) modelCalls.set(name, (modelCalls.get(name) || 0) + value)
  }
  const rankedModels = Array.from(modelCalls, ([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value || a.name.localeCompare(b.name))
  const modelDistData = rankedModels.length > 6
    ? [...rankedModels.slice(0, 5), { name: '其他模型', value: rankedModels.slice(5).reduce((sum, m) => sum + m.value, 0) }]
    : rankedModels
  const usageSummary = usageQ.data?.data || { requests: 0, input_tokens: 0, output_tokens: 0, total_cost: 0 }
  const usageTokenTotal = (usageSummary.input_tokens || 0) + (usageSummary.output_tokens || 0)
  const trafficSummaryResponse = trafficSummaryQ.data?.data
  const trafficSummaryUnavailable = !trafficSummaryQ.isLoading && (
    trafficSummaryQ.isError || Boolean(trafficSummaryResponse?.summary_error) || !trafficSummaryResponse?.summary
  )
  const trafficSummary = trafficSummaryUnavailable ? undefined : trafficSummaryResponse?.summary
  const gatewayRequests = Number(trafficSummary?.total) || 0
  const modelCallCount = Number(trafficSummary?.llm_count) || 0
  const aiIdeCallCount = Number(trafficSummary?.ai_ide_count) || 0
  const normalPublicRequests = Number(trafficSummary?.normal_public_count) || 0
  const retainedContentRequests = Number(trafficSummary?.retained_content_count) || 0
  const userTokenTotal = userTokens.reduce((sum: number, item: any) => sum + (item.total_tokens || 0), 0)
  const userRequestTotal = userRequests.reduce((sum: number, item: any) => sum + (item.request_count || 0), 0)
  const modelRequestTotal = models.reduce((sum: number, item: any) => sum + (item.request_count || 0), 0)
  const rawKeyUsage: any[] = Array.isArray(byKeyQ.data?.data) ? byKeyQ.data.data : (Array.isArray(byKeyQ.data?.data?.data) ? byKeyQ.data.data.data : [])
  const keyUsage = rawKeyUsage.filter((item: any) => currentKeyIDs.has(item.id) || currentKeyPrefixes.has(item.key_prefix))
  const aiRelatedCalls = modelCallCount + aiIdeCallCount
  const _orgRaw: any = orgStatsQ.data?.data?.data || orgStatsQ.data?.data || {}
  const orgUnits: any[] = Array.isArray(_orgRaw.units) ? _orgRaw.units : []
  const securityAlertTotal = securityAlertsQ.data?.data.total || 0
  const topRiskCategories = useMemo(() => {
    const groups = new Map<string, {label: string; keys: string[]; count: number}>()
    for (const item of securityAlertsQ.data?.data.categories || []) {
      const label = getRiskCategoryLabel(item.category)
      const group = groups.get(label) || {label, keys: [], count: 0}
      group.keys.push(item.category); group.count += item.count; groups.set(label, group)
    }
    return [...groups.values()].map(group => ({...group, keys: group.keys.sort().join(',')}))
      .sort((a,b) => b.count-a.count || a.label.localeCompare(b.label)).slice(0,5)
  }, [securityAlertsQ.data])

  const billingSummary: any = billingSummaryQ.data || {}
  const billingRows: any[] = Array.isArray(billingBreakdownQ.data) ? billingBreakdownQ.data : []
  const billingSeriesRows: any[] = Array.isArray(billingSeriesQ.data) ? billingSeriesQ.data : []
  const billingRequests = Number(billingSummary.requests) || 0
  const billingPricedRequests = Number(billingSummary.priced_requests) || 0
  const billingTokenTotal = Number(billingSummary.total_tokens) || 0
  const billingCost = (Number(billingSummary.billable_micros) || 0) / 1_000_000
  const billingUpstreamCost = (Number(billingSummary.upstream_cost_micros) || 0) / 1_000_000
  const billingCoverageRatio = billingRequests > 0 ? billingPricedRequests / billingRequests : 0
  const billingDimensionLabel = BILLING_DIMENSIONS.find((item) => item.key === billingDimension)?.label || '维度'
  const billingTrendData = billingSeriesRows.map((row: any) => ({
    date: formatInTimezone(row.bucket, reportTz, 'MM-DD'),
    cost: (Number(row.billable_micros) || 0) / 1_000_000,
    tokens: Number(row.total_tokens) || 0,
  }))
  const billingShareData = billingRows
    .map((row: any) => ({ name: row.name || row.id || '未命名', value: (Number(row.billable_micros) || 0) / 1_000_000 }))
    .filter((row) => row.value > 0)
    .slice(0, 10)
  const billingColumns = [
    { title: '排名', key: 'rank', width: 60, render: (_: any, __: any, index: number) => <Tag color={index < 3 ? 'gold' : 'default'}>{index + 1}</Tag> },
    {
      title: billingDimensionLabel,
      key: 'name',
      render: (_: any, row: any) => (
        <span>
          <Text strong>{row.name || row.id || '未命名'}</Text>
          {row.secondary ? <Text type="secondary" style={{ marginLeft: 8, fontSize: 12 }}>{row.secondary}</Text> : null}
        </span>
      ),
    },
    { title: '请求数', dataIndex: 'requests', key: 'requests', render: (v: number) => <CompactNumber value={v || 0} /> },
    { title: 'Token 总量', dataIndex: 'total_tokens', key: 'total_tokens', render: (v: number) => <CompactNumber value={v || 0} /> },
    { title: '费用', key: 'cost', render: (_: any, row: any) => <Text strong style={{ color: 'var(--brand-orange)' }}>{formatCurrency((Number(row.billable_micros) || 0) / 1_000_000, 4)}</Text> },
    { title: '费用占比', key: 'share', render: (_: any, row: any) => <Tag color="blue">{((Number(row.cost_share) || 0) * 100).toFixed(1)}%</Tag> },
  ]
  const topApps = apps
    .map((item: any) => ({ name: item.project_name || item.name || item.project_id || item.id || '未命名应用', value: Number(item.requests ?? item.request_count) || 0 }))
    .filter((item: { value: number }) => item.value > 0)
    .sort((a: { value: number }, b: { value: number }) => b.value - a.value)
    .slice(0, 5)
  const todayRequestsDelta = todayRequests - (overview.yesterday_requests || 0)
  const todayTokensDelta = todayTokens - (overview.yesterday_tokens || 0)

  const userTokenColumns = [
    { title: '排名', key: 'rank', width: 60, render: (_: any, __: any, index: number) => <Tag color={index < 3 ? 'gold' : 'default'}>{index + 1}</Tag> },
    { title: '用户名', dataIndex: 'username', key: 'username' },
    { title: 'Token 用量', dataIndex: 'total_tokens', key: 'total_tokens', render: (v: number) => <CompactNumber value={v} /> },
    { title: '占比', key: 'percentage', render: (_: unknown, record: any) => <Tag color="blue">{(((record.total_tokens || 0) / (userTokenDenominator || userTokenTotal || 1)) * 100).toFixed(1)}%</Tag> },
  ]
  const userRequestColumns = [
    { title: '排名', key: 'rank', width: 60, render: (_: any, __: any, index: number) => <Tag color={index < 3 ? 'gold' : 'default'}>{index + 1}</Tag> },
    { title: '用户名', dataIndex: 'username', key: 'username' },
    { title: '请求数', dataIndex: 'request_count', key: 'request_count', render: (v: number) => <CompactNumber value={v} /> },
    { title: '占比', key: 'percentage', render: (_: unknown, record: any) => <Tag color="green">{(((record.request_count || 0) / (userRequestDenominator || userRequestTotal || 1)) * 100).toFixed(1)}%</Tag> },
  ]
  const appColumns = [
    { title: '排名', key: 'rank', width: 60, render: (_: any, __: any, index: number) => <Tag color={index < 3 ? 'gold' : 'default'}>{index + 1}</Tag> },
    { title: '应用名称', key: 'project_name', render: (_: unknown, record: any) => record.project_name || record.name || record.project_id || record.id || '未命名应用' },
    { title: '请求数', key: 'requests', render: (_: unknown, record: any) => <CompactNumber value={Number(record.requests ?? record.request_count) || 0} /> },
    // usage/by-project 的 success_rate 是 0~1 比例，转换成 0~100 后统一截位。
    { title: '成功率', key: 'success_rate', render: (_: unknown, record: any) => <Progress percent={percentValue((Number(record.success_rate) || 0) * 100)} size="small" style={{ width: 120, marginBottom: 0 }} /> },
  ]
  const modelColumns = [
    { title: '排名', key: 'rank', width: 60, render: (_: any, __: any, index: number) => <Tag color={index < 3 ? 'gold' : 'default'}>{index + 1}</Tag> },
    { title: '模型名称', dataIndex: 'model_name', key: 'model_name' },
    { title: '请求数', dataIndex: 'request_count', key: 'request_count', render: (v: number) => <CompactNumber value={v} /> },
    { title: 'Token 用量', key: 'tokens', render: (_: unknown, record: any) => <CompactNumber value={(record.input_tokens || 0) + (record.output_tokens || 0)} /> },
    { title: '调用占比', key: 'request_percentage', render: (_: unknown, record: any) => <Tag color="blue">{(((record.request_count || 0) / (modelRequestTotal || 1)) * 100).toFixed(1)}%</Tag> },
  ]

  // 导出的是当前时间范围 + 当前维度下的真实统计，不额外请求数据，避免报告与页面显示不一致。
  const exportBillingReport = () => {
    try {
      const blocks: ReportBlock[] = [
        { type: 'heading', text: '一、用量与费用汇总', level: 2 },
        {
          type: 'metrics',
          items: [
            { label: '请求总数', value: billingRequests.toLocaleString(), note: billingRangeLabel },
            { label: '已计价请求', value: billingPricedRequests.toLocaleString(), note: `价格覆盖率 ${ratioToPercentText(billingCoverageRatio)}` },
            { label: 'Token 总量', value: billingTokenTotal.toLocaleString(), note: `输入 ${(Number(billingSummary.prompt_tokens) || 0).toLocaleString()} · 输出 ${(Number(billingSummary.output_tokens) || 0).toLocaleString()}` },
            { label: '费用合计', value: formatCurrency(billingCost, 4), note: billingUpstreamCost > 0 ? `采购成本 ${formatCurrency(billingUpstreamCost, 4)}` : '未记录上游成本' },
          ],
        },
        { type: 'heading', text: `二、按${billingDimensionLabel}的用量与费用`, level: 2 },
        {
          type: 'table',
          columns: [billingDimensionLabel, '请求数', 'Token 总量', '费用', '费用占比'],
          rows: billingRows.map((row: any) => [
            row.name || row.id || '未命名',
            String(Number(row.requests) || 0),
            String(Number(row.total_tokens) || 0),
            formatCurrency((Number(row.billable_micros) || 0) / 1_000_000, 4),
            `${((Number(row.cost_share) || 0) * 100).toFixed(1)}%`,
          ]),
        },
        { type: 'heading', text: '三、说明', level: 2 },
        {
          type: 'bullets',
          items: [
            `统计范围为${billingRangeLabel}（${billingRange.start_date} 至 ${billingRange.end_date}，统计时区 ${reportTz}），费用取自不可变计费事实，与计费治理页口径一致。`,
            billingCoverageRatio < 0.95
              ? `当前价格覆盖率为 ${ratioToPercentText(billingCoverageRatio)}，存在未计价调用，费用合计可能低于实际应计金额。`
              : '当前模型价格覆盖率正常，费用合计可信。',
          ],
        },
      ]
      const blob = buildReportDocx({
        title: 'Token 用量与费用报告',
        subtitle: `${billingRangeLabel}用量统计与费用构成`,
        meta: [
          { label: '统计时间范围', value: `${billingRangeLabel}（${billingRange.start_date} 至 ${billingRange.end_date}，截至 ${nowInTimezone(reportTz, 'YYYY-MM-DD HH:mm')}）` },
          { label: '生成时间', value: nowInTimezone(reportTz) },
          { label: '统计维度', value: billingDimensionLabel },
          ...reportMetaItems(reportCtx),
        ],
        blocks,
      })
      downloadBlob(blob, safeFilename(['用量与费用报告', billingRangeLabel, nowInTimezone(reportTz, 'YYYYMMDD')]) + '.docx')
      message.success('用量与费用报告已导出')
    } catch {
      message.error('报告生成失败，请重试')
    }
  }

  const statisticsRangeSelector = (
    <ReportRangeSelector
      value={statisticsRangeKey}
      options={OVERVIEW_RANGE_KEYS}
      custom={statisticsCustom}
      timezone={reportTz}
      onChange={(key, custom) => { setStatisticsRangeKey(key); if (custom) setStatisticsCustom(custom) }}
      style={{ marginBottom: 16 }}
    />
  )

  const tabItems = [
    {
      key: 'overview',
      label: <span><DashboardOutlined /> 系统概览</span>,
      children: (
        <Spin spinning={overviewQ.isLoading || usageQ.isLoading}>
          <div className="enterprise-page">
            <div className="enterprise-metric-grid">
              <MetricCard label="今日请求" valueNumber={todayRequests} tone="blue" hint={`昨日: ${compactNumber(overview.yesterday_requests || 0)}`} footer={<Text type="secondary" style={{ fontSize: 12 }}>{todayRequestsDelta >= 0 ? '↑' : '↓'} 较昨日 {compactNumber(Math.abs(todayRequestsDelta))} 次</Text>} />
              <MetricCard label="今日 Token 用量" valueNumber={todayTokens} tone="blue" hint={`昨日: ${compactNumber(overview.yesterday_tokens || 0)}`} footer={<Text type="secondary" style={{ fontSize: 12 }}>{todayTokensDelta >= 0 ? '↑' : '↓'} 较昨日 {compactNumber(Math.abs(todayTokensDelta))}</Text>} />
              <MetricCard label="活跃应用" valueNumber={overview.active_projects || 0} tone="blue" hint={`总请求: ${compactNumber(overview.total_requests || 0)}`} />
              <MetricCard
                label="近24小时待处置告警"
                valueNumber={securityAlertsQ.isSuccess ? securityAlertTotal : undefined}
                value={securityAlertsQ.isError ? '加载失败' : '加载中…'}
                tone="orange"
                hint="未处置且未抑制的告警问题，与安全告警页「待处置」同一集合"
                onClick={() => navigate(alertLink())}
                ariaLabel="查看近24小时安全告警"
              />
            </div>


            <Row gutter={[16, 16]}>
              <Col xs={24} lg={12}>
                <SectionPanel
                  title="近24小时待处置告警分类 TOP"
                  description="按待处置问题计数，点击查看同一时间范围和分类的告警"
                  extra={<Button type="link" size="small" onClick={() => navigate(alertLink())}>查看全部告警</Button>}
                >
                  <Spin spinning={securityAlertsQ.isLoading}>
                    {securityAlertsQ.isError ? <Alert type="error" message="告警统计加载失败" action={<Button onClick={() => void securityAlertsQ.refetch()}>重试</Button>} /> : null}
                    {topRiskCategories.length > 0 ? (
                      <RankedList
                        data={topRiskCategories.map((item: any) => ({
                          name: item.label,
                          value: item.count,
                          key: item.keys,
                        }))}
                        height={200}
                        unit="项"
                        onItemClick={(item) => navigate(alertLink(item.key || item.name))}
                      />
                    ) : (
                      <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)', fontSize: 13 }}>暂无风险分类命中</div>
                    )}
                  </Spin>
                </SectionPanel>
              </Col>
              <Col xs={24} lg={12}>
                <SectionPanel title={`${statisticsRangeLabel}应用调用 TOP`} description={`${statisticsRangeLabel}请求量最高的应用（统计时区 ${reportTz}）`}>
                  {topApps.length > 0 ? (
                    <RankedList data={topApps} height={200} unit="次" />
                  ) : (
                    <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)', fontSize: 13 }}>暂无应用调用数据</div>
                  )}
                </SectionPanel>
              </Col>
            </Row>

            <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
              <Col xs={24} lg={15}>
                <SectionPanel title="近30天请求与 Token 趋势" description="每日请求数与 Token 用量趋势，帮助判断调用增长或异常">
                  <Spin spinning={trendQ.isLoading}>
                    {trendData.length > 0 ? (
                      <TrendArea data={trendData} series={[{ key: 'requests', label: '请求数' }, { key: 'tokens', label: 'Token' }]} />
                    ) : (
                      <div style={{ height: 240, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)', fontSize: 13 }}>暂无趋势数据</div>
                    )}
                  </Spin>
                </SectionPanel>
              </Col>
              <Col xs={24} lg={9}>
                <SectionPanel title="模型调用占比" description="近30天已关联模型的调用占比；不含未识别模型的代理流量和普通网页访问">
                  <Spin spinning={modelDistQ.isLoading}>
                    {modelDistData.length > 0 ? (
                      <ModelShareRadial data={modelDistData} height={240} unit="次" />
                    ) : (
                      <div style={{ height: 240, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)', fontSize: 13 }}>暂无模型调用数据</div>
                    )}
                  </Spin>
                </SectionPanel>
              </Col>
            </Row>

            <SectionPanel title="近30天网关访问与 AI 用量" description="总网关访问包含普通公网流量；AI 相关调用仅含模型调用与 AI IDE 请求；内容留证为已保存正文的 AI 调用。">
              {trafficSummaryQ.isLoading ? <Text type="secondary" style={{ display: 'block', marginBottom: 12 }}>网关访问统计加载中，Token 用量先行展示。</Text> : null}
              {trafficSummaryUnavailable ? (
                <Alert type="warning" showIcon message="网关访问统计加载失败，未以 0 替代真实数据" style={{ marginBottom: 12 }} />
              ) : null}
              <div className="enterprise-metric-grid">
                <MetricCard label="总网关访问" {...(trafficSummaryQ.isLoading || trafficSummaryUnavailable ? { value: '—' } : { valueNumber: gatewayRequests })} tone="blue" hint={trafficSummaryQ.isLoading ? '正在刷新统计' : trafficSummaryUnavailable ? '统计暂不可用' : `普通公网访问 ${compactNumber(normalPublicRequests)} 次`} />
                <MetricCard label="AI 相关调用" {...(trafficSummaryQ.isLoading || trafficSummaryUnavailable ? { value: '—' } : { valueNumber: aiRelatedCalls })} tone="blue" hint={trafficSummaryQ.isLoading ? '正在刷新统计' : trafficSummaryUnavailable ? '统计暂不可用' : `模型 ${compactNumber(modelCallCount)} 次 · AI IDE ${compactNumber(aiIdeCallCount)} 次`} />
                <MetricCard
                  label="内容留证"
                  {...(trafficSummaryQ.isLoading || trafficSummaryUnavailable ? { value: '—' } : { valueNumber: retainedContentRequests })}
                  tone="blue"
                  hint={trafficSummaryQ.isLoading ? '正在刷新统计' : trafficSummaryUnavailable ? '统计暂不可用' : '已保存请求或响应正文'}
                  onClick={() => navigate(`/audit/access-retention?${new URLSearchParams(dashboardUsageRange.access).toString()}`)}
                  ariaLabel="查看近30天内容留证"
                />
                <MetricCard label="总 Token 用量" {...(usageQ.isLoading ? { value: '—' } : { valueNumber: usageTokenTotal })} tone="blue" hint={usageQ.isLoading ? '正在刷新用量' : undefined} />
                <MetricCard label="输入 Token" {...(usageQ.isLoading ? { value: '—' } : { valueNumber: usageSummary.input_tokens || 0 })} tone="blue" hint={usageQ.isLoading ? '正在刷新用量' : undefined} />
                <MetricCard label="输出 Token" {...(usageQ.isLoading ? { value: '—' } : { valueNumber: usageSummary.output_tokens || 0 })} tone="blue" hint={usageQ.isLoading ? '正在刷新用量' : undefined} />
              </div>
              <Text type="secondary" style={{ display: 'block', marginTop: 12, fontSize: 12 }}>{trafficSummaryUnavailable ? '网关访问统计暂不可用，未将缺失数据展示为 0。' : '口径说明：内容留证是 AI 相关调用中已保存正文的子集，不代表全部网关访问。'}</Text>
            </SectionPanel>
          </div>
        </Spin>
      ),
    },
    {
      key: 'billing',
      label: <span><FundOutlined /> 用量与费用</span>,
      children: (
        <Spin spinning={billingSummaryQ.isLoading || billingBreakdownQ.isLoading}>
          <div className="enterprise-page">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8, marginBottom: 16 }}>
              <ReportRangeSelector
                value={billingRangeKey}
                options={OVERVIEW_RANGE_KEYS}
                custom={billingCustom}
                timezone={reportTz}
                onChange={(key, custom) => { setBillingRangeKey(key); if (custom) setBillingCustom(custom) }}
              />
              <Button icon={<DownloadOutlined />} onClick={exportBillingReport}>导出报告</Button>
            </div>
            {billingSummaryQ.isError ? (
              <Alert type="error" showIcon message="费用统计加载失败" description="没有把查询失败伪装成 0 元，请重试或缩小时间范围。" style={{ marginBottom: 16 }} />
            ) : null}
            <div className="enterprise-metric-grid">
              <MetricCard label={`${billingRangeLabel}请求总数`} valueNumber={billingRequests} tone="blue" hint={`已计价 ${compactNumber(billingPricedRequests)} 次`} />
              <MetricCard label="Token 总量" valueNumber={billingTokenTotal} tone="blue" hint={`输入 ${compactNumber(Number(billingSummary.prompt_tokens) || 0)} · 输出 ${compactNumber(Number(billingSummary.output_tokens) || 0)}`} />
              <MetricCard label="费用合计" value={formatCurrency(billingCost, 4)} tone="orange" hint={billingUpstreamCost > 0 ? `采购成本 ${formatCurrency(billingUpstreamCost, 4)}` : '未记录上游成本'} />
              <MetricCard label="价格覆盖率" value={ratioToPercentText(billingCoverageRatio)} tone={billingCoverageRatio >= 0.95 ? 'green' : 'orange'} hint={`未计价 ${compactNumber(Number(billingSummary.unpriced_requests) || 0)} 次`} />
            </div>

            <SectionPanel
              title={`按${billingDimensionLabel}的用量与费用`}
              description="按每次调用实际记下的费用，统计所选时间范围"
              extra={<Segmented size="small" value={billingDimension} onChange={(value) => setBillingDimension(value as BillingDimension)} options={BILLING_DIMENSIONS.map((item) => ({ label: item.label, value: item.key }))} />}
            >
              {billingRows.length > 0 ? (
                <Table
                  dataSource={billingRows}
                  columns={billingColumns as any}
                  rowKey={(row: any) => String(row.id ?? row.name)}
                  pagination={{ defaultPageSize: 10, showTotal: (t: number) => `共 ${t} 项` }}
                  size="small"
                />
              ) : (
                <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: 13 }}>所选范围暂无计费用量</div>
              )}
            </SectionPanel>

            <Row gutter={[16, 16]}>
              <Col xs={24} lg={15}>
                <SectionPanel title={`${billingRangeLabel}费用与 Token 趋势`} description="按日聚合的计费金额与 Token 消耗">
                  {billingTrendData.length > 0 ? (
                    <TrendArea
                      data={billingTrendData}
                      series={[{ key: 'cost', label: '费用' }, { key: 'tokens', label: 'Token' }]}
                      height={240}
                      currencyFormatter={(value: number) => formatCurrency(value, 4)}
                    />
                  ) : (
                    <div style={{ height: 240, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)', fontSize: 13 }}>暂无趋势数据</div>
                  )}
                </SectionPanel>
              </Col>
              <Col xs={24} lg={9}>
                <SectionPanel title={`${billingDimensionLabel}费用占比`}>
                  {billingShareData.length > 0 ? (
                    <DistributionPie data={billingShareData} height={240} />
                  ) : (
                    <div style={{ height: 240, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)', fontSize: 13 }}>暂无费用数据</div>
                  )}
                </SectionPanel>
              </Col>
            </Row>
          </div>
        </Spin>
      ),
    },
    ...(canViewOrgStats ? [{ key: 'org', label: <span><ApartmentOutlined /> 组织统计</span>, children: <Spin spinning={orgStatsQ.isLoading}><SectionPanel title="单位统计（部门 / 用户 / 应用）"><Table dataSource={orgUnits} rowKey="id" pagination={false} size="small" columns={[{ title: '单位', dataIndex: 'name', key: 'name', render: (v: string) => <Text strong>{v}</Text> }, { title: '部门数', dataIndex: 'dept_count', key: 'dept_count', width: 100 }, { title: '用户数', dataIndex: 'user_count', key: 'user_count', width: 100 }, { title: '应用数', dataIndex: 'project_count', key: 'project_count', width: 100 }, { title: '状态', dataIndex: 'status', key: 'status', width: 100, render: (s: string) => <Tag color={s === 'active' ? 'success' : 'default'}>{s === 'active' ? '启用' : s}</Tag> }]} /></SectionPanel></Spin> }] : []),
    { key: 'keys', label: <span><KeyOutlined /> 密钥统计</span>, children: <>{statisticsRangeSelector}<Spin spinning={byKeyQ.isLoading || keyListQ.isLoading}><SectionPanel title={`${statisticsRangeLabel} API Key 消耗（仅显示当前仍存在的密钥）`}><Table dataSource={keyUsage} rowKey={(r: any) => r.id || r.key_prefix} pagination={{ defaultPageSize: 10, showTotal: (t) => `共 ${t} 个密钥` }} size="small" columns={[{ title: 'Key 前缀', dataIndex: 'key_prefix', key: 'key_prefix', ellipsis: true, render: (v: string) => <Text strong>{v || '-'}</Text> }, { title: '所属应用', dataIndex: 'project_name', key: 'project_name', ellipsis: true, render: (v: string) => v || '-' }, { title: '所属用户', dataIndex: 'username', key: 'username', ellipsis: true, render: (v: string) => v || '-' }, { title: '请求数', dataIndex: 'requests', key: 'requests', render: (v: number) => <CompactNumber value={v} /> }, { title: '输入 Token', dataIndex: 'input_tokens', key: 'input_tokens', render: (v: number) => <CompactNumber value={v || 0} /> }, { title: '输出 Token', dataIndex: 'output_tokens', key: 'output_tokens', render: (v: number) => <CompactNumber value={v || 0} /> }, { title: 'Token 总量', key: 'tokens', render: (_: any, r: any) => <CompactNumber value={r.total_tokens || (r.input_tokens || 0) + (r.output_tokens || 0)} /> }, { title: '最后调用', dataIndex: 'last_called_at', key: 'last_called_at', render: (v: string) => formatInTimezone(v, reportTz) }]} /></SectionPanel></Spin></> },
    { key: 'users', label: <span><TeamOutlined /> 用户统计</span>, children: <>{statisticsRangeSelector}<Spin spinning={userTokenQ.isLoading || userReqQ.isLoading}><Row gutter={[16, 16]}><Col xs={24} lg={12}><SectionPanel title={`${statisticsRangeLabel} Token 排行 TOP 10`}><Table dataSource={userTokens} columns={userTokenColumns} rowKey="user_id" pagination={false} size="small" /></SectionPanel></Col><Col xs={24} lg={12}><SectionPanel title={`${statisticsRangeLabel}请求排行 TOP 10`}><Table dataSource={userRequests} columns={userRequestColumns} rowKey="user_id" pagination={false} size="small" /></SectionPanel></Col></Row></Spin></> },
    { key: 'apps', label: <span><ProjectOutlined /> 应用统计</span>, children: <>{statisticsRangeSelector}<Spin spinning={appQ.isLoading || projectListQ.isLoading}><SectionPanel title={`${statisticsRangeLabel}应用使用排行 TOP 10`}><Table dataSource={apps} columns={appColumns} rowKey={(record: any) => record.project_id || record.id} pagination={false} size="small" /></SectionPanel></Spin></> },
    { key: 'models', label: <span><ApiOutlined /> 模型统计</span>, children: <>{statisticsRangeSelector}<Spin spinning={modelQ.isLoading}><SectionPanel title={`${statisticsRangeLabel}模型调用量 TOP 10`}><Table dataSource={models} columns={modelColumns} rowKey="model_id" pagination={false} size="small" /></SectionPanel></Spin></> },
    { key: 'agents', label: <span><BarChartOutlined /> 智能体统计</span>, children: <>{statisticsRangeSelector}<AgentStats range={statisticsRange.stats} rangeLabel={statisticsRangeLabel} /></> },
  ]

  return (
    <div className="enterprise-page">
      <EnterprisePageHeader
        eyebrow={copy.homeEyebrow}
        title="态势总览"
        description={copy.homeDescription}
        meta={
          <Space size={8} wrap data-testid="report-context">
            <Tag color={reportCtx.executionMode?.effective_mode === 'protect' ? 'red' : 'blue'}>执行模式：{reportCtx.modeLabel}</Tag>
            <Tag>统计时区：{reportTz}</Tag>
            <Text type="secondary" style={{ fontSize: 12 }}>口径：{METRICS_DEFINITION_NOTE}</Text>
          </Space>
        }
      />
      <Tabs activeKey={activeTab} onChange={setActiveTab} items={tabItems} size="large" />
    </div>
  )
}

function Dashboard() {
  const productQ = useQuery({
    queryKey: ['dashboard-product-identity'],
    queryFn: async () => resolveProductIdentity((await productApi.get()).data),
    retry: false,
    staleTime: 60_000,
  })
  if (productQ.isPending) return <Spin spinning />
  const product = productQ.data ?? resolveProductIdentity()
  return <GatewayDashboard product={product} />
}

export default Dashboard

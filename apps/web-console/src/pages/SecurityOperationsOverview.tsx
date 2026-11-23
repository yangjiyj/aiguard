import { useMemo, useState } from 'react'
import { Alert, Button, Col, Modal, Row, Space, Spin, Table, Tag, Typography, message } from 'antd'
import { DownloadOutlined, PrinterOutlined, ReloadOutlined } from '@ant-design/icons'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { accessRetentionApi, contentAuditApi, licenseApi } from '../services/api'
import { alertOccurrencesApi } from '../services/alertOccurrences'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import ReportRangeSelector from '../components/ReportRangeSelector'
import { METRICS_DEFINITION_NOTE, formatInTimezone, nowInTimezone, reportMetaItems, resolveReportRange, useReportContext } from '../utils/ws8ReportRange'
import type { CustomDateRange, ReportRangeKey } from '../utils/ws8ReportRange'
import { agentEndpointApi, agentKeys } from '../services/agentEndpoint'
import { EnterprisePageHeader, MetricCard, SectionPanel } from '../components/EnterpriseUI'
import { DistributionPie, RankedList, TrendArea } from '../components/Charts'
import { getRiskCategoryLabel, severityOptions } from '../utils/risk'
import { buildReportDocx, downloadBlob, safeFilename } from '../utils/reportExport'
import type { ReportBlock } from '../utils/reportExport'
import { compactNumber, ratioToPercentText } from '../utils/format'

const { Text } = Typography

// 预设档与安全告警页的 window_hours 集合（24h/7d/30d/90d/180d）一致；自然周/月与自定义起止
// 下钻时改传 start_time/end_time（告警页优先使用显式起止），两边窗口仍然一致。
// 口径见 docs/design/ws8-metrics-definitions.md。
const ALERT_RANGE_KEYS: ReportRangeKey[] = ['24h', '7d', '30d', '90d', '180d', 'this_week', 'last_week', 'this_month', 'last_month', 'custom']

const SEVERITY_ROWS = severityOptions().map(({ value, label }) => ({ key: value, label }))

// 同一行里「风险分类 TOP」和「风险等级分布」必须等高，否则一个面板会比另一个矮一截。
// 榜单最多 8 行，用真实 CSS + headless Chromium 实测：4 行 159 / 5 行 201 / 6 行 243 /
// 7 行 285 / 8 行 327（每多一行 +42px）。RankedList 用 minHeight，所以行数少于 8 时
// 盒子仍然保持 327，两栏恒定等高；饼图也用这个常量，不再是随手写的 240。
const OVERVIEW_CHART_HEIGHT = 327

// 这里曾经有一组「处置状态」枚举（待处置/跟进中/已确认风险/已处理/误报），读 audit_dispositions /
// alert_groups.status，当时安全告警页没有处置入口，「待处置」恒等于告警总数，因此整组移除。
// 现在安全告警页的告警问题详情可以「标为已处理 / 误报」（subject_type=alert_case），
// 待处置已是可闭环的真实状态。W8 8.2 统一口径：本页与首页都用
// alert-occurrences/summary?grouping=cases&disposition=pending，同一时间窗，只显示这一个数，
// 不恢复那组五态枚举。

// 代理与行为类检测不属于客户关心的风险分类，展示时剔除（与首页风险分类 TOP 一致）。
function isDisplayableRiskCategory(key: string) {
  return Boolean(key) && key !== 'agent_detect' && !key.startsWith('agent_')
}

function SecurityOperationsOverview() {
  const navigate = useNavigate()
  // 默认近 7 天：24h/7d 由单次聚合查询秒级返回，30d 及以上需要数秒，用户按需切换。
  const [rangeKey, setRangeKey] = useState<ReportRangeKey>('7d')
  const [customRange, setCustomRange] = useState<CustomDateRange | null>(null)
  const [reportOpen, setReportOpen] = useState(false)
  const reportCtx = useReportContext()
  const reportTz = reportCtx.timezone
  const activeRange = useMemo(
    () => resolveReportRange(rangeKey, { timezone: reportTz, custom: customRange }),
    [rangeKey, customRange, reportTz],
  )
  const window_ = activeRange.window
  const rangeLabel = activeRange.label
  const rangeSpan = `${formatInTimezone(activeRange.start, reportTz, 'YYYY-MM-DD HH:mm')} 至 ${formatInTimezone(activeRange.end, reportTz, 'YYYY-MM-DD HH:mm')}`

  // 一个聚合请求顶掉原先「按维度各发一次精确计数」的二十多个请求：
  // 服务端用一条 SQL 同时算出会话级告警总数、涉及主体数与严重级别 / 风险分类分布。
  // 注意：不要退回用 contentAuditApi.list({limit:1, alert_only:true}) 数总数——
  // alert_only 走服务端快速路径，那条路径返回的 total 是渐进式分页值而非精确计数。
  const overviewQ = useQuery({
    queryKey: ['secops-overview', window_],
    queryFn: async () => {
      const response = await contentAuditApi.securityOverview(window_)
      return response.data?.data
    },
    // 同窗口 5 分钟内复用；切窗口时保留上一次结果，避免出现「先闪一堆 0 再跳数」的中间态。
    staleTime: 5 * 60 * 1000,
    placeholderData: keepPreviousData,
  })

  // 覆盖统计只取汇总（getSummary 已固定带 summary_only），不要再带 summary_detail=counts：
  // counts 模式明确不返回 timeline，趋势图会永远是空的。
  const coverageQ = useQuery({
    queryKey: ['secops-coverage', window_],
    queryFn: () => accessRetentionApi.getSummary({ ...window_, access_type: 'all' }),
    staleTime: 5 * 60 * 1000,
    placeholderData: keepPreviousData,
  })

  // 8.2：与首页「待处置告警」同一接口、同一参数、同一时间窗。
  const alertIdentity = useAuditQueryIdentity()
  const pendingQ = useQuery({
    queryKey: ['alert-case-summary', alertIdentity, window_],
    queryFn: ({ signal }) => alertOccurrencesApi.summary({
      grouping: 'cases', disposition: 'pending', start_time: window_.from, end_time: window_.to, signal,
    }),
    staleTime: 15000,
    retry: false,
  })
  const pendingReady = pendingQ.isSuccess
  const pendingCount = Number(pendingQ.data?.data?.total) || 0
  // 智能体端点是可选功能：未授权 agent_security 时不请求；后端未开启该功能时接口 404，也视为「未启用」整块不显示，
  // 只有真正出错才提示（网关版默认不开，原先始终显示一整块灰卡和「暂不可用」，像系统坏了）。
  const licenseQ = useQuery({ queryKey: ['licenseStatus'], queryFn: () => licenseApi.status().then(response => response.data), retry: false, staleTime: 60_000 })
  const agentLicensed = licenseQ.data?.valid === true && licenseQ.data.features?.includes('agent_security') === true
  const agentOverviewQ = useQuery({ queryKey: agentKeys.overview, queryFn: agentEndpointApi.overview, staleTime: 60_000, retry: false, enabled: agentLicensed })
  const agentFeatureOff = (agentOverviewQ.error as { response?: { status?: number } } | null)?.response?.status === 404
  const showAgentSection = agentLicensed && !agentFeatureOff
  const agentOverview = agentOverviewQ.data
  const agentMetric = (value: number | undefined) => agentOverviewQ.isError || value == null ? { value: '—' } : { valueNumber: value }

  const coverageResponse: any = coverageQ.data?.data || {}
  const coverageUnavailable = !coverageQ.isLoading && (coverageQ.isError || Boolean(coverageResponse?.summary_error) || !coverageResponse?.summary)
  const coverage = coverageUnavailable ? undefined : coverageResponse.summary

  const overview = overviewQ.data
  const overviewReady = Boolean(overview)
  const alertTotal = overview?.total || 0

  const severityCounts = useMemo(() => {
    const counts = new Map<string, number>()
    for (const item of overview?.severity || []) counts.set(item.key, item.count)
    return counts
  }, [overview])
  const severityRows = useMemo(
    () => SEVERITY_ROWS.map((item) => ({ ...item, count: severityCounts.get(item.key) || 0 })),
    [severityCounts],
  )

  // 分类保持「一个检测项一行」的精确计数（同一会话命中多个检测项会分别计入各自检测项，
  // 但每一行的数量都不会超过告警总数）。若两个检测项落到同一个中文名，行名补上原始 key 以便区分。
  const categoryRows = useMemo(() => {
    const rows = (overview?.categories || []).filter((item) => isDisplayableRiskCategory(item.key))
    const labelHits = new Map<string, number>()
    for (const item of rows) {
      const label = getRiskCategoryLabel(item.key)
      labelHits.set(label, (labelHits.get(label) || 0) + 1)
    }
    return rows.map((item) => {
      const label = getRiskCategoryLabel(item.key)
      return {
        label: (labelHits.get(label) || 0) > 1 ? `${label}（${item.key}）` : label,
        key: item.key,
        count: item.count,
      }
    })
  }, [overview])

  const severeCount = severityRows
    .filter((row) => row.key === 'critical' || row.key === 'high')
    .reduce((sum, row) => sum + row.count, 0)
  // 涉及主体：窗口内产生过可处置告警的去重主体数（Key 归属），口径与告警明细页一致。
  const subjectCount = Number(overview?.subjects) || 0
  // 风险类型数用服务端精确去重计数，不能拿 categoryRows.length 当数：
  // categories 列表带 LIMIT 24，实测在真实数据上正好被截到 24 条。
  const categoryTypeCount = Number(overview?.category_count) || 0
  const auditTotal = Number(coverage?.total) || 0
  const llmCount = Number(coverage?.llm_count) || 0
  const aiIdeCount = Number(coverage?.ai_ide_count) || 0
  const retainedCount = Number(coverage?.retained_content_count) || 0
  const undetectedCount = typeof coverage?.undetected_count === 'number' ? coverage.undetected_count : null
  const completeEvidence = Number(coverage?.evidence_quality?.complete_count) || 0
  const evidenceQualityRatio = auditTotal > 0 ? completeEvidence / auditTotal : 0
  const riskCount = Number(coverage?.risk_count) || 0
  const blockedCount = Number(coverage?.blocked_count) || 0
  const timeline: any[] = Array.isArray(coverage?.timeline) ? coverage.timeline : []
  const timelineData = timeline.map((point: any) => ({
    date: formatInTimezone(point.bucket, reportTz, 'MM-DD'),
    total: Number(point.total_count) || 0,
    risk: Number(point.risk_count) || 0,
  }))
  const severityPie = severityRows.filter((row) => row.count > 0).map((row) => ({ name: row.label, value: row.count }))
  const loading = overviewQ.isFetching || coverageQ.isFetching
  // 首次加载（还没有任何数据）时不渲染数字，避免把「还没到」画成真实的 0。
  const firstLoad = (overviewQ.isLoading && !overviewQ.data) || (coverageQ.isLoading && !coverageQ.data)
  const anyError = overviewQ.isError || coverageQ.isError

  const gotoAlerts = (params: Record<string, string>) => {
    navigate(`/security/alerts?${new URLSearchParams({
      ...params,
      ...(activeRange.hours ? { window_hours: String(activeRange.hours) } : {}),
      start_time: window_.from,
      end_time: window_.to,
    }).toString()}`)
  }

  const buildReportBlocks = (): ReportBlock[] => {
    const blocks: ReportBlock[] = []
    blocks.push({ type: 'heading', text: '一、告警留痕总览', level: 2 })
    blocks.push({
      type: 'metrics',
      items: [
        { label: '告警总数', value: overviewReady ? String(alertTotal) : '—', note: `${rangeLabel}内有可处置告警的会话数` },
        { label: '严重与高危', value: overviewReady ? String(severeCount) : '—', note: alertTotal > 0 ? `占 ${((severeCount / alertTotal) * 100).toFixed(1)}%` : '—' },
        { label: '命中风险类型', value: overviewReady ? String(categoryTypeCount) : '—', note: '按检测项去重，已剔除智能体行为类' },
        { label: '涉及主体', value: overviewReady ? String(subjectCount) : '—', note: '产生过告警的 Key 归属主体数' },
        { label: '待处置告警', value: pendingReady ? String(pendingCount) : '—', note: '未处置且未抑制的告警问题，与安全告警页「待处置」一致' },
      ],
    })
    blocks.push({ type: 'heading', text: '二、风险分类分布', level: 2 })
    if (categoryRows.length > 0) {
      blocks.push({
        type: 'table',
        columns: ['风险分类', '数量', '占告警总数'],
        rows: categoryRows.map((row: any) => [
          row.label,
          String(row.count),
          alertTotal > 0 ? `${((row.count / alertTotal) * 100).toFixed(1)}%` : '—',
        ]),
      })
    } else {
      blocks.push({ type: 'paragraph', text: '该时间范围内未命中风险分类。' })
    }
    blocks.push({ type: 'heading', text: '三、风险等级分布', level: 2 })
    blocks.push({
      type: 'table',
      columns: ['风险等级', '数量'],
      rows: severityRows.map((row) => [row.label, overviewReady ? String(row.count) : '—']),
    })
    blocks.push({ type: 'heading', text: '四、审计与留证覆盖', level: 2 })
    if (coverageUnavailable) {
      blocks.push({ type: 'paragraph', text: '审计覆盖统计本次未取到数据，未以 0 代替。' })
    } else {
      blocks.push({
        type: 'metrics',
        items: [
          { label: '网关访问总量', value: String(auditTotal), note: '含普通公网访问' },
          { label: '模型调用', value: String(llmCount), note: '经网关的模型请求' },
          { label: 'AI IDE 调用', value: String(aiIdeCount), note: '编程助手类客户端' },
          { label: '内容留证', value: String(retainedCount), note: '已保存请求或响应正文' },
          { label: '未检测', value: undetectedCount === null ? '—' : String(undetectedCount), note: '仅转发加密流量的正向 CONNECT 隧道' },
          { label: '判定风险', value: String(riskCount), note: '命中监测或告警规则' },
          { label: '阻断', value: String(blockedCount), note: `只统计真实阻断；${reportCtx.modeNote}` },
          { label: '证据完整率', value: ratioToPercentText(evidenceQualityRatio), note: '请求与响应正文均留存的比例' },
        ],
      })
    }
    blocks.push({ type: 'heading', text: '五、结论与建议', level: 2 })
    const notes: string[] = []
    if (!overviewReady) {
      notes.push('本次告警统计未取到数据，未以 0 代替；请重试或缩短时间范围。')
    } else if (alertTotal === 0) {
      notes.push(`${rangeLabel}内没有可处置告警，网关未命中需要人工研判的风险规则。`)
    } else {
      notes.push(`${rangeLabel}内共产生 ${alertTotal} 条可处置告警，其中严重与高危 ${severeCount} 条，需优先安排研判。`)
      if (categoryRows.length > 0) notes.push(`风险最集中的分类为「${categoryRows[0].label}」，共 ${categoryRows[0].count} 条。`)
      if (retainedCount < alertTotal) notes.push('部分告警未留存请求或响应正文，如需事后取证建议调整内容留存策略。')
    }
    notes.push('本页只做汇总；需要人工研判闭环时，请在「安全告警」页打开告警问题标记已处理或误报，处置后即不再计入待处置。')
    blocks.push({ type: 'bullets', items: notes })
    return blocks
  }

  const exportWord = () => {
    try {
      const blob = buildReportDocx({
        title: '安全运营总览报告',
        subtitle: `${rangeLabel}告警留痕与审计覆盖汇总`,
        meta: [
          { label: '统计时间范围', value: `${rangeLabel}（${rangeSpan}）` },
          { label: '生成时间', value: nowInTimezone(reportTz) },
          { label: '数据口径', value: '与安全告警页、内容留证页一致' },
          ...reportMetaItems(reportCtx),
        ],
        blocks: buildReportBlocks(),
      })
      downloadBlob(blob, safeFilename(['安全运营总览报告', rangeLabel, nowInTimezone(reportTz, 'YYYYMMDD')]) + '.docx')
      message.success('Word 报告已导出')
    } catch {
      message.error('报告生成失败，请重试')
    }
  }

  return (
    <div className="enterprise-page">
      <EnterprisePageHeader
        eyebrow="安全运营与合规"
        title="安全运营总览"
        description="一页看清这段时间总体告警留痕、审计了哪些内容、集中风险在哪里。"
        meta={
          <Space size={8} wrap data-testid="report-context">
            <Tag color={reportCtx.executionMode?.effective_mode === 'protect' ? 'red' : 'blue'}>执行模式：{reportCtx.modeLabel}</Tag>
            <Tag>统计时区：{reportTz}</Tag>
            <Text type="secondary" style={{ fontSize: 12 }}>口径：{METRICS_DEFINITION_NOTE}</Text>
          </Space>
        }
        actions={
          <Space size={8} wrap>
            <ReportRangeSelector
              label="时间范围"
              value={rangeKey}
              options={ALERT_RANGE_KEYS}
              custom={customRange}
              onChange={(key, custom) => { setRangeKey(key); if (custom) setCustomRange(custom) }}
            />
            <Button icon={<DownloadOutlined />} onClick={() => setReportOpen(true)}>导出报告</Button>
          </Space>
        }
      />

      {anyError ? (
        <Alert
          type="warning"
          showIcon
          message="部分统计未能加载"
          description="缺失的指标已显示为“—”，没有用 0 冒充真实数据。请重试或缩短时间范围。"
          style={{ marginBottom: 16 }}
          action={<Button size="small" icon={<ReloadOutlined />} onClick={() => { overviewQ.refetch(); coverageQ.refetch() }}>重试</Button>}
        />
      ) : null}

      {firstLoad ? (
        <div style={{ padding: '12px 0', color: 'var(--text-tertiary)', fontSize: 13 }}>
          <Spin size="small" /> <span style={{ marginLeft: 8 }}>正在统计，较长的时间范围需要数秒…</span>
        </div>
      ) : null}

      <Spin spinning={loading}>
        <SectionPanel
          title="告警留痕"
          description={`${rangeLabel}内产生过可处置告警的会话数与影响范围；点击数字可直接下钻到告警明细`}
        >
          <div className="enterprise-metric-grid">
            <MetricCard
              label="告警总数"
              {...(overviewQ.isError ? { value: '—' } : overviewReady ? { valueNumber: alertTotal } : { value: '—' })}
              tone="orange"
              hint="会话内有可处置告警，与安全告警页同一批记录"
              onClick={() => gotoAlerts({})}
              ariaLabel="查看全部告警"
            />
            <MetricCard
              label="严重与高危"
              {...(overviewQ.isError ? { value: '—' } : overviewReady ? { valueNumber: severeCount } : { value: '—' })}
              tone="red"
              hint={alertTotal > 0 ? `占 ${((severeCount / alertTotal) * 100).toFixed(1)}%` : '暂无告警'}
              onClick={() => gotoAlerts({})}
              ariaLabel="查看严重与高危告警"
            />
            <MetricCard
              label="命中风险类型"
              {...(overviewQ.isError ? { value: '—' } : overviewReady ? { valueNumber: categoryTypeCount } : { value: '—' })}
              tone="blue"
              hint="按检测项去重，已剔除智能体行为类"
              ariaLabel="命中风险类型数"
            />
            <MetricCard
              label="涉及主体"
              {...(overviewQ.isError ? { value: '—' } : overviewReady ? { valueNumber: subjectCount } : { value: '—' })}
              tone="blue"
              hint={alertTotal > 0 ? `平均每主体 ${(alertTotal / Math.max(subjectCount, 1)).toFixed(1)} 条` : '暂无告警'}
              ariaLabel="涉及主体数"
            />
            <MetricCard
              label="待处置告警"
              {...(pendingReady ? { valueNumber: pendingCount } : { value: pendingQ.isError ? '加载失败' : '—' })}
              tone="orange"
              hint="未处置且未抑制的告警问题，与首页、安全告警页「待处置」同一集合"
              onClick={() => gotoAlerts({})}
              ariaLabel="查看待处置告警"
            />
          </div>
        </SectionPanel>

        {showAgentSection ? <SectionPanel title="智能体端点安全" description="端点与会话统计来自开发管理接口；未提供的口径不估算。">
          <div className="enterprise-metric-grid">
            <MetricCard label="端点总数" {...agentMetric(agentOverview?.endpoints_total)} tone="blue" hint="已注册端点" onClick={() => navigate('/agent/endpoints')} />
            <MetricCard label="活跃端点" {...agentMetric(agentOverview?.endpoints_active)} tone="blue" hint="服务端活跃状态口径" onClick={() => navigate('/agent/endpoints?status=active')} />
            <MetricCard label="失联端点" {...agentMetric(agentOverview?.endpoints_stale)} tone="orange" hint="服务端失联状态口径" onClick={() => navigate('/agent/endpoints?stale=true')} />
            <MetricCard label="活跃会话" {...agentMetric(agentOverview?.sessions_active)} tone="blue" hint="服务端活跃状态口径" onClick={() => navigate('/agent/sessions')} />
            <MetricCard label="近 24 小时事件" {...agentMetric(agentOverview?.events_24h)} tone="blue" hint="端点行为事件，非当前告警时间档位" />
            <MetricCard label="在库资产" {...agentMetric(agentOverview?.assets_present)} tone="blue" hint="服务端资产统计" />
            <MetricCard label="近 5 分钟 Hook 接收比例" value="—" tone="blue" hint="管理总览接口未提供接收量与分母，不推算" />
            <MetricCard label="今日阻断 / 收敛" value="—" tone="orange" hint="管理总览接口未提供今日决策统计；收敛不等于实际阻断" />
            <MetricCard label="采集积压" value="—" tone="orange" hint="管理总览接口未提供可汇总的积压口径" />
            <MetricCard label="策略版本 / 生成时间" value="—" tone="blue" hint="管理总览接口未提供策略包元数据" />
          </div>
          {agentOverviewQ.isError ? <Alert type="warning" showIcon message="智能体端点统计暂不可用，请检查管理接口或查看权限。" action={<Button size="small" onClick={() => void agentOverviewQ.refetch()}>重试</Button>} /> : null}
        </SectionPanel> : null}

        <Row gutter={[16, 16]}>
          <Col xs={24} lg={12}>
            <SectionPanel title="风险分类 TOP" description={`${rangeLabel}命中最多的问题类型；每个检测项独立精确计数，点击可下钻`}>
              {categoryRows.length > 0 ? (
                <RankedList
                  data={categoryRows.slice(0, 8).map((row: any) => ({ name: row.label, value: row.count, key: row.key }))}
                  height={OVERVIEW_CHART_HEIGHT}
                  unit="条"
                  onItemClick={(item) => gotoAlerts({ risk_category: item.key || item.name })}
                />
              ) : (
                <div style={{ height: OVERVIEW_CHART_HEIGHT, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)', fontSize: 13 }}>该时间范围暂无风险分类命中</div>
              )}
            </SectionPanel>
          </Col>
          <Col xs={24} lg={12}>
            <SectionPanel title="风险等级分布" description="含该等级告警的会话数；同一会话命中多个等级会分别计入" extra={<Button type="link" size="small" onClick={() => gotoAlerts({})}>查看明细</Button>}>
              {severityPie.length > 0 ? (
                <DistributionPie data={severityPie} height={OVERVIEW_CHART_HEIGHT} unit="条" />
              ) : (
                <div style={{ height: OVERVIEW_CHART_HEIGHT, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)', fontSize: 13 }}>该时间范围暂无告警</div>
              )}
            </SectionPanel>
          </Col>
        </Row>

        {/* 「处置状态分布」原来占这半行，已整块移除（五态枚举不恢复）；待处置只保留上方一个真实计数，
            口径见文件顶部注释。腾出的位置让「审计与留证覆盖」占满整行。 */}
        <SectionPanel
          title="审计与留证覆盖"
          description="网关这段时间实际审计了哪些内容；留证为已保存正文的调用。需要人工研判闭环请到「安全告警」页处置告警问题。"
          extra={<Button type="link" size="small" onClick={() => navigate(`/audit/access-retention?${new URLSearchParams(window_).toString()}`)}>查看留证</Button>}
        >
          {coverageUnavailable ? (
            <Alert type="warning" showIcon message="审计覆盖统计暂不可用，未以 0 替代真实数据" />
          ) : (
            <>
              <div className="enterprise-metric-grid">
                <MetricCard label="网关访问总量" valueNumber={auditTotal} tone="blue" hint={`普通公网 ${compactNumber(Number(coverage?.normal_public_count) || 0)} 次`} />
                <MetricCard label="模型调用" valueNumber={llmCount} tone="blue" hint={`AI IDE ${compactNumber(aiIdeCount)} 次`} />
                <MetricCard label="内容留证" valueNumber={retainedCount} tone="blue" hint="已保存请求或响应正文" />
                <MetricCard label="证据完整率" value={ratioToPercentText(evidenceQualityRatio)} tone={evidenceQualityRatio >= 0.9 ? 'green' : 'orange'} hint={`完整留存 ${compactNumber(completeEvidence)} 次`} />
              </div>
              <Tag data-testid="forward-proxy-undetected" color={undetectedCount ? 'orange' : 'default'} style={{ marginTop: 12 }}>
                未检测 {undetectedCount === null ? '—' : compactNumber(undetectedCount)} 次
              </Tag>
              <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
                <Col span={12}>
                  <Text type="secondary" style={{ fontSize: 12 }}>判定风险 {compactNumber(riskCount)} 次 · 阻断 {compactNumber(blockedCount)} 次（{reportCtx.modeLabel}）</Text>
                </Col>
                <Col span={12} style={{ textAlign: 'right' }}>
                  <Text type="secondary" style={{ fontSize: 12 }}>正向 {compactNumber(Number(coverage?.forward_count) || 0)} · 反向 {compactNumber(Number(coverage?.reverse_count) || 0)}</Text>
                </Col>
              </Row>
            </>
          )}
        </SectionPanel>

        <SectionPanel title="告警与审计趋势" description={`${rangeLabel}按时间分布，用于判断风险集中在哪个时段`}>
          {coverageUnavailable ? (
            <Alert type="warning" showIcon message="趋势数据暂不可用" />
          ) : timelineData.length > 0 ? (
            <TrendArea data={timelineData} series={[{ key: 'total', label: '网关访问' }, { key: 'risk', label: '判定风险' }]} height={240} />
          ) : (
            <div style={{ height: 240, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)', fontSize: 13 }}>暂无趋势数据</div>
          )}
        </SectionPanel>
      </Spin>

      <Modal
        open={reportOpen}
        onCancel={() => setReportOpen(false)}
        width={980}
        wrapClassName="billing-report-modal"
        title="安全运营总览报告"
        footer={[
          <Button key="close" onClick={() => setReportOpen(false)}>关闭</Button>,
          <Button key="print" icon={<PrinterOutlined />} onClick={() => window.print()}>打印 / 导出 PDF</Button>,
          <Button key="word" type="primary" icon={<DownloadOutlined />} onClick={exportWord}>导出 Word</Button>,
        ]}
      >
        <div className="billing-report-print-root">
          <div style={{ padding: '24px 32px' }}>
            <h2 style={{ margin: '0 0 8px', fontSize: 22 }}>安全运营总览报告</h2>
            <div style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 20 }}>
              {rangeLabel}（{rangeSpan}）告警留痕与审计覆盖汇总 · 生成于 {nowInTimezone(reportTz, 'YYYY-MM-DD HH:mm')} · 统计时区 {reportTz} · 执行模式 {reportCtx.modeLabel}
            </div>

            <h3 style={{ fontSize: 15, margin: '18px 0 8px' }}>一、告警留痕总览</h3>
            <Table
              size="small"
              pagination={false}
              rowKey="label"
              dataSource={[
                { label: '告警总数', value: overviewReady ? String(alertTotal) : '—', note: `${rangeLabel}内有可处置告警的会话数` },
                { label: '严重与高危', value: overviewReady ? String(severeCount) : '—', note: alertTotal > 0 ? `占 ${((severeCount / alertTotal) * 100).toFixed(1)}%` : '—' },
                { label: '命中风险类型', value: overviewReady ? String(categoryTypeCount) : '—', note: '按检测项去重' },
                { label: '涉及主体', value: overviewReady ? String(subjectCount) : '—', note: '产生过告警的 Key 归属主体数' },
                { label: '待处置告警', value: pendingReady ? String(pendingCount) : '—', note: '未处置且未抑制的告警问题' },
              ]}
              columns={[
                { title: '指标', dataIndex: 'label', key: 'label' },
                { title: '数值', dataIndex: 'value', key: 'value' },
                { title: '说明', dataIndex: 'note', key: 'note' },
              ]}
            />

            <h3 style={{ fontSize: 15, margin: '18px 0 8px' }}>二、风险分类分布</h3>
            <Table
              size="small"
              pagination={false}
              rowKey="label"
              dataSource={categoryRows}
              columns={[
                { title: '风险分类', dataIndex: 'label', key: 'label' },
                { title: '数量', dataIndex: 'count', key: 'count', render: (value: number) => value.toLocaleString() },
                { title: '占告警总数', key: 'ratio', render: (_: unknown, row: any) => (alertTotal > 0 ? `${((row.count / alertTotal) * 100).toFixed(1)}%` : '—') },
              ]}
            />

            <h3 style={{ fontSize: 15, margin: '18px 0 8px' }}>三、风险等级分布</h3>
            <Table
              size="small"
              pagination={false}
              rowKey="key"
              dataSource={severityRows.map((row) => ({ key: row.key, group: '风险等级', label: row.label, count: overviewReady ? String(row.count) : '—' }))}
              columns={[
                { title: '维度', dataIndex: 'group', key: 'group' },
                { title: '项目', dataIndex: 'label', key: 'label' },
                { title: '数量', dataIndex: 'count', key: 'count' },
              ]}
            />

            <h3 style={{ fontSize: 15, margin: '18px 0 8px' }}>四、审计与留证覆盖</h3>
            {coverageUnavailable ? (
              <div style={{ color: 'var(--status-warn)' }}>审计覆盖统计本次未取到数据，未以 0 代替。</div>
            ) : (
              <Table
                size="small"
                pagination={false}
                rowKey="label"
                dataSource={[
                  { label: '网关访问总量', value: auditTotal, note: '含普通公网访问' },
                  { label: '模型调用', value: llmCount, note: '经网关的模型请求' },
                  { label: 'AI IDE 调用', value: aiIdeCount, note: '编程助手类客户端' },
                  { label: '内容留证', value: retainedCount, note: '已保存请求或响应正文' },
                  { label: '判定风险', value: riskCount, note: '命中监测或告警规则' },
                  { label: '阻断', value: blockedCount, note: `只统计真实阻断；${reportCtx.modeNote}` },
                  { label: '证据完整', value: completeEvidence, note: `完整率 ${ratioToPercentText(evidenceQualityRatio)}` },
                ]}
                columns={[
                  { title: '指标', dataIndex: 'label', key: 'label' },
                  { title: '数值', dataIndex: 'value', key: 'value', render: (value: number) => value.toLocaleString() },
                  { title: '说明', dataIndex: 'note', key: 'note' },
                ]}
              />
            )}

            <h3 style={{ fontSize: 15, margin: '18px 0 8px' }}>五、结论与建议</h3>
            <ul style={{ paddingLeft: 20, margin: 0, fontSize: 13, lineHeight: 1.9 }}>
              {buildReportBlocks().filter((block): block is { type: 'bullets'; items: string[] } => block.type === 'bullets')
                .flatMap((block) => block.items)
                .map((item, index) => <li key={index}>{item}</li>)}
            </ul>
          </div>
        </div>
      </Modal>
    </div>
  )
}

export default SecurityOperationsOverview

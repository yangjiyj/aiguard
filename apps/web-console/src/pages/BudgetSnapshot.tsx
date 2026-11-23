import { CORE_SEVERITY_LABELS } from '../utils/risk'
import { Alert, Progress, Table, Tag, Typography, Row, Col, Card } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { alertApi, budgetApi } from '../services/api'
import { useCurrencyStore } from '../stores/currency'
import { AnalysisFlow, CompactNumber, EnterprisePageHeader, MetricCard, SectionPanel, StatusPill } from '../components/EnterpriseUI'
import { DistributionPie, RankingBar } from '../components/Charts'
import { compactNumber } from '../utils/format'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'

const { Text } = Typography

type Snapshot = Record<string, any>

type QuotaRow = {
  key: string
  name: string
  used: number
  limit: number
  unit: 'count' | 'tokens' | 'currency'
  description: string
}

type CostAlertRow = {
  id: string
  severity: string
  type: string
  message: string
  created_at: string
}

const COST_ALERT_MATCHERS = ['budget', 'cost', 'quota', 'usage', 'saving', 'forecast', 'expense', 'spend', 'token']
const COST_ALERT_TEXT_RE = /(预算|费用|成本|配额|用量|Token)/i

function pickString(obj: Snapshot | null | undefined, ...keys: string[]): string {
  if (!obj) return ''
  for (const key of keys) {
    const value = obj[key]
    if (typeof value === 'string' && value.trim() !== '') return value
    if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  }
  return ''
}

function normalizeCostAlert(raw: Snapshot): CostAlertRow {
  return {
    id: pickString(raw, 'id', 'ID'),
    severity: pickString(raw, 'severity', 'Severity') || 'info',
    type: pickString(raw, 'type', 'Type'),
    message: pickString(raw, 'message', 'title', 'Title'),
    created_at: pickString(raw, 'created_at', 'CreatedAt'),
  }
}

function isCostAlert(row: CostAlertRow): boolean {
  if (!row.message.trim()) return false
  const type = row.type.toLowerCase()
  if (type.includes('security')) return false
  if (COST_ALERT_MATCHERS.some((keyword) => type.includes(keyword))) return true
  return COST_ALERT_TEXT_RE.test(`${row.type} ${row.message}`)
}

function unwrapPayload(data: any): Snapshot | null {
  const raw = data?.data
  if (raw?.data && typeof raw.data === 'object' && !Array.isArray(raw.data)) return raw.data
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) return raw
  return null
}

function pickNumber(obj: Snapshot | null | undefined, ...keys: string[]): number {
  if (!obj) return 0
  for (const key of keys) {
    const value = obj[key]
    if (typeof value === 'number' && Number.isFinite(value)) return value
    if (typeof value === 'string' && value.trim() !== '') {
      const parsed = Number(value)
      if (Number.isFinite(parsed)) return parsed
    }
  }
  return 0
}

function formatNumber(value: number): string {
  return Math.round(value).toLocaleString('zh-CN')
}

function formatValue(value: number, unit: QuotaRow['unit'], formatCurrency: (value: number) => string): string {
  if (unit === 'currency') return formatCurrency(value)
  if (unit === 'tokens') return `${compactNumber(value)} 个 Token`
  return formatNumber(value)
}

function usagePercent(used: number, limit: number): number {
  if (!limit || limit <= 0) return 0
  return Math.min(100, Math.round((used / limit) * 100))
}

function progressStatus(pct: number): 'success' | 'normal' | 'exception' {
  if (pct >= 90) return 'exception'
  if (pct >= 70) return 'normal'
  return 'success'
}

const ALERT_SEVERITY_LABELS: Record<string, string> = { ...CORE_SEVERITY_LABELS, warning: '提醒', info: '信息' }

function severityTag(value?: string) {
  const colors: Record<string, string> = { critical: 'red', high: 'orange', warning: 'gold', info: 'blue' }
  const key = value || 'info'
  return <Tag color={colors[key] || 'blue'}>{ALERT_SEVERITY_LABELS[key] || '信息'}</Tag>
}

export default function BudgetSnapshot() {
  const auditIdentity = useAuditQueryIdentity()
  const { format } = useCurrencyStore()
  const formatCurrency = (value: number) => format(value, 2)

  const snapQ = useQuery({
    queryKey: ['budget-snapshot', auditIdentity, 'tenant'],
    queryFn: () => budgetApi.snapshot({ scope_type: 'tenant' }),
    refetchInterval: 30000,
    staleTime: 30000,
    refetchOnWindowFocus: false,
    placeholderData: (previousData) => previousData,
  })

  const inboxQ = useQuery({
    queryKey: ['alerts-inbox-snap', auditIdentity],
    queryFn: () => alertApi.inbox(false),
    refetchInterval: 30000,
    staleTime: 30000,
    refetchOnWindowFocus: false,
    placeholderData: (previousData) => previousData,
  })

  const snapshot = unwrapPayload(snapQ.data)
  const quota = snapshot?.effective_quota || snapshot?.EffectiveQuota || {}
  const rawAlerts: Snapshot[] = Array.isArray(inboxQ.data?.data?.items) ? inboxQ.data.data.items : []
  const alerts = rawAlerts.map(normalizeCostAlert).filter(isCostAlert)

  const dayRequests = pickNumber(snapshot, 'day_requests', 'DayRequests')
  const dayTokens = pickNumber(snapshot, 'day_tokens', 'DayTokens')
  const dayCost = pickNumber(snapshot, 'day_cost', 'DayCost')
  const monthRequests = pickNumber(snapshot, 'month_requests', 'MonthRequests')
  const monthTokens = pickNumber(snapshot, 'month_tokens', 'MonthTokens')
  const monthCost = pickNumber(snapshot, 'month_cost', 'MonthCost')
  const rpm = pickNumber(snapshot, 'rpm', 'Rpm', 'RPM')
  const concurrency = pickNumber(snapshot, 'concurrency', 'Concurrency')

  const quotaRows: QuotaRow[] = [
    { key: 'daily-token', name: '今日 Token 用量', used: dayTokens, limit: pickNumber(quota, 'daily_token_limit', 'DailyTokenLimit'), unit: 'tokens', description: '当天模型输入与输出 Token 合计' },
    { key: 'monthly-token', name: '本月 Token 用量', used: monthTokens, limit: pickNumber(quota, 'monthly_token_limit', 'MonthlyTokenLimit'), unit: 'tokens', description: '本月累计模型输入与输出 Token' },
    { key: 'daily-budget', name: '今日费用', used: dayCost, limit: pickNumber(quota, 'daily_budget_limit', 'DailyBudgetLimit'), unit: 'currency', description: '当天已产生的模型调用费用' },
    { key: 'monthly-budget', name: '本月费用', used: monthCost, limit: pickNumber(quota, 'monthly_budget_limit', 'MonthlyBudgetLimit'), unit: 'currency', description: '本月已产生的模型调用费用' },
    { key: 'rpm', name: '近一分钟请求', used: rpm, limit: pickNumber(quota, 'rpm_limit', 'RPMLimit'), unit: 'count', description: '最近一分钟内进入网关的请求量' },
    { key: 'concurrency', name: '当前并发', used: concurrency, limit: pickNumber(quota, 'concurrency_limit', 'ConcurrencyLimit'), unit: 'count', description: '当前正在处理的并发请求数' },
  ]

  const riskyQuota = quotaRows.find((row) => row.limit > 0 && usagePercent(row.used, row.limit) >= 80)

  const quotaColumns = [
    { title: '监控项', dataIndex: 'name', key: 'name', width: 180 },
    { title: '已使用', key: 'used', render: (_: any, row: QuotaRow) => row.unit === 'tokens' ? <CompactNumber value={row.used} suffix="个 Token" /> : formatValue(row.used, row.unit, formatCurrency), width: 180 },
    { title: '配额上限', key: 'limit', render: (_: any, row: QuotaRow) => row.limit > 0 ? (row.unit === 'tokens' ? <CompactNumber value={row.limit} suffix="个 Token" /> : formatValue(row.limit, row.unit, formatCurrency)) : <Tag>未配置</Tag>, width: 180 },
    {
      title: '使用率',
      key: 'percent',
      render: (_: any, row: QuotaRow) => {
        const pct = usagePercent(row.used, row.limit)
        return row.limit > 0 ? <Progress percent={pct} status={progressStatus(pct)} size="small" /> : <Text type="secondary">暂不计算</Text>
      },
      width: 220,
    },
    { title: '说明', dataIndex: 'description', key: 'description' },
  ]

  const alertColumns = [
    { title: '级别', dataIndex: 'severity', key: 'severity', render: (v: string) => severityTag(v), width: 100 },
    { title: '告警内容', dataIndex: 'message', key: 'message', ellipsis: true },
    { title: '发生时间', dataIndex: 'created_at', key: 'created_at', render: (v: string) => v ? new Date(v).toLocaleString('zh-CN') : '-', width: 180 },
  ]

  return (
    <div className="enterprise-page">
      <EnterprisePageHeader
        eyebrow="费用治理"
        title="用量监控"
        description="查看当前单位的模型调用量、费用消耗和配额使用情况，后台每 30 秒刷新一次。"
        meta={(
          <>
            <StatusPill tone={riskyQuota ? 'orange' : 'green'}>{riskyQuota ? `${riskyQuota.name} 接近上限` : '配额水位平稳'}</StatusPill>
          </>
        )}
      />

      {snapQ.isError ? (
        <Alert type="error" message="用量监控数据暂不可用" description="请检查控制面与 Redis 计费数据连接状态。" showIcon />
      ) : (
        <>
          <SectionPanel title="实时用量">
            <div className="enterprise-metric-grid six">
              <MetricCard label="今日请求" valueNumber={dayRequests} unit="次" tone="blue" />
              <MetricCard label="今日 Token" valueNumber={dayTokens} tone="green" />
              <MetricCard label="今日费用" value={formatCurrency(dayCost)} tone="orange" />
              <MetricCard label="本月费用" value={formatCurrency(monthCost)} tone="orange" />
              <MetricCard label="近一分钟请求" valueNumber={rpm} unit="次" tone="purple" />
              <MetricCard label="当前并发" value={formatNumber(concurrency)} unit="路" tone="cyan" />
            </div>
          </SectionPanel>

          {/* 配额水位预警看板：一目了然哪个配额即将到上限 */}
          <SectionPanel
            title="配额水位预警"
            description={riskyQuota ? `⚠️ ${riskyQuota.name} 已达 ${usagePercent(riskyQuota.used, riskyQuota.limit)}%，接近上限` : '所有配额水位正常'}
          >
            <Row gutter={[16, 16]}>
              {quotaRows.filter((row) => row.limit > 0).map((row) => {
                const pct = usagePercent(row.used, row.limit)
                const tone = pct >= 90 ? 'var(--status-danger)' : pct >= 70 ? 'var(--status-warn)' : 'var(--status-ok)'
                const status = pct >= 90 ? '危险' : pct >= 70 ? '警戒' : '正常'
                return (
                  <Col xs={24} sm={12} lg={8} key={row.key}>
                    <Card size="small" style={{ borderRadius: 8, borderLeft: `4px solid ${tone}` }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                        <Text strong style={{ fontSize: 14 }}>{row.name}</Text>
                        <Tag color={pct >= 90 ? 'red' : pct >= 70 ? 'orange' : 'green'}>{status}</Tag>
                      </div>
                      <div style={{ fontSize: 24, fontWeight: 600, color: tone, marginBottom: 4 }}>
                        {pct}%
                      </div>
                      <Progress percent={pct} strokeColor={tone} trailColor="var(--bg-secondary)" size="small" format={() => ''} />
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        {formatValue(row.used, row.unit, formatCurrency)} / {formatValue(row.limit, row.unit, formatCurrency)}
                      </Text>
                    </Card>
                  </Col>
                )
              })}
              {quotaRows.filter((r) => r.limit > 0).length === 0 && (
                <Col span={24}>
                  <Alert type="info" message="未配置配额上限" description="当前单位未设置任何配额限制，请在「费用治理 → 配额策略」中配置日/月 Token、费用、RPM、并发上限。" showIcon />
                </Col>
              )}
            </Row>
          </SectionPanel>

          <SectionPanel title="用量分析过程" description={`统计周期：今日 ${snapshot?.day || snapshot?.Day || '-'}，本月 ${snapshot?.month || snapshot?.Month || '-'}`}>
            <AnalysisFlow
              items={[
                { label: '采集实时用量', value: `${compactNumber(dayRequests)} 次请求`, tone: 'blue', description: `本月累计 ${compactNumber(monthRequests)} 次请求` },
                { label: '汇总 Token 与费用', value: formatCurrency(monthCost), tone: 'orange', description: `本月 Token ${compactNumber(monthTokens)}` },
                { label: '对照配额水位', value: riskyQuota ? riskyQuota.name : '未触发', tone: riskyQuota ? 'orange' : 'green', description: riskyQuota ? '建议查看配额策略' : '当前配额使用率正常' },
                { label: '形成动作', value: riskyQuota ? '复核或扩容' : '继续观察', tone: riskyQuota ? 'orange' : 'blue', description: '必要时进入配额策略调整阈值' },
              ]}
            />
          </SectionPanel>

          <SectionPanel title="配额使用情况">
            <Table size="small" dataSource={quotaRows} columns={quotaColumns} rowKey="key" pagination={false} loading={snapQ.isLoading} />
          </SectionPanel>

          {alerts.length > 0 && (
            <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
              <Col xs={24} lg={12}>
                <Card size="small" title="告警严重程度分布" style={{ borderRadius: 8 }}>
                  <DistributionPie
                    data={Object.entries(alerts.reduce((acc: Record<string, number>, a) => { acc[a.severity] = (acc[a.severity] || 0) + 1; return acc }, {})).map(([sev, count]) => ({ name: ALERT_SEVERITY_LABELS[sev] || sev, value: count }))}
                    height={220}
                  />
                </Card>
              </Col>
              <Col xs={24} lg={12}>
                <Card size="small" title="配额使用率对比" style={{ borderRadius: 8 }}>
                  <RankingBar
                    data={quotaRows.filter((r) => r.limit > 0).map((r) => ({ name: r.name, value: usagePercent(r.used, r.limit) }))}
                    unit="%"
                    horizontal={false}
                    height={220}
                  />
                </Card>
              </Col>
            </Row>
          )}
        </>
      )}

      <SectionPanel title="近期费用告警">
        <Table
          size="small"
          dataSource={alerts}
          columns={alertColumns}
          rowKey={(r: any) => r.id || r.created_at || r.message}
          pagination={{ defaultPageSize: 10 }}
          loading={inboxQ.isLoading}
          locale={{ emptyText: '暂无费用告警' }}
        />
      </SectionPanel>
    </div>
  )
}

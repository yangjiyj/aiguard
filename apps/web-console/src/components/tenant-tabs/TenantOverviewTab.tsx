import { Card, Progress, Row, Col, Spin, Tooltip, Alert } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { budgetApi, tenantApi, usageApi } from '../../services/api'
import { useCurrencyStore } from '../../stores/currency'
import { TrendArea } from '../Charts'
import { compactNumber, formatFull } from '../../utils/format'

function pct(used: number, quota: number): number {
  if (!quota || quota <= 0) return 0
  return Math.min(100, Math.round((used / quota) * 100))
}

function pickNumber(obj: any, ...keys: string[]): number {
  if (!obj) return 0
  for (const k of keys) {
    const v = obj[k]
    if (typeof v === 'number') return v
    if (typeof v === 'string' && v.trim() !== '' && !isNaN(Number(v))) return Number(v)
  }
  return 0
}

function resourceCount(response: any): number {
  const payload = response?.data
  if (Array.isArray(payload?.data)) return payload.data.length
  if (Array.isArray(payload)) return payload.length
  return 0
}

const cardStyle = { borderRadius: 8 }

export function TenantOverviewTab({ tenantId, isOwn }: { tenantId: string; isOwn: boolean }) {
  const { format } = useCurrencyStore()
  const q = useQuery({
    queryKey: ['tenant-overview', tenantId],
    enabled: !!tenantId && isOwn,
    queryFn: () => budgetApi.snapshot({ scope_type: 'tenant', scope_id: tenantId }),
  })
  const trendQ = useQuery({
    queryKey: ['tenant-usage-trend', tenantId],
    enabled: !!tenantId && isOwn,
    queryFn: () => usageApi.trend({ start_date: getNDaysAgo(30), end_date: getToday() }),
  })
  const resourcesQ = useQuery({
    queryKey: ['tenant-resource-overview', tenantId],
    enabled: !!tenantId && !isOwn,
    queryFn: () => Promise.all([
      tenantApi.listTeams(tenantId),
      tenantApi.listUsers(tenantId),
      tenantApi.listProjects(tenantId),
      tenantApi.listKeys(tenantId),
    ]),
  })

  if (!isOwn) {
    const counts = resourcesQ.data?.map(resourceCount) || [0, 0, 0, 0]
    return (
      <Spin spinning={resourcesQ.isLoading}>
        <Alert
          type="info"
          showIcon
          message="跨单位仅展示资源规模，不展示用量/费用"
          style={{ marginBottom: 16 }}
        />
        <Row gutter={[16, 16]}>
          {[
            ['部门数', counts[0]],
            ['用户数', counts[1]],
            ['应用数', counts[2]],
            ['密钥数', counts[3]],
          ].map(([label, count]) => (
            <Col xs={24} sm={12} lg={6} key={String(label)}>
              <Card size="small" style={cardStyle}>
                <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 4 }}>{label}</div>
                <div style={{ fontSize: 24, fontWeight: 600, color: 'var(--text-primary)' }}>{count}</div>
              </Card>
            </Col>
          ))}
        </Row>
      </Spin>
    )
  }

  const raw = q.data?.data
  const obj = (raw?.data && typeof raw.data === 'object') ? raw.data : raw
  const s: any = Array.isArray(obj) ? (obj[0] || {}) : (obj || {})
  const quota = s?.effective_quota || s?.EffectiveQuota || {}

  const monthCost = pickNumber(s, 'month_cost', 'MonthCost')
  const monthBudgetLimit = pickNumber(quota, 'monthly_budget_limit', 'MonthlyBudgetLimit')
  const monthTokens = pickNumber(s, 'month_tokens', 'MonthTokens')
  const monthlyTokenLimit = pickNumber(quota, 'monthly_token_limit', 'MonthlyTokenLimit')
  const dayTokens = pickNumber(s, 'day_tokens', 'DayTokens')
  const dailyTokenLimit = pickNumber(quota, 'daily_token_limit', 'DailyTokenLimit')
  const trendData = (trendQ.data?.data?.data || []).map((d: any) => ({ date: d.date, cost: d.total_cost || 0, requests: d.requests || 0 }))

  return (
    <Spin spinning={q.isLoading}>
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={8}>
          <Card size="small" style={cardStyle}>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 4 }}>本月预算消耗</div>
            <div style={{ fontSize: 24, fontWeight: 600, color: 'var(--text-primary)' }}>
              {format(monthCost, 2)}
              {monthBudgetLimit > 0 && <span style={{ fontSize: 13, color: 'var(--text-tertiary)', marginLeft: 4 }}>/ {format(monthBudgetLimit, 0)}</span>}
            </div>
            <Progress percent={pct(monthCost, monthBudgetLimit)} size="small" status={pct(monthCost, monthBudgetLimit) >= 80 ? 'exception' : 'active'} style={{ marginTop: 8 }} />
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card size="small" style={cardStyle}>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 4 }}>本月 Token 用量</div>
            <div style={{ fontSize: 24, fontWeight: 600, color: 'var(--text-primary)' }}>
              <Tooltip title={formatFull(monthTokens)}>{compactNumber(monthTokens)}</Tooltip>
              {monthlyTokenLimit > 0 && <span style={{ fontSize: 13, color: 'var(--text-tertiary)', marginLeft: 4 }}>/ {compactNumber(monthlyTokenLimit)}</span>}
            </div>
            <Progress percent={pct(monthTokens, monthlyTokenLimit)} size="small" status={pct(monthTokens, monthlyTokenLimit) >= 80 ? 'exception' : 'active'} style={{ marginTop: 8 }} />
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card size="small" style={cardStyle}>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 4 }}>今日 Token 用量</div>
            <div style={{ fontSize: 24, fontWeight: 600, color: 'var(--text-primary)' }}>
              <Tooltip title={formatFull(dayTokens)}>{compactNumber(dayTokens)}</Tooltip>
              {dailyTokenLimit > 0 && <span style={{ fontSize: 13, color: 'var(--text-tertiary)', marginLeft: 4 }}>/ {compactNumber(dailyTokenLimit)}</span>}
            </div>
            <Progress percent={pct(dayTokens, dailyTokenLimit)} size="small" status={pct(dayTokens, dailyTokenLimit) >= 80 ? 'exception' : 'active'} style={{ marginTop: 8 }} />
          </Card>
        </Col>
      </Row>

      <Card size="small" style={{ marginTop: 16, borderRadius: 8 }} title={<span style={{ fontSize: 14, fontWeight: 600 }}>近30天费用与请求趋势</span>}>
        {trendData.length > 0 ? (
          <TrendArea data={trendData} series={[{ key: 'cost', label: '费用' }, { key: 'requests', label: '请求数' }]} currencyFormatter={(v) => format(v, 2)} />
        ) : (
          <div style={{ height: 240, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)', fontSize: 13 }}>暂无趋势数据</div>
        )}
      </Card>
    </Spin>
  )
}

function getToday(): string {
  const d = new Date()
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

function getNDaysAgo(n: number): string {
  const d = new Date(Date.now() - n * 24 * 60 * 60 * 1000)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

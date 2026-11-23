import { Alert, Button, Col, Row, Spin, Table, Typography } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import dayjs from 'dayjs'
import { useNavigate } from 'react-router-dom'
import { EnterprisePageHeader, MetricCard, SectionPanel } from '../components/EnterpriseUI'
import { licenseApi } from '../services/api'
import { agentEndpointApi, agentKeys } from '../services/agentEndpoint'
import type { AgentEndpoint } from '../services/agentEndpoint.types'
import type { ProductIdentity } from '../product/profiles'
import { label, products, time } from './agent/dict'

export default function PlatformDashboard({ product }: { product: ProductIdentity }) {
  const navigate = useNavigate()
  const [todayStart] = useState(() => dayjs().startOf('day').toISOString())
  const tomorrowStart = dayjs(todayStart).add(1, 'day').toISOString()
  const licenseQ = useQuery({ queryKey: ['licenseStatus'], queryFn: () => licenseApi.status().then(response => response.data), retry: false, staleTime: 60_000 })
  const enabled = licenseQ.data?.valid === true && licenseQ.data.features?.includes('agent_security') === true
  const overviewQ = useQuery({ queryKey: agentKeys.overview, queryFn: agentEndpointApi.overview, enabled, retry: false })
  const sessionsQ = useQuery({ queryKey: agentKeys.sessions({ from: todayStart, to: tomorrowStart, page: 1, page_size: 200 }), queryFn: () => agentEndpointApi.sessions({ from: todayStart, to: tomorrowStart, page: 1, page_size: 200 }), enabled, retry: false })
  const eventsQ = useQuery({ queryKey: [...agentKeys.scope, 'today-events', todayStart], queryFn: () => agentEndpointApi.todayEvents(todayStart, tomorrowStart), enabled, retry: false })
  const endpointsQ = useQuery({ queryKey: agentKeys.endpoints({ page: 1, page_size: 200 }), queryFn: () => agentEndpointApi.endpoints({ page: 1, page_size: 200 }), enabled, retry: false })
  const productPagesQ = useQuery({
    queryKey: [...agentKeys.scope, 'dashboard-product-counts'],
    queryFn: () => Promise.all(products.map(async item => ({ product: item, page: await agentEndpointApi.endpoints({ product: item.value, page: 1, page_size: 1 }) }))),
    enabled, retry: false,
  })
  const policyQ = useQuery({ queryKey: [...agentKeys.scope, 'current-policy-bundle'], queryFn: agentEndpointApi.currentPolicyBundle, enabled, retry: false })
  const metric = (value: number | undefined, error = false) => !enabled || error || value == null ? { value: '—' } : { valueNumber: value }
  const allTodaySessions = sessionsQ.data && sessionsQ.data.total <= sessionsQ.data.items.length
  const blocked = allTodaySessions ? sessionsQ.data!.items.reduce((sum, item) => sum + item.blocked_count, 0) : undefined
  const wouldBlock = allTodaySessions ? sessionsQ.data!.items.reduce((sum, item) => sum + item.would_block_count, 0) : undefined
  const endpointRows = endpointsQ.data?.items ?? []
  const knownProducts = productPagesQ.data?.reduce((sum, item) => sum + item.page.total, 0)
  const unclassified = overviewQ.isSuccess && productPagesQ.isSuccess ? overviewQ.data.endpoints_total - (knownProducts ?? 0) : 0
  const productDistributionReady = productPagesQ.isSuccess && overviewQ.isSuccess && unclassified >= 0
  const healthAvailable = endpointsQ.data && endpointsQ.data.total <= endpointRows.length
  const queueEvents = healthAvailable && endpointRows.every(item => typeof item.health?.queue_events === 'number')
    ? endpointRows.reduce((sum, item) => sum + Number(item.health.queue_events), 0) : undefined
  const droppedEvents = healthAvailable && endpointRows.every(item => typeof item.health?.dropped_events === 'number')
    ? endpointRows.reduce((sum, item) => sum + Number(item.health.dropped_events), 0) : undefined

  return <div className="enterprise-page">
    <EnterprisePageHeader eyebrow="智能体安全与模型网关" title="智能体安全态势" description={`${product.name} · 今日按浏览器本地自然日统计；缺少可靠接口的指标显示不可用。`} />
    {licenseQ.isPending ? <Spin spinning><div style={{ minHeight: 120 }} /></Spin> : null}
    {!enabled && !licenseQ.isPending ? <Alert type="info" showIcon message={licenseQ.isError ? '授权状态暂不可用；未请求端侧接口' : '当前未授权 agent_security；端侧态势暂不可用'} description="以下端侧指标仅作占位，不代表已发现端点或采集事件。" style={{ marginBottom: 16 }} /> : null}
    {enabled && [overviewQ, sessionsQ, eventsQ, endpointsQ, productPagesQ, policyQ].some(query => query.isError) ? <Alert type="warning" showIcon message="部分端侧接口暂不可用，相关数值不以 0 代替" style={{ marginBottom: 16 }} /> : null}
    {enabled ? <Button type="link" onClick={() => navigate('/agent/assets')}>查看资产覆盖与风险体检</Button> : null}
    <SectionPanel title="今日态势" description="今日会话按开始时间，今日事件按发生时间；阻断和收敛为今日新会话的累计值，不等同于今日发生的全部命中。">
      <div className="enterprise-metric-grid">
        <MetricCard label="今日会话" {...metric(sessionsQ.data?.total, sessionsQ.isError)} tone="blue" onClick={enabled ? () => navigate('/agent/sessions') : undefined} />
        <MetricCard label="今日端侧事件" {...metric(eventsQ.data?.total, eventsQ.isError)} tone="blue" />
        <MetricCard label="今日新会话累计阻断" {...metric(blocked, sessionsQ.isError)} tone="orange" hint={sessionsQ.data && !allTodaySessions ? '超过 200 条会话，无法准确汇总' : undefined} />
        <MetricCard label="今日新会话累计收敛" {...metric(wouldBlock, sessionsQ.isError)} tone="orange" hint={sessionsQ.data && !allTodaySessions ? '超过 200 条会话，无法准确汇总' : undefined} />
        <MetricCard label="活跃会话" {...metric(overviewQ.data?.sessions_active, overviewQ.isError)} tone="blue" />
        <MetricCard label="近24小时端侧事件（非今日）" {...metric(overviewQ.data?.events_24h, overviewQ.isError)} tone="blue" />
      </div>
    </SectionPanel>
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={12}><SectionPanel title="产品分布" description="按已注册端点的产品字段统计，包含吊销端点；未知产品按总量差额列示。">
        {enabled && productDistributionReady && productPagesQ.data ? <Table size="small" pagination={false} rowKey="value" dataSource={[...productPagesQ.data.filter(item => item.page.total > 0).map(item => ({ ...item.product, total: item.page.total })), ...(unclassified > 0 ? [{ value: 'unclassified', label: '未识别产品', total: unclassified }] : [])]} columns={[{ title: '产品', dataIndex: 'label' }, { title: '端点数', dataIndex: 'total' }]} locale={{ emptyText: '暂无端点' }} /> : <Typography.Text type="secondary">不可用（授权、端点统计或产品分布尚未就绪）</Typography.Text>}
      </SectionPanel></Col>
      <Col xs={24} lg={12}><SectionPanel title="采集健康" description="仅在全部端点均已加载且心跳带有采集健康字段时展示汇总。">
        <div className="enterprise-metric-grid">
          <MetricCard label="已注册端点" {...metric(overviewQ.data?.endpoints_total, overviewQ.isError)} tone="blue" />
          <MetricCard label="活跃端点（含失联）" {...metric(overviewQ.data?.endpoints_active, overviewQ.isError)} tone="blue" />
          <MetricCard label="失联端点" {...metric(overviewQ.data?.endpoints_stale, overviewQ.isError)} tone="orange" />
          <MetricCard label="积压事件" {...metric(queueEvents)} tone="orange" />
          <MetricCard label="丢弃事件" {...metric(droppedEvents)} tone="orange" />
        </div>
        {enabled && endpointsQ.data && !healthAvailable ? <Typography.Text type="secondary">端点超过 200 台，采集健康汇总暂不可用。</Typography.Text> : null}
        {enabled ? <Button type="link" onClick={() => navigate('/agent/endpoints')}>查看端点采集详情</Button> : null}
      </SectionPanel></Col>
    </Row>
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={12}><SectionPanel title="Top 风险端点" description="当前端点列表不支持按风险排序，且未提供全量端点风险聚合接口。"><Typography.Text type="secondary">暂不可用，不能将前 200 台端点误作全量风险排名。</Typography.Text></SectionPanel></Col>
      <Col xs={24} lg={12}><SectionPanel title="最近 10 条端侧告警" description="当前仅会话详情含关联告警，没有可按时间排序的全局端侧告警接口。"><Typography.Text type="secondary">暂不可用；请从关联会话查看告警。</Typography.Text></SectionPanel></Col>
    </Row>
    <SectionPanel title="当前策略包版本" description="读取已发布的最新端侧策略包，不等同于端点实际应用版本。">
      {enabled && policyQ.isSuccess ? <Typography.Text>版本 {policyQ.data.version} · 发布于 {time(policyQ.data.created_at)}</Typography.Text> : <Typography.Text type="secondary">{policyQ.isError ? '暂不可用（尚未发布策略包或接口失败）' : '—'}</Typography.Text>}
      {enabled && healthAvailable ? <Table size="small" rowKey="id" pagination={{ pageSize: 5 }} dataSource={endpointRows} columns={[{ title: '端点', dataIndex: 'hostname', render: (host: string, endpoint: AgentEndpoint) => host || endpoint.id }, { title: '产品', dataIndex: 'product', render: (value: string) => label(products, value) }, { title: '端点已应用版本', dataIndex: 'last_policy_version', render: (value: number) => value > 0 ? value : '未上报' }]} /> : null}
    </SectionPanel>
  </div>
}

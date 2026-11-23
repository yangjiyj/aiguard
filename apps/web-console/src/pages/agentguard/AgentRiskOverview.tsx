import { SEVERITY_LABELS } from '../../utils/risk'
import { useMemo, useState } from 'react'
import { Alert, Button, Card, Col, DatePicker, Progress, Row, Space, Statistic, Table, Tag, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import dayjs, { type Dayjs } from 'dayjs'
import {
  agentStatsApi,
  getAgentRiskOverview,
  type ObjectCount,
  type PolicyCount,
  type RiskLevelCount,
  type ToolCount,
} from '../../services/api'
import { formatAgentType, getAgentColor, getAgentDetection } from '../../utils/agents'
import { compactNumber, formatFull } from '../../utils/format'
import { getRuntimeModeLabel, getStatusSourceLabel } from '../../utils/statusSource'
import { getActivationProps } from '../../utils/interaction'
import { CompactNumber } from '../../components/EnterpriseUI'

const { RangePicker } = DatePicker
const { Text } = Typography

const modeColors: Record<string, string> = {
  allow: 'green',
  audit: 'blue',
  confirm: 'orange',
  block: 'red',
}

const modeLabels: Record<string, string> = {
  allow: '放行',
  audit: '审计',
  confirm: '确认',
  block: '阻断',
}

const riskColors: Record<string, string> = {
  low: 'green',
  medium: 'orange',
  high: 'red',
  critical: 'magenta',
}

const decisionOrder = ['allow', 'audit', 'confirm', 'block'] as const

const decisionLabels: Record<(typeof decisionOrder)[number], string> = {
  allow: '放行',
  audit: '审计',
  confirm: '需确认',
  block: '阻断',
}

const formatCount = (value?: number) => <CompactNumber value={value} />
const metricValue = (value?: number) => value ?? '暂不可用'
const metricFormatter = (value: string | number) =>
  value === '暂不可用' ? value : compactNumber(Number(value))

type AgentStatItem = {
  agent_type: string
  session_count: number
  request_count: number
  content_request_count?: number
  tool_backed_request_count?: number
  percent: number
}

// 部分厂商品牌色接近纯黑，在暗色背景下不可见——替换为可见的中性色
const barColor = (agentType: string) => {
  const color = getAgentColor(agentType)
  return ['#000000', '#111827'].includes(color.toLowerCase()) ? '#64748b' : color
}

const canOpenRetainedEvidence = (item: AgentStatItem) => {
  const requestCount = item.request_count || 0
  if (requestCount <= 0) return false
  if (typeof item.content_request_count === 'number') {
    return item.content_request_count === requestCount
  }
  return getAgentDetection(item.agent_type).label === '客户端标识/特征识别'
}

function AgentRiskOverview() {
  const navigate = useNavigate()
  const [range, setRange] = useState<[Dayjs, Dayjs]>(() => [dayjs().subtract(7, 'day'), dayjs()])
  const params = useMemo(() => ({
    start: range[0].toISOString(),
    end: range[1].toISOString(),
  }), [range])

  const overviewQ = useQuery({
    queryKey: ['agent-risk-overview', params],
    queryFn: () => getAgentRiskOverview(params),
  })
  const overview = overviewQ.data?.data

  const agentStatsQ = useQuery({
    queryKey: ['agent-identification-stats', params],
    queryFn: () => agentStatsApi.getStats(params),
  })
  const agentStats = ((agentStatsQ.data?.data as AgentStatItem[] | undefined) || [])
    .slice()
    .sort((a, b) => (b.request_count || 0) - (a.request_count || 0))
  const agentTotal = agentStats.reduce((sum, item) => sum + (item.request_count || 0), 0)
  const identifiedRequests = agentStats
    .filter((item) => getAgentDetection(item.agent_type).label === '客户端标识/特征识别')
    .reduce((sum, item) => sum + (item.request_count || 0), 0)
  const identificationCoverage = agentTotal ? Math.round((identifiedRequests / agentTotal) * 1000) / 10 : 0

  const appendCurrentRange = (search: URLSearchParams) => {
    search.set('from', params.start)
    search.set('to', params.end)
  }

  const jumpToToolAudit = (filters: Record<string, string>) => {
    const search = new URLSearchParams()
    Object.entries(filters).forEach(([key, value]) => {
      if (value) search.set(key, value)
    })
    appendCurrentRange(search)
    navigate(`/security/agent-tools?${search.toString()}`)
  }

  const jumpToAccessRetention = (filters: Record<string, string>) => {
    const search = new URLSearchParams()
    Object.entries(filters).forEach(([key, value]) => {
      if (value) search.set(key, value)
    })
    appendCurrentRange(search)
    search.set('content_only', 'true')
    navigate(`/audit/access-retention?${search.toString()}`)
  }

  const riskColumns = useMemo<ColumnsType<RiskLevelCount>>(() => [
    {
      title: '风险分类',
      dataIndex: 'risk_level',
      key: 'risk_level',
      render: (value: string) => <Tag color={riskColors[value] || 'default'}>{SEVERITY_LABELS[value] || value || '-'}</Tag>,
    },
    {
      title: '数量',
      dataIndex: 'count',
      key: 'count',
      align: 'right',
      render: formatCount,
    },
  ], [])

  const toolColumns = useMemo<ColumnsType<ToolCount>>(() => [
    {
      title: '工具',
      dataIndex: 'tool_name',
      key: 'tool_name',
      render: (value: string) => <Text code>{value || '-'}</Text>,
    },
    {
      title: '调用数',
      dataIndex: 'count',
      key: 'count',
      align: 'right',
      render: formatCount,
    },
  ], [])

  const policyColumns = useMemo<ColumnsType<PolicyCount>>(() => [
    {
      title: '治理方案',
      dataIndex: 'policy_name',
      key: 'policy_name',
      render: (value: string) => value || '未命名方案',
    },
    {
      title: '动作',
      dataIndex: 'mode',
      key: 'mode',
      render: (value: string) => <Tag color={modeColors[value] || 'default'}>{modeLabels[value] || value || '-'}</Tag>,
    },
    {
      title: '次数',
      dataIndex: 'count',
      key: 'count',
      align: 'right',
      render: formatCount,
    },
  ], [])

  const objectColumns = (fallbackLabel: string): ColumnsType<ObjectCount> => [
    {
      title: '对象',
      key: 'object',
      render: (_, record) => <Text>{record.name && record.name !== record.id ? record.name : fallbackLabel}</Text>,
    },
    {
      title: '次数',
      dataIndex: 'count',
      key: 'count',
      align: 'right',
      width: 90,
      render: formatCount,
    },
  ]

  const objectTable = (
    title: string,
    data: ObjectCount[] | undefined,
    filterKey: string,
    riskLevel: 'all' | 'high+',
    fallbackLabel: string,
  ) => (
    <Card title={title}>
      <Table
        rowKey="id"
        size="small"
        columns={objectColumns(fallbackLabel)}
        dataSource={data || []}
        pagination={false}
        loading={overviewQ.isLoading}
        onRow={(record) => ({
          ...getActivationProps(() => jumpToToolAudit({ [filterKey]: record.id, risk_level: riskLevel })),
          style: { cursor: 'pointer' },
        })}
      />
    </Card>
  )

  if (overviewQ.isLoading || (!overviewQ.isError && !overviewQ.isSuccess)) {
    return <Card data-testid="agent-risk-loading" loading style={{ minHeight: 240 }} />
  }

  if (overviewQ.isError || !overview) {
    return (
      <Alert
        type="error"
        showIcon
        message="智能体风险数据加载失败"
        description="无法取得风险态势数据，请检查网络或后端版本后重试。"
        action={<Button onClick={() => overviewQ.refetch()}>重新加载</Button>}
      />
    )
  }

  const toolCallAttempts = overview.tool_call_attempts
  const totalCalls = toolCallAttempts ?? overview.total_tool_calls
  const highRiskCalls = overview.high_risk_calls
  const rawDecisions = overview.raw_decisions
  const effectiveDecisions = overview.effective_decisions
  const hasDoubleDecision = rawDecisions !== undefined && effectiveDecisions !== undefined
  const blockedCalls = effectiveDecisions?.block ?? overview.blocked_calls
  const auditCalls = effectiveDecisions?.audit ?? overview.audit_calls
  const confirmCalls = rawDecisions?.confirm ?? overview.confirm_calls
  const pendingConfirm = overview.confirmation_pending ?? overview.pending_confirm
  const configuredMode = overview.configured_mode ? getRuntimeModeLabel(overview.configured_mode) : '暂不可用'
  const effectiveMode = getRuntimeModeLabel(overview.effective_mode)
  const hasConfirmationLifecycle = [
    overview.confirmation_pending,
    overview.confirmation_approved,
    overview.confirmation_rejected,
    overview.confirmation_expired,
    overview.confirmation_executed,
  ].every((value) => value !== undefined)
  const rangeDays = Math.max(1, range[1].diff(range[0], 'day'))

  return (
    <div>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 12,
          marginBottom: 16,
          padding: '12px 18px',
          borderRadius: 8,
          border: '1px solid var(--border-color)',
          borderLeft: '3px solid var(--brand-blue)',
          background: 'var(--bg-elevated)',
        }}
      >
        <div style={{ fontSize: 14, color: 'var(--text-primary)' }}>
          <div style={{ marginBottom: 6 }}>
            近 {rangeDays} 天 · 已评估行为 <Tooltip title={formatFull(totalCalls)}><Text strong>{compactNumber(totalCalls)}</Text></Tooltip>
            {' · 需关注信号 '}
            <Tooltip title={formatFull(highRiskCalls)}><Text strong style={{ color: 'var(--brand-red)' }}>{compactNumber(highRiskCalls)}</Text></Tooltip>
            {' · 实际阻断 '}
            <Tooltip title={formatFull(blockedCalls)}><Text strong>{compactNumber(blockedCalls)}</Text></Tooltip>
          </div>
          <Space size={8} wrap>
            <Tooltip title={getStatusSourceLabel(overview.configured_mode_source)}>
              <Tag color="blue">配置意图：{configuredMode}</Tag>
            </Tooltip>
            {overview.runtime_mode_verified ? (
              <Tooltip title={getStatusSourceLabel(overview.effective_mode_source)}><Tag color="green">运行态：{effectiveMode}</Tag></Tooltip>
            ) : (
              <Tooltip title={getStatusSourceLabel(overview.effective_mode_source)}><Tag>运行态未验证</Tag></Tooltip>
            )}
          </Space>
        </div>
        <RangePicker
          allowClear={false}
          showTime
          value={range}
          onChange={(value) => {
            if (value?.[0] && value?.[1]) setRange([value[0], value[1]])
          }}
        />
      </div>

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={12} md={8} xl={3}>
          <Card {...getActivationProps(() => jumpToToolAudit({ risk_level: 'all' }))} style={{ cursor: 'pointer' }}>
            <Statistic title="调用事实（去重）" value={metricValue(toolCallAttempts)} formatter={metricFormatter} />
          </Card>
        </Col>
        <Col xs={12} md={8} xl={3}>
          <Card>
            <Statistic title="工具定义暴露（网关观察）" value={metricValue(overview.definition_exposed_count)} formatter={metricFormatter} />
          </Card>
        </Col>
        <Col xs={12} md={8} xl={3}>
          <Card>
            <Statistic title="模型提出调用" value={metricValue(overview.invocation_proposed_count)} formatter={metricFormatter} />
          </Card>
        </Col>
        <Col xs={12} md={8} xl={3}>
          <Card>
            <Statistic title="已证实转发" value={metricValue(overview.execution_forwarded_count)} valueStyle={{ color: 'var(--brand-green)' }} formatter={metricFormatter} />
          </Card>
        </Col>
        <Col xs={12} md={8} xl={3}>
          <Card><Statistic title="结果已观察" value={metricValue(overview.result_observed_count)} formatter={metricFormatter} /></Card>
        </Col>
        <Col xs={12} md={8} xl={3}>
          <Card><Statistic title="确认重放记录" value={metricValue(overview.confirmation_replay_count)} formatter={metricFormatter} /></Card>
        </Col>
        <Col xs={12} md={8} xl={3}>
          <Card>
            <Statistic title="历史未知事件" value={metricValue(overview.unknown_event_count)} valueStyle={{ color: 'var(--text-secondary)' }} formatter={metricFormatter} />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={12} md={8} xl={4}>
          <Card {...getActivationProps(() => jumpToToolAudit({ risk_level: 'high+' }))} style={{ cursor: 'pointer' }}>
            <Statistic title="高危调用" value={highRiskCalls} valueStyle={{ color: 'var(--brand-red)' }} formatter={(v) => compactNumber(Number(v))} />
          </Card>
        </Col>
        <Col xs={12} md={8} xl={4}>
          <Card {...getActivationProps(() => jumpToToolAudit({ effective_decision: 'block', risk_level: 'all' }))} style={{ cursor: 'pointer' }}>
            <Statistic title="已阻断" value={blockedCalls} valueStyle={{ color: blockedCalls > 0 ? 'var(--brand-red)' : 'var(--text-secondary)' }} formatter={(v) => compactNumber(Number(v))} />
          </Card>
        </Col>
        <Col xs={12} md={8} xl={4}>
          <Card {...getActivationProps(() => jumpToToolAudit({ effective_decision: 'audit', risk_level: 'all' }))} style={{ cursor: 'pointer' }}>
            <Statistic title="实际审计" value={auditCalls} valueStyle={{ color: 'var(--brand-blue)' }} formatter={(v) => compactNumber(Number(v))} />
          </Card>
        </Col>
        <Col xs={12} md={8} xl={4}>
          <Card {...getActivationProps(() => jumpToToolAudit({ raw_decision: 'confirm', risk_level: 'all' }))} style={{ cursor: 'pointer' }}>
            <Statistic title="需确认判定" value={confirmCalls} valueStyle={{ color: 'var(--brand-orange)' }} formatter={(v) => compactNumber(Number(v))} />
          </Card>
        </Col>
        <Col xs={12} md={8} xl={4}>
          <Card {...getActivationProps(() => navigate('/security/agentguard?tab=confirmations'))} style={{ cursor: 'pointer' }}>
            <Statistic title="待处理确认单" value={pendingConfirm} valueStyle={{ color: 'var(--brand-orange)' }} formatter={(v) => compactNumber(Number(v))} />
          </Card>
        </Col>
      </Row>

      <Card title="原始判定 → 实际动作" style={{ marginBottom: 16 }} loading={overviewQ.isLoading}>
        {hasDoubleDecision ? (
          <Row gutter={[24, 16]}>
            <Col xs={24} lg={12}>
              <Text strong>原始判定</Text>
              <Row gutter={[8, 8]} style={{ marginTop: 10 }}>
                {decisionOrder.map((decision) => (
                  <Col span={6} key={decision}>
                    <div data-testid={`raw-decision-${decision}`} style={{ padding: '10px 12px', border: '1px solid var(--border-color)', borderRadius: 6 }}>
                      <Text type="secondary">{decisionLabels[decision]}</Text>
                      <div><Text strong>{compactNumber(rawDecisions?.[decision] ?? 0)}</Text></div>
                    </div>
                  </Col>
                ))}
              </Row>
            </Col>
            <Col xs={24} lg={12}>
              <Text strong>实际动作</Text>
              <Row gutter={[8, 8]} style={{ marginTop: 10 }}>
                {decisionOrder.map((decision) => (
                  <Col span={6} key={decision}>
                    <div data-testid={`effective-decision-${decision}`} style={{ padding: '10px 12px', border: '1px solid var(--border-color)', borderRadius: 6 }}>
                      <Text type="secondary">{decisionLabels[decision]}</Text>
                      <div><Text strong>{compactNumber(effectiveDecisions?.[decision] ?? 0)}</Text></div>
                    </div>
                  </Col>
                ))}
              </Row>
            </Col>
          </Row>
        ) : (
          <Alert type="warning" showIcon message="后端版本不支持双决策统计" />
        )}
        {hasConfirmationLifecycle ? (
          <Space size={[8, 8]} wrap style={{ marginTop: 14 }}>
            <Text type="secondary">确认单闭环：</Text>
            <Tag>待处理 {overview.confirmation_pending}</Tag>
            <Tag color="green">已批准 {overview.confirmation_approved}</Tag>
            <Tag color="red">已拒绝 {overview.confirmation_rejected}</Tag>
            <Tag>已过期 {overview.confirmation_expired}</Tag>
            <Tag color="blue">已证实执行 {overview.confirmation_executed}</Tag>
            {overview.confirmation_executing !== undefined && (
              <Tag color="processing">MCP执行中 {overview.confirmation_executing}</Tag>
            )}
            {overview.confirmation_failed !== undefined && (
              <Tag color="error">MCP执行失败 {overview.confirmation_failed}</Tag>
            )}
            {overview.confirmation_unknown !== undefined && (
              <Tag color="warning">MCP结果不确定 {overview.confirmation_unknown}</Tag>
            )}
            {overview.confirmation_evidence_failed !== undefined && (
              <Tag color="magenta">MCP留证失败 {overview.confirmation_evidence_failed}</Tag>
            )}
          </Space>
        ) : (
          <Tag style={{ marginTop: 14 }}>确认单闭环：暂不可用（后端版本不支持）</Tag>
        )}
      </Card>

      <Card
        style={{ marginBottom: 16 }}
        loading={agentStatsQ.isLoading}
        title={
          <Space size={8}>
            <span>智能体识别分布</span>
            <Tag color="blue">有效交互</Tag>
            <Text type="secondary" style={{ fontWeight: 400, fontSize: 12 }}>
              仅统计有内容留存或工具调用的智能体交互；后台心跳、配置、遥测不计入
            </Text>
          </Space>
        }
      >
        {agentStatsQ.isError ? (
          <Alert
            type="error"
            showIcon
            message="智能体识别数据加载失败"
            description="风险态势仍可使用；智能体识别分布暂时不可用。"
            action={(
              <Button onClick={() => agentStatsQ.refetch()} aria-label="重新加载智能体识别">重新加载</Button>
            )}
          />
        ) : (
          <>
        <Row gutter={[16, 16]} style={{ marginBottom: 4 }}>
          <Col xs={12} md={8}>
            <Statistic title="已识别智能体类型" value={agentStats.length} suffix="类" />
          </Col>
          <Col xs={12} md={8}>
            <Statistic title="累计请求" value={agentTotal} formatter={(v) => compactNumber(Number(v))} />
          </Col>
          <Col xs={24} md={8}>
            <Statistic title="特征识别覆盖率" value={identificationCoverage} suffix="%" valueStyle={{ color: 'var(--brand-green)' }} />
          </Col>
        </Row>

        {agentStats.length === 0 ? (
          <Text type="secondary">暂无智能体识别数据</Text>
        ) : (
          <div style={{ marginTop: 8 }}>
            {agentStats.map((item) => {
              const detection = getAgentDetection(item.agent_type)
              const pct = agentTotal ? (item.request_count / agentTotal) * 100 : 0
              const canDrillToRetainedContent = canOpenRetainedEvidence(item)
              return (
                <div
                  key={item.agent_type}
                  {...(canDrillToRetainedContent
                    ? getActivationProps(() => jumpToAccessRetention({ agent_type: item.agent_type }))
                    : {})}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    padding: '9px 0',
                    borderBottom: '1px solid var(--border-color)',
                    cursor: canDrillToRetainedContent ? 'pointer' : 'default',
                  }}
                >
                  <span style={{ width: 10, height: 10, borderRadius: '50%', background: barColor(item.agent_type), flex: 'none' }} />
                  <div style={{ width: 132, flex: 'none' }}>
                    <Text strong>{formatAgentType(item.agent_type)}</Text>
                  </div>
                  <Tooltip title={detection.coverage}>
                    <Tag color={detection.color} style={{ flex: 'none' }}>{detection.label}</Tag>
                  </Tooltip>
                  <div style={{ flex: 1, minWidth: 80 }}>
                    <Progress percent={Math.round(pct * 10) / 10} strokeColor={barColor(item.agent_type)} showInfo={false} size="small" />
                  </div>
                  <div style={{ width: 150, textAlign: 'right', flex: 'none' }}>
                    <Tooltip title={formatFull(item.request_count)}><Text strong>{compactNumber(item.request_count)}</Text></Tooltip>
                    <Text type="secondary" style={{ marginLeft: 6 }}>{pct.toFixed(1)}%</Text>
                  </div>
                </div>
              )
            })}
          </div>
        )}
          </>
        )}
      </Card>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card title="风险分类">
            <Table
              rowKey="risk_level"
              size="small"
              columns={riskColumns}
              dataSource={overview?.by_risk_level || []}
              loading={overviewQ.isLoading}
              pagination={false}
              onRow={(record) => ({
                ...getActivationProps(() => jumpToToolAudit({ risk_level: record.risk_level })),
                style: { cursor: 'pointer' },
              })}
            />
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title="工具调用 TOP 10（全部风险）">
            <Table
              rowKey="tool_name"
              size="small"
              columns={toolColumns}
              dataSource={overview?.top_tools || []}
              loading={overviewQ.isLoading}
              pagination={false}
              onRow={(record) => ({
                ...getActivationProps(() => jumpToToolAudit({ tool_name: record.tool_name, risk_level: 'all' })),
                style: { cursor: 'pointer' },
              })}
            />
          </Card>
        </Col>
        <Col span={24}>
          <Card title="策略维度">
            <Table
              rowKey={(record) => `${record.policy_id}-${record.mode}`}
              size="small"
              columns={policyColumns}
              dataSource={overview?.by_policy || []}
              loading={overviewQ.isLoading}
              pagination={false}
              onRow={(record) => ({
                ...getActivationProps(() => jumpToToolAudit({ policy_id: record.policy_id, mode: record.mode, risk_level: 'all' })),
                style: { cursor: 'pointer' },
              })}
            />
          </Card>
        </Col>
        <Col span={24}>{objectTable('需关注行为来源 TOP 5', overview.top_agents, 'agent_type', 'high+', '智能体')}</Col>
        <Col xs={24} md={12} xl={6}>{objectTable('行为用户 TOP 5', overview.top_users, 'user_id', 'all', '用户')}</Col>
        <Col xs={24} md={12} xl={6}>{objectTable('应用 TOP 5', overview.top_apps, 'project_id', 'all', '应用')}</Col>
        <Col xs={24} md={12} xl={6}>{objectTable('Key TOP 5', overview.top_keys, 'client_id', 'all', 'API Key')}</Col>
        <Col xs={24} md={12} xl={6}>{objectTable('会话 TOP 5', overview.top_sessions, 'session_id', 'all', '会话')}</Col>
      </Row>
    </div>
  )
}

export default AgentRiskOverview

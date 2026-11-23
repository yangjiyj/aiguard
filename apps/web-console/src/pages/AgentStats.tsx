import { useState } from 'react'
import { Button, Typography, Card, Tag, Select, Progress, Spin, Row, Col, Drawer, List, Statistic, Space, Tooltip } from 'antd'
import { UserOutlined, BarChartOutlined, PieChartOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { agentStatsApi, userApi } from '../services/api'
import type { StatsRangeParams } from '../services/api'
import { useCurrencyStore } from '../stores/currency'
import { getAgentRuleInfo } from '../utils/risk'
import { formatAgentType, getAgentColor, getAgentDetection, agentSourceLabel, isKnownAgentType } from '../utils/agents'
import { compactNumber, formatFull } from '../utils/format'
import ResizableTable from '../components/ResizableTable'

import AgentIdentityPanel from '../components/AgentIdentityPanel'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import { useAuthStore } from '../stores/auth'

const { Title, Text } = Typography

const AGENT_STATS_CACHE_MS = 5 * 60 * 1000

type AgentStatsProps = {
  range?: StatsRangeParams
  rangeLabel?: string
}

function AgentStats({ range, rangeLabel = '近90天' }: AgentStatsProps = {}) {
 const identity = useAuditQueryIdentity()
 const role = useAuthStore(s => s.user?.role)
 const canManageIdentity = ['platform_admin', 'tenant_owner', 'tenant_admin'].includes(role || '')
 const [identityOpen, setIdentityOpen] = useState(false)
  const [selectedUser, setSelectedUser] = useState<string | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const { format } = useCurrencyStore()

  // Queries
  const statsQ = useQuery({
    queryKey: ['agent-stats', identity, range],
    queryFn: () => agentStatsApi.getStats(range),
    staleTime: AGENT_STATS_CACHE_MS,
  })
  const distributionQ = useQuery({
    queryKey: ['agent-distribution', identity, range],
    queryFn: () => agentStatsApi.getDistribution(range),
    staleTime: AGENT_STATS_CACHE_MS,
  })
  const usersQ = useQuery({ queryKey: ['users', identity], queryFn: userApi.list, staleTime: AGENT_STATS_CACHE_MS })
  const userDetailQ = useQuery({
    queryKey: ['agent-user-detail', identity, selectedUser, range],
    queryFn: () => agentStatsApi.getUserDetail(selectedUser!, range),
    enabled: selectedUser !== null && drawerOpen,
  })

  const stats = statsQ.data?.data || statsQ.data || []
  const distribution = distributionQ.data?.data || distributionQ.data || []
  const _usersRaw = usersQ.data?.data
  const users = Array.isArray(_usersRaw?.items) ? _usersRaw.items
               : Array.isArray(_usersRaw?.data) ? _usersRaw.data
               : Array.isArray(_usersRaw) ? _usersRaw
               : []
  const userDetail = userDetailQ.data?.data || userDetailQ.data || []

  // Calculate total for pie chart display
  const totalCount = distribution.reduce((sum: number, d: any) => sum + (d.count || 0), 0)

  // Agent stats table columns
  const agentColumns = [
    {
      title: '智能体类型',
      dataIndex: 'agent_type',
      key: 'agent_type',
      width: 170,
      render: (v: string) => (
        <Tag color={getAgentColor(v)} style={{ fontSize: 13, padding: '4px 12px' }}>
          {isKnownAgentType(v) ? formatAgentType(v) : `自报：${v}`}
        </Tag>
      ),
    },
    {
      title: '识别方式',
      dataIndex: 'agent_type',
      key: 'detection',
      width: 150,
      render: (v: string, record: any) => {
        if (record.detection_sources?.length) return <Space wrap size={4}>{record.detection_sources.map((source: string) => <Tag key={source}>{agentSourceLabel(source)}</Tag>)}</Space>
        const detection = getAgentDetection(v)
        return <Tag color={detection.color}>{detection.label}</Tag>
      },
    },
    {
      title: '识别规则',
      dataIndex: 'agent_type',
      key: 'agent_rule',
      width: 190,
      render: (v: string) => <Tag color="blue">{isKnownAgentType(v) ? getAgentRuleInfo(v).rule : '尚未确认客户端类型'}</Tag>,
    },
    {
      title: '关注风险分类',
      dataIndex: 'agent_type',
      key: 'risk_categories',
      width: 220,
      render: (v: string) => (
        <Space size={4} wrap>
          {getAgentRuleInfo(v).categories.map((category) => <Tag key={category} color="purple">{category}</Tag>)}
        </Space>
      ),
    },
    {
      title: '采集覆盖',
      dataIndex: 'agent_type',
      key: 'coverage',
      width: 320,
      render: (v: string) => (
        <Text style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{getAgentDetection(v).coverage}</Text>
      ),
    },
    {
      title: '请求数',
      dataIndex: 'request_count',
      key: 'request_count',
      width: 100,
      render: (v: number) => v?.toLocaleString() || 0,
      sorter: (a: any, b: any) => (a.request_count || 0) - (b.request_count || 0),
    },
    {
      title: '会话数',
      dataIndex: 'session_count',
      key: 'session_count',
      width: 100,
      render: (v: number) => v?.toLocaleString() || 0,
    },
    {
      title: '占比',
      dataIndex: 'percent',
      key: 'percent',
      width: 130,
      render: (v: number, record: any) => (
        <Progress
          percent={Math.round(v || 0)}
          size="small"
          style={{ width: 100 }}
          strokeColor={getAgentColor(record?.agent_type)}
        />
      ),
    },
    {
      title: '操作',
      key: 'action',
      width: 180,
      render: () => (
        <Select
          size="small"
          style={{ width: 150 }}
          placeholder="查看用户详情"
          onChange={(userId) => { setSelectedUser(userId); setDrawerOpen(true) }}
          options={users.filter((u: any) => u.id).map((u: any) => ({ value: u.id, label: u.username }))}
          allowClear
        />
      ),
    },
  ]

  // Distribution pie chart alternative - using Progress bars
  const distributionItems = distribution.map((d: any) => {
    const percent = totalCount > 0 ? Math.round((d.count / totalCount) * 100) : 0
    const color = getAgentColor(d.agent_type)
    return (
      <div key={d.agent_type} style={{ marginBottom: 12 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
          <Tag color={color}>{formatAgentType(d.agent_type)}</Tag>
          <Tooltip title={formatFull(d.count)}><Text>{compactNumber(d.count)} ({percent}%)</Text></Tooltip>
        </div>
        <Progress
          percent={percent}
          size="small"
          strokeColor={color}
          showInfo={false}
        />
      </div>
    )
  })

  return (
    <div>
      <Space wrap style={{ width: '100%', justifyContent: 'space-between', marginBottom: 16 }}>
       <Title level={4} style={{ margin: 0, color: 'var(--text-primary)' }}>智能体使用统计</Title>
       {canManageIdentity && <Button type="primary" onClick={() => setIdentityOpen(true)}>待识别处理 / 接入登记</Button>}
      </Space>
      {canManageIdentity && <AgentIdentityPanel open={identityOpen} onClose={() => setIdentityOpen(false)} />}

      <Row gutter={[16, 16]}>
        {/* Agent type distribution */}
        <Col xs={24} lg={8} xl={6}>
          <Card
            title={<span><PieChartOutlined /> 智能体类型分布</span>}
            style={{ height: '100%' }}
          >
            <Spin spinning={distributionQ.isLoading}>
              {distribution.length > 0 ? (
                <div>
                  <Statistic
                    title="已识别请求数"
                    value={totalCount}
                    formatter={(v) => compactNumber(Number(v))}
                    style={{ marginBottom: 16 }}
                  />
                  {distributionItems}
                </div>
              ) : (
                <Text type="secondary">暂无已识别的智能体请求。请先让 Claude Code、OpenCode 等客户端通过网关发起请求。</Text>
              )}
            </Spin>
          </Card>
        </Col>

        {/* Agent stats table */}
        <Col xs={24} lg={16} xl={18}>
          <Card title={<span><BarChartOutlined /> 客户端识别与使用明细</span>}>
            <Spin spinning={statsQ.isLoading}>
              <ResizableTable
                columnStorageKey="agent-stats-columns"
                dataSource={stats}
                columns={agentColumns}
                rowKey="agent_type"
                size="small"
                pagination={false}
                minColumnWidth={90}
                maxColumnWidth={720}
              />
            </Spin>
          </Card>
        </Col>
      </Row>

      {/* User agent detail drawer */}
      <Drawer
        title={<span><UserOutlined /> {rangeLabel}用户智能体使用详情</span>}
        open={drawerOpen}
        onClose={() => { setDrawerOpen(false); setSelectedUser(null) }}
        width={600}
      >
        <Spin spinning={userDetailQ.isLoading}>
          {userDetail.length > 0 ? (
            <List
              dataSource={userDetail}
              renderItem={(item: any) => (
                <List.Item>
                  <List.Item.Meta
                    avatar={
                      <Tag color={getAgentColor(item.agent_type)} style={{ fontSize: 12, padding: '4px 8px' }}>
                        {formatAgentType(item.agent_type)}
                      </Tag>
                    }
                    title={<Text strong>{formatAgentType(item.agent_type)}</Text>}
                    description={
                      <div>
                        <div style={{ marginBottom: 8 }}>
                          <Text>请求数: <strong><Tooltip title={formatFull(item.request_count)}>{compactNumber(item.request_count)}</Tooltip> 次</strong></Text>
                          <Text style={{ marginLeft: 16 }}>总 Token 用量: <strong><Tooltip title={formatFull(item.total_tokens)}>{compactNumber(item.total_tokens)}</Tooltip> tokens</strong></Text>
                        </div>
                        <div>
                          <Text type="secondary" style={{ fontSize: 12 }}>
                            输入 Token: {compactNumber(item.input_tokens)} tokens | 输出 Token: {compactNumber(item.output_tokens)} tokens
                          </Text>
                        </div>
                        <div style={{ marginTop: 8 }}>
                          <Text type="secondary" style={{ fontSize: 12 }}>
                            首次使用: {item.first_use || '未知'}
                          </Text>
                        </div>
                        <div>
                          <Text type="secondary" style={{ fontSize: 12 }}>
                            最后使用: {item.last_use || '未知'}
                          </Text>
                        </div>
                        <div style={{ marginTop: 8 }}>
                          <Text style={{ fontSize: 13 }}>费用: <strong style={{ color: 'var(--status-ok)' }}>{format(item.total_cost || 0, 2)}</strong></Text>
                        </div>
                      </div>
                    }
                  />
                </List.Item>
              )}
            />
          ) : (
            <Text type="secondary">该用户暂无 Agent 使用记录</Text>
          )}
        </Spin>
      </Drawer>
    </div>
  )
}

export default AgentStats

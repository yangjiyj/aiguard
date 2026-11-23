import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Empty, Popconfirm, Space, Table, Tabs, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import dayjs from 'dayjs'
import { useSearchParams } from 'react-router-dom'
import {
  agentGuardApi,
  type AgentGuardConfirmation,
} from '../services/api'
import { getReadableToolReason } from '../utils/risk'
import AgentRiskOverview from './agentguard/AgentRiskOverview'
import { agentGuardResolutionErrorMessage, agentGuardResolutionSuccessMessage } from './agentguard/confirmationMessages'

const { Text, Title } = Typography

const decisionLabels: Record<string, string> = {
  allow: '放行',
  audit: '审计',
  confirm: '需确认',
  block: '阻断',
}

const decisionColors: Record<string, string> = {
  allow: 'green',
  audit: 'blue',
  confirm: 'orange',
  block: 'red',
}

const getDecisionLabel = (value?: string) => decisionLabels[value || ''] || '未识别动作'

const getConfirmations = (payload: unknown): AgentGuardConfirmation[] => {
  const response = payload as { data?: { data?: AgentGuardConfirmation[] } }
  return Array.isArray(response?.data?.data) ? response.data.data : []
}

const pendingConfirmationsQueryKey = ['agent-security', 'confirmations', 'pending'] as const

function AgentSecurity() {
  const [searchParams, setSearchParams] = useSearchParams()
  const queryClient = useQueryClient()
  const [resolutionNotice, setResolutionNotice] = useState<string>()
  const activeTab = searchParams.get('tab') === 'confirmations' ? 'confirmations' : 'risk-overview'

  const confirmationsQ = useQuery({
    queryKey: pendingConfirmationsQueryKey,
    queryFn: () => agentGuardApi.listConfirmations('pending'),
    enabled: activeTab === 'confirmations',
  })
  // Defense in depth: the API requests source=agentguard, and this page also
  // refuses a stale/cache-poisoned MCP item with different approval semantics.
  const confirmations = getConfirmations(confirmationsQ.data).filter((item) => item.source !== "mcp")

  const resolveConfirmation = useMutation({
    mutationFn: (payload: { id: string; status: 'approved' | 'rejected' }) =>
      agentGuardApi.resolveConfirmation(payload.id, {
        status: payload.status,
        note: payload.status === 'approved' ? '控制台批准' : '控制台拒绝',
      }),
    onMutate: () => setResolutionNotice(undefined),
    onSuccess: (response) => {
      if (response?.status === 202) setResolutionNotice(agentGuardResolutionSuccessMessage(202))
    },
    onError: (error) => setResolutionNotice(agentGuardResolutionErrorMessage(error, '处理结果需重新核验，已刷新列表')),
    onSettled: async () => {
      await queryClient.invalidateQueries({
        queryKey: pendingConfirmationsQueryKey,
        refetchType: 'none',
      })
      await queryClient.refetchQueries({ queryKey: pendingConfirmationsQueryKey, type: 'active' })
    },
  })

  const columns: ColumnsType<AgentGuardConfirmation> = [
    {
      title: '工具',
      dataIndex: 'tool_name',
      key: 'tool_name',
      render: (value: string) => <Text code>{value || '未知工具'}</Text>,
    },
    {
      title: '原始判定',
      dataIndex: 'raw_decision',
      key: 'raw_decision',
      render: (value: string) => <Tag color={decisionColors[value]}>{getDecisionLabel(value)}</Tag>,
    },
    {
      title: '实际动作',
      dataIndex: 'effective_decision',
      key: 'effective_decision',
      render: (value: string) => <Tag color={decisionColors[value]}>{getDecisionLabel(value)}</Tag>,
    },
    {
      title: '确认原因',
      dataIndex: 'reason',
      key: 'reason',
      render: (value: string) => getReadableToolReason(value),
    },
    {
      title: '超时处置',
      dataIndex: 'timeout_action',
      key: 'timeout_action',
      render: (value: string) => <Tag color={decisionColors[value]}>{getDecisionLabel(value)}</Tag>,
    },
    {
      title: '到期时间',
      dataIndex: 'expires_at',
      key: 'expires_at',
      render: (value: string) => value ? dayjs(value).format('YYYY-MM-DD HH:mm:ss') : '未记录',
    },
    {
      title: '操作',
      key: 'actions',
      render: (_, record) => (
        <Space>
          <Popconfirm
            title={`允许发起人以相同参数重试工具“${record.tool_name || '未知工具'}”一次？`}
            okText="允许重试"
            cancelText="取消"
            onConfirm={() => resolveConfirmation.mutate({ id: record.id, status: 'approved' })}
          >
            <Button
              type="primary"
              size="small"
              aria-label="允许客户端重试"
              loading={resolveConfirmation.isPending && resolveConfirmation.variables?.id === record.id}
            >
              允许重试
            </Button>
          </Popconfirm>
          <Popconfirm
            title={`确认拒绝工具“${record.tool_name || '未知工具'}”的本次调用？`}
            okText="确认拒绝"
            okButtonProps={{ danger: true }}
            cancelText="取消"
            onConfirm={() => resolveConfirmation.mutate({ id: record.id, status: 'rejected' })}
          >
            <Button
              danger
              size="small"
              aria-label="拒绝本次调用"
              loading={resolveConfirmation.isPending && resolveConfirmation.variables?.id === record.id}
            >
              拒绝
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  const confirmationsContent = (
    <Space direction="vertical" size={12} style={{ width: '100%' }}>
      <Alert
        type="info"
        showIcon
        message="本地工具确认只授权客户端重试"
        description="批准后，同一发起人以相同参数重试时网关放行一次（批准后 30 分钟内有效）；中心端不会执行本地工具。审批人不能批准自己触发的调用。远程 MCP 工具请在 MCP 人工确认页查看真实执行和留证状态。"
      />
      {resolutionNotice ? <Alert type="warning" showIcon message={resolutionNotice} /> : null}
      {confirmationsQ.isError ? (
        <Alert
          type="error"
          showIcon
          message="人工确认数据加载失败"
          description="无法取得待处理确认单，请检查网络后重试。"
          action={<Button onClick={() => confirmationsQ.refetch()}>重新加载</Button>}
        />
      ) : (
        <Table
          rowKey="id"
          columns={columns}
          dataSource={confirmations}
          loading={confirmationsQ.isLoading}
          locale={{ emptyText: <Empty description="暂无待处理确认单" /> }}
          pagination={false}
        />
      )}
    </Space>
  )

  return (
    <div className="enterprise-page">
      <div className="page-header">
        <Title level={3}>智能体安全</Title>
        <Text type="secondary">查看真实工具调用风险，并完成人工确认闭环。</Text>
      </div>
      <Tabs
        activeKey={activeTab}
        onChange={(tab) => setSearchParams({ tab })}
        items={[
          { key: 'risk-overview', label: '风险态势', children: <AgentRiskOverview /> },
          { key: 'confirmations', label: '人工确认', children: confirmationsContent },
        ]}
      />
    </div>
  )
}

export default AgentSecurity

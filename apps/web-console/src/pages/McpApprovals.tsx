import { useState } from 'react'
import {
  Alert,
  Button,
  DatePicker,
  Empty,
  Form,
  Input,
  Modal,
  Popconfirm,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
  message,
} from 'antd'
import { CheckOutlined, CloseOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import dayjs from 'dayjs'
import { useNavigate } from 'react-router-dom'
import {
  agentGuardApi,
  mcpApprovalApi,
  type McpConfirmation,
} from '../services/api'
import { EnterprisePageHeader, MetricCard, SectionPanel, StatusPill } from '../components/EnterpriseUI'
import { getDecisionLabel, getReadableToolReason } from '../utils/risk'

const { Text } = Typography

// 双决策动作配色（原始判定 / 实际动作 / 例外降级动作共用）
const DECISION_COLORS: Record<string, string> = {
  allow: 'green',
  audit: 'blue',
  confirm: 'orange',
  block: 'red',
}

// 确认单状态中文（getDecisionLabel 只覆盖 allow/audit/confirm/block，状态另建字典避免露英文）
const STATUS_LABELS: Record<string, string> = {
  pending: '待确认',
  approved: '已通过',
  rejected: '已拒绝',
  expired: '已超时',
  resolved: '已处理',
}
const STATUS_COLORS: Record<string, string> = {
  pending: 'orange',
  approved: 'green',
  rejected: 'red',
  expired: 'default',
  resolved: 'blue',
}
const statusLabel = (v?: string) => (v ? STATUS_LABELS[v] || v : '-')

const EXECUTION_ERROR_LABELS: Record<string, string> = {
  approval_context_drift: '审批上下文已变化，未执行',
  current_policy_blocked: '当前策略或准入保护已阻断，未执行',
  approval_expired: '审批已过期，未执行',
  mcp_server_unavailable: 'MCP 服务不可用，未执行',
  upstream_outcome_unknown: '上游结果不确定，禁止自动重试',
  upstream_response_invalid: '上游已接收调用，但返回无效',
  audit_intent_failed: '执行前留证失败，未执行',
}

const executionPresentation = (record: McpConfirmation) => {
  const execution = record.mcp_execution
  if (!execution) {
    if (record.status === 'rejected') return { label: '已拒绝 · 未执行', color: 'red' }
    if (record.status === 'pending') return { label: '等待人工确认', color: 'orange' }
    return { label: '执行状态未回传', color: 'default' }
  }
  switch (execution.execution_status) {
    case 'pending':
      return { label: '等待执行', color: 'orange' }
    case 'executing':
      return { label: '正在执行', color: 'processing' }
    case 'executed':
      if (execution.evidence_status === 'failed') {
        return { label: '已执行 · 留证失败', color: 'red' }
      }
      if (execution.evidence_status !== 'complete') {
        return { label: '已执行 · 留证待完成', color: 'orange' }
      }
      return { label: execution.result_available ? '已执行 · 结果可取 · 留证完成' : '已执行 · 留证完成', color: 'green' }
    case 'failed':
      return { label: EXECUTION_ERROR_LABELS[execution.error_code || ''] || '执行失败 · 未转发或未完成', color: 'red' }
    case 'unknown':
      return { label: '结果不确定 · 禁止自动重试', color: 'volcano' }
    default:
      return { label: '执行状态未识别', color: 'default' }
  }
}

// 作用范围中文枚举（例外表单与列表共用）
const SCOPE_OPTIONS = [
  { value: 'tenant', label: '全租户' },
  { value: 'project', label: '指定应用' },
  { value: 'key', label: '指定密钥' },
  { value: 'user', label: '指定用户' },
  { value: 'agent', label: '指定智能体' },
  { value: 'session', label: '指定会话' },
]

const getScopeLabel = (scopeType?: string, scopeRef?: string) => {
  const label = SCOPE_OPTIONS.find((item) => item.value === scopeType)?.label || scopeType || '-'
  return scopeRef ? `${label}: ${scopeRef}` : label
}

// 审计里 MCP tool_name 记录为「服务名__工具名」：按第一个 '__' 拆开展示
const splitMcpToolName = (name?: string): { server: string; tool: string } => {
  const text = String(name || '')
  const idx = text.indexOf('__')
  if (idx > 0) return { server: text.slice(0, idx), tool: text.slice(idx + 2) }
  return { server: '', tool: text }
}

const formatTime = (value?: string) => {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '-'
  return date.toLocaleString('zh-CN', { hour12: false })
}

// 响应解包三连：control-plane 返回结构不统一（{items:[]} / {data:[]} / 裸数组）
const unpackList = (raw: any, extraKey?: string): any[] => {
  if (Array.isArray(raw?.items)) return raw.items
  if (Array.isArray(raw?.data)) return raw.data
  if (extraKey && Array.isArray(raw?.[extraKey])) return raw[extraKey]
  return Array.isArray(raw) ? raw : []
}

interface McpException {
  id: string
  scope_type: string
  scope_ref?: string
  rule_id?: string
  target_pattern?: string
  decision: string
  reason: string
  expires_at: string
  enabled: boolean
}

function McpApprovals() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [confirmationStatus, setConfirmationStatus] = useState('all')
  const [exceptionModalOpen, setExceptionModalOpen] = useState(false)
  const [exceptionForm] = Form.useForm()

  const confirmationsQuery = useQuery({
    queryKey: ['mcpApprovals', 'confirmations', confirmationStatus],
    queryFn: () => mcpApprovalApi.list({
      source: 'mcp',
      ...(confirmationStatus === 'all' ? {} : { status: confirmationStatus }),
    }),
    refetchInterval: 5_000,
  })

  const exceptionsQuery = useQuery({
    queryKey: ['mcpApprovals', 'exceptions'],
    queryFn: () => agentGuardApi.listExceptions(),
  })

  const confirmations: McpConfirmation[] = unpackList(confirmationsQuery.data?.data)
  const exceptions: McpException[] = unpackList(exceptionsQuery.data?.data)

  const resolveMutation = useMutation({
    mutationFn: ({ id, status, note }: { id: string; status: 'approved' | 'rejected'; note?: string }) =>
      mcpApprovalApi.resolve(id, { status, note }),
    onSuccess: (response) => {
      const resolved = response.data
      const execution = resolved.mcp_execution
      if (resolved.status === 'rejected') {
        message.success('确认请求已拒绝，工具未执行')
      } else if (!execution || execution.execution_status === 'pending' || execution.execution_status === 'executing') {
        message.info('批准已记录，MCP 工具正在执行；请以执行状态为准')
      } else if (execution.execution_status === 'unknown') {
        message.warning('批准已记录，但上游结果不确定；系统不会自动重试')
      } else if (execution.execution_status === 'failed') {
        const reason = EXECUTION_ERROR_LABELS[execution.error_code || ''] || '执行失败'
        message.error(`批准已记录，但${reason}`)
      } else if (execution.evidence_status === 'failed') {
        message.warning('MCP 工具已执行，但留证失败；请立即核查')
      } else if (execution.evidence_status === 'complete') {
        message.success('MCP 工具已执行，运行证据已完整保存')
      } else {
        message.info('MCP 工具已执行，正在等待留证完成')
      }
      queryClient.invalidateQueries({ queryKey: ['mcpApprovals'] })
    },
    onError: (error: any) => message.error(
      '确认请求处理失败：' + (error?.response?.data?.error?.message || error?.message || '未知错误'),
    ),
  })

  const exceptionMutation = useMutation({
    mutationFn: (payload: any) => agentGuardApi.createException(payload),
    onSuccess: () => {
      message.success('例外已创建')
      setExceptionModalOpen(false)
      exceptionForm.resetFields()
      queryClient.invalidateQueries({ queryKey: ['mcpApprovals', 'exceptions'] })
    },
    onError: () => message.error('例外创建失败'),
  })

  const deleteExceptionMutation = useMutation({
    mutationFn: (id: string) => agentGuardApi.deleteException(id),
    onSuccess: () => {
      message.success('例外已删除')
      queryClient.invalidateQueries({ queryKey: ['mcpApprovals', 'exceptions'] })
    },
    onError: () => message.error('例外删除失败'),
  })

  const submitException = (values: any) => {
    exceptionMutation.mutate({
      scope_type: values.scope_type,
      scope_ref: values.scope_ref || '',
      rule_id: values.rule_id || '',
      target_pattern: values.target_pattern || '',
      decision: values.decision,
      reason: values.reason,
      expires_at: values.expires_at?.toISOString(),
      enabled: values.enabled !== false,
    })
  }

  const pendingCount = confirmations.filter((c) => c.status === 'pending').length
  const executionAttentionCount = confirmations.filter((confirmation) => {
    const status = confirmation.mcp_execution?.execution_status
    const evidence = confirmation.mcp_execution?.evidence_status
    return status === 'failed' || status === 'unknown' || evidence === 'failed'
  }).length
  const enabledExceptionCount = exceptions.filter((e) => e.enabled).length

  const confirmationColumns = [
    {
      title: 'MCP 服务',
      key: 'server',
      width: 130,
      render: (_: unknown, record: McpConfirmation) => {
        const { server } = splitMcpToolName(record.tool_name)
        return server ? <Tag color="geekblue">{server}</Tag> : <Text type="secondary">未记录</Text>
      },
    },
    {
      title: '工具',
      key: 'tool',
      width: 170,
      render: (_: unknown, record: McpConfirmation) => {
        const { tool } = splitMcpToolName(record.tool_name)
        return <Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{tool || '-'}</Text>
      },
    },
    {
      title: '原始判定',
      dataIndex: 'raw_decision',
      key: 'raw_decision',
      width: 100,
      render: (value: string) => <Tag color={DECISION_COLORS[value] || 'default'}>{getDecisionLabel(value)}</Tag>,
    },
    {
      title: '实际动作',
      dataIndex: 'effective_decision',
      key: 'effective_decision',
      width: 100,
      render: (value: string) => <Tag color={DECISION_COLORS[value] || 'default'}>{getDecisionLabel(value)}</Tag>,
    },
    {
      title: '判定原因',
      dataIndex: 'reason',
      key: 'reason',
      ellipsis: true,
      render: (value: string) => (
        <Text style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{getReadableToolReason(value)}</Text>
      ),
    },
    {
      title: '超时动作',
      dataIndex: 'timeout_action',
      key: 'timeout_action',
      width: 100,
      render: (value: string) => <Tag color={DECISION_COLORS[value] || 'default'}>{getDecisionLabel(value)}</Tag>,
    },
    {
      title: '到期时间',
      dataIndex: 'expires_at',
      key: 'expires_at',
      width: 160,
      render: formatTime,
    },
    {
      title: '真实执行状态',
      key: 'execution_status',
      width: 230,
      render: (_: unknown, record: McpConfirmation) => {
        const presentation = executionPresentation(record)
        const auditRequestID = record.mcp_execution?.evidence_status === 'complete'
          ? record.mcp_execution?.audit_request_id
          : ''
        return (
          <Space direction="vertical" size={2}>
            <Tag color={presentation.color}>{presentation.label}</Tag>
            {auditRequestID ? (
              <Button
                size="small"
                type="link"
                style={{ padding: 0, height: 'auto' }}
                onClick={() => navigate(`/mcp-gateway/audit?request_id=${encodeURIComponent(auditRequestID)}`)}
              >
                查看执行审计
              </Button>
            ) : null}
          </Space>
        )
      },
    },
    {
      title: '处理',
      key: 'action',
      width: 180,
      render: (_: unknown, record: McpConfirmation) =>
        record.status === 'pending' ? (
          <Space size={4}>
            <Popconfirm
              title="批准本次 MCP 工具调用?"
              onConfirm={() => resolveMutation.mutate({ id: record.id, status: 'approved', note: '控制台批准' })}
              okText="批准"
              cancelText="取消"
            >
              <Button size="small" type="link" icon={<CheckOutlined />}>批准</Button>
            </Popconfirm>
            <Popconfirm
              title="拒绝本次 MCP 工具调用?"
              onConfirm={() => resolveMutation.mutate({ id: record.id, status: 'rejected', note: '控制台拒绝' })}
              okText="拒绝"
              cancelText="取消"
            >
              <Button size="small" type="link" danger icon={<CloseOutlined />}>拒绝</Button>
            </Popconfirm>
          </Space>
        ) : (
          <Tag color={STATUS_COLORS[record.status] || 'default'}>{statusLabel(record.status)}</Tag>
        ),
    },
  ]

  const exceptionColumns = [
    {
      title: '作用范围',
      key: 'scope',
      render: (_: unknown, record: McpException) => getScopeLabel(record.scope_type, record.scope_ref),
    },
    {
      title: '关联规则',
      dataIndex: 'rule_id',
      key: 'rule_id',
      render: (value: string) => value || '-',
    },
    {
      title: '目标匹配',
      dataIndex: 'target_pattern',
      key: 'target_pattern',
      render: (value: string) => <Text style={{ wordBreak: 'break-all' }}>{value || '-'}</Text>,
    },
    {
      title: '降级动作',
      dataIndex: 'decision',
      key: 'decision',
      render: (value: string) => <Tag color={DECISION_COLORS[value] || 'default'}>{getDecisionLabel(value)}</Tag>,
    },
    {
      title: '原因',
      dataIndex: 'reason',
      key: 'reason',
      render: (value: string) => getReadableToolReason(value),
    },
    {
      title: '过期时间',
      dataIndex: 'expires_at',
      key: 'expires_at',
      render: formatTime,
    },
    {
      title: '操作',
      key: 'actions',
      width: 90,
      render: (_: unknown, record: McpException) => (
        <Button
          size="small"
          danger
          aria-label="删除"
          loading={deleteExceptionMutation.isPending}
          onClick={() => deleteExceptionMutation.mutate(record.id)}
        >
          删除
        </Button>
      ),
    },
  ]

  return (
    <div className="enterprise-page">
      <EnterprisePageHeader
        eyebrow="MCP 安全网关"
        title="MCP 审批与例外"
        description="集中处置 MCP 工具调用触发的人工确认队列，并维护误报降级例外。例外只能降级已确认的误报风险，且必须设置过期时间。"
        meta={
          <Space size={8} wrap>
            <StatusPill tone="orange">人工确认</StatusPill>
          </Space>
        }
        actions={
          <Button
            icon={<ReloadOutlined />}
            onClick={() => queryClient.invalidateQueries({ queryKey: ['mcpApprovals'] })}
            loading={confirmationsQuery.isFetching || exceptionsQuery.isFetching}
          >
            刷新
          </Button>
        }
      />

      <SectionPanel title="处置概览" description="待人工确认为当前挂起的 MCP 调用；有效例外为仍在有效期内的降级放行/审计规则。">
        <div className="enterprise-metric-grid">
          <MetricCard label="待人工确认" value={pendingCount} tone="orange" hint="等待批准/拒绝的 MCP 调用" />
          <MetricCard label="需核查执行" value={executionAttentionCount} tone="red" hint="执行失败、结果不确定或留证失败" />
          <MetricCard label="有效例外" value={enabledExceptionCount} tone="blue" hint="仍在启用且未过期的降级例外" />
        </div>
      </SectionPanel>

      <SectionPanel
        title="确认与执行记录"
        description="审批状态只表示人工意图；真实执行、结果确定性和留证完整性必须分别核验。"
        extra={(
          <Select
            aria-label="确认状态筛选"
            value={confirmationStatus}
            onChange={setConfirmationStatus}
            style={{ width: 150 }}
            options={[
              { value: 'all', label: '全部确认记录' },
              { value: 'pending', label: '仅待确认' },
              { value: 'approved', label: '仅已批准' },
              { value: 'rejected', label: '仅已拒绝' },
            ]}
          />
        )}
      >
        <Table
          rowKey="id"
          columns={confirmationColumns}
          dataSource={confirmations}
          loading={confirmationsQuery.isLoading}
          scroll={{ x: 'max-content' }}
          pagination={{ defaultPageSize: 20, hideOnSinglePage: true, showTotal: (total) => `共 ${total} 条` }}
          locale={{ emptyText: <Empty description="当前筛选范围内暂无 MCP 确认记录。" /> }}
        />
      </SectionPanel>

      <SectionPanel
        title="处置例外"
        description="例外用于把已确认的误报降级为审计或放行，必须设置过期时间。"
        extra={
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              exceptionForm.resetFields()
              exceptionForm.setFieldsValue({
                scope_type: 'project',
                decision: 'audit',
                enabled: true,
                expires_at: dayjs().add(7, 'day'),
              })
              setExceptionModalOpen(true)
            }}
          >
            新增处置例外
          </Button>
        }
      >
        <Table
          rowKey="id"
          columns={exceptionColumns}
          dataSource={exceptions}
          loading={exceptionsQuery.isLoading}
          scroll={{ x: 'max-content' }}
          pagination={{ hideOnSinglePage: true }}
          locale={{ emptyText: <Empty description="暂无处置例外" /> }}
        />
      </SectionPanel>

      <Modal
        title="新增处置例外"
        open={exceptionModalOpen}
        onCancel={() => setExceptionModalOpen(false)}
        footer={null}
        width={620}
        destroyOnHidden
      >
        <Alert
          type="info"
          showIcon
          style={{ marginTop: 16 }}
          message="例外不等于关闭安全策略"
          description="例外只能用于已确认的误报，并且必须设置过期时间；请写明业务依据，避免对真实风险放行。"
        />
        <Form form={exceptionForm} layout="vertical" onFinish={submitException} style={{ marginTop: 16 }}>
          <Space size={12} style={{ display: 'flex' }}>
            <Form.Item name="scope_type" label="适用范围" rules={[{ required: true, message: '请选择适用范围' }]} style={{ flex: 1 }}>
              <Select options={SCOPE_OPTIONS} />
            </Form.Item>
            <Form.Item name="scope_ref" label="具体对象" style={{ flex: 1 }}>
              <Input placeholder="例如应用 ID、用户 ID 或 Key 前缀" />
            </Form.Item>
          </Space>
          <Form.Item name="rule_id" label="关联规则">
            <Input placeholder="可选，留空表示按目标匹配" />
          </Form.Item>
          <Form.Item name="target_pattern" label="目标匹配">
            <Input placeholder="例如 filesystem__read_file 或 /safe/path" />
          </Form.Item>
          <Space size={12} style={{ display: 'flex' }}>
            <Form.Item name="decision" label="降级动作" rules={[{ required: true, message: '请选择降级动作' }]} style={{ flex: 1 }}>
              <Select
                options={[
                  { value: 'audit', label: '记录审计' },
                  { value: 'allow', label: '放行' },
                ]}
              />
            </Form.Item>
            <Form.Item name="expires_at" label="过期时间" rules={[{ required: true, message: '请选择过期时间' }]} style={{ flex: 1 }}>
              <DatePicker showTime style={{ width: '100%' }} />
            </Form.Item>
          </Space>
          <Form.Item name="reason" label="审批原因" rules={[{ required: true, message: '请输入审批原因' }]}>
            <Input.TextArea rows={3} placeholder="说明业务必要性和审批依据" />
          </Form.Item>
          <Form.Item name="enabled" label="启用状态" valuePropName="checked">
            <Switch checkedChildren="启用" unCheckedChildren="停用" />
          </Form.Item>
          <Form.Item style={{ marginBottom: 0 }}>
            <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
              <Button onClick={() => setExceptionModalOpen(false)}>取消</Button>
              <Button type="primary" htmlType="submit" loading={exceptionMutation.isPending}>创建例外</Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default McpApprovals

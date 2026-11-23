import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Button,
  Card,
  Popconfirm,
  Space,
  Table,
  Tabs,
  Tag,
  Typography,
  message,
  type TableProps,
} from 'antd'
import { CheckOutlined, CloseOutlined, PlusOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { agentGuardResolutionErrorMessage, agentGuardResolutionSuccessMessage } from './agentguard/confirmationMessages'
import { agentGuardApi, LONG_TERM_EXCEPTION_EXPIRY, securitySystemSettingsApi, systemSettingsApi } from '../services/api'
import AgentExceptionModal, { type AgentExceptionPrefill } from '../components/protection/AgentExceptionModal'
import ConfirmSwitch from '../components/protection/ConfirmSwitch'
import { AGENT_EXCEPTION_SCOPE_OPTIONS } from '../components/protection/constants'
import { useAccess } from '../hooks/useAccess'
import { SYSTEM_SETTINGS_QUERY_KEY } from '../hooks/useSettingsForm'
import { extractApiError } from '../utils/apiError'
import { settingBool } from '../utils/settingsValue'

const { Title, Text } = Typography

function ReadableTable<RecordType extends object>({ columns = [], className, ...props }: TableProps<RecordType>) {
  const labelledColumns = columns.map((column) => {
    const label = typeof column.title === 'string' ? column.title : ''
    return {
      ...column,
      onCell: (record: RecordType, rowIndex?: number) => ({
        ...(column.onCell?.(record, rowIndex) ?? {}),
        'data-label': label,
      }),
    }
  })
  return (
    <Table<RecordType>
      {...props}
      className={['agentguard-readable-table', className].filter(Boolean).join(' ')}
      columns={labelledColumns}
    />
  )
}

type AgentGuardException = {
  id: string
  scope_type: string
  scope_ref?: string
  scope_name?: string
  rule_id?: string
  rule_name?: string
  target_pattern?: string
  decision: string
  reason: string
  expires_at?: string
  enabled: boolean
}

type AgentGuardConfirmation = {
  id: string
  tool_name?: string
  raw_decision?: string
  effective_decision?: string
  status: string
  timeout_action?: string
  reason?: string
  expires_at?: string
  source?: string
}

const SELF_APPROVAL_KEY = 'agentguard_allow_self_approval'

const ACTION_LABELS: Record<string, string> = {
  allow: '放行',
  audit: '记录审计',
  confirm: '人工确认',
  block: '直接阻断',
  approved: '已通过',
  rejected: '已拒绝',
  pending: '待确认',
}

const ACTION_COLORS: Record<string, string> = {
  allow: 'green',
  audit: 'blue',
  confirm: 'orange',
  block: 'red',
  approved: 'green',
  rejected: 'red',
  pending: 'orange',
}

const REASON_LABELS: Record<string, string> = {
  sensitive_personal_data_egress: '敏感个人数据外传',
  high_confidence_secret_egress: '高可信密钥外泄',
  destructive_tool: '破坏性工具调用',
  blocked_destructive_sql: '拦截破坏性 SQL',
  scoped_mutation_requires_confirm: '带条件写库需人工确认',
  blocked_shell_metacharacter: '命中危险 Shell 特殊字符',
  confirm_channel_available: '转人工确认',
  restricted_file_pattern: '命中受限文件模式',
}

const getArray = <T,>(response: unknown): T[] => {
  const raw = response as { data?: { data?: unknown } | unknown[] } | undefined
  if (Array.isArray(raw?.data)) return raw.data as T[]
  if (Array.isArray((raw?.data as { data?: unknown } | undefined)?.data)) {
    return (raw?.data as { data: T[] }).data
  }
  return []
}

const scopeLabel = (scopeType?: string, scopeName?: string) => {
  const label = AGENT_EXCEPTION_SCOPE_OPTIONS.find((item) => item.value === scopeType)?.label || '指定范围'
  return scopeName?.trim() || label
}

const isLongTerm = (value: string) => value.slice(0, 10) === LONG_TERM_EXCEPTION_EXPIRY.slice(0, 10)
const formatTime = (value?: string) => (value ? (isLongTerm(value) ? '长期' : dayjs(value).format('YYYY-MM-DD HH:mm')) : '-')
const reasonLabel = (value?: string) => (value ? REASON_LABELS[value] || value : '-')

function AgentGuard() {
  const [searchParams, setSearchParams] = useSearchParams()
  const requestedTab = searchParams.get('tab')
  const activeTab = requestedTab === 'confirmations' ? 'confirmations' : 'exceptions'
  const [exceptionPrefill, setExceptionPrefill] = useState<AgentExceptionPrefill | null>(null)
  const queryClient = useQueryClient()
  // “允许本人批准”是全平台共享的安全键，只有平台级角色能改。
  const canManage = useAccess().canManagePlatformSecuritySettings

  useEffect(() => {
    if (requestedTab !== 'policies' && !searchParams.has('behavior')) return
    const next = new URLSearchParams(searchParams)
    next.set('tab', 'exceptions')
    next.delete('behavior')
    setSearchParams(next, { replace: true })
  }, [requestedTab, searchParams, setSearchParams])

  // 从阻断记录跳来：带 rule（和 target）时预填放行例外并打开弹窗，随后从地址栏去掉这两个参数。
  useEffect(() => {
    const rule = searchParams.get('rule')
    if (!rule) return
    setExceptionPrefill({ scope_type: 'tenant', rule_id: rule, target_pattern: searchParams.get('target') || '' })
    const next = new URLSearchParams(searchParams)
    next.delete('rule')
    next.delete('target')
    setSearchParams(next, { replace: true })
  }, [searchParams, setSearchParams])

  const exceptionsQ = useQuery({
    queryKey: ['agentguard', 'exceptions'],
    queryFn: agentGuardApi.listExceptions,
  })
  const confirmationsQ = useQuery({
    queryKey: ['agentguard', 'confirmations', 'pending'],
    queryFn: () => agentGuardApi.listConfirmations('pending'),
  })
  const exceptions = getArray<AgentGuardException>(exceptionsQ.data)
  const confirmations = getArray<AgentGuardConfirmation>(confirmationsQ.data).filter((item) => item.source !== 'mcp')
  const refreshExceptions = () => queryClient.invalidateQueries({ queryKey: ['agentguard', 'exceptions'] })
  const refreshConfirmations = () => queryClient.invalidateQueries({ queryKey: ['agentguard', 'confirmations'] })

  const settingsQ = useQuery({
    queryKey: SYSTEM_SETTINGS_QUERY_KEY,
    queryFn: () => systemSettingsApi.get().then((response) => response.data),
  })
  const selfApproval = settingBool(settingsQ.data?.[SELF_APPROVAL_KEY])
  const selfApprovalMutation = useMutation({
    mutationFn: (enabled: boolean) => securitySystemSettingsApi.update({ [SELF_APPROVAL_KEY]: enabled }),
    onSuccess: async () => {
      message.success('已保存')
      await queryClient.invalidateQueries({ queryKey: SYSTEM_SETTINGS_QUERY_KEY })
    },
    onError: (error) => message.error(extractApiError(error) || '保存失败'),
  })
  const deleteExceptionMutation = useMutation({
    mutationFn: (id: string) => agentGuardApi.deleteException(id),
    onSuccess: async () => {
      message.success('例外已删除')
      await refreshExceptions()
    },
    onError: () => message.error('例外删除失败'),
  })
  const resolveMutation = useMutation({
    mutationFn: ({ id, status, note }: { id: string; status: 'approved' | 'rejected'; note: string }) =>
      agentGuardApi.resolveConfirmation(id, { status, note }),
    onSuccess: async (response) => {
      message.success(agentGuardResolutionSuccessMessage(response?.status))
      await refreshConfirmations()
    },
    onError: (error) => message.error(agentGuardResolutionErrorMessage(error, '确认请求处理失败')),
  })

  const openCreateException = () => setExceptionPrefill({ scope_type: 'project' })
  const setLinkedTab = (tab: string) => {
    const next = new URLSearchParams(searchParams)
    next.set('tab', tab)
    next.delete('behavior')
    setSearchParams(next, { replace: true })
  }

  const exceptionColumns = [
    {
      title: '作用范围',
      key: 'scope',
      render: (_: unknown, record: AgentGuardException) => scopeLabel(record.scope_type, record.scope_name),
    },
    {
      title: '关联规则',
      dataIndex: 'rule_id',
      key: 'rule_id',
      render: (_: unknown, record: AgentGuardException) => record.rule_name?.trim() || '按目标匹配',
    },
    {
      title: '目标',
      dataIndex: 'target_pattern',
      key: 'target_pattern',
      render: (value?: string) => <Text style={{ wordBreak: 'break-all' }}>{value || '-'}</Text>,
    },
    {
      title: '降级动作',
      dataIndex: 'decision',
      key: 'decision',
      render: (value: string) => <Tag color={ACTION_COLORS[value] || 'default'}>{ACTION_LABELS[value] || value}</Tag>,
    },
    { title: '原因', dataIndex: 'reason', key: 'reason', render: reasonLabel },
    { title: '过期时间', dataIndex: 'expires_at', key: 'expires_at', render: formatTime },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, record: AgentGuardException) => (
        <Button size="small" danger aria-label="删除" loading={deleteExceptionMutation.isPending} onClick={() => deleteExceptionMutation.mutate(record.id)}>删除</Button>
      ),
    },
  ]
  const confirmationColumns = [
    {
      title: '工具',
      dataIndex: 'tool_name',
      key: 'tool_name',
      render: (value?: string) => value ? <Text code>{value}</Text> : '-',
    },
    {
      title: '实际动作',
      dataIndex: 'effective_decision',
      key: 'effective_decision',
      render: (value?: string) => value ? <Tag color={ACTION_COLORS[value] || 'default'}>{ACTION_LABELS[value] || value}</Tag> : '-',
    },
    { title: '原因', dataIndex: 'reason', key: 'reason', render: reasonLabel },
    {
      title: '超时动作',
      dataIndex: 'timeout_action',
      key: 'timeout_action',
      render: (value?: string) => value ? <Tag color={ACTION_COLORS[value] || 'default'}>{ACTION_LABELS[value] || value}</Tag> : '-',
    },
    { title: '到期时间', dataIndex: 'expires_at', key: 'expires_at', render: formatTime },
    {
      title: '处理',
      key: 'action',
      render: (_: unknown, record: AgentGuardConfirmation) => (
        record.status === 'pending' ? (
          <Space size={4} wrap>
            <Popconfirm
              title="批准后，同一发起人以相同参数重试时网关放行一次（批准后 30 分钟内有效）；中心端不会执行本地工具。"
              onConfirm={() => resolveMutation.mutate({ id: record.id, status: 'approved', note: '控制台批准' })}
              okText="允许重试"
              cancelText="取消"
            >
              <Button size="small" type="link" icon={<CheckOutlined />} aria-label="允许重试">允许重试</Button>
            </Popconfirm>
            <Popconfirm
              title="拒绝本次工具调用？"
              onConfirm={() => resolveMutation.mutate({ id: record.id, status: 'rejected', note: '控制台拒绝' })}
              okText="拒绝"
              cancelText="取消"
            >
              <Button size="small" type="link" danger icon={<CloseOutlined />} aria-label="拒绝">拒绝</Button>
            </Popconfirm>
          </Space>
        ) : <Tag color={ACTION_COLORS[record.status] || 'default'}>{ACTION_LABELS[record.status] || record.status}</Tag>
      ),
    },
  ]
  const tabs = [
    {
      key: 'exceptions',
      label: '例外放行',
      children: (
        <Card
          title="例外放行"
          extra={<Button type="primary" icon={<PlusOutlined />} aria-label="新增放行" onClick={openCreateException}>新增放行</Button>}
        >
          <ReadableTable
            rowKey="id"
            columns={exceptionColumns}
            dataSource={exceptions}
            loading={exceptionsQ.isLoading}
            scroll={{ x: 'max-content' }}
            locale={{ emptyText: '暂无例外放行' }}
          />
        </Card>
      ),
    },
    {
      key: 'confirmations',
      label: '待确认操作',
      children: (
        <Card
          title="待确认操作"
          extra={(
            <Space size={8}>
              <span>允许本人批准</span>
              <ConfirmSwitch
                ariaLabel="允许本人批准"
                checked={selfApproval}
                disabled={!canManage || settingsQ.isError || settingsQ.isLoading}
                loading={selfApprovalMutation.isPending}
                confirmTitle="允许本人批准？"
                confirmContent="触发确认的人可以自己批准这次操作。"
                onChange={(enabled) => selfApprovalMutation.mutate(enabled)}
              />
            </Space>
          )}
        >
          <Tag>授权客户端重试</Tag><Tag>端侧执行：未知</Tag>
          <ReadableTable
            rowKey="id"
            columns={confirmationColumns}
            dataSource={confirmations}
            loading={confirmationsQ.isLoading}
            scroll={{ x: 'max-content' }}
            locale={{ emptyText: '暂无待确认操作' }}
          />
        </Card>
      ),
    },
  ]

  return (
    <div className="agentguard-page">
      <div className="page-header">
        <Title level={4} style={{ margin: 0, fontSize: 20, fontWeight: 600, color: 'var(--text-primary)' }}>工具确认与例外</Title>
      </div>
      <Tabs className="agentguard-settings-tabs" activeKey={activeTab} onChange={setLinkedTab} items={tabs} />

      {exceptionPrefill ? <AgentExceptionModal prefill={exceptionPrefill} onClose={() => setExceptionPrefill(null)} /> : null}
    </div>
  )
}

export default AgentGuard

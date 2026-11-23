import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Descriptions, Drawer, Form, Radio, Segmented, Select, Space, Switch, Table, Tag, Typography, message } from 'antd'
import { SaveOutlined } from '@ant-design/icons'
import { useAuthStore } from '../stores/auth'
import {
  agentApi,
  agentOperationProtectionApi,
  projectApi,
  tenantApi,
  type AgentOperationAction,
  type AgentOperationEvent,
  type AgentOperationMode,
  type AgentOperationPolicy,
  type AgentOperationScope,
  type AgentOperationTenantScope,
} from '../services/api'
import { formatAgentType } from '../utils/agents'
import { Link } from 'react-router-dom'
import { canAccessPath } from '../utils/access'
import { DESTRUCTIVE_SUBCATEGORY_LABELS } from '../utils/alertReadable'

const { Text } = Typography
const MODE_OPTIONS: Array<{ label: string; value: AgentOperationMode }> = [
  { label: '审计：仅记录', value: 'audit' },
  { label: '轻管理：告警并放行', value: 'light' },
  { label: '严格管控：阻断', value: 'strict' },
]
const MODE_DEFAULT_ACTIONS: Record<AgentOperationMode, AgentOperationAction> = {
  audit: 'record',
  light: 'alert_allow',
  strict: 'block',
}
const ACTION_OPTIONS: Array<{ label: string; value: AgentOperationAction }> = [
  { label: '仅记录', value: 'record' },
  { label: '告警并放行', value: 'alert_allow' },
  { label: '确认后执行', value: 'confirm' },
  { label: '阻断', value: 'block' },
]
const STATUS_LABELS: Record<string, string> = {
  recorded: '已记录',
  record: '已记录',
  alert_allowed: '已告警并放行',
  alert_allow: '已告警并放行',
  pending_confirmation: '等待确认',
  confirm: '等待确认',
  blocked: '已阻断',
  block: '已阻断',
  forwarded: '网关已转发',
  execution_forwarded: '网关已转发',
  observed: '已收到工具结果',
  result_observed: '已收到工具结果',
}
const DEFAULT_DISCARDABLE_PATHS = ['node_modules', 'dist', 'build', '.cache', 'tmp', 'test-output']
const statusLabel = (event: AgentOperationEvent) => STATUS_LABELS[event.status_code] || '处理结果待确认'
// 子类名称以网关 agentguard_block_notice.go 的 destructiveSubcategoryLabels 为准；后两项是页面原有、网关字典未收录的编码。
const OPERATION_LABELS: Record<string, string> = {
  ...DESTRUCTIVE_SUBCATEGORY_LABELS,
  database_destructive: '数据库破坏性操作',
  database_drop: '删除数据库对象',
}
const PROTOCOL_LABELS: Record<string, string> = { chat: 'OpenAI Chat', chat_completions: 'OpenAI Chat', responses: 'Responses', messages: 'Claude Messages', anthropic_messages: 'Claude Messages', mcp: 'MCP' }
// 目标说明保留页面自己的写法：这里要强调“具体路径未提供”，alertReadable 的“（N 个目标）”不带这层意思。
function operationDescription(event: AgentOperationEvent) {
  const matched = /^([a-z][a-z0-9_]*):(\d+)-targets$/.exec(event.target_summary || '')
  const category = event.subcategory_code && OPERATION_LABELS[event.subcategory_code] ? event.subcategory_code : matched?.[1] || ''
  return {
    operation: OPERATION_LABELS[category] || '其他破坏性操作',
    target: matched ? `识别到 ${matched[2]} 个目标；具体路径未提供` : event.target_summary === 'target-incomplete' || event.target_summary?.endsWith(':target-incomplete') ? '目标信息不完整' : '具体目标未提供',
  }
}
function operationTime(value: string) {
  return value && !Number.isNaN(Date.parse(value)) ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '时间未记录'
}
function technicalID(value?: string) {
  return value ? <Text code copyable style={{ overflowWrap: 'anywhere' }}>{value}</Text> : '未提供'
}

type ScopeOption = { label: string; value: string; disabled?: boolean }

function toArray(value: unknown): Array<Record<string, any>> {
  if (Array.isArray(value)) return value as Array<Record<string, any>>
  if (!value || typeof value !== 'object') return []
  const record = value as { data?: unknown; items?: unknown }
  if (Array.isArray(record.data)) return record.data as Array<Record<string, any>>
  if (Array.isArray(record.items)) return record.items as Array<Record<string, any>>
  return []
}

function isNotFound(error: unknown) {
  if (!error || typeof error !== 'object') return false
  return (error as { response?: { status?: number } }).response?.status === 404
}

function defaultPolicy(
  scopeType: AgentOperationScope,
  scopeRef = '',
  tenantScope: AgentOperationTenantScope = 'tenant',
  tenantID = '',
): AgentOperationPolicy {
  return {
    tenant_scope: tenantScope,
    ...(tenantScope === 'tenant' && tenantID ? { tenant_id: tenantID } : {}),
    scope_type: scopeType,
    scope_ref: scopeRef,
    mode: 'audit',
    action: 'record',
    protocol: '',
    mode_default_action: 'record',
    current_action: 'record',
    config_source: 'new_scope',
    discardable_paths: [...DEFAULT_DISCARDABLE_PATHS],
    notify_channel_ids: [],
    channels: [],
    version: 1,
    updated_at: '',
  }
}

function agentScopeLabel(session: Record<string, any>) {
  const clientName = String(session.client_name || '').trim()
  if (clientName) return clientName
  const agentType = String(session.agent_type || '').trim()
  const knownLabel = formatAgentType(agentType)
  if (knownLabel !== agentType) return knownLabel
  if (agentType === 'agent-tool-call') return '工具调用智能体（网关识别）'
  return '其他智能体'
}

export default function AgentOperationProtection() {
  const [selectedRecord, setSelectedRecord] = useState<AgentOperationEvent | null>(null)
  const [form] = Form.useForm<AgentOperationPolicy>()
  const queryClient = useQueryClient()
  const user = useAuthStore((state) => state.user)
  const isPlatformAdmin = user?.role === 'platform_admin'
  const currentTenantID = String(user?.tenant_id || '')
  const initialTenantScope: AgentOperationTenantScope = isPlatformAdmin ? 'all' : 'tenant'
  const initialTenantID = isPlatformAdmin ? '' : currentTenantID
  const [tenantScope, setTenantScope] = useState<AgentOperationTenantScope>(initialTenantScope)
  const [tenantID, setTenantID] = useState(initialTenantID)
  const [followMode, setFollowMode] = useState(true)
  const scopeType = (Form.useWatch('scope_type', form) || 'tenant') as AgentOperationScope
  const scopeRef = String(Form.useWatch('scope_ref', form) || '')
  const selectedScopeRef = scopeType === 'tenant' ? '' : scopeRef
  const selectedMode = (Form.useWatch('mode', form) || 'audit') as AgentOperationMode
  const modeDefaultAction = MODE_DEFAULT_ACTIONS[selectedMode]


  const tenantsQuery = useQuery({
    queryKey: ['agent-operation-tenants'],
    queryFn: () => tenantApi.list(),
    enabled: Boolean(isPlatformAdmin),
  })
  const policyQuery = useQuery({
    queryKey: ['agent-operation-protection', tenantScope, tenantID, scopeType, selectedScopeRef],
    enabled: (tenantScope === 'all' || Boolean(tenantID)) && (scopeType === 'tenant' || Boolean(selectedScopeRef)),
    queryFn: async () => {
      const target = tenantScope === 'tenant'
        ? { tenant_scope: tenantScope, tenant_id: tenantID }
        : { tenant_scope: tenantScope }
      try {
        return (await agentOperationProtectionApi.getPolicy({
          ...target,
          scope_type: scopeType,
          scope_ref: selectedScopeRef,
        })).data
      } catch (error) {
        if (isNotFound(error)) return defaultPolicy(scopeType, selectedScopeRef, tenantScope, tenantID)
        throw error
      }
    },
  })
  const eventsQuery = useQuery({
    queryKey: ['agent-operation-events'],
    queryFn: async () => (await agentOperationProtectionApi.listEvents({ limit: 20, offset: 0 })).data,
  })
  const projectsQuery = useQuery({
    queryKey: ['agent-operation-scope-projects', tenantScope, tenantID],
    queryFn: () => projectApi.list(),
    enabled: scopeType === 'application' && tenantScope === 'tenant' && Boolean(tenantID),
  })
  const agentsQuery = useQuery({
    queryKey: ['agent-operation-scope-agents', tenantScope, tenantID],
    queryFn: () => agentApi.list({
      tenant_scope: tenantScope,
      ...(tenantScope === 'tenant' ? { tenant_id: tenantID } : {}),
    }),
    enabled: scopeType === 'agent' && (tenantScope === 'all' || Boolean(tenantID)),
  })

  useEffect(() => {
    const nextScope: AgentOperationTenantScope = isPlatformAdmin ? 'all' : 'tenant'
    const nextID = isPlatformAdmin ? '' : currentTenantID
    setTenantScope(nextScope)
    setTenantID(nextID)
    form.setFieldsValue(defaultPolicy('tenant', '', nextScope, nextID))
  }, [currentTenantID, form, isPlatformAdmin])

  useEffect(() => {
    if (!policyQuery.data) return
    const responseTenantScope = policyQuery.data.tenant_scope || tenantScope
    const responseTenantID = String(policyQuery.data.tenant_id || '')
    if (responseTenantScope !== tenantScope || (tenantScope === 'tenant' && responseTenantID !== tenantID)) return
    form.setFieldsValue(policyQuery.data)
    setFollowMode(policyQuery.data.action === policyQuery.data.mode_default_action)
  }, [form, policyQuery.data, tenantID, tenantScope])

  useEffect(() => {
    if (followMode && form.getFieldValue('action') !== modeDefaultAction) {
      form.setFieldValue('action', modeDefaultAction)
    }
  }, [followMode, form, modeDefaultAction])

  const tenantOptions = useMemo<ScopeOption[]>(() => {
    const options: ScopeOption[] = [{ label: '所有租户', value: 'all' }]
    for (const tenant of toArray(tenantsQuery.data?.data)) {
      const value = String(tenant.id || '').trim()
      if (!value || tenant.status === 'deleted') continue
      options.push({ value, label: String(tenant.name || '未命名租户') })
    }
    return options
  }, [tenantsQuery.data])

  const applicationOptions = useMemo<ScopeOption[]>(() => toArray(projectsQuery.data?.data)
    .filter((project) => !project.status || project.status === 'active')
    .map((project) => ({ value: String(project.id || ''), label: String(project.name || '未命名应用') }))
    .filter((option) => option.value), [projectsQuery.data])

  const agentOptions = useMemo<ScopeOption[]>(() => {
    const options = new Map<string, ScopeOption>()
    for (const session of toArray(agentsQuery.data?.data)) {
      const value = String(session.agent_type || '').trim()
      if (value && value !== '*' && !options.has(value)) options.set(value, { value, label: agentScopeLabel(session) })
    }
    return [
      { label: '所有 Agent', value: '*' },
      ...Array.from(options.values()).sort((left, right) => left.label.localeCompare(right.label, 'zh-CN')),
    ]
  }, [agentsQuery.data])

  const scopeOptions = scopeType === 'application' ? applicationOptions : agentOptions
  const scopeLoading = scopeType === 'application' ? projectsQuery.isFetching : agentsQuery.isFetching
  const scopeObjectLabel = scopeType === 'agent' ? '智能体类型' : '应用'
  const scopeReady = (tenantScope === 'all' || Boolean(tenantID)) && (scopeType === 'tenant' || Boolean(scopeRef))

  const updateMutation = useMutation({
    mutationFn: (values: AgentOperationPolicy) => {
      const action = followMode ? MODE_DEFAULT_ACTIONS[values.mode] : values.action
      return agentOperationProtectionApi.updatePolicy({
        tenant_scope: tenantScope,
        ...(tenantScope === 'tenant' ? { tenant_id: tenantID } : {}),
        scope_type: values.scope_type,
        scope_ref: values.scope_type === 'tenant' ? '' : values.scope_ref,
        mode: values.mode,
        action,
        // 2.9.22：确认不再只限 MCP。非 MCP 有确认通道时走普通确认票据，没有通道时按防护项“需要确认但无法确认”处置。
        protocol: values.protocol || '',
        discardable_paths: values.discardable_paths || [],
        notify_channel_ids: tenantScope === 'tenant' ? (values.notify_channel_ids || []) : [],
        version: policyQuery.data?.version || values.version,
      })
    },
    onSuccess: () => {
      message.success('策略已保存')
      queryClient.invalidateQueries({ queryKey: ['agent-operation-protection'] })
    },
    onError: () => message.error('策略保存失败'),
  })

  const channels = tenantScope === 'tenant' ? (policyQuery.data?.channels || []) : []
  const columns = [
    { title: '时间', dataIndex: 'created_at', width: 180, render: operationTime },
    { title: '操作', width: 180, render: (_: unknown, event: AgentOperationEvent) => operationDescription(event).operation },
    { title: '识别目标', render: (_: unknown, event: AgentOperationEvent) => operationDescription(event).target },
    { title: '网关处理结果', width: 160, render: (_: unknown, event: AgentOperationEvent) => <Tag>{statusLabel(event)}</Tag> },
    { title: '操作详情', width: 100, render: (_: unknown, event: AgentOperationEvent) => <Button type="link" onClick={() => setSelectedRecord(event)}>查看详情</Button> },
  ]

  const resetTarget = (nextScope: AgentOperationTenantScope, nextID: string) => {
    setTenantScope(nextScope)
    setTenantID(nextID)
    setFollowMode(true)
    form.setFieldsValue(defaultPolicy('tenant', '', nextScope, nextID))
  }
  const resetScope = (nextScopeType: AgentOperationScope) => {
    setFollowMode(true)
    form.setFieldsValue(defaultPolicy(nextScopeType, '', tenantScope, tenantID))
  }
  const resetScopeObject = (value: string) => {
    setFollowMode(true)
    form.setFieldsValue(defaultPolicy(scopeType, value, tenantScope, tenantID))
  }

  return <div>
    <Space wrap style={{ marginBottom: 16 }}><Tag>控制对象：拟调用</Tag><Tag>端侧执行：未知</Tag></Space>
    <Form
      form={form}
      layout="vertical"
      initialValues={defaultPolicy('tenant', '', initialTenantScope, initialTenantID)}
      onFinish={(values) => updateMutation.mutate(values)}
    >
      <Space direction="vertical" size={18} style={{ width: '100%' }}>
        {isPlatformAdmin && (
          <Form.Item label="目标租户">
            <Select
              aria-label="目标租户"
              value={tenantScope === 'all' ? 'all' : tenantID}
              options={tenantOptions}
              loading={tenantsQuery.isFetching}
              onChange={(value) => resetTarget(value === 'all' ? 'all' : 'tenant', value === 'all' ? '' : value)}
            />
          </Form.Item>
        )}
        {policyQuery.data && policyQuery.data.enabled === false ? (
          <Alert
            type="warning"
            showIcon
            message="该范围的策略已停用"
            description={`停用前保存的是「${MODE_OPTIONS.find((option) => option.value === policyQuery.data.mode)?.label ?? policyQuery.data.mode}」，当前不生效，请以下方的表单为准重新保存才会启用。`}
          />
        ) : policyQuery.data && (policyQuery.data.configured === false || policyQuery.data.config_source === 'new_scope') ? (
          <Alert type="info" showIcon message="该范围尚未配置，当前显示系统默认值" />
        ) : null}
        <Form.Item label="防护模式">
          <Form.Item name="mode" noStyle><Segmented options={MODE_OPTIONS} /></Form.Item>
        </Form.Item>
        <Form.Item label="动作来源">
          <Space>
            <Switch checked={followMode} onChange={setFollowMode} aria-label="跟随模式" />
            <Text>跟随模式</Text>
            {!followMode && <Text type="secondary">自定义动作</Text>}
          </Space>
        </Form.Item>
        {!followMode && (
          <Form.Item label="自定义动作" name="action">
            <Radio.Group>
              {ACTION_OPTIONS.map((option) => (
                <Radio key={option.value} value={option.value}>
                  {option.label}
                </Radio>
              ))}
            </Radio.Group>
          </Form.Item>
        )}
        <Space size={16} wrap align="start">
          <Form.Item label="作用域" name="scope_type" style={{ minWidth: 180 }}>
            <Select
              onChange={(value) => resetScope(value as AgentOperationScope)}
              options={[
                { label: '租户', value: 'tenant' },
                { label: '应用', value: 'application', disabled: tenantScope === 'all' },
                { label: 'Agent', value: 'agent' },
              ]}
            />
          </Form.Item>
          {scopeType !== 'tenant' && (
            <Form.Item label={scopeObjectLabel} name="scope_ref" rules={[{ required: true, message: '请选择' + scopeObjectLabel }]} style={{ minWidth: 260 }}>
              <Select
                showSearch
                optionFilterProp="label"
                placeholder={'选择' + scopeObjectLabel}
                options={scopeOptions}
                loading={scopeLoading}
                notFoundContent={scopeLoading ? '加载中…' : '暂无可配置' + scopeObjectLabel}
                onChange={resetScopeObject}
              />
            </Form.Item>
          )}
          <Form.Item label="协议能力" name="protocol" style={{ minWidth: 180 }}>
            <Select options={[{ label: '通用模型客户端', value: '' }, { label: 'MCP', value: 'mcp' }]} />
          </Form.Item>
        </Space>
        <Form.Item label="可丢弃路径" name="discardable_paths">
          <Select mode="tags" tokenSeparators={[',']} options={[]} maxCount={32} />
        </Form.Item>
        {tenantScope === 'tenant' && (
          <Form.Item label="告警通知渠道" name="notify_channel_ids">
            <Select mode="multiple" options={channels.map((channel) => ({ label: channel.name, value: channel.id, disabled: !channel.enabled }))} />
          </Form.Item>
        )}
        <Space>
          <Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={updateMutation.isPending} disabled={!scopeReady || policyQuery.isFetching}>
            保存策略
          </Button>
        </Space>
      </Space>
    </Form>
    <div style={{ marginTop: 30 }}>
      <Typography.Title level={4}>最近操作记录</Typography.Title>
      <Table<AgentOperationEvent> rowKey="public_event_id" columns={columns} dataSource={eventsQuery.data?.items || []} loading={eventsQuery.isLoading} pagination={false} scroll={{ x: 780 }} />
    </div>
    <Drawer title="操作记录详情" open={Boolean(selectedRecord)} width={Math.min(680, typeof window === 'undefined' ? 680 : window.innerWidth)} onClose={() => setSelectedRecord(null)}>
      {selectedRecord && <>
        <Space wrap style={{ marginBottom: 16 }}><Tag>{statusLabel(selectedRecord)}</Tag><Tag>端侧执行：未知</Tag></Space>
        <Descriptions size="small" column={1}>
          <Descriptions.Item label="时间">{operationTime(selectedRecord.created_at)}</Descriptions.Item>
          <Descriptions.Item label="操作类别">{operationDescription(selectedRecord).operation}</Descriptions.Item>
          <Descriptions.Item label="识别目标">{operationDescription(selectedRecord).target}</Descriptions.Item>
          <Descriptions.Item label="工具">{selectedRecord.tool_name || '未提供'}</Descriptions.Item>
          <Descriptions.Item label="协议">{PROTOCOL_LABELS[selectedRecord.protocol] || '协议待确认'}</Descriptions.Item>
          <Descriptions.Item label="协议原码">{selectedRecord.protocol || '未提供'}</Descriptions.Item>
          <Descriptions.Item label="识别置信度">{typeof selectedRecord.confidence === 'number' ? selectedRecord.confidence : '待确认'}</Descriptions.Item>
          <Descriptions.Item label="事件编号">{technicalID(selectedRecord.public_event_id)}</Descriptions.Item>
          <Descriptions.Item label="操作编号">{technicalID(selectedRecord.operation_id)}</Descriptions.Item>
          <Descriptions.Item label="请求编号">{technicalID(selectedRecord.request_id)}</Descriptions.Item>
          <Descriptions.Item label="追踪编号">{technicalID(selectedRecord.trace_id)}</Descriptions.Item>
          <Descriptions.Item label="工具调用编号">{technicalID(selectedRecord.tool_call_id)}</Descriptions.Item>
          <Descriptions.Item label="状态原码">{selectedRecord.status_code || '未提供'}</Descriptions.Item>
          <Descriptions.Item label="通知原码">{selectedRecord.notification_code || '未提供'}</Descriptions.Item>
          <Descriptions.Item label="识别摘要原文">{selectedRecord.target_summary || '未提供'}</Descriptions.Item>
        </Descriptions>
        {selectedRecord.request_id && canAccessPath(user?.role, '/audit/access-retention') && <Link to={`/audit/access-retention?request_id=${encodeURIComponent(selectedRecord.request_id)}`}>查看请求记录</Link>}
      </>}
    </Drawer>
  </div>
}

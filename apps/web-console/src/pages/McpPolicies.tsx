import { useMemo, useState } from 'react'
import {
  Table,
  Button,
  Space,
  Modal,
  Form,
  Input,
  InputNumber,
  Select,
  AutoComplete,
  Switch,
  Tag,
  Tooltip,
  Typography,
  message,
  Popconfirm,
  Alert,
  Empty,
} from 'antd'
import { PlusOutlined, EditOutlined, DeleteOutlined, ExperimentOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api, {
  mcpPolicyApi,
  mcpServerApi,
  projectApi,
  userApi,
  proxyKeyApi,
  orgApi,
  type McpPolicy,
  type McpPolicyPayload,
  type McpServer,
  type McpTool,
  type McpPolicyWithConditions,
  type McpPolicyPayloadWithConditions,
  type McpArgConditionFormRow,
} from '../services/api'
import { AGENT_DEFINITIONS } from '../utils/agents'
import { EnterprisePageHeader, MetricCard, SectionPanel, StatusPill } from '../components/EnterpriseUI'
import { effectiveSecurityAction, normalizeSecurityExecutionMode } from '../services/securityExecutionMode'
import McpRedlineSettings from './McpRedlineSettings'
import McpProtectionSettings from './McpProtectionSettings'
import { useAuthStore } from '../stores/auth'
import { canManageSecurityPolicy } from '../utils/access'
import McpArgConditionsEditor from './McpArgConditionsEditor'
import { fromArgConditions, toArgConditions } from './McpArgConditionUtils'

const { Text } = Typography

// 遮蔽检测警告（后端 GET /admin/v1/mcp-policies/shadow-check 权威口径，前端只做展示）
interface ShadowWarning {
  shadowed_block_id: string
  winning_allow_id: string
  scope: string
  reason: string
}

// simulate 预演响应
interface SimulateResult {
  winning: McpPolicy | null
  candidates: McpPolicy[]
}

// 解析优先级：会话 > API Key > 智能体类型 > 成员 > 部门 > 项目 > 租户全局（与网关运行时 ResolveMCPPolicy 同源口径）
const SCOPE_RANK: Record<string, number> = {
  session: 7,
  key: 6,
  agent: 5,
  user: 4,
  department: 3,
  project: 2,
  tenant: 1,
}

// 作用域档位中文字典（解析优先级：会话 > API Key > 智能体类型 > 成员 > 部门 > 项目 > 租户全局）
const SCOPE_TYPE_OPTIONS = [
  { value: 'tenant', label: '租户全局' },
  { value: 'project', label: '项目' },
  { value: 'department', label: '部门' },
  { value: 'user', label: '成员' },
  { value: 'key', label: 'API Key' },
  { value: 'agent', label: '智能体类型' },
  { value: 'session', label: '会话' },
]
const SCOPE_TYPE_LABELS: Record<string, string> = Object.fromEntries(
  SCOPE_TYPE_OPTIONS.map((o) => [o.value, o.label]),
)
const SCOPE_TYPE_COLORS: Record<string, string> = {
  tenant: 'blue',
  project: 'cyan',
  department: 'geekblue',
  user: 'green',
  key: 'gold',
  agent: 'purple',
  session: 'magenta',
}

// scope_ref 按档位动态提示：空串 = 该档位通配
const SCOPE_REF_PLACEHOLDERS: Record<string, string> = {
  tenant: '留空即可：租户全局策略作用于本租户全部 MCP 调用',
  project: '填项目 ID；留空 = 匹配任意项目',
  department: '选择部门（按调用成员所属部门匹配）；留空 = 匹配任意部门',
  user: '填成员用户 ID；留空 = 匹配任意成员',
  key: '填 API Key 前缀；留空 = 匹配任意密钥',
  agent: '填智能体类型（如 claude-code）；留空 = 匹配任意智能体',
  session: '填会话 ID；留空 = 匹配任意会话',
}

const MODE_OPTIONS = [
  { value: 'observe', label: '观察模式' },
  { value: 'audit', label: '审计模式' },
  { value: 'strict', label: '严格模式' },
]
const MODE_DESCRIPTIONS: Record<string, string> = {
  observe: '观察模式：阻断/确认原始判定只记录，不中断调用。',
  audit: '审计模式：记录并标注“应阻断/应人工确认”，不中断调用。',
  strict: '严格模式：按处置动作实际执行；未准入、隔离、撤销或快照漂移按确定性准入保护处理。',
}
const MODE_COLORS: Record<string, string> = {
  observe: 'default',
  audit: 'blue',
  strict: 'red',
}
const MODE_LABELS: Record<string, string> = Object.fromEntries(
  MODE_OPTIONS.map((o) => [o.value, o.label]),
)

const ACTION_OPTIONS = [
  { value: 'allow', label: '允许' },
  { value: 'audit', label: '审计' },
  { value: 'confirm', label: '人工确认' },
  { value: 'block', label: '阻断' },
]
const ACTION_DESCRIPTIONS: Record<string, string> = {
  allow: '允许：命中即放行，仅保留基础调用记录。',
  audit: '审计：放行并完整留痕，是推荐的默认动作。',
  confirm: '人工确认：本次调用先拒绝并生成待办确认单，管理员批准后留痕可回放。',
  block: '阻断：直接拒绝该工具调用（是否真拦截取决于生效模式与平台执行模式）。',
}
const ACTION_COLORS: Record<string, string> = {
  allow: 'green',
  audit: 'blue',
  confirm: 'orange',
  block: 'red',
}
const ACTION_LABELS: Record<string, string> = Object.fromEntries(
  ACTION_OPTIONS.map((o) => [o.value, o.label]),
)

// 响应解包三连：control-plane 返回结构不统一（{items:[]} / {data:[]} / 裸数组）
const unpackList = (raw: any, extraKey?: string): any[] => {
  if (Array.isArray(raw?.items)) return raw.items
  if (Array.isArray(raw?.data)) return raw.data
  if (extraKey && Array.isArray(raw?.[extraKey])) return raw[extraKey]
  return Array.isArray(raw) ? raw : []
}

function McpPolicies() {
  const queryClient = useQueryClient()
  const canEditProtection = canManageSecurityPolicy(useAuthStore((state) => state.user?.role))
  const [modalOpen, setModalOpen] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<McpPolicy | null>(null)
  const [pendingValues, setPendingValues] = useState<McpPolicyPayloadWithConditions | null>(null)
  const [simResult, setSimResult] = useState<SimulateResult | null>(null)
  const [form] = Form.useForm()
  const watchScopeType = Form.useWatch('scope_type', form)
  const watchServerId = Form.useWatch('server_id', form)
  const watchToolPattern = Form.useWatch('tool_pattern', form)
  const watchMode = Form.useWatch('mode', form)
  const watchAction = Form.useWatch('default_action', form)

  const policiesQuery = useQuery({
    queryKey: ['mcpPolicies'],
    queryFn: () => mcpPolicyApi.list(),
  })

  const serversQuery = useQuery({
    queryKey: ['mcpServers'],
    queryFn: () => mcpServerApi.list(),
  })

  // 遮蔽检测：后端权威结论，命中即用红字汇总 + 行内红 Tag 展示
  const shadowQuery = useQuery({
    queryKey: ['mcpPolicyShadowCheck'],
    queryFn: () => mcpPolicyApi.shadowCheck(),
  })

  const settingsQuery = useQuery({
    queryKey: ['system-settings', 'runtime-mode'],
    queryFn: () => api.get('/system/settings').then((r) => r.data),
  })

  // scope_ref 联动候选：按作用档位加载对应的项目/成员/API Key/智能体列表
  const projectsQuery = useQuery({
    queryKey: ['projects'],
    queryFn: () => projectApi.list(),
    enabled: watchScopeType === 'project',
  })
  const usersQuery = useQuery({
    queryKey: ['users'],
    queryFn: () => userApi.list(),
    enabled: watchScopeType === 'user',
  })
  const teamsQuery = useQuery({
    queryKey: ['teams'],
    queryFn: () => orgApi.listTeams(),
    enabled: watchScopeType === 'department',
  })
  const keysQuery = useQuery({
    queryKey: ['proxyAccessKeys'],
    queryFn: () => proxyKeyApi.list(),
    enabled: watchScopeType === 'key',
  })

  // 工具模式联想：选中服务后拉其工具清单，供 tool_pattern 自动补全
  const policyToolsQuery = useQuery({
    queryKey: ['mcpPolicyServerTools', watchServerId],
    queryFn: () => mcpServerApi.listTools(watchServerId as string),
    enabled: !!watchServerId,
  })

  const saveMutation = useMutation({
    mutationFn: (data: { id?: string } & McpPolicyPayloadWithConditions) => {
      const { id, ...rest } = data
      return id ? mcpPolicyApi.update(id, rest) : mcpPolicyApi.create(rest)
    },
    onSuccess: () => {
      message.success('策略已保存')
      queryClient.invalidateQueries({ queryKey: ['mcpPolicies'] })
      queryClient.invalidateQueries({ queryKey: ['mcpPolicyShadowCheck'] })
      setModalOpen(false)
      setEditingPolicy(null)
      setPendingValues(null)
      setSimResult(null)
      form.resetFields()
    },
    onError: () => message.error('保存失败'),
  })

  // 保存前预演：调 simulate 返回同作用域下的胜出策略与全部候选，帮助管理员确认新策略是否被遮蔽/是否会遮蔽他人
  const simulateMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => mcpPolicyApi.simulate(body as any),
    onSuccess: (res) => setSimResult((res.data || { winning: null, candidates: [] }) as SimulateResult),
    onError: () => message.error('预演失败，请稍后重试'),
  })

  const toggleMutation = useMutation({
    mutationFn: ({ record, enabled }: { record: McpPolicy; enabled: boolean }) =>
      mcpPolicyApi.update(record.id, {
        scope_type: record.scope_type,
        scope_ref: record.scope_ref,
        server_id: record.server_id,
        tool_pattern: record.tool_pattern,
        mode: record.mode,
        default_action: record.default_action,
        priority: record.priority,
        note: record.note,
        enabled,
        // 启停只改 enabled：目标类别与参数条件原样带回，避免被重置为默认值
        target_kind: (record as McpPolicyWithConditions).target_kind,
        arg_conditions: (record as McpPolicyWithConditions).arg_conditions,
      } as McpPolicyPayloadWithConditions),
    onSuccess: (_res, vars) => {
      message.success(vars.enabled ? '策略已启用' : '策略已停用')
      queryClient.invalidateQueries({ queryKey: ['mcpPolicies'] })
      queryClient.invalidateQueries({ queryKey: ['mcpPolicyShadowCheck'] })
    },
    onError: () => message.error('操作失败'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => mcpPolicyApi.delete(id),
    onSuccess: () => {
      message.success('删除成功')
      queryClient.invalidateQueries({ queryKey: ['mcpPolicies'] })
      queryClient.invalidateQueries({ queryKey: ['mcpPolicyShadowCheck'] })
    },
    onError: () => message.error('删除失败'),
  })

  const policies: McpPolicy[] = unpackList(policiesQuery.data?.data)
  const servers: McpServer[] = unpackList(serversQuery.data?.data, 'servers')
  const serverNameById: Record<string, string> = Object.fromEntries(servers.map((s) => [s.id, s.name]))
  const policyById: Record<string, McpPolicy> = Object.fromEntries(policies.map((p) => [p.id, p]))

  // 遮蔽检测结果：block 策略 id → 警告
  const shadowWarnings: ShadowWarning[] = (shadowQuery.data?.data?.warnings || []) as ShadowWarning[]
  const shadowByBlockId = new Map(shadowWarnings.map((w) => [w.shadowed_block_id, w]))

  // 展示排序：按解析优先级（作用域档位 rank 降序）→ 同档位比 priority 数值（大者先），与运行时解析同序
  const sortedPolicies = useMemo(() => {
    return [...policies].sort((a, b) => {
      const ra = SCOPE_RANK[a.scope_type] || 0
      const rb = SCOPE_RANK[b.scope_type] || 0
      if (ra !== rb) return rb - ra
      return (b.priority ?? 0) - (a.priority ?? 0)
    })
  }, [policies])

  // scope_ref 联动候选列表
  const projectOptions = unpackList(projectsQuery.data?.data).map((p: any) => ({ value: p.id, label: `${p.name || p.id}${p.code ? `（${p.code}）` : ''}` }))
  const userOptions = unpackList(usersQuery.data?.data).map((u: any) => ({ value: u.id, label: u.username || u.id }))
  const departmentOptions = unpackList(teamsQuery.data?.data, 'teams').map((d: any) => ({ value: d.id, label: d.name || d.id }))
  const keyOptions = unpackList(keysQuery.data?.data).map((k: any) => ({ value: k.proxy_key_prefix, label: k.proxy_key_prefix }))
  const agentOptions = AGENT_DEFINITIONS.map((a) => ({ value: a.type, label: a.label }))

  // tool_pattern 联想：选中服务的工具名 + 前缀通配建议
  const serverTools: McpTool[] = unpackList(policyToolsQuery.data?.data)
  const toolNames = serverTools.map((t) => t.tool_name).filter(Boolean)
  const toolPatternOptions = [
    ...toolNames.map((n) => ({ value: n })),
    ...Array.from(new Set(toolNames.map((n) => n.split(/[._-]/)[0]).filter(Boolean))).map((prefix) => ({
      value: `${prefix}.*`,
      label: `${prefix}.*（前缀匹配）`,
    })),
  ]
  // 无匹配提示：选了服务、填了 pattern，但当前服务无任何工具命中该 pattern
  const patternMatchesAnyTool = (() => {
    const p = String(watchToolPattern || '').trim()
    if (!p || !watchServerId || toolNames.length === 0) return true
    if (p.endsWith('.*')) {
      const prefix = p.slice(0, -2)
      return toolNames.some((n) => n.startsWith(prefix))
    }
    return toolNames.includes(p)
  })()

  // mode × default_action 自相矛盾防呆
  const modeActionConflict =
    watchMode === 'observe' && (watchAction === 'block' || watchAction === 'confirm')
      ? '观察模式只记录、一律不干预，此处的「阻断/人工确认」不会实际生效，仅作留痕。若希望真正管控，请改用审计或严格模式。'
      : watchMode === 'strict' && watchAction === 'allow'
        ? '严格模式下配置「允许」等于对该作用域显式放行（豁免管控），请确认这不是误配——通常放行动作用于为更宽的阻断策略开例外。'
        : ''

  const securityExecutionMode = normalizeSecurityExecutionMode(settingsQuery.data)
  const securityAuditOnly = securityExecutionMode?.effective_mode === 'record'

  const enabledCount = policies.filter((p) => p.enabled).length
  const enforceCount = policies.filter((p) => p.enabled && (p.default_action === 'block' || p.default_action === 'confirm')).length
  const strictCount = policies.filter((p) => p.enabled && p.mode === 'strict').length

  const handleCreate = () => {
    setEditingPolicy(null)
    form.resetFields()
    form.setFieldsValue({
      scope_type: 'tenant',
      scope_ref: '',
      server_id: '',
      tool_pattern: '',
      mode: 'audit',
      default_action: 'audit',
      priority: 0,
      enabled: true,
      note: '',
      arg_conditions: [],
    })
    setSimResult(null)
    setModalOpen(true)
  }

  const handleEdit = (record: McpPolicy) => {
    setEditingPolicy(record)
    form.setFieldsValue({
      scope_type: record.scope_type,
      scope_ref: record.scope_ref,
      server_id: record.server_id || '',
      tool_pattern: record.tool_pattern,
      mode: record.mode,
      default_action: record.default_action,
      priority: record.priority,
      enabled: record.enabled,
      note: record.note,
      arg_conditions: fromArgConditions((record as McpPolicyWithConditions).arg_conditions),
    })
    setSimResult(null)
    setModalOpen(true)
  }

  const closeModal = () => {
    setModalOpen(false)
    setSimResult(null)
  }

  // 预演：把当前表单值组装成 simulate 请求，scope_ref 按档位落到对应字段，tool_name 去掉尾部通配
  const handleSimulate = () => {
    const v = form.getFieldsValue()
    const ref = String(v.scope_ref || '').trim()
    const toolName = String(v.tool_pattern || '').replace(/\.\*$/, '').trim()
    const body: Record<string, unknown> = {
      scope_type: v.scope_type,
      scope_ref: ref,
      server_id: v.server_id || '',
      tool_name: toolName,
    }
    if (v.scope_type === 'project') body.project_id = ref
    if (v.scope_type === 'department') body.department_id = ref
    if (v.scope_type === 'user') body.user_id = ref
    if (v.scope_type === 'key') body.key_prefix = ref
    if (v.scope_type === 'agent') body.agent_id = ref
    if (v.scope_type === 'session') body.session_id = ref
    simulateMutation.mutate(body)
  }

  const doSave = (values: McpPolicyPayloadWithConditions) => {
    // 表单没有目标类别字段：编辑时沿用原值，避免资源/提示词/方法类策略被改回工具类
    saveMutation.mutate(editingPolicy
      ? { target_kind: (editingPolicy as McpPolicyWithConditions).target_kind, ...values, id: editingPolicy.id }
      : values)
  }

  // 阻断/人工确认动作保存前二次确认（文案按平台执行模式动态措辞，检测模式下不许暗示会真拦）
  const handleSubmit = (formValues: McpPolicyPayload & { arg_conditions?: McpArgConditionFormRow[] }) => {
    let values: McpPolicyPayloadWithConditions
    try {
      values = { ...formValues, arg_conditions: toArgConditions(formValues.arg_conditions) }
    } catch (err) {
      message.error(err instanceof Error ? err.message : '参数条件填写有误')
      return
    }
    if (values.default_action === 'block' || values.default_action === 'confirm') {
      setPendingValues(values)
      return
    }
    doSave(values)
  }

  const confirmModalBody = () => {
    if (!pendingValues) return null
    const actionLabel = ACTION_LABELS[pendingValues.default_action] || pendingValues.default_action
    if (securityAuditOnly) {
      return (
        <Space direction="vertical" size={6}>
          <Text>该策略的处置动作为「{actionLabel}」。</Text>
          <Text strong>平台只审计是统一执行上限：该策略及准入保护产生的阻断/确认原始判定只记录，不实际中断。</Text>
          <Text type="secondary">待平台切换为强制阻断模式且策略为严格模式时，普通强处置动作才会真正生效。</Text>
        </Space>
      )
    }
    return (
      <Space direction="vertical" size={6}>
        <Text style={{ color: 'var(--status-danger)' }}>
          该策略的处置动作为「{actionLabel}」，且平台处于强制阻断模式：
        </Text>
        <Text style={{ color: 'var(--status-danger)' }}>
          {pendingValues.default_action === 'block'
            ? '保存后，命中该策略且生效模式为严格的 MCP 工具调用将被直接拒绝。'
            : '保存后，命中该策略且生效模式为严格的 MCP 工具调用会先被拒绝并生成待办确认单，需管理员处理。'}
        </Text>
        <Text type="secondary">请确认作用域、服务与工具模式不会误伤正常业务。</Text>
      </Space>
    )
  }

  const columns = [
    {
      title: '作用域',
      key: 'scope',
      width: 220,
      render: (_: unknown, record: McpPolicy) => {
        const shadow = shadowByBlockId.get(record.id)
        const winner = shadow ? policyById[shadow.winning_allow_id] : undefined
        return (
          <Space size={4} wrap>
            <Tag color={SCOPE_TYPE_COLORS[record.scope_type] || 'default'}>
              {SCOPE_TYPE_LABELS[record.scope_type] || '自定义作用域'}
            </Tag>
            {record.scope_ref
              ? <Text style={{ fontSize: 12, fontFamily: 'monospace' }}>{record.scope_ref}</Text>
              : <Text style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>（该档位通配）</Text>}
            {shadow ? (
              <Tooltip title={shadow.reason || '该阻断策略被更宽松/更高优先级的放行策略遮蔽，实际不会生效。'}>
                <Tag color="red">
                  被{winner ? `「${SCOPE_TYPE_LABELS[winner.scope_type] || winner.scope_type}」放行` : '更宽松放行'}遮蔽
                </Tag>
              </Tooltip>
            ) : null}
          </Space>
        )
      },
    },
    {
      title: '解析序',
      key: 'resolve_rank',
      width: 90,
      render: (_: unknown, record: McpPolicy) => (
        <Tooltip title="解析优先级：会话 > API Key > 智能体类型 > 成员 > 部门 > 项目 > 租户全局；同档位比优先级数值（大者先）。">
          <Tag color={SCOPE_TYPE_COLORS[record.scope_type] || 'default'}>第 {SCOPE_RANK[record.scope_type] || 0} 档</Tag>
        </Tooltip>
      ),
    },
    {
      title: '服务',
      dataIndex: 'server_id',
      key: 'server_id',
      width: 140,
      render: (v: string) => (
        v
          ? <Text style={{ fontSize: 12 }}>{serverNameById[v] || '未知服务'}</Text>
          : <Tag color="default">全部服务</Tag>
      ),
    },
    {
      title: '工具模式',
      dataIndex: 'tool_pattern',
      key: 'tool_pattern',
      width: 150,
      render: (v: string, record: McpPolicy) => {
        const conds = (record as McpPolicyWithConditions).arg_conditions || []
        return (
          <Space size={4} wrap>
            {v
              ? <Text style={{ fontSize: 12, fontFamily: 'monospace' }}>{v}</Text>
              : <Tag color="default">全部工具</Tag>}
            {conds.length > 0 ? (
              <Tooltip title={conds.map((c) => `${c.path} ${c.op}${c.value === undefined ? '' : ` ${JSON.stringify(c.value)}`}`).join('；')}>
                <Tag color="purple">参数条件 {conds.length}</Tag>
              </Tooltip>
            ) : null}
          </Space>
        )
      },
    },
    {
      title: '生效模式',
      dataIndex: 'mode',
      key: 'mode',
      width: 100,
      render: (v: string) => <Tag color={MODE_COLORS[v] || 'default'}>{MODE_LABELS[v] || '自定义模式'}</Tag>,
    },
    {
      title: '配置动作',
      dataIndex: 'default_action',
      key: 'default_action',
      width: 100,
      render: (v: string) => <Tag color={ACTION_COLORS[v] || 'default'}>{ACTION_LABELS[v] || '自定义动作'}</Tag>,
    },
    {
      title: '实际动作',
      key: 'effective_action',
      width: 120,
      render: (_: unknown, record: McpPolicy) => {
        // 与网关一致：观察/审计模式下的阻断、人工确认只记录告警，不中断调用。
        const modeCapped = (record.mode === 'observe' || record.mode === 'audit') && ['block', 'confirm'].includes(record.default_action)
        const actual = modeCapped ? '记录/告警放行' : effectiveSecurityAction(record.default_action, securityExecutionMode?.effective_mode)
        return <Tag color={actual === '记录/告警放行' ? 'orange' : ACTION_COLORS[record.default_action] || 'default'}>{actual === record.default_action ? ACTION_LABELS[record.default_action] || '自定义动作' : actual}</Tag>
      },
    },
    {
      title: '优先级',
      dataIndex: 'priority',
      key: 'priority',
      width: 80,
      render: (v: number) => <Text>{v ?? 0}</Text>,
    },
    {
      title: '启用',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 80,
      render: (v: boolean, record: McpPolicy) => (
        <Switch
          size="small"
          checked={v}
          loading={toggleMutation.isPending && toggleMutation.variables?.record.id === record.id}
          onChange={(checked) => toggleMutation.mutate({ record, enabled: checked })}
        />
      ),
    },
    {
      title: '备注',
      dataIndex: 'note',
      key: 'note',
      ellipsis: true,
      render: (v: string) => (v ? <Text style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{v}</Text> : <span style={{ color: 'var(--text-tertiary)' }}>-</span>),
    },
    {
      title: '操作',
      key: 'action',
      width: 150,
      render: (_: unknown, record: McpPolicy) => (
        <Space size={4}>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>编辑</Button>
          <Popconfirm
            title="确认删除？"
            description="删除后命中范围内的调用将回退到默认审计姿态。"
            onConfirm={() => deleteMutation.mutate(record.id)}
            okText="确认"
            cancelText="取消"
          >
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  return (
    <div className="enterprise-page">
      <EnterprisePageHeader
        eyebrow="MCP 安全网关"
        title="MCP 调用策略"
        description="按作用域（租户/项目/成员/API Key/智能体/会话）× 服务 × 工具模式配置 MCP 调用的处置动作；同一调用命中多条时取作用域最具体的一条。"
        meta={
          <Space size={8} wrap>
            <StatusPill tone="blue">六档作用域回退</StatusPill>
            <StatusPill tone="purple">未命中默认审计</StatusPill>
          </Space>
        }
        actions={<Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>新建策略</Button>}
      />

      <SectionPanel title="策略概览" description="未配置任何策略时，全部 MCP 调用按审计姿态放行并留痕。">
        <div className="enterprise-metric-grid">
          <MetricCard label="策略总数" value={policies.length} tone="blue" hint="含已停用策略" />
          <MetricCard label="启用中" value={enabledCount} tone="green" hint="当前参与决策的策略" />
          <MetricCard label="强制处置" value={enforceCount} tone="red" hint="动作为阻断/人工确认的启用策略" />
          <MetricCard label="严格模式" value={strictCount} tone="orange" hint="配置为严格模式的启用策略" />
        </div>
      </SectionPanel>

      <McpProtectionSettings canEdit={canEditProtection} />
      <McpRedlineSettings canEdit={canEditProtection} />

      {shadowWarnings.length > 0 && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 16 }}
          message={<Text style={{ color: 'var(--status-danger)' }}>检测到 {shadowWarnings.length} 条阻断策略被更宽松/更高优先级的放行策略遮蔽</Text>}
          description={
            <Space direction="vertical" size={2}>
              <Text>以下阻断策略因解析优先级更低或作用域更窄，会被放行策略先命中，实际不会生效，形成管控盲区：</Text>
              {shadowWarnings.map((w) => {
                const blocked = policyById[w.shadowed_block_id]
                const winner = policyById[w.winning_allow_id]
                return (
                  <Text key={w.shadowed_block_id} style={{ fontSize: 12 }}>
                    ·「{blocked ? `${SCOPE_TYPE_LABELS[blocked.scope_type] || blocked.scope_type}${blocked.scope_ref ? ` ${blocked.scope_ref}` : ''}` : w.shadowed_block_id}」的阻断
                    被「{winner ? `${SCOPE_TYPE_LABELS[winner.scope_type] || winner.scope_type}${winner.scope_ref ? ` ${winner.scope_ref}` : ''}` : w.winning_allow_id}」的放行遮蔽
                    {w.reason ? `（${w.reason}）` : ''}
                  </Text>
                )
              })}
              <Text type="secondary" style={{ fontSize: 12 }}>建议：提高阻断策略的作用域档位/优先级，或收紧对应放行策略的作用范围。</Text>
            </Space>
          }
        />
      )}

      <SectionPanel title="策略列表" description="按解析优先级排序展示：会话 > API Key > 智能体类型 > 成员 > 部门 > 项目 > 租户全局；同档位比优先级数值（大者先），靠前者先命中。">
        <Table
          columns={columns}
          dataSource={sortedPolicies}
          rowKey="id"
          loading={policiesQuery.isLoading}
          scroll={{ x: 'max-content' }}
          locale={{
            emptyText: (
              <Empty description="暂无 MCP 权限策略。未配置时全部调用按审计姿态放行并留痕；如需默认拒绝，可新建一条租户全局的阻断策略。">
                <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>新建策略</Button>
              </Empty>
            ),
          }}
          pagination={{
            defaultPageSize: 10,
            showSizeChanger: true,
            pageSizeOptions: ['10', '50', '100'],
            showTotal: (total) => `共 ${total} 条`,
          }}
        />
      </SectionPanel>

      {/* 新建/编辑 Modal */}
      <Modal
        title={editingPolicy ? '编辑 MCP 调用策略' : '新建 MCP 调用策略'}
        open={modalOpen}
        onCancel={closeModal}
        footer={null}
        width={560}
      >
        <Form form={form} onFinish={handleSubmit} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="scope_type" label="作用档位" rules={[{ required: true, message: '请选择作用档位' }]}>
            <Select placeholder="请选择作用档位" options={SCOPE_TYPE_OPTIONS} />
          </Form.Item>
          <Form.Item
            name="scope_ref"
            label="作用对象"
            extra={SCOPE_REF_PLACEHOLDERS[watchScopeType as string] || '留空 = 该档位通配'}
          >
            {watchScopeType === 'project' ? (
              <Select allowClear showSearch optionFilterProp="label" placeholder="选择项目；留空 = 匹配任意项目" options={projectOptions} loading={projectsQuery.isLoading} />
            ) : watchScopeType === 'department' ? (
              <Select allowClear showSearch optionFilterProp="label" placeholder="选择部门；留空 = 匹配任意部门" options={departmentOptions} loading={teamsQuery.isLoading} />
            ) : watchScopeType === 'user' ? (
              <Select allowClear showSearch optionFilterProp="label" placeholder="选择成员；留空 = 匹配任意成员" options={userOptions} loading={usersQuery.isLoading} />
            ) : watchScopeType === 'key' ? (
              <Select allowClear showSearch optionFilterProp="label" placeholder="选择 API Key 前缀；留空 = 匹配任意密钥" options={keyOptions} loading={keysQuery.isLoading} />
            ) : watchScopeType === 'agent' ? (
              <Select allowClear showSearch optionFilterProp="label" placeholder="选择智能体类型；留空 = 匹配任意智能体" options={agentOptions} />
            ) : watchScopeType === 'tenant' ? (
              <Input disabled placeholder="租户全局策略作用于本租户全部 MCP 调用，无需填写" />
            ) : (
              <Input placeholder={SCOPE_REF_PLACEHOLDERS[watchScopeType as string] || '留空 = 该档位通配'} />
            )}
          </Form.Item>
          <Form.Item name="server_id" label="MCP 服务">
            <Select
              showSearch
              optionFilterProp="label"
              options={[{ value: '', label: '全部服务' }, ...servers.map((s) => ({ value: s.id, label: s.name }))]}
            />
          </Form.Item>
          <Form.Item
            name="tool_pattern"
            label="工具模式"
            extra={
              watchServerId
                ? '留空 = 全部工具；可从选中服务的工具名联想，或填「前缀.*」做前缀匹配（如 file.*）。'
                : '留空 = 全部工具；选中具体服务后可从其工具清单联想。填精确工具名或「前缀.*」。'
            }
            validateStatus={patternMatchesAnyTool ? undefined : 'warning'}
            help={patternMatchesAnyTool ? undefined : '当前所选服务的工具清单中没有与该模式匹配的工具，请确认拼写或先同步该服务能力。'}
          >
            <AutoComplete
              options={toolPatternOptions}
              placeholder="留空 = 全部工具"
              filterOption={(input, option) => String(option?.value || '').toLowerCase().includes(input.toLowerCase())}
              allowClear
            />
          </Form.Item>
          <Form.Item
            name="mode"
            label="生效模式"
            rules={[{ required: true, message: '请选择生效模式' }]}
            extra={MODE_DESCRIPTIONS[watchMode as string] || ''}
          >
            <Select options={MODE_OPTIONS} />
          </Form.Item>
          <Form.Item
            name="default_action"
            label="处置动作"
            rules={[{ required: true, message: '请选择处置动作' }]}
            extra={ACTION_DESCRIPTIONS[watchAction as string] || ''}
          >
            <Select options={ACTION_OPTIONS} />
          </Form.Item>
          <McpArgConditionsEditor />
          {modeActionConflict ? (
            <Alert type="warning" showIcon style={{ marginBottom: 16 }} message="模式与处置动作组合需确认" description={modeActionConflict} />
          ) : null}
          <Form.Item name="priority" label="优先级" extra="同档位命中多条时数值大者优先。">
            <InputNumber min={0} max={1000} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked">
            <Switch checkedChildren="启用" unCheckedChildren="停用" />
          </Form.Item>
          <Form.Item name="note" label="备注">
            <Input.TextArea placeholder="选填，说明该策略的业务用途" rows={2} />
          </Form.Item>

          {/* 保存前预演：simulate 返回同作用域下的胜出策略与全部候选 */}
          {simResult ? (
            <Alert
              type={simResult.winning && simResult.winning.default_action !== 'block' && (form.getFieldValue('default_action') === 'block' || form.getFieldValue('default_action') === 'confirm')
                ? 'warning'
                : 'info'}
              showIcon
              style={{ marginBottom: 16 }}
              message="解析预演结果"
              description={
                <Space direction="vertical" size={2}>
                  {simResult.winning ? (
                    <Text style={{ fontSize: 12 }}>
                      同作用域下将由「{SCOPE_TYPE_LABELS[simResult.winning.scope_type] || simResult.winning.scope_type}
                      {simResult.winning.scope_ref ? ` ${simResult.winning.scope_ref}` : ''}」的
                      <Tag color={ACTION_COLORS[simResult.winning.default_action] || 'default'} style={{ marginInline: 4 }}>{ACTION_LABELS[simResult.winning.default_action] || simResult.winning.default_action}</Tag>
                      策略生效（共 {simResult.candidates?.length ?? 0} 条候选）。
                    </Text>
                  ) : (
                    <Text style={{ fontSize: 12 }}>同作用域下没有任何策略命中，将回退到默认审计姿态放行并留痕。</Text>
                  )}
                  <Text type="secondary" style={{ fontSize: 12 }}>若这里的胜出者不是你正在配置的策略，说明它会被更高优先级的策略遮蔽。</Text>
                </Space>
              }
            />
          ) : null}

          <Form.Item style={{ marginBottom: 0 }}>
            <Space style={{ width: '100%', justifyContent: 'space-between' }}>
              <Button icon={<ExperimentOutlined />} onClick={handleSimulate} loading={simulateMutation.isPending}>预演生效策略</Button>
              <Space>
                <Button onClick={closeModal}>取消</Button>
                <Button type="primary" htmlType="submit" loading={saveMutation.isPending}>提交</Button>
              </Space>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* 阻断/人工确认二次确认 Modal */}
      <Modal
        open={!!pendingValues}
        title={securityAuditOnly ? '确认保存强处置策略（当前只审计）' : '确认启用强处置动作'}
        okText={securityAuditOnly ? '确认保存' : '确认启用'}
        cancelText="再想想"
        okButtonProps={securityAuditOnly ? {} : { danger: true }}
        confirmLoading={saveMutation.isPending}
        onOk={() => { if (pendingValues) doSave(pendingValues) }}
        onCancel={() => setPendingValues(null)}
      >
        {confirmModalBody()}
      </Modal>
    </div>
  )
}

export default McpPolicies

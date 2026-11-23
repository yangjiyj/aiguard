import GatewayAccess from '../components/GatewayAccess'
import {useGatewayAccess} from '../hooks/useGatewayAccess'
import { useState } from 'react'
import {
  Table,
  Button,
  Space,
  Modal,
  Form,
  Input,
  Select,
  Tag,
  Typography,
  message,
  Popconfirm,
  Tooltip,
  Alert,
  Drawer,
  Empty,
  List,
  Divider,
} from 'antd'
import {
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
  SyncOutlined,
  UnorderedListOutlined,
  ApiOutlined,
  SearchOutlined,
} from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api, {
  mcpServerApi,
  mcpToolApi,
  type McpServer,
  type McpServerCreate,
  type McpSyncResult,
  type McpTool,
  type McpAdmissionStatus,
  type McpShadowToolWarning,
} from '../services/api'
import { EnterprisePageHeader, MetricCard, SectionPanel, StatusPill } from '../components/EnterpriseUI'
import ConfirmSwitch from '../components/protection/ConfirmSwitch'
import EgressOverrideFields from '../components/protection/EgressOverrideFields'
import { normalizeEgressOverrides } from '../utils/egressOverrides'
import { useAccess } from '../hooks/useAccess'
import { normalizeSecurityExecutionMode } from '../services/securityExecutionMode'
import {
  MCP_TRANSPORT_OPTIONS,
  MCP_TRANSPORT_LABELS,
  MCP_AUTH_LOCATION_OPTIONS,
  mcpTemplateOptionsFor,
  templateFromOptionValue,
  templateToOptionValue,
  MCP_UPSTREAM_DEFAULTS,
  MCP_VENDOR_PRESETS,
  applyVendorPreset,
  capabilitiesFromForm,
  formValuesFromServer,
  validateUpstreamForm,
  serverUrlForSubmit,
  serverUrlForDisplay,
  urlHasInlineSecret,
  type McpUpstreamFormValues,
} from './mcp/upstreamConfig'
import {
  getMcpRiskTagLabel,
  getMcpRiskTagDescription,
  getMcpTrustLevelDescription,
  getMcpServerStatusDescription,
  getMcpTestConnErrorLabel,
  getMcpTestConnErrorDetail,
  getMcpPoisonFlagLabel,
  getMcpPoisonFlagDescription,
  MCP_RISK_TAG_COLORS,
  MCP_RISK_TAG_ORDER,
  MCP_HIGH_RISK_TAGS,
} from '../utils/risk'

// 测试连接结果结构（后端 POST /admin/v1/mcp-servers/{id}/test-connection 返回）
interface McpTestConnResult {
  ok: boolean
  error_kind?: string
  message?: string
  server_info?: Record<string, unknown>
}

interface AdmissionMutationInput {
  assetType: 'server' | 'tool'
  id: string
  status: Exclude<McpAdmissionStatus, 'unverified'>
  expectedHash: string
  expectedRouteHash?: string
}

const { Text } = Typography

// 传输协议中文字典（UI 零裸英文铁律：所有枚举 {value,label} 中文化）
const TRANSPORT_OPTIONS = MCP_TRANSPORT_OPTIONS
const TRANSPORT_COLORS: Record<string, string> = {
  auto: 'purple',
  streamable_http: 'blue',
  sse: 'cyan',
}

const TRUST_LEVEL_OPTIONS = [
  { value: 'low', label: '低信任' },
  { value: 'medium', label: '中信任' },
  { value: 'high', label: '高信任' },
]
// 兜底字典：历史数据可能存在其它取值，渲染时也不许露英文
const TRUST_LEVEL_FALLBACK_LABELS: Record<string, string> = {
  low: '低信任',
  medium: '中信任',
  high: '高信任',
  trusted: '可信',
  verified: '已验证',
  untrusted: '不可信',
}
const TRUST_LEVEL_COLORS: Record<string, string> = {
  low: 'orange',
  medium: 'blue',
  high: 'green',
  trusted: 'green',
  verified: 'green',
  untrusted: 'red',
}

const STATUS_OPTIONS = [
  { value: 'active', label: '启用' },
  { value: 'disabled', label: '停用' },
]
const STATUS_FALLBACK_LABELS: Record<string, string> = {
  active: '启用',
  disabled: '停用',
  inactive: '停用',
}
const STATUS_COLORS: Record<string, string> = {
  active: 'green',
  disabled: 'default',
  inactive: 'default',
}

const ADMISSION_LABELS: Record<McpAdmissionStatus, string> = {
  unverified: '待准入 · 批准前调用阻断',
  approved: '已准入',
  quarantined: '已隔离 · 调用硬阻断',
  revoked: '已撤销 · 调用硬阻断',
}
const ADMISSION_COLORS: Record<McpAdmissionStatus, string> = {
  unverified: 'warning',
  approved: 'success',
  quarantined: 'error',
  revoked: 'default',
}
const ADMISSION_REASON_LABELS: Record<string, string> = {
  description_poison: '描述投毒已触发自动隔离',
  shadow_schema_diverges: '同名影子工具结构不一致，已触发自动隔离',
  rug_pull_schema_changed: '工具定义指纹漂移，已触发自动隔离',
  rug_pull_manifest_changed: '能力清单指纹漂移，已触发自动隔离',
  route_binding_changed: '服务地址、鉴权或传输绑定发生变化，已触发自动隔离',
  route_binding_mismatch: '当前路由与批准快照不一致',
  schema_binding_mismatch: '当前工具定义与批准快照不一致',
  manual_admin_quarantine: '管理员手工隔离',
  manual_admin_revocation: '管理员撤销准入',
}
const HASH_PATTERN = /^[a-f0-9]{64}$/

const admissionStatus = (value?: string): McpAdmissionStatus => {
  if (value === 'approved' || value === 'quarantined' || value === 'revoked') return value
  return 'unverified'
}

const admissionReasonLabel = (reason?: string) => {
  if (!reason) return ''
  return ADMISSION_REASON_LABELS[reason] || '供应链准入状态已变化'
}

const formatTime = (value?: string | null) => {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '-'
  return date.toLocaleString('zh-CN', { hour12: false })
}

// gateway_public_base_url 沿用密钥管理页的 OpenAI Base URL 契约，通常以
// /v1 结尾。MCP 是同一 gateway-core 上的并列入口，因此先还原网关根地址，
// 再拼 /mcp/{serverID}；未配置时使用管理台当前同源 HTTPS 入口。
const buildMcpGatewayEndpoint = (serverID: string, configuredBase?: string, currentOrigin?: string) => {
  const browserOrigin = currentOrigin || (typeof window !== 'undefined' ? window.location.origin : '')
  const fallbackRoot = browserOrigin.replace(/\/+$/, '')
  const rawBase = String(configuredBase || '').trim() || fallbackRoot
  const encodedServerID = encodeURIComponent(serverID)

  if (!rawBase) return `/mcp/${encodedServerID}`

  try {
    const parsed = new URL(rawBase, fallbackRoot || 'http://localhost')
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('unsupported gateway URL protocol')
    parsed.search = ''
    parsed.hash = ''
    parsed.pathname = parsed.pathname.replace(/\/+$/, '').replace(/\/v1$/, '') || '/'
    const root = parsed.toString().replace(/\/+$/, '')
    return `${root}/mcp/${encodedServerID}`
  } catch {
    return `${fallbackRoot}/mcp/${encodedServerID}`
  }
}

// 响应解包三连：control-plane 返回结构不统一（{items:[]} / {data:[]} / 裸数组）
const unpackList = (raw: any, extraKey?: string): any[] => {
  if (Array.isArray(raw?.items)) return raw.items
  if (Array.isArray(raw?.data)) return raw.data
  if (extraKey && Array.isArray(raw?.[extraKey])) return raw[extraKey]
  return Array.isArray(raw) ? raw : []
}

// 值模板下拉：option value 用内部代号（避免读屏软件读出 `{secret}`，R1）；与 Form.Item 之间读写的仍是后端模板值。
// 自定义/历史模板（如 "Token {secret}"）以中文标签的不透明代号选项承载，选中后原样还原。
function McpTemplateSelect({ value, onChange }: { value?: string; onChange?: (next: string) => void }) {
  return (
    <Select
      options={mcpTemplateOptionsFor(value)}
      value={templateToOptionValue(value)}
      placeholder="按鉴权位置使用默认格式"
      onChange={(code: string) => onChange?.(templateFromOptionValue(code, value))}
    />
  )
}

function McpServers() {
  const queryClient = useQueryClient()
  const canEnableEgress = useAccess().isPlatformLevel
  const [modalOpen, setModalOpen] = useState(false)
  const [editingServer, setEditingServer] = useState<McpServer | null>(null)
  const [toolsServer, setToolsServer] = useState<McpServer | null>(null)
  const [syncingId, setSyncingId] = useState<string>('')
  const [syncResult, setSyncResult] = useState<{ server: McpServer; result: McpSyncResult } | null>(null)
  const [testingId, setTestingId] = useState<string>('')
  const [testResult, setTestResult] = useState<{ server: McpServer; result: McpTestConnResult } | null>(null)
  // 服务名搜索关键字
  const [keyword, setKeyword] = useState('')
  const [form] = Form.useForm()
  const watchTrustLevel = Form.useWatch('trust_level', form)
  const watchStatus = Form.useWatch('status', form)
  const watchAuthLocation = Form.useWatch('auth_location', form) as 'header' | 'query' | 'path' | undefined
  const watchServerUrl = Form.useWatch('server_url', form) as string | undefined

  const serversQuery = useQuery({
    queryKey: ['mcpServers'],
    queryFn: () => mcpServerApi.list(),
  })

  const settingsQuery = useQuery({
    queryKey: ['system-settings', 'runtime-mode'],
    queryFn: () => api.get('/system/settings').then((r) => r.data),
  })

  // 页面加载即检查同名跨服务工具；异构定义由同步事务自动隔离，同构重复保留人工告警。
  // 端点短暂不可用不影响资产列表，但不把缺失结果解释为"安全"。
  const shadowQuery = useQuery({
    queryKey: ['mcpToolShadowCheck'],
    queryFn: () => mcpToolApi.shadowCheck().then((r) => r.data),
    retry: false,
  })

  const toolsQuery = useQuery({
    queryKey: ['mcpServerTools', toolsServer?.id],
    queryFn: () => mcpServerApi.listTools(toolsServer!.id),
    enabled: !!toolsServer?.id,
  })

  const createMutation = useMutation({
    mutationFn: (data: McpServerCreate) => mcpServerApi.create(data),
    onSuccess: () => {
      message.success('MCP 服务注册成功，建议立即执行一次「同步能力」')
      queryClient.invalidateQueries({ queryKey: ['mcpServers'] })
      setModalOpen(false)
      form.resetFields()
    },
    onError: () => message.error('注册失败'),
  })

  const updateMutation = useMutation({
    mutationFn: (data: { id: string } & McpServerCreate) => {
      const { id, ...rest } = data
      return mcpServerApi.update(id, rest)
    },
    onSuccess: () => {
      message.success('更新成功')
      queryClient.invalidateQueries({ queryKey: ['mcpServers'] })
      setModalOpen(false)
      setEditingServer(null)
      form.resetFields()
    },
    onError: () => message.error('更新失败'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => mcpServerApi.delete(id),
    onSuccess: () => {
      message.success('删除成功')
      queryClient.invalidateQueries({ queryKey: ['mcpServers'] })
    },
    onError: () => message.error('删除失败'),
  })

  const admissionMutation = useMutation({
    mutationFn: (input: AdmissionMutationInput) => {
      const reason = input.status === 'approved'
        ? 'manual_admin_approval'
        : input.status === 'quarantined'
          ? 'manual_admin_quarantine'
          : 'manual_admin_revocation'
      const payload = {
        status: input.status,
        expected_hash: input.expectedHash,
        ...(input.assetType === 'server' ? { expected_route_hash: input.expectedRouteHash } : {}),
        reason,
      }
      return input.assetType === 'server'
        ? mcpServerApi.setAdmission(input.id, payload)
        : mcpToolApi.setAdmission(input.id, payload)
    },
    onSuccess: (_response, input) => {
      message.success(input.status === 'approved' ? '已按当前快照批准准入' : input.status === 'quarantined' ? '已隔离，调用将被硬阻断' : '已撤销准入，调用将被硬阻断')
      queryClient.invalidateQueries({ queryKey: ['mcpServers'] })
      queryClient.invalidateQueries({ queryKey: ['mcpServerTools'] })
      queryClient.invalidateQueries({ queryKey: ['mcpToolShadowCheck'] })
    },
    onError: (error: any) => {
      if (error?.response?.status === 409 && error?.response?.data?.error?.code === 'snapshot_changed') {
        message.warning('快照已变化，请刷新并重新复核后再操作')
        queryClient.invalidateQueries({ queryKey: ['mcpServers'] })
        queryClient.invalidateQueries({ queryKey: ['mcpServerTools'] })
        return
      }
      message.error('准入状态更新失败')
    },
  })

  const syncMutation = useMutation({
    mutationFn: (server: McpServer) => mcpServerApi.sync(server.id),
    onMutate: (server) => setSyncingId(server.id),
    onSuccess: (res, server) => {
      const result = (res.data || {}) as McpSyncResult
      setSyncResult({ server, result })
      queryClient.invalidateQueries({ queryKey: ['mcpServers'] })
      queryClient.invalidateQueries({ queryKey: ['mcpServerTools', server.id] })
    },
    onError: (error: any) => {
      const detail = error?.response?.data?.error?.message
      message.error(detail ? `同步能力失败：${detail}` : '同步能力失败，请确认服务地址可达、鉴权令牌有效', 8)
    },
    onSettled: () => setSyncingId(''),
  })

  // 测试连接：只探测可达性与鉴权，不改任何数据；失败按 error_kind 结构化归因（DNS/超时/401/TLS）。
  const testConnMutation = useMutation({
    mutationFn: (server: McpServer) => mcpServerApi.testConnection(server.id),
    onMutate: (server) => setTestingId(server.id),
    onSuccess: (res, server) => {
      const result = (res.data || {}) as McpTestConnResult
      setTestResult({ server, result })
    },
    onError: (_err, server) => {
      // 网络层异常（后端未返回结构化 error_kind 时）也走同一弹窗，归为未知连接失败。
      setTestResult({ server, result: { ok: false, error_kind: 'unknown' } })
    },
    onSettled: () => setTestingId(''),
  })

  const handleCreate = () => {
    setEditingServer(null)
    form.resetFields()
    // 新建服务默认「自动识别」传输方式；存量服务编辑时保持其原值。
    form.setFieldsValue({ ...MCP_UPSTREAM_DEFAULTS, trust_level: 'low', status: 'active', allow_private_egress: false, egress_overrides: {} })
    setModalOpen(true)
  }

  const handleEdit = (record: McpServer) => {
    setEditingServer(record)
    form.setFieldsValue({
      name: record.name,
      owner: record.owner,
      ...formValuesFromServer(record.transport, record.capabilities),
      server_url: serverUrlForDisplay(record.server_url, formValuesFromServer(record.transport, record.capabilities).auth_location),
      trust_level: record.trust_level || 'low',
      status: record.status || 'active',
      allow_private_egress: !!record.allow_private_egress,
      egress_overrides: record.egress_overrides ?? {},
      auth_token: '',
    })
    setModalOpen(true)
  }

  // 厂商预设：只是预填表单（传输方式 / 鉴权位置 / 参数名 / 值模板），不写死任何后端逻辑。
  const handlePreset = (key: string) => {
    const preset = MCP_VENDOR_PRESETS.find((p) => p.key === key)
    if (!preset) return
    form.setFieldsValue(applyVendorPreset(preset))
    if (!form.getFieldValue('server_url')) form.setFieldsValue({ server_url: '' })
    message.info(`已按「${preset.label}」预填：${preset.hint}`)
  }

  const handleSubmit = (values: McpServerCreate & McpUpstreamFormValues) => {
    const upstream: McpUpstreamFormValues = {
      transport: values.transport,
      auth_location: values.auth_location || 'header',
      auth_name: values.auth_name || '',
      auth_template: values.auth_template || '',
      extra_headers: values.extra_headers || [],
    }
    const problem = validateUpstreamForm(upstream, values.server_url || '')
    if (problem) {
      message.error(problem)
      return
    }
    const { auth_location, auth_name, auth_template, extra_headers, ...rest } = values as McpServerCreate & McpUpstreamFormValues
    void auth_location; void auth_name; void auth_template; void extra_headers
    const payload: McpServerCreate = {
      ...rest,
      // 路径密钥：界面上的 {密钥} 在提交前转换成后端的 {secret}
      server_url: serverUrlForSubmit(values.server_url || '', upstream.auth_location),
      // 只合并上游连接相关键；协议版本、探测结果等其余 capabilities 原样保留。
      capabilities: capabilitiesFromForm(upstream, editingServer?.capabilities),
      allow_private_egress: Boolean(values.allow_private_egress),
      egress_overrides: normalizeEgressOverrides(values.egress_overrides, true),
    }
    if (editingServer) {
      updateMutation.mutate({ ...payload, id: editingServer.id })
    } else {
      createMutation.mutate(payload)
    }
  }

  const servers: McpServer[] = unpackList(serversQuery.data?.data, 'servers')
  const tools: McpTool[] = unpackList(toolsQuery.data?.data)

  // 服务名搜索：大小写不敏感，按名称/地址/负责人任一命中
  const kw = keyword.trim().toLowerCase()
  const filteredServers = kw
    ? servers.filter((s) =>
        [s.name, s.server_url, s.owner].filter(Boolean).some((v) => String(v).toLowerCase().includes(kw)))
    : servers

  // 工具清单抽屉：高危工具（破坏性/凭证访问）计数
  const highRiskToolCount = tools.filter((t) => (t.risk_tags || []).some((tag) => MCP_HIGH_RISK_TAGS.has(tag))).length
  // 工具清单抽屉：疑似描述投毒工具计数（poison_flags 非空）
  const poisonToolCount = tools.filter((t) => (t.poison_flags || []).length > 0).length

  // 同名跨服务工具：异构定义已经由同步事务隔离；同构重复仍需管理员确认是否符合资产规划。
  const shadowWarnings: McpShadowToolWarning[] = Array.isArray(shadowQuery.data?.warnings)
    ? shadowQuery.data!.warnings
    : []
  const divergingShadowCount = shadowWarnings.filter((w) => w.schema_diverges).length

  const totalToolCount = servers.reduce((sum, s) => sum + (s.tool_count || 0), 0)
  const pendingSyncCount = servers.filter((s) => !s.last_synced_at).length
  const pendingAdmissionCount = servers.filter((s) => admissionStatus(s.admission_status) === 'unverified').length
  const hardBlockedServerCount = servers.filter((s) => ['quarantined', 'revoked'].includes(admissionStatus(s.admission_status))).length
  const manifestChangedServers = servers.filter((s) => !!s.last_manifest_changed_at && admissionStatus(s.admission_status) !== 'approved')

  const securityExecutionMode = normalizeSecurityExecutionMode(settingsQuery.data)
  const gatewayAccess = useGatewayAccess(settingsQuery.data)
  const gatewayPublicBase = gatewayAccess.url

  // 同步结果弹窗的新增/变更/移除计数：优先用后端计数字段，缺失时按工具清单回退推算
  const syncRemovedCount = (result: McpSyncResult) => {
    if (typeof result.removed_count === 'number') return result.removed_count
    if (Array.isArray(result.tools)) return result.tools.filter((t) => t.removed).length
    return undefined
  }

  const renderAdmission = (value?: string, reason?: string) => {
    const status = admissionStatus(value)
    const reasonLabel = admissionReasonLabel(reason)
    return (
      <Space direction="vertical" size={2}>
        <Tag color={ADMISSION_COLORS[status]}>{ADMISSION_LABELS[status]}</Tag>
        {reasonLabel && <Text type="secondary" style={{ fontSize: 11 }}>{reasonLabel}</Text>}
      </Space>
    )
  }

  const admissionActions = (assetType: 'server' | 'tool', asset: McpServer | McpTool) => {
    const status = admissionStatus(asset.admission_status)
    const expectedHash = assetType === 'server'
      ? (asset as McpServer).manifest_hash || ''
      : (asset as McpTool).schema_hash || ''
    const expectedRouteHash = assetType === 'server' ? (asset as McpServer).observed_route_hash || '' : undefined
    const snapshotReady = HASH_PATTERN.test(expectedHash) && (assetType === 'tool' || HASH_PATTERN.test(expectedRouteHash || ''))
    const noun = assetType === 'server' ? '服务' : '工具'
    const mutate = (nextStatus: Exclude<McpAdmissionStatus, 'unverified'>) => {
      if (!snapshotReady) {
        message.warning(assetType === 'server' ? '请先同步能力并取得完整路由快照' : '工具定义快照不完整，请重新同步能力')
        return
      }
      admissionMutation.mutate({
        assetType,
        id: asset.id,
        status: nextStatus,
        expectedHash,
        expectedRouteHash,
      })
    }
    return (
      <Space size={4} wrap>
        {status !== 'approved' && (
          <Popconfirm
            title={`批准该${noun}当前快照？`}
            description="批准只绑定当前观察到的指纹；地址、鉴权、传输或工具定义再次变化时会自动隔离。"
            onConfirm={() => mutate('approved')}
            okText="确认批准"
            cancelText="取消"
            disabled={!snapshotReady}
          >
            <Button type="link" size="small" disabled={!snapshotReady}>批准{noun}准入</Button>
          </Popconfirm>
        )}
        {status !== 'quarantined' && status !== 'revoked' && (
          <Popconfirm title={`确认隔离该${noun}？`} onConfirm={() => mutate('quarantined')} okText="确认隔离" cancelText="取消">
            <Button type="link" size="small" danger disabled={!snapshotReady}>隔离{noun}</Button>
          </Popconfirm>
        )}
        {status !== 'revoked' && (
          <Popconfirm title={`确认撤销该${noun}准入？`} onConfirm={() => mutate('revoked')} okText="确认撤销" cancelText="取消">
            <Button type="link" size="small" danger disabled={!snapshotReady}>撤销{noun}</Button>
          </Popconfirm>
        )}
      </Space>
    )
  }

  // 同步结果的「具体变更工具」：后端在 tools[] 上按需带 added/updated/removed 标记时用于逐条列出，
  // 便于 rug-pull 复核（谁被新增、谁的能力/schema 被改、谁被下线）。无标记则回退展示当前全量工具。
  const changedTools = (result: McpSyncResult) => {
    const list = (result.tools || []) as Array<McpTool & { added?: boolean; updated?: boolean }>
    const changed = list.filter((t) => t.added || t.updated || t.removed)
    return changed.length > 0 ? changed : list
  }
  const changeTag = (t: McpTool & { added?: boolean; updated?: boolean }) => {
    if (t.added) return <Tag color="green">新增</Tag>
    if (t.removed) return <Tag color="default">已下线</Tag>
    if (t.updated) return <Tag color="orange">能力/结构变更</Tag>
    return null
  }

  const columns = [
    {
      title: '服务名称',
      dataIndex: 'name',
      key: 'name',
      width: 180,
      render: (v: string) => <Text strong style={{ color: 'var(--text-primary)' }}>{v}</Text>,
    },
    {
      title: '传输协议',
      dataIndex: 'transport',
      key: 'transport',
      width: 190,
      render: (v: string, record: McpServer) => {
        const value = v || 'streamable_http'
        const label = MCP_TRANSPORT_LABELS[value] || 'Streamable HTTP'
        const detected = record.upstream?.detected_transport
        return (
          <Space size={4} wrap>
            <Tag color={TRANSPORT_COLORS[value] || 'default'}>{label}</Tag>
            {value === 'auto' && (
              detected
                ? <Tooltip title="同步时探测到的实际传输方式"><Tag color="success">已识别：{MCP_TRANSPORT_LABELS[detected] || detected}</Tag></Tooltip>
                : <Tooltip title="尚未探测，执行一次「同步能力」或「测试连接」后记录"><Tag>待探测</Tag></Tooltip>
            )}
          </Space>
        )
      },
    },
    {
      title: '上游地址',
      dataIndex: 'server_url',
      key: 'server_url',
      ellipsis: true,
      render: (v: string, record: McpServer) => {
        // 路径密钥：库里只存占位形式，界面统一显示成 {密钥}
        const shown = serverUrlForDisplay(v, record.upstream?.auth_location === 'path' ? 'path' : 'header')
        return shown ? (
          <Tooltip title={shown} placement="topLeft">
            <Text style={{ fontSize: 12, fontFamily: 'monospace' }}>{shown}</Text>
          </Tooltip>
        ) : <span style={{ color: 'var(--text-tertiary)' }}>-</span>
      },
    },
    {
      title: '用户调用地址',
      key: 'gateway_endpoint',
      width: 360,
      render: (_: unknown, record: McpServer) => {
        const endpoint = buildMcpGatewayEndpoint(record.id, gatewayPublicBase)
        return (
          <Tooltip title="用户在 Cursor、Claude Code 等客户端中填写此地址，并使用包含 MCP 权限的网关密钥鉴权。上游令牌不会下发给用户。">
            <Text
              code
              copyable={{ text: endpoint, tooltips: ['复制调用地址', '已复制'] }}
              style={{ fontSize: 12, wordBreak: 'break-all' }}
            >
              {endpoint}
            </Text>
          </Tooltip>
        )
      },
    },
    {
      title: '工具数',
      dataIndex: 'tool_count',
      key: 'tool_count',
      width: 80,
      render: (v: number | undefined, record: McpServer) => (
        record.last_synced_at ? <Text>{v ?? 0}</Text> : <Text style={{ color: 'var(--text-tertiary)' }}>未同步</Text>
      ),
    },
    {
      title: '信任级别',
      dataIndex: 'trust_level',
      key: 'trust_level',
      width: 100,
      render: (v: string) => {
        const value = v || 'low'
        return (
          <Tooltip title={getMcpTrustLevelDescription(value)}>
            <Tag color={TRUST_LEVEL_COLORS[value] || 'default'}>{TRUST_LEVEL_FALLBACK_LABELS[value] || '低信任'}</Tag>
          </Tooltip>
        )
      },
    },
    {
      title: '负责人',
      dataIndex: 'owner',
      key: 'owner',
      width: 120,
      render: (v: string) => (v ? <Text style={{ fontSize: 12 }}>{v}</Text> : <span style={{ color: 'var(--text-tertiary)' }}>-</span>),
    },
    {
      title: '内网放行',
      dataIndex: 'allow_private_egress',
      key: 'allow_private_egress',
      width: 100,
      render: (v: boolean) => (
        v
          ? <Tooltip title="已显式授权网关转发到内网地址（仅限企业自建 MCP 服务）"><Tag color="orange">已放行</Tag></Tooltip>
          : <Tag color="default">默认封禁</Tag>
      ),
    },
    {
      title: '供应链准入',
      key: 'admission_state',
      width: 300,
      render: (_: unknown, record: McpServer) => {
        if (!record.manifest_hash) return <Tag color="default">未同步</Tag>
        return (
          <Space direction="vertical" size={4}>
            {renderAdmission(record.admission_status, record.quarantine_reason)}
            {admissionActions('server', record)}
          </Space>
        )
      },
    },
    {
      title: '服务状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (v: string) => {
        const value = v || 'active'
        return <Tag color={STATUS_COLORS[value] || 'default'}>{STATUS_FALLBACK_LABELS[value] || '启用'}</Tag>
      },
    },
    {
      title: '最近同步',
      dataIndex: 'last_synced_at',
      key: 'last_synced_at',
      width: 160,
      render: (v: string | null) => <Text style={{ fontSize: 12 }}>{formatTime(v)}</Text>,
    },
    {
      title: '操作',
      key: 'action',
      width: 360,
      render: (_: unknown, record: McpServer) => (
        <Space size={4} wrap>
          <Button
            type="link"
            size="small"
            icon={<ApiOutlined />}
            loading={testingId === record.id}
            onClick={() => testConnMutation.mutate(record)}
          >
            测试连接
          </Button>
          <Button
            type="link"
            size="small"
            icon={<SyncOutlined />}
            loading={syncingId === record.id}
            onClick={() => syncMutation.mutate(record)}
          >
            同步能力
          </Button>
          <Button
            type="link"
            size="small"
            icon={<UnorderedListOutlined />}
            onClick={() => setToolsServer(record)}
          >
            工具清单
          </Button>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>编辑</Button>
          <Popconfirm
            title="确认删除？"
            description="删除后该服务的工具清单一并移除，经网关的调用将无法路由。"
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
        title="MCP 服务管理"
        description="登记企业允许使用的 MCP 服务，同步其工具能力清单并自动标注风险，作为权限策略和调用审计的资产底座。"
        meta={
          <Space size={8} wrap>
            <StatusPill tone="blue">能力识别</StatusPill>
            <StatusPill tone="purple">供应链快照准入</StatusPill>
          </Space>
        }
        actions={
          <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>注册 MCP 服务</Button>
        }
      />

      {!settingsQuery.isPending && !settingsQuery.isError && <div style={{marginBottom:16}}><GatewayAccess access={gatewayAccess} showClientGuide={false}/></div>}

      {manifestChangedServers.length > 0 && (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message={`检测到 ${manifestChangedServers.length} 个 MCP 服务的能力清单发生变更`}
          description={
            <Space direction="vertical" size={4}>
              <Text>
                以下服务在最近一次同步时能力清单指纹发生变化（可能是正常升级，也可能是供应链能力替换攻击）：
                {manifestChangedServers.map((s) => s.name).join('、')}
              </Text>
              <Text strong>相关服务已进入未准入或隔离状态，数据面硬阻断。请逐项核对当前快照后重新批准，不再使用本地“已复核”假状态。</Text>
            </Space>
          }
        />
      )}

      {shadowWarnings.length > 0 && (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message={
            <Space size={8} wrap>
              <span>{`检测到 ${shadowWarnings.length} 个影子工具（同名跨服务）`}</span>
              {divergingShadowCount > 0 && <Tag color="red">其中 {divergingShadowCount} 个疑似冒充</Tag>}
            </Space>
          }
          description={
            <Space direction="vertical" size={8} style={{ width: '100%' }}>
              <Text>
                以下工具名在多台 MCP 服务上重复出现。被攻陷或恶意的服务可能提供与可信服务同名的工具，诱导 agent 误调用。
                定义指纹不一致的同名工具会在同步事务中自动隔离并硬阻断；
                定义一致的重复登记只保留风险提示，请确认是否符合预期资产规划。
              </Text>
              <List
                size="small"
                dataSource={shadowWarnings}
                rowKey="tool_name"
                style={{ maxHeight: 320, overflow: 'auto' }}
                renderItem={(w) => (
                  <List.Item style={{ display: 'block' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <Text strong style={{ fontFamily: 'monospace', fontSize: 12 }}>{w.tool_name}</Text>
                      <Tag color="orange">{`同名出现在 ${w.servers.length} 台服务`}</Tag>
                      {w.schema_diverges && (
                        <Tooltip title="同名工具的定义指纹不一致，说明它们并非同一工具——更可能是某台服务在冒充同名工具。">
                          <Tag color="red">异构定义 · 已隔离</Tag>
                        </Tooltip>
                      )}
                    </div>
                    <Text style={{ display: 'block', fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
                      {w.reason}
                    </Text>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 4 }}>
                      {w.servers.map((s) => (
                        <Tag key={s.server_id} color="default" style={{ marginInlineEnd: 0 }}>
                          {s.server_name}
                          {(s.risk_tags || []).length > 0
                            ? `（${(s.risk_tags || []).map((tag) => getMcpRiskTagLabel(tag)).join('、')}）`
                            : ''}
                        </Tag>
                      ))}
                    </div>
                  </List.Item>
                )}
              />
            </Space>
          }
        />
      )}

      <SectionPanel
        title="服务概览"
        description="按真实同步、准入和硬阻断状态掌握 MCP 资产面。"
        extra={(
          <StatusPill tone={securityExecutionMode?.effective_mode === 'protect' ? 'green' : securityExecutionMode?.effective_mode === 'record' ? 'orange' : 'gray'}>
            实际模式：{securityExecutionMode?.effective_mode === 'protect' ? '保护模式' : securityExecutionMode?.effective_mode === 'record' ? '记录模式' : '待确认'}
          </StatusPill>
        )}
      >
        <div className="enterprise-metric-grid">
          <MetricCard label="已注册服务" value={servers.length} tone="blue" hint="当前租户登记的 MCP 服务数" />
          <MetricCard label="工具总数" value={totalToolCount} tone="purple" hint="全部服务已同步的工具能力数" />
          <MetricCard label="待同步" value={pendingSyncCount} tone="orange" hint="尚未执行过能力同步的服务" />
          <MetricCard label="待准入" value={pendingAdmissionCount} tone="orange" hint="尚未批准当前服务与路由快照" />
          <MetricCard label="硬阻断服务" value={hardBlockedServerCount} tone="red" hint="隔离或撤销状态，任何模式下均拒绝调用" />
          <MetricCard label="影子工具风险" value={shadowWarnings.length} tone="orange" hint="异构定义已自动隔离；同构重复需人工核验" />
        </div>
      </SectionPanel>

      <SectionPanel
        title="服务列表"
        description="同步能力后，按当前 Manifest、Route 与工具 Schema 快照执行准入；后续漂移自动隔离。"
        extra={
          <Input
            allowClear
            size="small"
            prefix={<SearchOutlined />}
            placeholder="搜索服务名 / 地址 / 负责人"
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            style={{ width: 240 }}
          />
        }
      >
        <Table
          columns={columns}
          dataSource={filteredServers}
          rowKey="id"
          loading={serversQuery.isLoading}
          scroll={{ x: 'max-content' }}
          locale={{
            emptyText: (
              <Empty description="暂无已登记的 MCP 服务。注册后执行「同步能力」即可生成工具清单。">
                <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>注册 MCP 服务</Button>
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

      {/* 注册/编辑 Modal */}
      <Modal
        title={editingServer ? '编辑 MCP 服务' : '注册 MCP 服务'}
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        footer={null}
        width={640}
      >
        <Form form={form} onFinish={handleSubmit} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item
            name="name"
            label="服务名称"
            rules={[{ required: true, message: '请输入服务名称' }]}
            extra="调用审计里以「服务名称__工具名」记录，请使用稳定、可辨识的名称。"
          >
            <Input placeholder="例如: 内部知识库检索" />
          </Form.Item>
          <Form.Item label="厂商预设" extra="选择后仅预填下方「传输方式 / 鉴权」选项，可继续修改；不会改变网关的任何处理逻辑。">
            <Select
              allowClear
              placeholder="选择厂商快速填充（可选）"
              options={MCP_VENDOR_PRESETS.map((p) => ({ value: p.key, label: p.label }))}
              onChange={(key) => key && handlePreset(key as string)}
            />
          </Form.Item>
          <Form.Item
            name="server_url"
            label="服务地址"
            rules={[{ required: true, message: '请输入服务地址' }]}
            extra={watchAuthLocation === 'path'
              ? '用 {密钥} 标出密钥所在的路径位置，例如 https://x.com/mcp/{密钥}/sse。密钥在下方「鉴权密钥」中填写，加密存储；地址里不要写真实密钥。'
              : 'MCP 服务的 HTTP 入口地址，网关将向该地址转发调用。'}
          >
            <Input placeholder={watchAuthLocation === 'path' ? '例如: https://x.com/mcp/{密钥}/sse' : '例如: https://mcp.example.com/mcp'} />
          </Form.Item>
          {urlHasInlineSecret(watchServerUrl) && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 16 }}
              message="服务地址中带有疑似密钥的参数"
              description="保存时系统会自动把该参数拆出，转为「URL 参数」鉴权并加密存储，地址中不再保留明文密钥。如无法自动拆分（例如含多个密钥参数），保存会被拒绝，请改在下方「鉴权」中单独填写。"
            />
          )}
          <Form.Item
            name="transport"
            label="传输方式"
            rules={[{ required: true, message: '请选择传输方式' }]}
            extra="自动识别：先按 Streamable HTTP 探测，明显不是该协议的端点（或地址以 /sse 结尾）则回退旧版 SSE，并记住探测结果。"
          >
            <Select placeholder="请选择传输方式" options={TRANSPORT_OPTIONS} />
          </Form.Item>
          <Divider orientation="left" plain style={{ margin: '8px 0 12px' }}>鉴权</Divider>
          <Form.Item
            name="auth_token"
            label="鉴权密钥"
            extra={editingServer ? '留空不修改。密钥加密存储，不再回显，仅用于网关向该服务转发时注入。' : '选填。密钥加密存储且不再回显，仅用于网关向该服务转发时注入。'}
          >
            <Input.Password placeholder={editingServer ? '留空不修改' : '选填，该服务要求的访问密钥'} autoComplete="new-password" />
          </Form.Item>
          <Form.Item name="auth_location" label="鉴权位置" extra="密钥放在请求头里、拼在 URL 参数中，还是作为 URL 路径中的一段（例如 /mcp/<密钥>/sse）。">
            <Select options={MCP_AUTH_LOCATION_OPTIONS} />
          </Form.Item>
          {watchAuthLocation !== 'path' && (
            <>
              <Form.Item
                name="auth_name"
                label={watchAuthLocation === 'query' ? 'URL 参数名' : '请求头名称'}
                extra={watchAuthLocation === 'query' ? '例如 key、ak、api_key、Authorization。' : '默认 Authorization；部分服务使用自定义头名。'}
              >
                <Input placeholder={watchAuthLocation === 'query' ? '例如: key' : '默认: Authorization'} />
              </Form.Item>
              <Form.Item name="auth_template" label="值模板" extra="密钥写入时的格式：选「Bearer + 密钥」会加 Bearer 前缀；选「仅密钥」原样写入。">
                <McpTemplateSelect />
              </Form.Item>
            </>
          )}
          <Divider orientation="left" plain style={{ margin: '8px 0 12px' }}>额外请求头</Divider>
          <Form.List name="extra_headers">
            {(fields, { add, remove }) => (
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 8 }}>
                  部分服务要求固定的附加请求头（例如账户标识）。此处明文保存，请勿填写密钥；密钥请在上方「鉴权」中填写。
                </div>
                {fields.map((field) => (
                  <Space key={field.key} align="baseline" style={{ display: 'flex', marginBottom: 8 }}>
                    <Form.Item name={[field.name, 'name']} style={{ marginBottom: 0 }} rules={[{ required: true, message: '请输入头名称' }]}>
                      <Input placeholder="请求头名称" style={{ width: 200 }} />
                    </Form.Item>
                    <Form.Item name={[field.name, 'value']} style={{ marginBottom: 0 }} rules={[{ required: true, message: '请输入头取值' }]}>
                      <Input placeholder="请求头取值" style={{ width: 220 }} />
                    </Form.Item>
                    <Button type="link" danger onClick={() => remove(field.name)}>删除</Button>
                  </Space>
                ))}
                <Button type="dashed" icon={<PlusOutlined />} onClick={() => add({ name: '', value: '' })}>添加额外请求头</Button>
              </div>
            )}
          </Form.List>
          <Form.Item
            name="allow_private_egress"
            label="允许内网地址"
            valuePropName="checked"
          >
            <ConfirmSwitch ariaLabel="允许内网地址" allowEnable={canEnableEgress} confirmTitle="允许内网地址？" />
          </Form.Item>
          <EgressOverrideFields includeMcp canEnable={canEnableEgress} />
          <Form.Item
            name="trust_level"
            label="信任级别"
            rules={[{ required: true, message: '请选择信任级别' }]}
            extra={getMcpTrustLevelDescription((watchTrustLevel as string) || 'low')}
          >
            <Select placeholder="请选择信任级别" options={TRUST_LEVEL_OPTIONS} />
          </Form.Item>
          <Form.Item
            name="status"
            label="服务状态"
            extra={getMcpServerStatusDescription((watchStatus as string) || 'active')}
          >
            <Select options={STATUS_OPTIONS} />
          </Form.Item>
          <Form.Item name="owner" label="负责人">
            <Input placeholder="选填，服务负责人" />
          </Form.Item>
          <Form.Item style={{ marginBottom: 0 }}>
            <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
              <Button onClick={() => setModalOpen(false)}>取消</Button>
              <Button type="primary" htmlType="submit" loading={createMutation.isPending || updateMutation.isPending}>提交</Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* 同步结果 Modal */}
      <Modal
        title="能力同步完成"
        open={!!syncResult}
        onCancel={() => setSyncResult(null)}
        footer={
          <Space>
            {syncResult && (
              <Button onClick={() => { setToolsServer(syncResult.server); setSyncResult(null) }}>查看工具清单</Button>
            )}
            <Button type="primary" onClick={() => setSyncResult(null)}>知道了</Button>
          </Space>
        }
      >
        {syncResult && (
          <Space direction="vertical" size={8} style={{ width: '100%' }}>
            <div>
              <Text type="secondary">服务：</Text>
              <Text strong>{syncResult.server.name}</Text>
            </div>
            <div>
              <Text type="secondary">能力清单：</Text>
              {syncResult.result.changed
                ? <Tag color="warning">与上次同步相比有变更</Tag>
                : <Tag color="success">无变化</Tag>}
            </div>
            <div>
              <Text type="secondary">工具总数：</Text>
              <Text strong>{syncResult.result.tool_count ?? 0}</Text>
            </div>
            {syncResult.result.supply_chain && (
              <Alert
                type={['quarantined', 'revoked'].includes(syncResult.result.supply_chain.server_status) ? 'error' : 'success'}
                showIcon
                message={
                  <Space size={6} wrap>
                    <span>供应链同步结果</span>
                    {renderAdmission(syncResult.result.supply_chain.server_status, syncResult.result.supply_chain.server_reason)}
                  </Space>
                }
                description={
                  <Space direction="vertical" size={2}>
                    <Text>
                      已准入工具 {syncResult.result.supply_chain.approved_tool_count} 个；
                      已隔离 {syncResult.result.supply_chain.quarantined_tool_count} 个；
                      已撤销 {syncResult.result.supply_chain.revoked_tool_count} 个；
                      已下线 {syncResult.result.supply_chain.removed_tool_count} 个。
                    </Text>
                    <Text>描述投毒扫描：{syncResult.result.supply_chain.description_scan_complete ? '已完整执行' : '未完整执行，新工具不会被视为干净'}</Text>
                  </Space>
                }
              />
            )}
            {typeof syncResult.result.added_count === 'number' && (
              <div><Text type="secondary">新增工具：</Text><Text strong>{syncResult.result.added_count}</Text></div>
            )}
            {typeof syncResult.result.updated_count === 'number' && (
              <div><Text type="secondary">变更工具：</Text><Text strong>{syncResult.result.updated_count}</Text></div>
            )}
            {typeof syncRemovedCount(syncResult.result) === 'number' && (
              <div><Text type="secondary">移除（下线）工具：</Text><Text strong>{syncRemovedCount(syncResult.result)}</Text></div>
            )}
            {syncResult.result.changed && (
              <Alert
                type="warning"
                showIcon
                message="能力清单发生变更"
                description="如果这不是预期内的服务升级，可能存在供应链能力替换风险，请逐条复核以下工具与参数结构。"
              />
            )}
            {changedTools(syncResult.result).length > 0 && (
              <div>
                <Text type="secondary" style={{ display: 'block', marginBottom: 6 }}>
                  {syncResult.result.changed ? '变更工具明细（展开可看参数结构）' : '工具清单（展开可看参数结构）'}
                </Text>
                <List
                  size="small"
                  dataSource={changedTools(syncResult.result)}
                  rowKey="tool_name"
                  style={{ maxHeight: 300, overflow: 'auto' }}
                  renderItem={(tool: McpTool & { added?: boolean; updated?: boolean }) => (
                    <List.Item style={{ display: 'block' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <Text strong style={{ fontFamily: 'monospace', fontSize: 12 }}>{tool.tool_name}</Text>
                        {changeTag(tool)}
                        {(tool.risk_tags || []).map((tag) => (
                          <Tag key={tag} color={MCP_RISK_TAG_COLORS[tag] || 'purple'}>{getMcpRiskTagLabel(tag)}</Tag>
                        ))}
                      </div>
                      {tool.input_schema && Object.keys(tool.input_schema).length > 0 ? (
                        <details style={{ marginTop: 4 }}>
                          <summary style={{ fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' }}>参数结构</summary>
                          <pre style={{ fontSize: 11, background: 'var(--bg-secondary)', padding: 8, borderRadius: 4, overflow: 'auto', maxHeight: 200 }}>
                            {JSON.stringify(tool.input_schema, null, 2)}
                          </pre>
                        </details>
                      ) : null}
                    </List.Item>
                  )}
                />
              </div>
            )}
          </Space>
        )}
      </Modal>

      {/* 测试连接结果 Modal：结构化归因，失败按 DNS/超时/401/TLS 分类给可读提示 */}
      <Modal
        title="连接测试结果"
        open={!!testResult}
        onCancel={() => setTestResult(null)}
        footer={<Button type="primary" onClick={() => setTestResult(null)}>知道了</Button>}
      >
        {testResult && (
          <Space direction="vertical" size={8} style={{ width: '100%' }}>
            <div>
              <Text type="secondary">服务：</Text>
              <Text strong>{testResult.server.name}</Text>
            </div>
            <div>
              <Text type="secondary">服务地址：</Text>
              <Text style={{ fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all' }}>{serverUrlForDisplay(testResult.server.server_url || '', testResult.server.upstream?.auth_location === 'path' ? 'path' : 'header') || '-'}</Text>
            </div>
            {testResult.result.ok ? (
              <Alert
                type="success"
                showIcon
                message="连接正常"
                description="已成功与该 MCP 服务建立连接并完成握手，可执行「同步能力」拉取工具清单。"
              />
            ) : (
              <Alert
                type="error"
                showIcon
                message="连接失败"
                description={(
                  <Space direction="vertical" size={4} style={{ width: '100%' }}>
                    <span>{getMcpTestConnErrorLabel(testResult.result.error_kind, testResult.result.message)}</span>
                    {getMcpTestConnErrorDetail(testResult.result.error_kind, testResult.result.message) ? (
                      <Text type="secondary" style={{ fontSize: 12, wordBreak: 'break-all' }}>
                        {getMcpTestConnErrorDetail(testResult.result.error_kind, testResult.result.message)}
                      </Text>
                    ) : null}
                  </Space>
                )}
              />
            )}
            {testResult.result.ok && testResult.result.server_info?.transport ? (
              <div>
                <Text type="secondary">实际传输方式：</Text>
                <Text strong>{MCP_TRANSPORT_LABELS[String(testResult.result.server_info.transport)] || String(testResult.result.server_info.transport)}</Text>
                {testResult.result.server_info.auto_detected ? <Tag color="purple" style={{ marginLeft: 8 }}>自动识别</Tag> : null}
              </div>
            ) : null}
            {testResult.result.ok && testResult.result.server_info?.protocol_version ? (
              <div>
                <Text type="secondary">协商协议版本：</Text>
                <Text strong>{String(testResult.result.server_info.protocol_version)}</Text>
                {testResult.result.server_info.protocol_version_raw ? (
                  <Tooltip title="上游声明的版本晚于网关已知的最新版本，已前向兼容并按最新已知版本的语义处理">
                    <Tag color="warning" style={{ marginLeft: 8 }}>上游声明 {String(testResult.result.server_info.protocol_version_raw)}（前向兼容）</Tag>
                  </Tooltip>
                ) : null}
              </div>
            ) : null}
            {testResult.result.ok && testResult.result.server_info && Object.keys(testResult.result.server_info).length > 0 ? (
              <details>
                <summary style={{ fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' }}>服务端信息</summary>
                <pre style={{ fontSize: 11, background: 'var(--bg-secondary)', padding: 8, borderRadius: 4, overflow: 'auto', maxHeight: 200 }}>
                  {JSON.stringify(testResult.result.server_info, null, 2)}
                </pre>
              </details>
            ) : null}
          </Space>
        )}
      </Modal>

      {/* 工具清单 Drawer */}
      <Drawer
        title={toolsServer ? `工具清单：${toolsServer.name}` : '工具清单'}
        open={!!toolsServer}
        onClose={() => setToolsServer(null)}
        width={640}
      >
        {toolsServer?.last_manifest_changed_at && (
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: 12 }}
            message="该服务能力清单发生过变更"
            description={`最近变更时间：${formatTime(toolsServer.last_manifest_changed_at)}。服务已自动隔离并硬阻断；复核工具和路由快照后才能重新批准。`}
          />
        )}
        {toolsServer?.upstream && (
          <div style={{ marginBottom: 12, padding: 10, background: 'var(--bg-secondary)', borderRadius: 6 }}>
            <Space direction="vertical" size={4} style={{ width: '100%' }}>
              <Text strong style={{ fontSize: 12 }}>上游连接</Text>
              <div>
                <Text type="secondary" style={{ fontSize: 12 }}>传输方式：</Text>
                <Tag>{MCP_TRANSPORT_LABELS[toolsServer.upstream.transport] || toolsServer.upstream.transport}</Tag>
                {toolsServer.upstream.transport === 'auto' && (
                  <Tag color={toolsServer.upstream.detected_transport ? 'success' : 'default'}>
                    {toolsServer.upstream.detected_transport
                      ? `检测到：${MCP_TRANSPORT_LABELS[toolsServer.upstream.detected_transport] || toolsServer.upstream.detected_transport}`
                      : '尚未探测'}
                  </Tag>
                )}
              </div>
              <div>
                <Text type="secondary" style={{ fontSize: 12 }}>协商协议版本：</Text>
                <Text style={{ fontSize: 12 }}>{toolsServer.upstream.protocol_version || '尚未同步'}</Text>
                {toolsServer.upstream.protocol_version_raw && (
                  <Tooltip title="上游声明的版本晚于网关已知的最新版本，已前向兼容并按最新已知版本的语义处理">
                    <Tag color="warning" style={{ marginLeft: 8 }}>上游声明 {toolsServer.upstream.protocol_version_raw}（前向兼容）</Tag>
                  </Tooltip>
                )}
              </div>
              <div>
                <Text type="secondary" style={{ fontSize: 12 }}>鉴权：</Text>
                <Text style={{ fontSize: 12 }}>
                  {toolsServer.auth_configured
                    ? (toolsServer.upstream.auth_location === 'path'
                      ? 'URL 路径（密钥替换地址中的 {密钥} 占位，已加密保存）'
                      : `${toolsServer.upstream.auth_location === 'query' ? 'URL 参数' : '请求头'} ${toolsServer.upstream.auth_name || '（未设置）'}（密钥已加密保存）`)
                    : '未配置密钥'}
                </Text>
              </div>
              {toolsServer.upstream.extra_headers && Object.keys(toolsServer.upstream.extra_headers).length > 0 && (
                <div>
                  <Text type="secondary" style={{ fontSize: 12 }}>额外请求头：</Text>
                  {Object.keys(toolsServer.upstream.extra_headers).map((name) => <Tag key={name}>{name}</Tag>)}
                </div>
              )}
              {toolsServer.upstream.url_has_plaintext_secret && (
                <Alert type="warning" showIcon message="该服务地址中仍带有明文密钥参数，请编辑并保存一次，系统会自动拆出并加密存储。" />
              )}
              {toolsServer.upstream.config_error && (
                <Alert type="error" showIcon message={`上游连接配置无效：${toolsServer.upstream.config_error}`} />
              )}
            </Space>
          </div>
        )}
        {toolsServer && toolsServer.manifest_hash && (
          <Space direction="vertical" size={4} style={{ width: '100%', marginBottom: 12 }}>
            {renderAdmission(toolsServer.admission_status, toolsServer.quarantine_reason)}
            {admissionActions('server', toolsServer)}
          </Space>
        )}
        {toolsQuery.isLoading ? (
          <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-tertiary)' }}>加载中...</div>
        ) : tools.length === 0 ? (
          <Empty description="暂无工具清单。请先执行「同步能力」拉取该服务的工具列表。" />
        ) : (
          <>
            <div style={{ marginBottom: 12, padding: 10, background: 'var(--bg-secondary)', borderRadius: 6 }}>
              <Space size={8} wrap style={{ marginBottom: 6 }}>
                <Text strong style={{ fontSize: 12 }}>共 {tools.length} 个工具</Text>
                {highRiskToolCount > 0 ? (
                  <Tag color="red">高危 {highRiskToolCount}</Tag>
                ) : (
                  <Tag color="green">无高危标注</Tag>
                )}
                {poisonToolCount > 0 && (
                  <Tooltip title="工具描述中检测到疑似操纵调用方 agent 的内容，已自动隔离并在数据面硬阻断。">
                    <Tag color="red">疑似投毒 {poisonToolCount}</Tag>
                  </Tooltip>
                )}
              </Space>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {MCP_RISK_TAG_ORDER.map((tag) => (
                  <Tooltip key={tag} title={getMcpRiskTagDescription(tag)}>
                    <Tag color={MCP_RISK_TAG_COLORS[tag] || 'purple'} style={{ marginInlineEnd: 0 }}>{getMcpRiskTagLabel(tag)}</Tag>
                  </Tooltip>
                ))}
              </div>
              <Text type="secondary" style={{ display: 'block', fontSize: 11, marginTop: 6 }}>
                风险标注由能力同步时自动识别；「破坏性」「凭证访问」计入高危工具，建议为其单独配置权限策略。
              </Text>
            </div>
          <List
            dataSource={tools}
            rowKey="id"
            renderItem={(tool) => (
              <List.Item style={{ display: 'block' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <Text strong style={{ fontFamily: 'monospace' }}>{tool.tool_name}</Text>
                  {tool.removed && <Tag color="default">已下线</Tag>}
                  {(tool.risk_tags || []).map((tag) => (
                    <Tag key={tag} color={MCP_RISK_TAG_COLORS[tag] || 'purple'}>{getMcpRiskTagLabel(tag)}</Tag>
                  ))}
                  {(tool.poison_flags || []).length > 0 && (
                    <Tooltip
                      title={
                        <span>
                          该工具描述命中投毒检测，已自动隔离并在数据面硬阻断。
                          <br />
                          命中类型：
                          {(tool.poison_flags || []).map((f) => getMcpPoisonFlagLabel(f)).join('、')}
                          <br />
                          {(tool.poison_flags || []).map((f) => getMcpPoisonFlagDescription(f)).join('；')}
                          <br />
                          建议人工复核该工具描述后再决定是否信任。
                        </span>
                      }
                    >
                      <Tag color="red">描述投毒</Tag>
                    </Tooltip>
                  )}
                </div>
                <Space direction="vertical" size={4} style={{ width: '100%', marginTop: 6 }}>
                  {renderAdmission(tool.admission_status, tool.quarantine_reason)}
                  {!tool.removed && admissionActions('tool', tool)}
                </Space>
                {tool.description ? (
                  <Text style={{ display: 'block', fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
                    {tool.description}
                  </Text>
                ) : null}
                <Text style={{ display: 'block', fontSize: 11, color: 'var(--text-tertiary)', marginTop: 4 }}>
                  首次发现：{formatTime(tool.first_seen_at)} ｜ 最近出现：{formatTime(tool.last_seen_at)}
                </Text>
                {tool.input_schema && Object.keys(tool.input_schema).length > 0 ? (
                  <details style={{ marginTop: 4 }}>
                    <summary style={{ fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' }}>参数结构</summary>
                    <pre style={{
                      fontSize: 11,
                      background: 'var(--bg-secondary)',
                      padding: 8,
                      borderRadius: 4,
                      overflow: 'auto',
                      maxHeight: 240,
                    }}>
                      {JSON.stringify(tool.input_schema, null, 2)}
                    </pre>
                  </details>
                ) : null}
              </List.Item>
            )}
          />
          </>
        )}
      </Drawer>
    </div>
  )
}

export default McpServers

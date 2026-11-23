import { useEffect, useMemo, useState } from 'react'
import {
  Table,
  Button,
  Space,
  Select,
  Input,
  Tag,
  Typography,
  Drawer,
  Tooltip,
  Empty,
  message,
} from 'antd'
import { EyeOutlined, ReloadOutlined, DownloadOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import {
  mcpAuditApi,
  mcpAuditExportApi,
  mcpServerApi,
  type McpAuditExportFormat,
  type McpServer,
} from '../services/api'
import { EnterprisePageHeader, MetricCard, SectionPanel, StatusPill } from '../components/EnterpriseUI'
import {
  getDecisionLabel,
  getExecutionModeLabel,
  getReadableToolReason,
  getToolEvidenceRuleLabel,
  getRiskCategoryLabel,
  getProvenanceLabel,
  getMcpJsonRpcFieldLabel,
  TOOL_PARAMETER_LABELS,
} from '../utils/risk'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import { formatAgentType } from '../utils/agents'

// 参数键中文回显：常见键走字典；MCP 工具的自定义参数键属于数据（非枚举），原样保留便于排查
const paramKeyLabel = (key: string) => TOOL_PARAMETER_LABELS[key] || key

const { Text } = Typography

const DECISION_COLORS: Record<string, string> = {
  allow: 'green',
  audit: 'blue',
  confirm: 'orange',
  block: 'red',
}

// 实际动作过滤（effective_decision 维度）——服务端下发
const EFFECTIVE_FILTER_OPTIONS = [
  { value: 'all', label: '全部实际动作' },
  { value: 'allow', label: '放行' },
  { value: 'audit', label: '仅记录' },
  { value: 'confirm', label: '人工确认' },
  { value: 'block', label: '阻断' },
]

// 原始判定过滤（raw_decision 维度）——用于查「应阻断/应确认」被执行模式折算的行
const RAW_FILTER_OPTIONS = [
  { value: 'all', label: '全部原始判定' },
  { value: 'allow', label: '原判放行' },
  { value: 'audit', label: '原判仅记录' },
  { value: 'confirm', label: '原判应确认' },
  { value: 'block', label: '原判应阻断' },
]

const MODE_FILTER_OPTIONS = [
  { value: 'all', label: '全部生效模式' },
  { value: 'observe', label: '观察模式' },
  { value: 'audit', label: '审计模式' },
  { value: 'strict', label: '严格模式' },
]

const TIME_RANGE_OPTIONS = [
  { value: '1h', label: '近 1 小时' },
  { value: '24h', label: '近 24 小时' },
  { value: '7d', label: '近 7 天' },
  { value: '30d', label: '近 30 天' },
]

const TIME_RANGE_MS: Record<string, number> = {
  '1h': 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
}

// 审计里 tool_name 记录为「服务名__工具名」：按第一个 '__' 拆开展示
const splitMcpToolName = (name?: string): { server: string; tool: string } => {
  const text = String(name || '')
  const idx = text.indexOf('__')
  if (idx > 0) {
    return { server: text.slice(0, idx), tool: text.slice(idx + 2) }
  }
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

const formatParamValue = (value: unknown) => {
  if (value === undefined || value === null || value === '') return '未记录'
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

// evidence_json 可能是数组，也可能是 JSON 字符串：统一成数组
const normalizeJsonArray = (value: any): any[] => {
  if (Array.isArray(value)) return value
  if (typeof value === 'string' && value.trim()) {
    try {
      const parsed = JSON.parse(value)
      return Array.isArray(parsed) ? parsed : []
    } catch {
      return []
    }
  }
  return []
}

// CSV 单元格转义：含逗号/引号/换行时包裹并转义双引号
const DEFAULT_FILTERS = {
  effective_decision: 'all',
  raw_decision: 'all',
  server: 'all',
  mode: 'all',
  user_id: '',
  session_id: '',
  policy_id: '',
  agent_type: '',
  request_id: '',
}

type AuditFilters = typeof DEFAULT_FILTERS

function McpAudit() {
  const auditIdentity = useAuditQueryIdentity()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const linkedRequestID = String(searchParams.get('request_id') || '').trim()
  const [filters, setFilters] = useState<AuditFilters>({
    ...DEFAULT_FILTERS, request_id: linkedRequestID,
  })
  const [timeRange, setTimeRange] = useState('24h')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detail, setDetail] = useState<any | null>(null)

  const setFilter = (key: keyof AuditFilters, value: string) => {
    setFilters((prev) => ({ ...prev, [key]: value }))
    setPage(1)
  }
  const resetFilters = () => {
    setFilters({ ...DEFAULT_FILTERS })
    setPage(1)
  }
  const hasActiveFilters = useMemo(
    () => (Object.keys(DEFAULT_FILTERS) as (keyof AuditFilters)[]).some((k) => filters[k] !== DEFAULT_FILTERS[k]),
    [filters],
  )

  // 服务端过滤参数：去掉旧的「最近 200 条」内存窗口，所有过滤 + 分页均下发给后端，避免旧记录被静默丢弃。
  const queryParams = useMemo(() => {
    const to = new Date()
    const from = new Date(to.getTime() - (TIME_RANGE_MS[timeRange] || TIME_RANGE_MS['24h']))
    const params: Record<string, unknown> = {
      from: from.toISOString(),
      to: to.toISOString(),
      limit: pageSize,
      offset: (page - 1) * pageSize,
    }
    if (filters.effective_decision !== 'all') params.effective_decision = filters.effective_decision
    if (filters.raw_decision !== 'all') params.raw_decision = filters.raw_decision
    if (filters.server !== 'all') params.server = filters.server
    if (filters.mode !== 'all') params.mode = filters.mode
    if (filters.user_id.trim()) params.user_id = filters.user_id.trim()
    if (filters.session_id.trim()) params.session_id = filters.session_id.trim()
    if (filters.policy_id.trim()) params.policy_id = filters.policy_id.trim()
    if (filters.request_id.trim()) params.request_id = filters.request_id.trim()
    if (filters.agent_type.trim()) params.agent_type = filters.agent_type.trim()
    return params
  }, [filters, timeRange, page, pageSize])

  const auditQuery = useQuery({
    queryKey: ['mcpAudit', auditIdentity, queryParams],
    queryFn: () => mcpAuditApi.list(queryParams),
  })

  const serversQuery = useQuery({
    queryKey: ['mcpServers'],
    queryFn: () => mcpServerApi.list(),
  })

  const servers: McpServer[] = unpackList(serversQuery.data?.data, 'servers')

  // 当前页记录：mcpAuditApi 已按 tool_type='mcp' 下发，保留防御性过滤兜底
  const rows: any[] = useMemo(() => {
    const list = unpackList(auditQuery.data?.data)
    return list.filter((row) => row?.tool_type === 'mcp')
  }, [auditQuery.data])

  // 总数由服务端返回（符合当前筛选与时间窗口），不再受页大小截断误导
  useEffect(() => {
    if (!linkedRequestID || detail || rows.length === 0) return
    const linked = rows.find((row) => row?.request_id === linkedRequestID)
    if (linked) setDetail(linked)
  }, [detail, linkedRequestID, rows])

  const total = Number(auditQuery.data?.data?.total ?? rows.length)

  // 服务过滤下拉：以已登记服务名为候选（服务端按服务名过滤）
  const serverOptions = useMemo(() => {
    const names = Array.from(new Set(servers.map((s) => s.name).filter(Boolean))).sort()
    return [{ value: 'all', label: '全部服务' }, ...names.map((n) => ({ value: n, label: n }))]
  }, [servers])

  // W1 1.13：服务端按当前筛选导出全量（非仅当前页），服务端写导出留痕
  const [exporting, setExporting] = useState<McpAuditExportFormat | null>(null)
  const exportAudit = async (format: McpAuditExportFormat) => {
    if (total === 0) {
      message.info('当前筛选无可导出的记录')
      return
    }
    const { limit: _limit, offset: _offset, ...exportParams } = queryParams
    void _limit
    void _offset
    setExporting(format)
    try {
      const res = await mcpAuditExportApi.export(format, exportParams)
      const url = URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = url
      a.download = `mcp-audit-${new Date().toISOString().slice(0, 19).replace(/[:T-]/g, '')}.${format}`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      const count = Number(res.headers?.['x-export-row-count'] ?? 0)
      if (String(res.headers?.['x-export-truncated']) === 'true') {
        message.warning(`导出成功 · 共 ${count} 条（超出上限）`)
      } else {
        message.success(`导出成功 · 共 ${count} 条`)
      }
    } catch (err) {
      console.error('导出失败', err)
      message.error('导出失败')
    } finally {
      setExporting(null)
    }
  }

  const columns = [
    {
      title: '时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 145,
      render: (v: string) => <Text style={{ fontSize: 12 }}>{formatTime(v)}</Text>,
    },
    {
      title: '身份',
      key: 'identity',
      width: 135,
      render: (_: unknown, record: any) => (
        <Space direction="vertical" size={0}>
          <Text style={{ fontSize: 12 }}>{record.user_id || '未记录用户'}</Text>
          {record.session_id ? (
            <Text style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>会话 {String(record.session_id).slice(0, 12)}</Text>
          ) : null}
        </Space>
      ),
    },
    {
      title: '项目',
      dataIndex: 'project_id',
      key: 'project_id',
      width: 100,
      render: (v: string) => (v ? <Text style={{ fontSize: 12 }}>{v}</Text> : <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>-</Text>),
    },
    {
      title: 'API Key',
      key: 'key',
      width: 105,
      render: (_: unknown, record: any) => {
        const v = record.key_prefix || record.client_id
        return v
          ? <Text style={{ fontSize: 12, fontFamily: 'monospace' }}>{v}</Text>
          : <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>-</Text>
      },
    },
    {
      title: '智能体',
      dataIndex: 'agent_type',
      key: 'agent_type',
      width: 95,
      render: (v: string) => (v ? <Tag color="purple">{formatAgentType(v)}</Tag> : <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>-</Text>),
    },
    {
      title: 'MCP 服务',
      key: 'server',
      width: 115,
      render: (_: unknown, record: any) => {
        const { server } = splitMcpToolName(record.tool_name)
        return server
          ? <Tag color="geekblue">{server}</Tag>
          : <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>未记录</Text>
      },
    },
    {
      title: '工具',
      key: 'tool',
      width: 150,
      render: (_: unknown, record: any) => {
        const { tool } = splitMcpToolName(record.tool_name)
        return <Text style={{ fontSize: 12, fontFamily: 'monospace' }}>{tool || '-'}</Text>
      },
    },
    {
      title: '原始判定',
      dataIndex: 'raw_decision',
      key: 'raw_decision',
      width: 88,
      render: (v: string) => (
        <Tag color={DECISION_COLORS[v] || 'default'}>{getDecisionLabel(v)}</Tag>
      ),
    },
    {
      title: '实际动作',
      dataIndex: 'effective_decision',
      key: 'effective_decision',
      width: 88,
      render: (v: string, record: any) => (
        <Tooltip title={getReadableToolReason(record.effective_reason || record.match_reason)}>
          <Tag color={DECISION_COLORS[v] || 'default'}>{getDecisionLabel(v)}</Tag>
        </Tooltip>
      ),
    },
    {
      title: '生效模式',
      dataIndex: 'mode',
      key: 'mode',
      width: 88,
      render: (v: string) => <Tag>{getExecutionModeLabel(v)}</Tag>,
    },
    {
      title: '判定原因',
      key: 'reason',
      ellipsis: true,
      render: (_: unknown, record: any) => (
        <Text style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
          {getReadableToolReason(record.effective_reason || record.match_reason)}
        </Text>
      ),
    },
    {
      title: '操作',
      key: 'action',
      width: 64,
      render: (_: unknown, record: any) => (
        <Button type="link" size="small" icon={<EyeOutlined />} onClick={() => setDetail(record)}>详情</Button>
      ),
    },
  ]

  const detailSplit = splitMcpToolName(detail?.tool_name)
  const detailParams: Array<[string, unknown]> =
    detail?.parameters && typeof detail.parameters === 'object' && !Array.isArray(detail.parameters)
      ? Object.entries(detail.parameters)
      : []
  const detailEvidence = normalizeJsonArray(detail?.evidence_json)
  // 原始 JSON-RPC 报文：MCP 工具调用统一走 tools/call；入参优先取记录的原始 arguments，回退到脱敏 parameters
  const detailRpc = {
    method: detail?.rpc_method || 'tools/call',
    id: detail?.rpc_id ?? detail?.request_id ?? null,
    name: detailSplit.tool || detail?.tool_name || '',
    arguments: detail?.arguments ?? detail?.raw_arguments ?? detail?.parameters ?? null,
  }

  return (
    <div className="enterprise-page">
      <EnterprisePageHeader
        eyebrow="MCP 安全网关"
        title="MCP 调用审计"
        description="经网关代理的 MCP 工具调用全量留痕：原始判定如实记录策略结论，实际动作反映执行模式钳制后的处置结果。"
        meta={
          <Space size={8} wrap>
            <StatusPill tone="blue">双决策留痕</StatusPill>
          </Space>
        }
        actions={
          <Space>
            <Button icon={<DownloadOutlined />} loading={exporting === 'csv'} disabled={exporting !== null} onClick={() => exportAudit('csv')}>导出 CSV</Button>
            <Button icon={<DownloadOutlined />} loading={exporting === 'xlsx'} disabled={exporting !== null} onClick={() => exportAudit('xlsx')}>导出 XLSX</Button>
            <Button icon={<ReloadOutlined />} onClick={() => auditQuery.refetch()} loading={auditQuery.isFetching}>
              刷新
            </Button>
          </Space>
        }
      />

      <SectionPanel title="调用概览" description="统计口径为当前筛选条件与时间窗口下的服务端全量匹配数。">
        <div className="enterprise-metric-grid">
          <MetricCard label="符合筛选的调用" valueNumber={total} tone="blue" hint="服务端按当前筛选与时间窗口返回的匹配总数" />
        </div>
      </SectionPanel>

      <SectionPanel
        title="调用明细"
        description="「原始判定」是策略原始结论；「实际动作」是按执行模式折算后的真实处置，两者不一致说明只审计模式在兜底。用「原判应阻断 + 实际放行」可精确定位被折算的行。"
        extra={
          <Space size={8} wrap>
            <Select size="small" style={{ width: 130 }} value={filters.effective_decision} onChange={(v) => setFilter('effective_decision', v)} options={EFFECTIVE_FILTER_OPTIONS} />
            <Select size="small" style={{ width: 130 }} value={filters.raw_decision} onChange={(v) => setFilter('raw_decision', v)} options={RAW_FILTER_OPTIONS} />
            <Select size="small" style={{ width: 160 }} value={filters.server} onChange={(v) => setFilter('server', v)} options={serverOptions} showSearch optionFilterProp="label" />
            <Select size="small" style={{ width: 130 }} value={filters.mode} onChange={(v) => setFilter('mode', v)} options={MODE_FILTER_OPTIONS} />
            <Input size="small" style={{ width: 130 }} allowClear placeholder="用户 ID" value={filters.user_id} onChange={(e) => setFilter('user_id', e.target.value)} />
            <Input size="small" style={{ width: 130 }} allowClear placeholder="会话 ID" value={filters.session_id} onChange={(e) => setFilter('session_id', e.target.value)} />
            <Input size="small" style={{ width: 130 }} allowClear placeholder="策略 ID" value={filters.policy_id} onChange={(e) => setFilter('policy_id', e.target.value)} />
            <Input size="small" style={{ width: 130 }} allowClear placeholder="智能体类型" value={filters.agent_type} onChange={(e) => setFilter('agent_type', e.target.value)} />
            <Input size="small" style={{ width: 170 }} allowClear placeholder="审计请求 ID" value={filters.request_id} onChange={(e) => setFilter('request_id', e.target.value)} />
            <Select size="small" style={{ width: 120 }} value={timeRange} onChange={(v) => { setTimeRange(v); setPage(1) }} options={TIME_RANGE_OPTIONS} />
            <Button size="small" disabled={!hasActiveFilters} onClick={resetFilters}>重置筛选</Button>
          </Space>
        }
      >
        <Table
          columns={columns}
          dataSource={rows}
          rowKey="id"
          loading={auditQuery.isLoading}
          scroll={{ x: 'max-content' }}
          locale={{ emptyText: <Empty description="当前筛选与时间窗口内没有 MCP 调用记录。接入方经网关调用 MCP 服务后，这里会出现全量留痕。" /> }}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: true,
            pageSizeOptions: ['20', '50', '100'],
            showTotal: (t) => `共 ${t} 条`,
            onChange: (p, ps) => { setPage(p); setPageSize(ps) },
          }}
        />
      </SectionPanel>

      {/* 调用详情 Drawer */}
      <Drawer
        title="MCP 调用详情"
        open={!!detail}
        onClose={() => setDetail(null)}
        width={640}
      >
        {detail && (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <div>
              <Text type="secondary">调用时间：</Text>
              <Text>{formatTime(detail.created_at)}</Text>
            </div>
            <div>
              <Text type="secondary">MCP 服务：</Text>
              {detailSplit.server ? <Tag color="geekblue">{detailSplit.server}</Tag> : <Text>未记录</Text>}
              <Text type="secondary" style={{ marginLeft: 12 }}>工具：</Text>
              <Text style={{ fontFamily: 'monospace' }}>{detailSplit.tool || '-'}</Text>
            </div>
            <div>
              <Space size={8} wrap>
                <span>
                  <Text type="secondary">原始判定：</Text>
                  <Tag color={DECISION_COLORS[detail.raw_decision] || 'default'}>{getDecisionLabel(detail.raw_decision)}</Tag>
                </span>
                <span>
                  <Text type="secondary">实际动作：</Text>
                  <Tag color={DECISION_COLORS[detail.effective_decision] || 'default'}>{getDecisionLabel(detail.effective_decision)}</Tag>
                </span>
                <span>
                  <Text type="secondary">生效模式：</Text>
                  <Tag>{getExecutionModeLabel(detail.mode)}</Tag>
                </span>
                {detail.provenance ? (
                  <span>
                    <Text type="secondary">来源可信度：</Text>
                    <Tag color={detail.provenance === 'tainted' ? 'red' : 'blue'}>{getProvenanceLabel(detail.provenance)}</Tag>
                  </span>
                ) : null}
              </Space>
            </div>
            <div>
              <Text type="secondary">判定原因：</Text>
              <Text>{getReadableToolReason(detail.effective_reason || detail.match_reason)}</Text>
            </div>
            <div>
              <Text type="secondary">身份：</Text>
              <Text>{detail.user_id || '未记录用户'}</Text>
              {detail.session_id ? (
                <Text type="secondary" style={{ marginLeft: 12 }}>会话：{detail.session_id}</Text>
              ) : null}
            </div>
            <div>
              <Space size={16} wrap>
                <span><Text type="secondary">项目：</Text><Text>{detail.project_id || '未记录'}</Text></span>
                <span><Text type="secondary">API Key：</Text><Text style={{ fontFamily: 'monospace' }}>{detail.key_prefix || detail.client_id || '未记录'}</Text></span>
                <span><Text type="secondary">智能体：</Text><Text>{detail.agent_type ? formatAgentType(detail.agent_type) : '未记录'}</Text></span>
              </Space>
            </div>
            {/* 命中策略：可跳转策略页复核 */}
            {(detail.matched_policy_id || detail.policy_version) && (
              <div>
                <Text type="secondary">命中策略：</Text>
                <Text style={{ fontFamily: 'monospace' }}>{detail.matched_policy_id || '未记录'}</Text>
                {detail.policy_version ? (
                  <Text type="secondary" style={{ marginLeft: 12 }}>策略版本：{detail.policy_version}</Text>
                ) : null}
                <Button type="link" size="small" onClick={() => navigate('/mcp-gateway/policies')}>查看权限策略</Button>
              </div>
            )}
            {detail.request_id ? (
              <div>
                <Text type="secondary">请求编号：</Text>
                <Text style={{ fontFamily: 'monospace' }}>{detail.request_id}</Text>
              </div>
            ) : null}

            {/* 原始 JSON-RPC 报文：method / id / 原始 arguments */}
            <div>
              <Text type="secondary" style={{ display: 'block', marginBottom: 6 }}>JSON-RPC 报文</Text>
              <div style={{ display: 'grid', gap: 6, background: 'var(--bg-secondary)', padding: 10, borderRadius: 6 }}>
                <div>
                  <Text type="secondary" style={{ fontSize: 12 }}>{getMcpJsonRpcFieldLabel('method')}：</Text>
                  <Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{detailRpc.method}</Text>
                </div>
                <div>
                  <Text type="secondary" style={{ fontSize: 12 }}>{getMcpJsonRpcFieldLabel('id')}：</Text>
                  <Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{detailRpc.id ?? '未记录'}</Text>
                </div>
                <div>
                  <Text type="secondary" style={{ fontSize: 12 }}>{getMcpJsonRpcFieldLabel('name')}：</Text>
                  <Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{detailRpc.name || '-'}</Text>
                </div>
                <div>
                  <Text type="secondary" style={{ display: 'block', fontSize: 12, marginBottom: 2 }}>{getMcpJsonRpcFieldLabel('arguments')}（已脱敏留痕）</Text>
                  <Text style={{ display: 'block', whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontSize: 12 }}>
                    {formatParamValue(detailRpc.arguments)}
                  </Text>
                </div>
              </div>
            </div>

            {/* 结构化调用参数 */}
            <div>
              <Text type="secondary" style={{ display: 'block', marginBottom: 6 }}>调用参数（已脱敏留痕）</Text>
              {detailParams.length > 0 ? (
                <div style={{ display: 'grid', gap: 8, background: 'var(--bg-secondary)', padding: 10, borderRadius: 6 }}>
                  {detailParams.map(([key, value]) => (
                    <div key={key}>
                      <Text type="secondary" style={{ display: 'block', marginBottom: 2, fontSize: 12 }}>{paramKeyLabel(key)}</Text>
                      <Text style={{ display: 'block', whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontSize: 12 }}>
                        {formatParamValue(value)}
                      </Text>
                    </div>
                  ))}
                </div>
              ) : (
                <Text type="secondary">暂无调用参数</Text>
              )}
            </div>

            {/* 命中安全证据 */}
            <div>
              <Text type="secondary" style={{ display: 'block', marginBottom: 6 }}>安全证据</Text>
              {detailEvidence.length > 0 ? (
                detailEvidence.map((evidence: any, index: number) => (
                  <div key={String(evidence.rule_id || 'evidence') + '-' + index} style={{ marginTop: 6, padding: 8, background: 'var(--bg-secondary)', borderRadius: 4 }}>
                    <Space size={4} wrap>
                      <Tag color="purple">{getToolEvidenceRuleLabel(evidence.rule_id)}</Tag>
                      {evidence.category ? <Tag>{getRiskCategoryLabel(evidence.category)}</Tag> : null}
                      {evidence.source_field ? <Tag color="blue">{paramKeyLabel(evidence.source_field)}</Tag> : null}
                    </Space>
                    {evidence.masked_preview ? (
                      <Text style={{ display: 'block', marginTop: 4, wordBreak: 'break-all', fontSize: 12 }}>{evidence.masked_preview}</Text>
                    ) : null}
                    {evidence.hash ? (
                      <Text type="secondary" style={{ display: 'block', wordBreak: 'break-all', fontSize: 12 }}>证据指纹：{evidence.hash}</Text>
                    ) : null}
                  </div>
                ))
              ) : (
                <Text type="secondary">暂无脱敏证据</Text>
              )}
            </div>
          </Space>
        )}
      </Drawer>
    </div>
  )
}

export default McpAudit

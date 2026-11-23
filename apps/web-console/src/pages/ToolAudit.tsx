import { useState, useEffect, useMemo } from 'react'
import { rawEvidenceDisplay } from '../utils/alertEvidence'
import {
  Alert,
  Typography,
  Descriptions,
  Tag,
  Spin,
  Space,
  Drawer,
  List,
  Row,
  Col,
  Button,
  Segmented,
  Empty,
  message,
  Input,
  Select,
} from 'antd'
import {
  ToolOutlined,
  WarningOutlined,
  EyeOutlined,
  ThunderboltOutlined,
  FileOutlined,
  GlobalOutlined,
  DatabaseOutlined,
  SettingOutlined,
} from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { agentEndpointApi, agentKeys } from '../services/agentEndpoint'
import ResizableTable from '../components/ResizableTable'
import {
  EnterprisePageHeader,
  AnalysisFlow,
  SectionPanel,
  StatusPill,
} from '../components/EnterpriseUI'
import {
  agentGuardApi,
  auditDispositionApi,
  boundedTimeWindowParams,
  toolAuditApi,
  type AuditDispositionStatus,
} from '../services/api'
import {
  getDecisionLabel,
  getExecutionModeLabel,
  getProvenanceLabel,
  getReadableToolReason,
  getRiskCategoryLabel,
  getToolEvidenceRuleLabel,
  getToolMatchReason,
  getToolAuditNoteLabel,
  getToolNameLabel,
  getToolParameterLabel,
  getToolPolicyName,
  getToolRiskCategory,
  getToolStatusLabel,
  severityLabel,
  severityOptions,
  verdictLabel,
} from '../utils/risk'
import {
  getToolTriage,
  sortByTriage,
  summarizeTriage,
} from '../utils/riskTriage'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import { exactToolPreEvents } from './agent/testable'

const { Text } = Typography

const TOOL_TYPE_ICONS: Record<string, React.ReactNode> = {
  file: <FileOutlined />,
  network: <GlobalOutlined />,
  database: <DatabaseOutlined />,
  mcp: <ThunderboltOutlined />,
  system: <SettingOutlined />,
}

const RISK_COLORS: Record<string, string> = {
  low: 'green',
  medium: 'orange',
  high: 'red',
  critical: 'magenta',
}

const DECISION_COLORS: Record<string, string> = {
  allow: 'green',
  audit: 'blue',
  confirm: 'orange',
  block: 'red',
}

const TOOL_TYPE_LABELS: Record<string, string> = {
  file: '文件操作',
  network: '网络请求',
  database: '数据库操作',
  mcp: 'MCP 调用',
  system: '系统命令',
  unknown: '未识别工具调用',
}

const DISPOSITION_LABELS: Record<string, string> = {
  open: '未处理',
  resolved: '已处理',
  false_positive: '已确认误报',
  accepted: '已确认风险',
  escalated: '跟进中',
}

const DISPOSITION_COLORS: Record<string, string> = {
  open: 'default',
  resolved: 'green',
  false_positive: 'blue',
  accepted: 'orange',
  escalated: 'processing',
}

const ALERT_SEVERITY_OPTIONS = [
  { label: '全部级别', value: 'all' },
  ...severityOptions(),
]

const ALERT_DISPOSITION_OPTIONS = [
  { label: '全部状态', value: 'all' },
  { label: '未处理', value: 'open' },
  { label: '跟进中', value: 'escalated' },
  { label: '已处理', value: 'resolved' },
  { label: '已确认误报', value: 'false_positive' },
  { label: '已确认风险', value: 'accepted' },
]

const ALERT_TOOL_TYPE_OPTIONS = [
  { label: '全部工具', value: 'all' },
  { label: '系统命令', value: 'system' },
  { label: '文件操作', value: 'file' },
  { label: '网络请求', value: 'network' },
  { label: '数据库操作', value: 'database' },
  { label: 'MCP 调用', value: 'mcp' },
  { label: '未识别工具', value: 'unknown' },
]

const ALERT_MODE_OPTIONS = [
  { label: '全部动作', value: 'all' },
  { label: '放行', value: 'allow' },
  { label: '审计', value: 'audit' },
  { label: '人工确认', value: 'confirm' },
  { label: '阻断', value: 'block' },
]

const ALERT_TIME_RANGE_OPTIONS = [
  { label: '全部时间', value: 'all' },
  { label: '近 1 小时', value: '1h' },
  { label: '近 24 小时', value: '24h' },
  { label: '近 7 天', value: '7d' },
  { label: '近 30 天', value: '30d' },
]

const ALERT_TIME_RANGE_MS: Record<string, number> = {
  '1h': 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
}

type AlertFilterState = {
  keyword: string
  severity: string
  disposition: string
  toolType: string
  timeRange: string
  mode: string
  policyId: string
}

type ActiveTriage = 'all' | 'action_required' | 'review' | 'audit' | 'follow_up' | 'handled'

const TOOL_DRILLDOWN_KEYS = ['risk_level', 'mode', 'policy_id', 'tool_name', 'agent_type', 'user_id', 'client_id', 'project_id', 'session_id', 'raw_decision', 'effective_decision', 'server', 'keyword']
const TOOL_DRILLDOWN_PAGE_SIZE = 20

const hasToolDrilldownFilters = (searchParams: URLSearchParams) =>
  TOOL_DRILLDOWN_KEYS.some((key) => !!searchParams.get(key))

const DEFAULT_ALERT_FILTERS: AlertFilterState = {
  keyword: '',
  severity: 'all',
  disposition: 'all',
  toolType: 'all',
  timeRange: 'all',
  mode: 'all',
  policyId: '',
}

const linkedTimeWindowParams = (searchParams: URLSearchParams) => {
  const from = searchParams.get('from')
  const to = searchParams.get('to')
  if (from && to) {
    const fromTime = Date.parse(from)
    const toTime = Date.parse(to)
    if (!Number.isNaN(fromTime) && !Number.isNaN(toTime) && toTime > fromTime) {
      return { from, to }
    }
  }
  return boundedTimeWindowParams(24)
}

const getDispositionSubjectId = (item: any) =>
  typeof item === 'string' ? item : item?.id || ''
const isSecurityEventItem = (item: any) =>
  item?.event_source === 'security_event'
const normalizeFindings = (value: any): any[] =>
  Array.isArray(value) ? value : []
const isEvalSecurityEvent = (event: any) => {
  const summary = event?.matched_summary || event || {}
  return event?.event_type === 'eval_content_safety' || summary.source === 'llm_safety_eval'
}
const ACCESS_TYPE_LABELS: Record<string, string> = {
  llm: '大模型访问',
  ai_ide: 'AI 编程工具访问',
  normal_public: '普通公网访问',
  unknown_ai_candidate: '待识别 AI 访问',
}
const getAccessTypeLabel = (value?: string) =>
  value ? ACCESS_TYPE_LABELS[value] || value : '未记录'
const AI_PRODUCT_LABELS: Record<string, string> = {
  cursor_agent: 'Cursor Agent',
  cursor_api: 'Cursor API',
  cursor_tab: 'Cursor Tab / 代码补全',
  cursor_codebase_indexing: 'Cursor 代码库索引',
  github_copilot: 'GitHub Copilot / VS Code Copilot',
  github_copilot_telemetry: 'GitHub Copilot 遥测',
  github_copilot_reports: 'GitHub Copilot 报表',
  windsurf_codeium: 'Windsurf / Codeium',
  jetbrains_ai: 'JetBrains AI Assistant',
  sourcegraph_cody: 'Sourcegraph Cody',
  continue_dev: 'Continue',
}
const getAIProductLabel = (value?: string) =>
  value ? AI_PRODUCT_LABELS[value] || value : ''

const displayAlertName = (item: any) => getToolNameLabel(item.tool_name)

const normalizeToolType = (toolType?: string) =>
  toolType && toolType !== 'unknown' ? toolType : 'unknown'
const shouldShowToolAlert = (log: any) => {
  const action = String(log?.matched_action || log?.mode || '').toLowerCase()
  const status = String(log?.status || '').toLowerCase()
  return !(
    normalizeToolType(log?.tool_type) === 'system' &&
    action === 'audit' &&
    status !== 'blocked' &&
    status !== 'denied'
  )
}
const getToolTypeLabel = (toolType?: string) =>
  TOOL_TYPE_LABELS[normalizeToolType(toolType)] ||
  toolType ||
  TOOL_TYPE_LABELS.unknown
const getToolTypeIcon = (toolType?: string) =>
  TOOL_TYPE_ICONS[normalizeToolType(toolType)] || <ToolOutlined />
const getToolCategoryLabel = (toolType?: string) =>
  normalizeToolType(toolType) === 'unknown'
    ? '未识别工具'
    : getToolRiskCategory(toolType)

const formatAlertTime = (value?: string) => {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '-'
  return date.toLocaleString('zh-CN', { hour12: false })
}

const hasAgentGuardDecision = (item: any) =>
  Boolean(
    item?.raw_decision ||
    item?.effective_decision ||
    item?.provenance ||
    item?.normalized_target,
  )

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

const formatPercent = (value?: number) =>
  typeof value === 'number' ? `${Math.round(value * 100)}%` : '未记录'

const formatDisplayValue = (value: any) => {
  if (value === undefined || value === null || value === '') return '未记录'
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

const formatCustomerText = (value: any) => {
  const text = formatDisplayValue(value)
  return text
    .replace(/argument_tainted/g, getToolEvidenceRuleLabel('argument_tainted'))
    .replace(
      /command_shell_metacharacter/g,
      getToolEvidenceRuleLabel('command_shell_metacharacter'),
    )
    .replace(/provenance/g, getToolEvidenceRuleLabel('provenance'))
    .replace(/network\.upload/g, getToolNameLabel('network.upload'))
    .replace(/network\.fetch/g, getToolNameLabel('network.fetch'))
    .replace(/\bBash\b/g, getToolNameLabel('bash'))
    .replace(/\bShell\b/g, getToolNameLabel('shell'))
}

const renderFieldValue = (label: string, value: React.ReactNode) => (
  <Col span={12}>
    <Text type="secondary">{label}</Text>
    <div>{value}</div>
  </Col>
)

const renderToolParameters = (parameters: any) => {
  if (
    !parameters ||
    (typeof parameters === 'object' &&
      !Array.isArray(parameters) &&
      !Object.keys(parameters).length)
  ) {
    return <Text type="secondary">暂无调用参数</Text>
  }
  const entries =
    typeof parameters === 'object' && !Array.isArray(parameters)
      ? Object.entries(parameters)
      : [['value', parameters]]
  return (
    <div
      style={{
        display: 'grid',
        gap: 8,
        background: 'var(--bg-secondary)',
        padding: 10,
        borderRadius: 6,
      }}
    >
      {entries.map(([key, value]) => (
        <div key={String(key)}>
          <Text type="secondary" style={{ display: 'block', marginBottom: 2 }}>
            {getToolParameterLabel(String(key))}
          </Text>
          <Text
            style={{
              display: 'block',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
            }}
          >
            {key === '_audit_notes' && Array.isArray(value)
              ? value.map((note) => getToolAuditNoteLabel(String(note))).join('\n')
              : formatDisplayValue(value)}
          </Text>
        </div>
      ))}
    </div>
  )
}

const getAgentGuardEventLabel = (item: any, dispositionStatus?: string) => {
  if (dispositionStatus === 'false_positive')
    return {
      color: 'blue',
      label: '已确认误报',
      description:
        '该记录保留为原始告警日志，不计入真实告警事件；可生成有过期时间的例外建议。',
    }
  if (dispositionStatus === 'accepted')
    return {
      color: 'orange',
      label: '已确认真实告警',
      description: '已由管理员确认是真实安全事件，应进入后续处置和复盘闭环。',
    }
  if (dispositionStatus === 'resolved')
    return {
      color: 'green',
      label: '真实告警已处置',
      description: '该事件已完成处置闭环，原始判定和证据仍保留用于审计。',
    }
  if (dispositionStatus === 'escalated')
    return {
      color: 'processing',
      label: '真实告警跟进中',
      description: '该事件需要继续调查，暂不关闭。',
    }
  if (item?.effective_decision === 'block')
    return {
      color: 'red',
      label: '待确认真实告警',
      description: '实际动作已阻断。请在这里确认是真实告警、误报，或转入跟进。',
    }
  if (item?.effective_decision === 'confirm')
    return {
      color: 'orange',
      label: '待人工确认事件',
      description: '本次工具调用需要人工确认，超时动作按策略执行。',
    }
  if (item?.raw_decision === 'audit' || item?.effective_decision === 'audit')
    return {
      color: 'blue',
      label: '原始告警日志',
      description:
        '当前仅留痕审计，不默认作为真实告警；复核后可确认风险或标记误报。',
    }
  if (!item?.raw_decision || !item?.effective_decision)
    return {
      color: 'default',
      label: '服务端决策未记录',
      description:
        '工具审计记录未保存原始或生效决策，无法据此判断告警状态；如已加载，端点本地决策来源见下方。',
    }
  return {
    color: 'default',
    label: '未形成真实告警',
    description: '未命中阻断或确认动作，仅保留原始工具调用日志。',
  }
}

const renderAgentGuardDetails = (item: any, dispositionStatus?: string) => {
  if (!hasAgentGuardDecision(item)) return null
  const evidenceList = normalizeJsonArray(item.evidence_json)
  const taintedArguments = normalizeJsonArray(item.tainted_arguments)
  const event = getAgentGuardEventLabel(item, dispositionStatus)
  const decisionReason = getReadableToolReason(
    item.effective_reason || item.match_reason,
  )
  return (
    <div style={{ marginBottom: 12 }}>
      <div
        style={{
          marginBottom: 12,
          padding: 12,
          border: '1px solid var(--border-color)',
          borderRadius: 6,
        }}
      >
        <Space size={8} wrap style={{ marginBottom: 8 }}>
          <Text strong>服务端策略判定</Text>
          <Tag color={event.color}>{event.label}</Tag>
        </Space>
        <Text style={{ display: 'block', marginBottom: 10 }}>
          {event.description}
        </Text>
        <Row gutter={[8, 10]}>
          {renderFieldValue(
            '原始判定',
            <Tag color={DECISION_COLORS[item.raw_decision] || 'default'}>
              {getDecisionLabel(item.raw_decision)}
            </Tag>,
          )}
          {renderFieldValue(
            '实际动作',
            <Tag color={DECISION_COLORS[item.effective_decision] || 'default'}>
              {getDecisionLabel(item.effective_decision)}
            </Tag>,
          )}
          {renderFieldValue(
            '生效模式',
            <Tag>{getExecutionModeLabel(item.mode)}</Tag>,
          )}
          {renderFieldValue(
            '来源可信度',
            <Tag color={item.provenance === 'tainted' ? 'red' : 'blue'}>
              {getProvenanceLabel(item.provenance)}
            </Tag>,
          )}
          {renderFieldValue(
            '置信度',
            <Text>{formatPercent(item.confidence)}</Text>,
          )}
        </Row>
        <div style={{ marginTop: 10 }}>
          <Text type="secondary">判定原因：</Text>
          <Text>{decisionReason}</Text>
        </div>
        {item.policy_version || item.trace_id ? (
          <div style={{ marginTop: 8 }}>
            <Text type="secondary">策略版本：</Text>
            <Text>{item.policy_version || '未记录'}</Text>
            <Text type="secondary" style={{ marginLeft: 16 }}>
              追踪编号：
            </Text>
            <Text>{item.trace_id || '未记录'}</Text>
          </div>
        ) : null}
        {item.normalized_target ? (
          <div style={{ marginTop: 8 }}>
            <Text type="secondary">风险目标</Text>
            <Text style={{ display: 'block', wordBreak: 'break-all' }}>
              {item.normalized_target}
            </Text>
          </div>
        ) : null}
        {taintedArguments.length ? (
          <div style={{ marginTop: 8 }}>
            <Text type="secondary">命中参数</Text>
            <div style={{ marginTop: 4 }}>
              {taintedArguments.map((arg) => (
                <Tag key={String(arg)} color="red">
                  {getToolParameterLabel(String(arg))}
                </Tag>
              ))}
            </div>
          </div>
        ) : null}
        <div style={{ marginTop: 8 }}>
          <Text type="secondary">安全证据</Text>
          {evidenceList.length ? (
            evidenceList.map((evidence, index) => (
              <div
                key={String(evidence.rule_id || 'evidence') + '-' + index}
                style={{
                  marginTop: 6,
                  padding: 8,
                  background: 'var(--bg-secondary)',
                  borderRadius: 4,
                }}
              >
                <Space size={4} wrap>
                  <Tag color="purple">
                    {getToolEvidenceRuleLabel(evidence.rule_id)}
                  </Tag>
                  {evidence.category ? (
                    <Tag>{getRiskCategoryLabel(evidence.category)}</Tag>
                  ) : null}
                  {evidence.source_field ? (
                    <Tag color="blue">
                      {getToolParameterLabel(evidence.source_field)}
                    </Tag>
                  ) : null}
                </Space>
                {evidence.masked_preview ? (
                  <Text style={{ display: 'block', marginTop: 4 }}>
                    {evidence.masked_preview}
                  </Text>
                ) : null}
                {evidence.hash ? (
                  <Text
                    type="secondary"
                    style={{
                      display: 'block',
                      wordBreak: 'break-all',
                      fontSize: 12,
                    }}
                  >
                    证据指纹：{evidence.hash}
                  </Text>
                ) : null}
              </div>
            ))
          ) : (
            <div style={{ marginTop: 4 }}>
              <Text type="secondary">暂无证据</Text>
            </div>
          )}
        </div>
      </div>
      <div
        style={{
          marginBottom: 12,
          padding: 12,
          border: '1px solid var(--border-color)',
          borderRadius: 6,
        }}
      >
        <Space style={{ marginBottom: 8 }}>
          <Text strong>真实告警事件</Text>
          <Tag color={event.color}>{event.label}</Tag>
        </Space>
        <Text style={{ display: 'block' }}>{event.description}</Text>
      </div>
    </div>
  )
}

const readableEvidencePreview = (finding: any) => {
  if (!finding || typeof finding !== 'object') return ''
  // 有内容证据权限时接口带回命中原文，先显示原文。
  const raw = rawEvidenceDisplay(typeof finding.raw_evidence === 'string' ? finding.raw_evidence : '', finding.raw_evidence_truncated === true)
  if (raw) return raw
  const previewKey = Object.keys(finding).find(
    (key) =>
      key.endsWith('_preview') &&
      typeof finding[key] === 'string' &&
      finding[key],
  )
  if (previewKey) return finding[previewKey]
  return (
    finding.matched_text_preview ||
    finding.redacted_evidence ||
    finding.masked_preview ||
    ''
  )
}

const renderProxySecurityEventDetails = (item: any) => {
  if (!isSecurityEventItem(item)) return null
  const summary = item.matched_summary || {}
  const findings = normalizeFindings(summary.findings)
  const evalEvent = isEvalSecurityEvent({ matched_summary: summary })
  return (
    <div style={{ marginBottom: 12 }}>
      <div
        style={{
          marginBottom: 12,
          padding: 12,
          border: '1px solid var(--border-color)',
          borderRadius: 6,
        }}
      >
        <Space size={8} wrap style={{ marginBottom: 8 }}>
          <Text strong>
            {evalEvent ? '内容安全评估事件' : '代理访问安全事件'}
          </Text>
          {evalEvent ? (
            <Tag color="red">LSE 评估发现</Tag>
          ) : (
            <Tag color={summary.access_type === 'ai_ide' ? 'purple' : 'blue'}>
              {getAccessTypeLabel(summary.access_type)}
            </Tag>
          )}
          <Tag color={item.status === 'blocked' ? 'red' : 'blue'}>
            {getToolStatusLabel(item.status)}
          </Tag>
        </Space>
        <Row gutter={[8, 10]}>
          {evalEvent
            ? renderFieldValue(
                '风险域',
                <Text>{summary.risk_domain || '未记录'}</Text>,
              )
            : renderFieldValue(
                '服务商',
                <Text>{summary.provider || '未记录'}</Text>,
              )}
          {evalEvent
            ? renderFieldValue(
                '样本 ID',
                <Text>{summary.sample_id || '未记录'}</Text>,
              )
            : renderFieldValue(
                '产品',
                <Text>{getAIProductLabel(summary.product) || '未记录'}</Text>,
              )}
          {evalEvent
            ? renderFieldValue(
                '评估任务',
                <Text>{summary.task_id || '未记录'}</Text>,
              )
            : renderFieldValue(
                '访问目标',
                <Text style={{ wordBreak: 'break-all' }}>
                  {summary.target_host || '未记录'}
                </Text>,
              )}
          {evalEvent
            ? renderFieldValue(
                '判定',
                <Text>{verdictLabel(summary.verdict)}</Text>,
              )
            : renderFieldValue(
                '检测阶段',
                <Text>
                  {summary.stage === 'input'
                    ? '请求输入'
                    : summary.stage === 'output'
                      ? '模型输出'
                      : summary.stage || '未记录'}
                </Text>,
              )}
          {evalEvent
            ? renderFieldValue(
                '期望/实际',
                <Text>
                  {[summary.expected_behavior, summary.actual_behavior]
                    .filter(Boolean)
                    .join(' / ') || '未记录'}
                </Text>,
              )
            : renderFieldValue(
                'HTTPS 审计',
                <Tag color={summary.tls_inspected ? 'green' : 'orange'}>
                  {summary.tls_inspected
                    ? '已解密，可检测内容'
                    : '仅元数据可见'}
                </Tag>,
              )}
          {renderFieldValue(
            '事件编号',
            <Text copyable>{item.security_event_id || item.id}</Text>,
          )}
        </Row>
        {!evalEvent && !summary.tls_inspected ? (
          <Alert
            type="warning"
            showIcon
            style={{ marginTop: 10 }}
            message="仅元数据可见"
            description="客户端未信任网关 CA 或该连接未被解密时，只能看到域名、路径摘要和命中元信息，无法检测 prompt、代码片段或文件内容。"
          />
        ) : null}
        <div style={{ marginTop: 10 }}>
          <Text type="secondary">命中证据</Text>
          {findings.length ? (
            findings.map((finding, index) => (
              <div
                key={
                  String(finding.rule_id || finding.category || 'finding') +
                  '-' +
                  index
                }
                style={{
                  marginTop: 6,
                  padding: 8,
                  background: 'var(--bg-secondary)',
                  borderRadius: 4,
                }}
              >
                <Space size={4} wrap>
                  <Tag color="red">
                    {getRiskCategoryLabel(finding.category || finding.type)}
                  </Tag>
                  {finding.severity ? (
                    <Tag color={RISK_COLORS[finding.severity] || 'default'}>
                      {severityLabel(finding.severity)}
                    </Tag>
                  ) : null}
                  {finding.rule_id ? (
                    <Tag color="blue">
                      {formatCustomerText(finding.rule_id)}
                    </Tag>
                  ) : null}
                </Space>
                {readableEvidencePreview(finding) ? (
                  <Text style={{ display: 'block', marginTop: 4 }}>
                    {readableEvidencePreview(finding)}
                  </Text>
                ) : null}
              </div>
            ))
          ) : (
            <div style={{ marginTop: 4 }}>
              <Text type="secondary">暂无证据</Text>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function ToolAudit() {
  const auditIdentity = useAuditQueryIdentity()
  const queryClient = useQueryClient()
  const [searchParams] = useSearchParams()
  const [selectedSession, setSelectedSession] = useState<string | null>(null)
  const [selectedToolCall, setSelectedToolCall] = useState<any | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [activeTriage, setActiveTriage] = useState<ActiveTriage>('action_required')
  const [toolPage, setToolPage] = useState(1)
  const [committedKeyword, setCommittedKeyword] = useState('')
  const [alertFilters, setAlertFilters] = useState<AlertFilterState>({
    ...DEFAULT_ALERT_FILTERS,
  })
  const isLinkedDrilldown = useMemo(() => hasToolDrilldownFilters(searchParams), [searchParams])

  // Read session_id from URL on initial load and auto-open drawer
  useEffect(() => {
    const sessionIdParam = searchParams.get('session_id')
    if (sessionIdParam) {
      setSelectedSession(sessionIdParam)
      setSelectedToolCall(null)
      setDrawerOpen(true)
    }
  }, [searchParams])

  useEffect(() => {
    const riskLevel = searchParams.get('risk_level')
    const mode = searchParams.get('mode')
    const policyId = searchParams.get('policy_id')
    const keyword = searchParams.get('keyword') || ''
    if (!isLinkedDrilldown) return
    setToolPage(1)
    setAlertFilters((prev) => ({
      ...prev,
      keyword,
      severity: riskLevel && riskLevel !== 'all' && riskLevel !== 'high+' ? riskLevel : 'all',
      mode: mode || prev.mode,
      policyId: policyId || prev.policyId,
      timeRange: 'all',
    }))
    setCommittedKeyword(keyword)
    setActiveTriage('all')
  }, [isLinkedDrilldown, searchParams])

  const linkedToolFilters = useMemo(() => {
    const localWindowHours = alertFilters.timeRange === 'all'
      ? undefined
      : ALERT_TIME_RANGE_MS[alertFilters.timeRange] / (60 * 60 * 1000)
    const windowParams = localWindowHours
      ? boundedTimeWindowParams(localWindowHours)
      : linkedTimeWindowParams(searchParams)
    const params = {
      limit: TOOL_DRILLDOWN_PAGE_SIZE,
      offset: (toolPage - 1) * TOOL_DRILLDOWN_PAGE_SIZE,
      mode: searchParams.get('mode') || (alertFilters.mode !== 'all' ? alertFilters.mode : undefined),
      risk_level: searchParams.get('risk_level') || (alertFilters.severity !== 'all' ? alertFilters.severity : undefined),
      policy_id: searchParams.get('policy_id') || alertFilters.policyId || undefined,
      tool_name: searchParams.get('tool_name') || undefined,
      tool_type: alertFilters.toolType !== 'all' ? alertFilters.toolType : undefined,
      agent_type: searchParams.get('agent_type') || undefined,
      user_id: searchParams.get('user_id') || undefined,
      client_id: searchParams.get('client_id') || undefined,
      project_id: searchParams.get('project_id') || undefined,
      session_id: searchParams.get('session_id') || undefined,
      raw_decision: searchParams.get('raw_decision') || undefined,
      effective_decision: searchParams.get('effective_decision') || undefined,
      server: searchParams.get('server') || undefined,
      keyword: searchParams.get('keyword') || committedKeyword || undefined,
      disposition_status: alertFilters.disposition !== 'all' ? alertFilters.disposition : undefined,
      attention_only: !isLinkedDrilldown,
      skip_total: Boolean(searchParams.get('keyword') || committedKeyword),
      ...windowParams,
    }
    return params
  }, [alertFilters, committedKeyword, isLinkedDrilldown, searchParams, toolPage])

  // Queries
  const highRiskQ = useQuery({
    queryKey: ['tool-audit', auditIdentity, 'high-risk', linkedToolFilters],
    queryFn: ({ signal }) => toolAuditApi.listHighRisk({ ...linkedToolFilters, signal }),
  })
  const sessionQ = useQuery({
    queryKey: ['tool-audit', auditIdentity, 'session', selectedSession],
    queryFn: ({ signal }) => toolAuditApi.getSessionToolCalls(selectedSession!, { limit: 50, signal }),
    enabled: selectedSession !== null && drawerOpen,
  })
  const agentSessionQ = useQuery({
    queryKey: agentKeys.session(selectedSession || ''),
    queryFn: () => agentEndpointApi.session(selectedSession!),
    enabled: Boolean(selectedSession) && drawerOpen && isLinkedDrilldown,
  })

  const highRiskLogs = highRiskQ.data?.data?.data || []
  const toolAuditErrorMessage = highRiskQ.isError
    ? String(
        (highRiskQ.error as any)?.response?.data?.error?.message ||
          (highRiskQ.error as any)?.message ||
          '请稍后重试',
      )
    : ''
  const sessionLogs = sessionQ.data?.data || []
  const requestedToolCallId = searchParams.get('tool_call_log_id')
  const matchedToolCall = requestedToolCallId && (sessionLogs.find((log: any) => log.id === requestedToolCallId) || highRiskLogs.find((log: any) => log.id === requestedToolCallId))
  const triagedToolLogs = highRiskLogs
    .filter((log: any) => isLinkedDrilldown || shouldShowToolAlert(log))
    .map((log: any) => ({ ...log, triage: getToolTriage(log) }))
  const triagedHighRiskLogs = sortByTriage(triagedToolLogs)
  const getDispositionStatusForItem = (item?: any) => {
    if (typeof item === 'string') return 'open'
    return item?.disposition_status || 'open'
  }
  const isDispositionClosed = (item: any) => {
    const status = getDispositionStatusForItem(item)
    return (
      status === 'resolved' ||
      status === 'false_positive' ||
      status === 'accepted'
    )
  }
  const isDispositionFollowUp = (item: any) =>
    getDispositionStatusForItem(item) === 'escalated'
  const openToolLogs = triagedHighRiskLogs.filter(
    (item: any) => !isDispositionClosed(item) && !isDispositionFollowUp(item),
  )
  const followUpToolLogs = triagedHighRiskLogs.filter((item: any) =>
    isDispositionFollowUp(item),
  )
  const handledToolLogs = triagedHighRiskLogs.filter((item: any) =>
    isDispositionClosed(item),
  )
  const toolTriageSummary = summarizeTriage(
    openToolLogs.map((item) => item.triage),
  )
  const totalKnown = highRiskQ.data?.data?.total_known !== false
  const hasMore = Boolean(highRiskQ.data?.data?.has_more)
  const linkedDrilldownTotal = totalKnown
    ? Number(highRiskQ.data?.data?.total || 0)
    : (toolPage - 1) * TOOL_DRILLDOWN_PAGE_SIZE + highRiskLogs.length + (hasMore ? 1 : 0)
  const activeToolLogs =
    activeTriage === 'all'
      ? triagedHighRiskLogs
      : activeTriage === 'handled'
        ? handledToolLogs
        : activeTriage === 'follow_up'
          ? followUpToolLogs
          : openToolLogs.filter((item) => item.triage.level === activeTriage)
  const filteredToolLogs = activeToolLogs
  const hasActiveAlertFilters = Object.entries(alertFilters).some(
    ([key, value]) =>
      value !== DEFAULT_ALERT_FILTERS[key as keyof AlertFilterState],
  )
  const allQueueCount = triagedHighRiskLogs.length
  const tablePagination = {
    current: toolPage,
    pageSize: TOOL_DRILLDOWN_PAGE_SIZE,
    total: linkedDrilldownTotal,
    showTotal: (total: number) => `共 ${total} 条`,
    onChange: (page: number) => setToolPage(page),
  }
  const drawerLogs = selectedSession
    ? sessionQ.isError && matchedToolCall ? [matchedToolCall] : sessionLogs
    : selectedToolCall
      ? [selectedToolCall]
      : []

  const renderNativeLocalDecisionEvidence = (item: any) => {
    const session = agentSessionQ.data
    const events = session?.overview?.session_id === selectedSession && item.session_id === selectedSession
      ? exactToolPreEvents(session.events || [], session.overview, item)
      : []
    if (events.length === 0) {
      return <div style={{ marginBottom: 12 }}><Text type="secondary">未找到身份完整关联的端点本地决策事件</Text></div>
    }
    return events.map((event) => {
      const local = event.local_decision || {}
      const localDecision = String(local.effective_decision || local.effective || local.decision || local.raw_decision || local.raw || '')
      return <div key={event.id} style={{ marginBottom: 12, padding: 10, border: '1px solid rgba(128,128,128,0.25)', borderRadius: 8 }}>
        <Text strong>端点本地决策来源</Text>
        <Descriptions size="small" column={1} items={[
          { label: '端点 / 会话', children: event.endpoint_id + ' / ' + event.session_id },
          { label: '工具事件 / 调用', children: event.event_type + ' / ' + event.tool_name + ' / ' + event.tool_use_id },
          { label: '本地判定', children: localDecision || '未记录' },
          { label: '来源 / 模式', children: [local.source, local.mode].filter(Boolean).join(' / ') || '未记录' },
          { label: '规则', children: String(local.rule_id || local.matched_rule_id || '未记录') },
          { label: '策略版本', children: local.policy_version == null ? '未记录' : String(local.policy_version) },
          { label: '风险等级', children: String(local.risk_level || '未记录') },
        ]} />
      </div>
    })
  }

  const dispositionMutation = useMutation({
    mutationFn: (payload: {
      subject_type: string
      subject_id: string
      status: AuditDispositionStatus
      note?: string
    }) => auditDispositionApi.upsert(payload),
    onSuccess: () => {
      message.success('处置状态已保存')
      queryClient.invalidateQueries({
        queryKey: ['tool-audit', auditIdentity, 'high-risk'],
      })
    },
    onError: () => message.error('处置状态保存失败'),
  })

  const suggestExceptionMutation = useMutation({
    mutationFn: (payload: { tool_call_id: string; reason: string }) =>
      agentGuardApi.suggestException(payload),
    onSuccess: () => message.success('例外建议已生成'),
    onError: () => message.error('例外建议生成失败'),
  })

  const setAlertFilter = (key: keyof AlertFilterState, value: string) => {
    setToolPage(1)
    setAlertFilters((prev) => ({ ...prev, [key]: value }))
  }

  const resetAlertFilters = () => {
    setToolPage(1)
    setCommittedKeyword('')
    setAlertFilters({ ...DEFAULT_ALERT_FILTERS })
  }

  const renderDispositionTag = (item?: any) => {
    const status = getDispositionStatusForItem(item)
    return (
      <Tag color={DISPOSITION_COLORS[status] || 'default'}>
        {DISPOSITION_LABELS[status] || status}
      </Tag>
    )
  }

  const handleDisposition = (
    item: any,
    status: AuditDispositionStatus,
    note?: string,
  ) => {
    const subjectId = getDispositionSubjectId(item)
    if (!subjectId) {
      message.warning('缺少工具调用 ID')
      return
    }
    dispositionMutation.mutate({
      subject_type: 'tool_call',
      subject_id: subjectId,
      status,
      note,
    })
  }

  const handleFalsePositiveEvent = (item: any) => {
    if (!item?.id) {
      message.warning('缺少工具调用 ID')
      return
    }
    handleDisposition(item, 'false_positive', '已在安全告警中确认误报')
    if (hasAgentGuardDecision(item)) {
      suggestExceptionMutation.mutate({
        tool_call_id: item.id,
        reason: '已在安全告警中确认误报，生成有过期时间的例外建议',
      })
    }
  }

  const renderDispositionActions = (
    item: any,
    options?: { suggestException?: boolean },
  ) => {
    const canSuggestException =
      Boolean(options?.suggestException) &&
      typeof item !== 'string' &&
      hasAgentGuardDecision(item)
    return (
      <Space size={4} wrap>
        <Button
          aria-label="标记已处理"
          size="small"
          onClick={() => handleDisposition(item, 'resolved', '已完成告警处置')}
          loading={dispositionMutation.isPending}
        >
          处理
        </Button>
        <Button
          aria-label={
            canSuggestException ? '标记误报并生成例外建议' : '标记误报'
          }
          size="small"
          onClick={() =>
            canSuggestException
              ? handleFalsePositiveEvent(item)
              : handleDisposition(item, 'false_positive', '已确认误报')
          }
          loading={
            dispositionMutation.isPending || suggestExceptionMutation.isPending
          }
        >
          {canSuggestException ? '误报+例外' : '误报'}
        </Button>
        <Button
          aria-label="确认真实告警"
          size="small"
          onClick={() => handleDisposition(item, 'accepted', '已确认真实告警')}
          loading={dispositionMutation.isPending}
        >
          确认
        </Button>
        <Button
          aria-label="转入跟进"
          size="small"
          onClick={() =>
            handleDisposition(item, 'escalated', '转入安全事件跟进')
          }
          loading={dispositionMutation.isPending}
        >
          跟进
        </Button>
      </Space>
    )
  }

  return (
    <div className="enterprise-page">
      <EnterprisePageHeader
        eyebrow="安全运营中心"
        title={isLinkedDrilldown ? '工具调用明细' : '安全告警'}
        description={isLinkedDrilldown ? '按概览入口的同一时间窗口和筛选条件展示工具调用原始明细。' : '统一处理原始告警日志、智能体工具调用风险和确认后的真实告警事件。'}
        meta={
          <Space size={8} wrap>
            <StatusPill tone="red">处置闭环启用</StatusPill>
            <StatusPill tone="blue">原始日志与真实事件分层</StatusPill>
          </Space>
        }
      />

      <SectionPanel
        title={
          <Space>
            <WarningOutlined style={{ color: 'var(--brand-red)' }} />{' '}
            安全运营队列
          </Space>
        }
        description="按处置优先级组织告警，区分优先处理、人工复核、低危留痕、跟进中和已处理。"
        extra={<StatusPill tone="blue">告警处置闭环</StatusPill>}
      >
        <Spin spinning={highRiskQ.isLoading}>
          {highRiskQ.isError ? (
            <Alert
              type="error"
              showIcon
              message={isLinkedDrilldown ? '工具调用明细加载失败' : '安全运营队列加载失败'}
              description={toolAuditErrorMessage}
              style={{ marginBottom: 12 }}
            />
          ) : (
            <>
          <AnalysisFlow
            items={[
              {
                label: '本页优先处理',
                value: `${toolTriageSummary.actionRequired} 条待处置`,
                tone: 'red',
                description: '已阻断或需要立即确认的真实风险',
              },
              {
                label: '本页人工复核',
                value: `${toolTriageSummary.review} 条需复核`,
                tone: 'orange',
                description: '需要管理员判断是否转入事件',
              },
              {
                label: '本页低危留痕',
                value: `${toolTriageSummary.audit} 条仅审计`,
                tone: 'blue',
                description: '保留原始日志，不默认认定真实事件',
              },
              {
                label: '本页跟进中',
                value: `${followUpToolLogs.length} 条待闭环`,
                tone: 'purple',
                description: '已转入处置但尚未关闭',
              },
            ]}
          />
          <Text type="secondary" style={{ display: 'block', marginBottom: 8, fontSize: 12 }}>
            本页分组，不改变服务端筛选结果
          </Text>
          <Segmented
            className="enterprise-queue-tabs"
            style={{ marginBottom: 12 }}
            value={activeTriage}
            onChange={(value) => setActiveTriage(value as ActiveTriage)}
            options={[
              {
                label: `本页全部 ${allQueueCount}`,
                value: 'all',
              },
              {
                label: `本页优先处理 ${toolTriageSummary.actionRequired}`,
                value: 'action_required',
              },
              {
                label: `本页人工复核 ${toolTriageSummary.review}`,
                value: 'review',
              },
              {
                label: `本页低危留痕 ${toolTriageSummary.audit}`,
                value: 'audit',
              },
              {
                label: `本页跟进中 ${followUpToolLogs.length}`,
                value: 'follow_up',
              },
              { label: `本页已处理 ${handledToolLogs.length}`, value: 'handled' },
            ]}
          />
          <div
            style={{
              marginBottom: 12,
              padding: 12,
              border: '1px solid var(--border-color)',
              borderRadius: 8,
              background: 'var(--bg-secondary)',
            }}
          >
            <Space
              size={[8, 8]}
              wrap
              style={{ width: '100%', justifyContent: 'space-between' }}
            >
              <Space size={[8, 8]} wrap>
                <Input.Search
                  aria-label="告警关键词筛选"
                  allowClear
                  placeholder="搜索工具、策略或建议"
                  value={alertFilters.keyword}
                  onChange={(event) =>
                    {
                      const value = event.target.value
                      setAlertFilter('keyword', value)
                      if (!value) setCommittedKeyword('')
                    }
                  }
                  onSearch={(value) => {
                    setToolPage(1)
                    setCommittedKeyword(value.trim())
                  }}
                  style={{ width: 240 }}
                />
                <Select
                  aria-label="关注级别筛选"
                  value={alertFilters.severity}
                  options={ALERT_SEVERITY_OPTIONS}
                  onChange={(value) => setAlertFilter('severity', value)}
                  style={{ width: 124 }}
                />
                <Select
                  aria-label="处置状态筛选"
                  value={alertFilters.disposition}
                  options={ALERT_DISPOSITION_OPTIONS}
                  onChange={(value) => setAlertFilter('disposition', value)}
                  style={{ width: 140 }}
                />
                <Select
                  aria-label="工具类型筛选"
                  value={alertFilters.toolType}
                  options={ALERT_TOOL_TYPE_OPTIONS}
                  onChange={(value) => setAlertFilter('toolType', value)}
                  style={{ width: 132 }}
                />
                <Select
                  aria-label="动作筛选"
                  value={alertFilters.mode}
                  options={ALERT_MODE_OPTIONS}
                  onChange={(value) => setAlertFilter('mode', value)}
                  style={{ width: 120 }}
                />
                <Input
                  aria-label="策略 ID 筛选"
                  allowClear
                  placeholder="策略 ID"
                  value={alertFilters.policyId}
                  onChange={(event) =>
                    setAlertFilter('policyId', event.target.value)
                  }
                  style={{ width: 150 }}
                />
                <Select
                  aria-label="时间范围筛选"
                  value={alertFilters.timeRange}
                  options={ALERT_TIME_RANGE_OPTIONS}
                  onChange={(value) => setAlertFilter('timeRange', value)}
                  style={{ width: 132 }}
                />
              </Space>
              <Space size={8} wrap>
                <Text type="secondary" style={{ fontSize: 12 }}>
                  <span>显示 {filteredToolLogs.length} / {linkedDrilldownTotal} 条</span>
                  <span>；{totalKnown ? '服务端精确总数' : hasMore ? '服务端仍有下一页' : '服务端已到末页'}</span>
                </Text>
                <Button
                  size="small"
                  disabled={!hasActiveAlertFilters}
                  onClick={resetAlertFilters}
                >
                  重置筛选
                </Button>
              </Space>
            </Space>
          </div>
          <ResizableTable
            columnStorageKey="tool-audit-high-risk-columns"
            minColumnWidth={68}
            maxColumnWidth={420}
            dataSource={filteredToolLogs}
            rowKey="id"
            pagination={tablePagination}
            columns={[
              ...(activeTriage === 'handled'
                ? []
                : [
                    {
                      title: '关注级别',
                      key: 'triage',
                      width: 78,
                      render: (_: unknown, r: any) => (
                        <Tag color={r.triage.color}>{r.triage.label}</Tag>
                      ),
                    },
                  ]),
              {
                title: activeTriage === 'handled' ? '处理结果' : '处置状态',
                key: 'disposition',
                width: 88,
                render: (_: unknown, r: any) => renderDispositionTag(r),
              },
              {
                title: '发生时间',
                key: 'created_at',
                width: 145,
                render: (_: unknown, r: any) => (
                  <Space direction="vertical" size={0}>
                    <Text style={{ fontSize: 12 }}>
                      {formatAlertTime(r.created_at)}
                    </Text>
                    <Text type="secondary" style={{ fontSize: 12 }}>
                      {r.user_id || r.request_id || '来源未记录'}
                    </Text>
                  </Space>
                ),
              },
              {
                title: '工具',
                key: 'tool',
                width: 150,
                render: (_: unknown, r: any) => (
                  <Space direction="vertical" size={2}>
                    <Text strong style={{ fontSize: 12 }}>
                      {displayAlertName(r)}
                    </Text>
                    <Space size={4} wrap>
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        {getToolTypeIcon(r.tool_type)}{' '}
                        {getToolTypeLabel(r.tool_type)}
                      </Text>
                      <Tag color="purple">
                        {getToolCategoryLabel(r.tool_type)}
                      </Tag>
                      {isSecurityEventItem(r) ? (
                        <Tag color="geekblue">安全事件</Tag>
                      ) : null}
                    </Space>
                  </Space>
                ),
              },
              {
                title: '命中策略',
                key: 'matched_policy',
                width: 155,
                ellipsis: true,
                render: (_: unknown, r: any) => (
                  <Space direction="vertical" size={2}>
                    <Tag color="blue">{getToolPolicyName(r)}</Tag>
                    <Text type="secondary" style={{ fontSize: 12 }}>
                      {getToolMatchReason(r)}
                    </Text>
                  </Space>
                ),
              },
              ...(activeTriage === 'handled'
                ? []
                : [
                    {
                      title: '处置建议',
                      key: 'triage_advice',
                      render: (_: unknown, r: any) => (
                        <Space direction="vertical" size={2}>
                          <Text style={{ fontSize: 12 }}>
                            {r.triage.reason}
                          </Text>
                          <Text type="secondary" style={{ fontSize: 12 }}>
                            {r.triage.advice}
                          </Text>
                        </Space>
                      ),
                    },
                  ]),
              {
                title: '操作',
                key: 'actions',
                width: activeTriage === 'handled' ? 110 : 240,
                render: (_, r: any) => (
                  <Space size={4} wrap>
                    <Button
                      aria-label="查看详情"
                      size="small"
                      icon={<EyeOutlined />}
                      onClick={() => {
                        setSelectedToolCall(r)
                        setSelectedSession(r.session_id || null)
                        setDrawerOpen(true)
                      }}
                    >
                      详情
                    </Button>
                    {activeTriage === 'handled'
                      ? null
                      : renderDispositionActions(r)}
                  </Space>
                ),
              },
            ]}
          />
            </>
          )}
        </Spin>
      </SectionPanel>

      {/* Session Tool Calls Timeline Drawer */}
      <Drawer
        title={
          selectedSession
            ? `会话工具调用详情: ${selectedSession}`
            : selectedToolCall && isSecurityEventItem(selectedToolCall)
              ? '安全事件详情'
              : '工具调用详情'
        }
        open={drawerOpen}
        onClose={() => {
          if (selectedSession) {
            queryClient.cancelQueries({
              queryKey: ['tool-audit', auditIdentity, 'session', selectedSession],
            })
          }
          setDrawerOpen(false)
          setSelectedSession(null)
          setSelectedToolCall(null)
        }}
        width={700}
      >
        <Spin spinning={Boolean(selectedSession) && sessionQ.isLoading}>
          {!drawerLogs.length && !sessionQ.isLoading ? (
            <Empty description="暂无工具调用明细" />
          ) : null}
          {sessionQ.isError && selectedSession ? <Alert type="warning" showIcon message="完整会话工具明细暂不可用；仅展示审计列表中可核验的命中" style={{ marginBottom: 12 }} /> : null}
          {agentSessionQ.isError && selectedSession && isLinkedDrilldown ? <Alert type="warning" showIcon message="端点本地决策证据加载失败" description={String((agentSessionQ.error as any)?.response?.data?.error?.message || (agentSessionQ.error as any)?.message || '请检查权限或会话编号')} action={<Button size="small" onClick={() => void agentSessionQ.refetch()}>重试</Button>} style={{ marginBottom: 12 }} /> : null}
          {requestedToolCallId && selectedSession && !sessionQ.isLoading ? (matchedToolCall ? <Alert type="info" showIcon message={`已定位工具调用 ${requestedToolCallId}`} style={{ marginBottom: 12 }} /> : <Alert type="warning" showIcon message="本会话未返回该工具调用，无法确认具体审计记录" style={{ marginBottom: 12 }} />) : null}
          {matchedToolCall && matchedToolCall.session_id === selectedSession && agentSessionQ.data?.overview?.session_id === selectedSession && matchedToolCall.endpoint_id === agentSessionQ.data.overview.endpoint_id && agentSessionQ.data.overview.endpoint_id ? (
            <div style={{ marginBottom: 12 }}>关联端点：<Link to={`/agent/endpoints?endpoint=${encodeURIComponent(agentSessionQ.data.overview.endpoint_id)}`}>{agentSessionQ.data.overview.endpoint_id}</Link></div>
          ) : null}
          <List
            dataSource={drawerLogs}
            renderItem={(item: any) => (
              <List.Item
                style={{
                  borderLeft: `3px solid ${RISK_COLORS[item.risk_level] || '#ddd'}`,
                  background: requestedToolCallId === item.id ? 'rgba(22,119,255,0.12)' : undefined,
                  paddingLeft: 12,
                  marginBottom: 12,
                }}
              >
                <div style={{ width: '100%' }}>
                  <div style={{ marginBottom: 8 }}>
                    <Space>
                      {getToolTypeIcon(item.tool_type)}
                      <Text strong>{displayAlertName(item)}</Text>
                      {requestedToolCallId === item.id ? <Tag color="blue">当前定位</Tag> : null}
                      <Tag color={getToolTriage(item).color}>
                        {getToolTriage(item).label}
                      </Tag>
                      <Tag color="purple">
                        {getToolCategoryLabel(item.tool_type)}
                      </Tag>
                      <Tag color="blue">{getToolPolicyName(item)}</Tag>
                      {isSecurityEventItem(item) ? (
                        <Tag color="geekblue">安全事件</Tag>
                      ) : null}
                      <Tag
                        color={
                          item.status === 'success'
                            ? 'green'
                            : item.status === 'blocked'
                              ? 'red'
                              : item.status === 'audited'
                                ? 'blue'
                                : 'orange'
                        }
                      >
                        {getToolStatusLabel(item.status)}
                      </Tag>
                      {renderDispositionTag(item)}
                    </Space>
                    <Text type="secondary" style={{ marginLeft: 8 }}>
                      {new Date(item.created_at).toLocaleString()}
                    </Text>
                  </div>
                  <div style={{ marginBottom: 8 }}>
                    <Text type="secondary">关注原因:</Text>
                    <Text style={{ marginLeft: 8 }}>
                      {getToolTriage(item).reason}
                    </Text>
                  </div>
                  <div style={{ marginBottom: 8 }}>
                    <Text type="secondary">建议动作:</Text>
                    <Text style={{ marginLeft: 8 }}>
                      {getToolTriage(item).advice}
                    </Text>
                  </div>
                  <div style={{ marginBottom: 8 }}>
                    <Text type="secondary">命中依据:</Text>
                    <Text style={{ marginLeft: 8 }}>
                      {getToolMatchReason(item)}
                    </Text>
                  </div>
                  {renderProxySecurityEventDetails(item)}
                  {renderAgentGuardDetails(
                    item,
                    item.disposition_status,
                  )}
                  {isLinkedDrilldown ? renderNativeLocalDecisionEvidence(item) : null}
                  <div style={{ marginBottom: 8 }}>
                    <Text type="secondary">处置动作:</Text>
                    <div style={{ marginTop: 6 }}>
                      {renderDispositionActions(item, {
                        suggestException: true,
                      })}
                    </div>
                  </div>
                  <div style={{ marginBottom: 8 }}>
                    <Text type="secondary">调用参数</Text>
                    <div style={{ marginTop: 6 }}>
                      {renderToolParameters(item.parameters)}
                    </div>
                  </div>
                  {item.result && (
                    <div>
                      <Text type="secondary">执行结果</Text>
                      <Text
                        style={{
                          display: 'block',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-all',
                          maxWidth: '100%',
                          background: 'var(--bg-secondary)',
                          padding: 8,
                          borderRadius: 4,
                        }}
                      >
                        {item.result.length > 500
                          ? item.result.slice(0, 500) + '...'
                          : item.result}
                      </Text>
                    </div>
                  )}
                </div>
              </List.Item>
            )}
          />
        </Spin>
      </Drawer>
    </div>
  )
}

export default ToolAudit

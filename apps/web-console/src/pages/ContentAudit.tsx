import { useState, useEffect, useMemo, useRef } from 'react'
import { Typography, Card, Input, Button, Select, Tag, Spin, message, Space, Drawer, List, Descriptions, Segmented, Alert } from 'antd'
import { SearchOutlined, EyeOutlined, ExportOutlined, LeftOutlined, RightOutlined } from '@ant-design/icons'
import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import ResizableTable from '../components/ResizableTable'
import AlertOccurrences, { AlertOccurrenceSummary } from '../components/AlertOccurrences'
import type { AlertOccurrence, AlertOccurrenceParams } from '../services/alertOccurrences'
import { getFindingCategoryLabel } from '../utils/alertOccurrenceDisplay'
import { accessRetentionApi, auditApi, boundedTimeWindowParams, contentAuditApi, type ContentAuditListParams, type ContentAuditUserOption } from '../services/api'
import { EnterprisePageHeader, SectionPanel } from '../components/EnterpriseUI'
import CollapsibleFilters from '../components/CollapsibleFilters'
import { getRiskCategoryLabel, responsibilityDisplay, upstreamPrincipalLabel, NAT_SOURCE_NOTE, RISK_CATEGORY_LABELS, SEVERITY_LABELS, severityOptions } from '../utils/risk'
import {
  buildRuleEvidences,
  hasDirectApiCallLabel,
  findRelatedLogs,
  formatEvidenceLocation,
  isAgentMetaText,
  isAgentMetaUserMessage,
  recoverEvidencePreview,
  renderEvidenceContext,
} from '../utils/contentAuditEvidence'
import type { ContentAuditLog, ContentSecurityEvent, RuleEvidence } from '../utils/contentAuditEvidence'
import { minimumKeywordLength } from '../utils/keywordSearch'
import { formatAgentType } from '../utils/agents'
import { useAuthStore } from '../stores/auth'
import { canReadContentEvidence } from '../utils/access'
import { RAW_EVIDENCE_OMITTED_TEXT, RAW_EVIDENCE_TRUNCATED_SUFFIX } from '../utils/alertEvidence'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import { RECORD_MODE_PASS_LABEL } from '../utils/ws8ActionLabels'

const { Text, Paragraph } = Typography
const CONTENT_DETAIL_PAGE_SIZE = 20

// 责任主体四行的文案：与 proxy-server 的 principal_label 口径一致。
const ATTRIBUTION_USER_LABEL = '用户'
const ATTRIBUTION_UNLINKED_USER = '未关联用户'
const ATTRIBUTION_DEPARTMENT_PREFIX = '部门：'
const ATTRIBUTION_AGENT_LABEL = '智能体'
const ATTRIBUTION_CREDENTIAL_LABEL = '凭据 / 上游账号'
const ATTRIBUTION_CONVERSATION_LABEL = '对话 ID'
const ATTRIBUTION_VIEW_RETENTION = '查看留存'
const ATTRIBUTION_SOURCE_IP_PREFIX = '来源 IP '
const ATTRIBUTION_NO_CREDENTIAL = '未记录凭据名称'
const ATTRIBUTION_NOT_RECORDED = '未记录'
const ATTRIBUTION_TOOL_CALLS_TITLE = '工具调用'
const ATTRIBUTION_NO_TOOL_DETAILS = '未留存工具明细'

const ROLE_COLORS: Record<string, string> = {
  user: 'blue',
  assistant: 'green',
  system: 'purple',
  developer: 'purple',
  tool: 'orange',
}

const ROLE_LABELS: Record<string, string> = {
  user: '用户',
  assistant: 'AI',
  system: '系统',
  developer: '开发者指令',
  tool: '工具',
  other: '其它',
}

const SEVERITY_COLORS: Record<string, string> = {
  low: 'green',
  medium: 'gold',
  high: 'orange',
  critical: 'red',
}

const SEVERITY_RANK: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

const SUPPORTED_RISK_WINDOWS = new Set([0, 24, 24 * 7, 24 * 30, 24 * 90, 24 * 180])
const riskWindowFromSearch = (value: string | null, fallback = 0) => {
  if (value === null) return fallback
  const parsed = Number(value)
  return SUPPORTED_RISK_WINDOWS.has(parsed) ? parsed : fallback
}

const ACTION_LABELS: Record<string, string> = {
  allow: '放行',
  audit: '仅审计',
  alert: '告警',
  mask: '脱敏',
  block: '已拦截',
  security_audit_only: RECORD_MODE_PASS_LABEL,
  security_blocked: '已拦截',
}

const ACTION_COLORS: Record<string, string> = {
  allow: 'green',
  audit: 'blue',
  alert: 'gold',
  mask: 'purple',
  block: 'red',
}

type ConversationTurn = {
  key: string
  index: number
  user?: ContentAuditLog
  assistants: ContentAuditLog[]
  startedAt?: string
  tokens: number
}

const AGENT_RUNTIME_ASSISTANT_PATTERNS = [
  /^\[reasoning\]/i,
  /^<thinking>/i,
]

const AGENT_INVENTORY_SIGNAL_IDS = new Set([
  'agent_github_copilot',
  'agent_copilot_chat',
  'agent_cursor',
  'agent_claude_code',
  'agent_openai_codex',
  'agent_amazon_q',
  'agent_gemini_code_assist',
  'agent_cline',
  'agent_roo_code',
  'agent_windsurf',
  'agent_continue',
  'agent_aider',
  'agent_tabnine',
  'agent_sourcegraph_cody',
  'agent_replit_ai',
  'agent_coderabbit',
  'agent_langchain',
  'agent_llamaindex',
  'agent_crewai',
  'agent_autogen',
  'agent_dify',
  'agent_coze',
  'agent_autogpt',
  'agent_babyagi',
  'agent_direct_api_call',
  'agent_long_session',
  'agent_detect',
  'agent_behavior',
  'github_copilot',
  'cursor_agent',
])

const getRoleLabel = (role: string) => ROLE_LABELS[role] || role

const isAgentInventorySignal = (value?: string) => AGENT_INVENTORY_SIGNAL_IDS.has(String(value || '').toLowerCase())
const actionableRiskCategories = (record: any) => [
  ...(Array.isArray(record?.risk_categories) ? record.risk_categories : []),
  ...(Array.isArray(record?.risk_reasons) ? record.risk_reasons : []),
]
  .map((item) => String(item || '').trim())
  .filter((item) => item && !isAgentInventorySignal(item))

const agentTypeFromSignal = (value?: string) => {
  const normalized = String(value || '').trim().toLowerCase()
  if (!normalized.startsWith('agent_')) return ''
  if (['agent_direct_api_call', 'agent_long_session', 'agent_detect', 'agent_behavior'].includes(normalized)) return ''
  return normalized.slice('agent_'.length).replace(/_/g, '-')
}
const isLowRiskAgentSignal = (value?: string) => {
  const normalized = String(value || '').toLowerCase()
  return isAgentInventorySignal(normalized)
}
const isAgentRuntimeAssistantText = (content?: string) => AGENT_RUNTIME_ASSISTANT_PATTERNS.some((pattern) => pattern.test(String(content || '').trim()))

const isHiddenByDefault = (log: ContentAuditLog, previousLog?: ContentAuditLog) => {
  if (log.role === 'system' || log.role === 'tool') return true
  if (isAgentMetaUserMessage(log)) return true
  if (log.role === 'assistant' && (isAgentMetaUserMessage(previousLog) || isAgentRuntimeAssistantText(log.content))) return true
  return false
}

const summarizeText = (value?: string, fallback = '未识别到明确内容') => {
  const text = (value || '').replace(/\s+/g, ' ').trim()
  if (!text) return fallback
  return text.length > 180 ? `${text.slice(0, 180)}...` : text
}

const formatTokenUsage = (value?: number | string) => `${(Number(value) || 0).toLocaleString()} tokens`
const shortSessionId = (value?: string) => {
  if (!value) return '-'
  return value.length > 18 ? `${value.slice(0, 8)}...${value.slice(-5)}` : value
}

const ACCESS_RETENTION_SOURCE = 'access_retention'

const toResponseArray = (raw: any) =>
  Array.isArray(raw?.items) ? raw.items
    : Array.isArray(raw?.data) ? raw.data
      : Array.isArray(raw) ? raw
        : []

type ContentAuditSessionPage = {
  logs: ContentAuditLog[]
  total: number
  limit: number
  offset: number
  hasMore: boolean
}

const parseContentAuditSessionPage = (response: any, fallbackLimit: number): ContentAuditSessionPage => {
  const payload = response?.data
  const logs = (Array.isArray(payload) ? payload : toResponseArray(payload)) as ContentAuditLog[]
  const responseLimit = Number(payload?.limit)
  const responseOffset = Number(payload?.offset)
  const total = Array.isArray(payload) ? logs.length : Number(payload?.total) || logs.length
  const limit = Number.isFinite(responseLimit) && responseLimit > 0 ? responseLimit : fallbackLimit
  const offset = Number.isFinite(responseOffset) && responseOffset >= 0 ? responseOffset : 0
  const hasMore = typeof payload?.has_more === 'boolean'
    ? payload.has_more
    : offset < total && logs.length < total - offset

  return { logs, total, limit, offset, hasMore }
}
const accessRiskSeverity = (record: any) => {
  if (record?.risk_state === 'blocked') return 'high'
  if (record?.risk_state === 'risk') return Number(record?.security_event_count) > 0 ? 'medium' : 'low'
  return ''
}

const recordActionableAlertCount = (record: any) => (
  record?.actionable_alert_count == null
    ? Number(record?.security_event_count) || 0
    : Number(record?.actionable_alert_count) || 0
)

const isEnforcedAlertAction = (value?: string) => [
  'block',
  'blocked',
  'confirm',
  'reply',
  'tool_attempt_blocked',
  'tool_execution_risk',
].includes(String(value || '').trim().toLowerCase())

const hasContentRiskSignal = (record: any) => {
  const riskState = String(record?.risk_state || "").toLowerCase()
  const enforced = riskState === "blocked" || isEnforcedAlertAction(record?.action_taken)
  if (enforced) return true
  const allCategories = [
    ...(Array.isArray(record?.risk_categories) ? record.risk_categories : []),
    ...(Array.isArray(record?.risk_reasons) ? record.risk_reasons : []),
  ].map((item) => String(item || '').trim()).filter(Boolean)
  if (allCategories.length > 0 && actionableRiskCategories(record).length === 0) return false
  if (['low', 'info', 'informational'].includes(String(record?.highest_severity || '').toLowerCase())) return false
  return recordActionableAlertCount(record) > 0
}

const uniqueRecordsByRequest = (records: any[]) => {
  const seen = new Set<string>()
  return records.filter((record) => {
    const key = String(record?.request_id || record?.session_id || '')
    if (!key || seen.has(key)) return false
    seen.add(key)
    return true
  })
}

const recordOccurrenceTime = (record: any) => {
  const timestamp = Date.parse(String(record?.start_time || record?.created_at || ''))
  return Number.isFinite(timestamp) ? timestamp : 0
}

const buildRetainedAccessSession = (record: any) => {
  const riskReasons = Array.isArray(record?.risk_reasons) ? record.risk_reasons.filter(Boolean) : []
  return {
    _source: ACCESS_RETENTION_SOURCE,
    session_id: record?.request_id,
    request_id: record?.request_id,
    username: record?.username || '',
    user_id: record?.user_id || '',
    client_id: record?.client_id || '',
    client_name: record?.client_name || '',
    credential_type: record?.credential_type || (record?.client_name ? 'api_key' : ''),
    access_direction: record?.access_direction || '',
    source_ip: record?.source_ip || '-',
    start_time: record?.created_at,
    end_time: record?.created_at,
    message_count: record?.content_retained ? 2 : 1,
    turn_count: 1,
    snapshot_count: 1,
    total_tokens: 0,
    security_event_count: Number(record?.security_event_count) || 0,
    actionable_alert_count: Number(record?.actionable_alert_count) || 0,
    matched_rule_count: Math.max(riskReasons.length, Number(record?.security_event_count) || 0),
    highest_severity: accessRiskSeverity(record),
    risk_categories: riskReasons,
    risk_state: record?.risk_state,
    action_taken: record?.action_taken,
    target_host: record?.target_host,
    provider: record?.provider_cn || record?.provider,
    // 归属字段与 ListSessionsFiltered 的会话行同名，透传给抽屉的责任主体四行；
    // 访问留存投影暂时只带 agent_type / conversation_id，缺的字段按未记录渲染。
    agent_type: record?.agent_type || '',
    conversation_id: record?.conversation_id || '',
    department_id: record?.department_id || '',
    department_name: record?.department_name || '',
    principal_key: record?.principal_key || '',
    principal_proxy_nat: Boolean(record?.principal_proxy_nat),
    member_request_ids: Array.isArray(record?.member_request_ids) ? record.member_request_ids : [],
  }
}

const buildRetainedAccessLogs = (requestId: string, content: any, risk: any): ContentAuditLog[] => {
  const createdAt = risk?.start_time || risk?.created_at || new Date().toISOString()
  // New access-retention responses expose only the customer projection. Keep
  // the old raw fields as a compatibility fallback for historical deployments,
  // but never prefer them over user_input/model_output.
  const requestText = String(content?.user_input || content?.request_content || '').trim()
  const responseText = String(content?.model_output || content?.response_content || '').trim()
  const files = Array.isArray(content?.file_metadata) ? content.file_metadata : []
  const fileSummary = files
    .map((item: any) => [item?.file_name, item?.content_type, item?.text_preview].filter(Boolean).join(' | '))
    .filter(Boolean)
    .join('\n')
  const logs: ContentAuditLog[] = []

  if (requestText) {
    logs.push({
      id: `${requestId}-request`,
      request_id: requestId,
      role: isAgentMetaText(requestText) ? 'system' : 'user',
      content: requestText,
      tokens: 0,
      created_at: createdAt,
      whole_segment: true,
    })
  }
  if (responseText) {
    logs.push({
      id: `${requestId}-response`,
      request_id: requestId,
      role: 'assistant',
      content: responseText,
      tokens: 0,
      created_at: risk?.end_time || createdAt,
      whole_segment: true,
    })
  }
  if (!logs.length && fileSummary) {
    logs.push({
      id: `${requestId}-files`,
      request_id: requestId,
      role: 'user',
      content: fileSummary,
      tokens: 0,
      created_at: createdAt,
      whole_segment: true,
    })
  }
  return logs
}

const buildConversationTurns = (logs: ContentAuditLog[]) => {
  const turns: ConversationTurn[] = []
  let currentTurn: ConversationTurn | undefined

  logs.forEach((log) => {
    if (log.role === 'user') {
      currentTurn = {
        key: log.id || `${log.created_at}-${turns.length}`,
        index: turns.length + 1,
        user: log,
        assistants: [],
        startedAt: log.created_at,
        tokens: Number(log.tokens) || 0,
      }
      turns.push(currentTurn)
      return
    }

    if (log.role === 'assistant') {
      if (!currentTurn) {
        currentTurn = {
          key: log.id || `${log.created_at}-${turns.length}`,
          index: turns.length + 1,
          assistants: [],
          startedAt: log.created_at,
          tokens: 0,
        }
        turns.push(currentTurn)
      }

      currentTurn.assistants.push(log)
      currentTurn.tokens += Number(log.tokens) || 0
    }
  })

  return turns
}

const buildSessionOverview = (logs: ContentAuditLog[]) => {
  const visibleLogs = logs.filter((log, index) => !isHiddenByDefault(log, logs[index - 1]))
  const primaryUser = visibleLogs.find((log) => log.role === 'user')
  const assistant = [...visibleLogs].reverse().find((log) => log.role === 'assistant')
  const hiddenCount = logs.length - visibleLogs.length
  const totalTokens = logs.reduce((sum, log) => sum + (Number(log.tokens) || 0), 0)

  return {
    visibleLogs,
    turns: buildConversationTurns(visibleLogs),
    primaryUserText: summarizeText(primaryUser?.content, '未识别到明确用户意图'),
    assistantText: summarizeText(assistant?.content, '暂无模型输出摘要'),
    hiddenCount,
    totalTokens,
  }
}

const asEventArray = (raw: any): ContentSecurityEvent[] => {
  if (Array.isArray(raw?.data)) return raw.data
  if (Array.isArray(raw?.items)) return raw.items
  if (Array.isArray(raw)) return raw
  return []
}

const uniqueBy = <T,>(items: T[], getKey: (item: T) => string) => {
  const seen = new Set<string>()
  return items.filter((item) => {
    const key = getKey(item)
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

const isAgentInventoryEvidence = (evidence: RuleEvidence) =>
  isAgentInventorySignal(evidence.category) || isAgentInventorySignal(evidence.ruleId)

const parseRiskCategoryFilter = (value: string) => [...new Set(
  value.split(',').map((item) => item.trim()).filter(Boolean),
)]

const evidenceMatchesCategory = (evidence: RuleEvidence, category: string) => {
  if (!category) return true
  return evidence.category === category
    || evidence.ruleType === category
    || evidence.ruleId === category
}

const getContentRiskSummary = (risk?: any, evidences: RuleEvidence[] = []) => {
  const severity = [risk?.highest_severity, ...evidences.map((evidence) => evidence.severity)]
    .map((value) => String(value || '').toLowerCase())
    .filter((value) => value in SEVERITY_RANK)
    .reduce((highest, value) => SEVERITY_RANK[value] > (SEVERITY_RANK[highest] || 0) ? value : highest, '')
  const categories = Array.isArray(risk?.risk_categories) ? risk.risk_categories : []
  const effectiveCategories = categories.filter((category: string) => !isAgentInventorySignal(category))
  const inventoryOnlyCategories = categories.length > 0 && effectiveCategories.length === 0
  const effectiveEvidences = evidences.filter((evidence) => evidence.countsAsSecurityFinding && !isAgentInventoryEvidence(evidence))
  const inventoryOnlyEvidences = evidences.length > 0 && effectiveEvidences.length === 0
  const categoryItems = uniqueBy<{ value: string; label: string }>(effectiveCategories.map((category: string) => ({ value: category, label: getFindingCategoryLabel(category) })).filter((item: { value: string; label: string }) => item.label), (item) => item.value)
  const categoryLabels = categoryItems.map((item) => item.label)
  const matchedRuleCount = Number(risk?.matched_rule_count) || 0
  const securityEventCount = Number(risk?.security_event_count) || 0
  const mainCategory = categoryLabels[0] || '安全检测'
  const hasSensitiveData = effectiveCategories.some((category: string) => /secret|key|token|config|env|credential|data|leak|pii|file/.test(category))
  const hasPromptRisk = effectiveCategories.some((category: string) => /prompt|injection|encoding|keyword/.test(category))

  if ((inventoryOnlyCategories || inventoryOnlyEvidences) && effectiveEvidences.length === 0) {
    return {
      alertType: 'success' as const,
      title: '仅识别到 AI IDE 访问',
      description: '只命中了 GitHub Copilot/AI IDE 访问识别线索，未发现内容安全规则证据；该记录不应作为风险告警处置。',
      advice: '保留访问留存即可；只有叠加提示注入、敏感数据、越权工具调用等有效规则命中时才升级为安全告警。',
      categoryLabels: [],
      categoryItems: [],
      matchedRuleCount: 0,
      securityEventCount: 0,
      severity: '',
    }
  }

  if (!severity || (!matchedRuleCount && !securityEventCount)) {
    return {
      alertType: 'success' as const,
      title: '暂未发现明确风险',
      description: '当前会话没有形成需要处置的内容安全事件。',
      advice: '保留审计记录即可；如业务侧反馈异常，再切换全部原文复核。',
      categoryLabels,
      categoryItems,
      matchedRuleCount,
      securityEventCount,
      severity: '',
    }
  }

  const title = severity === 'critical' || severity === 'high'
    ? '需要优先复核'
    : severity === 'medium'
      ? '建议人工复核'
      : '留痕审计'
  const alertType = (severity === 'critical' || severity === 'high' ? 'warning' : severity === 'medium' ? 'info' : 'success') as 'success' | 'info' | 'warning'
  const advice = hasSensitiveData
    ? '核对是否包含配置文件、密钥、凭据或敏感数据；如确认外发风险，通知业务负责人并轮换相关凭据。'
    : hasPromptRisk
      ? '复核用户输入是否诱导模型绕过策略、泄露提示词或执行越权任务；必要时加入提示词防护规则。'
      : '结合全部原文确认是否为业务误报；连续误报可调整规则或新增限定范围的例外。'

  return {
    alertType,
    title,
    description: `${mainCategory} 等风险类型命中 ${matchedRuleCount} 条规则，产生 ${securityEventCount} 条安全事件。`,
    advice,
    categoryLabels,
    categoryItems,
    matchedRuleCount,
    securityEventCount,
    severity,
  }
}

const ACCESS_RAW_FOLD_RUNES = 120

const ACCESS_RAW_ROLE_LABELS: Record<string, string> = {
  ...ROLE_LABELS,
  other: '其它',
}

const ACCESS_RAW_MONO_STYLE = {
  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
  whiteSpace: 'pre-wrap' as const,
  wordBreak: 'break-all' as const,
  marginBottom: 0,
}

const accessRawRoleLabel = (role: string) => ACCESS_RAW_ROLE_LABELS[role] || role

const accessRawToolKindLabel = (kind: string) => (
  kind === 'invocation_proposed' ? '模型提出调用'
    : kind === 'result_observed' ? '已观察结果'
      : kind
)

const accessRawStageLabel = (stage: string) => (
  stage === 'response' ? '响应'
    : stage === 'request' ? '请求'
      : stage
)

const foldRetainedText = (text: string, limit: number) => {
  const runes = Array.from(text)
  return runes.length <= limit
    ? { text, folded: false }
    : { text: runes.slice(0, limit).join(''), folded: true }
}

const AccessRetentionRawSectionItem = ({ section }: { section: any }) => {
  const [expanded, setExpanded] = useState(false)
  const content = String(section?.content || '')
  const role = String(section?.role || '')
  const preview = role === 'user' || role === 'assistant'
    ? { text: content, folded: false }
    : foldRetainedText(content, ACCESS_RAW_FOLD_RUNES)
  return (
    <List.Item style={{ paddingLeft: 12, borderLeft: `3px solid ${ROLE_COLORS[role] || 'var(--text-tertiary)'}` }}>
      <div style={{ width: '100%' }}>
        <Space wrap size={6} style={{ marginBottom: 6 }}>
          <Tag color={ROLE_COLORS[role] || 'default'}>{accessRawRoleLabel(role)}</Tag>
          {section?.request_id ? <Text type="secondary">{String(section.request_id)}</Text> : null}
        </Space>
        <Paragraph style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', marginBottom: 0 }}>
          {preview.folded && !expanded ? `${preview.text}\u2026` : content}
        </Paragraph>
        {preview.folded ? (
          <Button size="small" type="link" style={{ paddingLeft: 0 }} onClick={() => setExpanded((value) => !value)}>
            {expanded ? '收起' : '展开'}
          </Button>
        ) : null}
      </div>
    </List.Item>
  )
}

const AccessRetentionRawToolCallList = ({ calls }: { calls: any[] }) => (
  <Card size="small" title="工具调用记录">
    <List
      size="small"
      dataSource={calls}
      renderItem={(call: any) => (
        <List.Item>
          <div style={{ width: '100%' }}>
            <Space wrap size={6}>
              <Text strong>{call?.name || '-'}</Text>
              <Tag color={call?.kind === 'result_observed' ? 'green' : 'blue'}>{accessRawToolKindLabel(String(call?.kind || ''))}</Tag>
              <Text type="secondary">{accessRawStageLabel(String(call?.stage || ''))}</Text>
            </Space>
            {call?.arguments_preview ? (
              <Paragraph style={{ ...ACCESS_RAW_MONO_STYLE, marginTop: 6 }}>{String(call.arguments_preview)}</Paragraph>
            ) : null}
            {call?.result_preview ? (
              <Paragraph style={{ ...ACCESS_RAW_MONO_STYLE, marginTop: 6 }}>{String(call.result_preview)}</Paragraph>
            ) : null}
          </div>
        </List.Item>
      )}
    />
  </Card>
)

const AccessRetentionEvidenceFallbackAlert = ({ entries }: { entries: any[] }) => (
  <Alert
    type="warning"
    showIcon
    message="正文未留存，以下为安全事件命中时保存的原文"
    description={(
      <List
        size="small"
        dataSource={entries}
        renderItem={(entry: any) => (
          <List.Item style={{ paddingLeft: 0 }}>
            <div style={{ width: '100%' }}>
              <Space wrap size={6}>
                <Text strong>{entry?.rule_name || entry?.category || '-'}</Text>
                {entry?.severity ? <Tag color={SEVERITY_COLORS[entry.severity] || 'default'}>{String(entry.severity)}</Tag> : null}
                <Text type="secondary">
                  {[entry?.content_source, entry?.message_role].filter(Boolean).join(' / ')}
                  {typeof entry?.message_index === 'number' ? ` #${entry.message_index}` : ''}
                </Text>
              </Space>
              {entry?.raw_evidence ? (
                <Paragraph style={{ ...ACCESS_RAW_MONO_STYLE, marginTop: 6 }}>{String(entry.raw_evidence)}</Paragraph>
              ) : null}
              {entry?.evidence_context ? (
                <Text type="secondary" style={{ display: 'block', marginTop: 6, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {String(entry.evidence_context)}
                </Text>
              ) : null}
            </div>
          </List.Item>
        )}
      />
    )}
  />
)

const AccessRetentionRawPanel = ({ query }: { query: { data?: any; isLoading: boolean; isError: boolean } }) => {
  const raw = query.data?.data
  const sections: any[] = Array.isArray(raw?.sections) ? raw.sections : []
  const toolCalls: any[] = Array.isArray(raw?.tool_calls) ? raw.tool_calls : []
  const fallback: any[] = Array.isArray(raw?.evidence_fallback) ? raw.evidence_fallback : []
  const requestSections = sections.filter((section) => section?.direction !== 'response')
  const responseSections = sections.filter((section) => section?.direction === 'response')
  if (query.isError) return <Alert type="error" showIcon message="留存内容加载失败" />
  if (query.isLoading) return <Card size="small" loading />
  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      {fallback.length > 0 ? <AccessRetentionEvidenceFallbackAlert entries={fallback} /> : null}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
        <Card size="small" title="请求">
          <List size="small" dataSource={requestSections} renderItem={(section: any) => <AccessRetentionRawSectionItem section={section} />} />
        </Card>
        <Card size="small" title="响应">
          <List size="small" dataSource={responseSections} renderItem={(section: any) => <AccessRetentionRawSectionItem section={section} />} />
        </Card>
      </div>
      <AccessRetentionRawToolCallList calls={toolCalls} />
    </Space>
  )
}

function ContentAudit() {
  const auditIdentity = useAuditQueryIdentity()
  const userRole = useAuthStore((state) => state.user?.role || '')
  const canReadContent = canReadContentEvidence(userRole)
  const [searchParams, setSearchParams] = useSearchParams()
  const navigate = useNavigate()
  const linkedRequestId = searchParams.get('request_id')?.trim() || ''
  const linkedRiskCategory = searchParams.get('risk_category')?.trim() || searchParams.get('class_key')?.trim() || ''
  const linkedRiskCategories = useMemo(() => parseRiskCategoryFilter(linkedRiskCategory), [linkedRiskCategory])
  const openedLinkedRequestRef = useRef('')
  const [searchType, setSearchType] = useState<'occurrences' | 'sessions' | 'session'>(() => searchParams.get('event_id')?.trim() ? 'occurrences' : searchParams.get('view') === 'conversations' ? 'sessions' : 'occurrences')
  const [linkedOccurrence, setLinkedOccurrence] = useState<AlertOccurrence | null>(null)
  const projectId = searchParams.get('project_id')?.trim() || ''
  const [projectIdInput, setProjectIdInput] = useState(projectId)
  const [userId, setUserId] = useState('')
  const [selectedUser, setSelectedUser] = useState<ContentAuditUserOption | null>(null)
  const [userSearchInput, setUserSearchInput] = useState('')
  const [userSearch, setUserSearch] = useState('')
  const [sessionIdInput, setSessionIdInput] = useState('')
  const [sessionId, setSessionId] = useState('')
  const [keywordInput, setKeywordInput] = useState('')
  const [keyword, setKeyword] = useState('')
  const [selectedSession, setSelectedSession] = useState<string | null>(null)
  const [selectedSessionRisk, setSelectedSessionRisk] = useState<any>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [detailView, setDetailView] = useState<'manager' | 'all'>('manager')
  const [rawPageOffset, setRawPageOffset] = useState(0)
  const [selectedRiskCategory, setSelectedRiskCategory] = useState<string | null>(null)
  const [riskCategoryFilter, setRiskCategoryFilter] = useState<string[]>(() => linkedRiskCategories)
  const [riskSeverityFilter, setRiskSeverityFilter] = useState<string | undefined>()
  // 默认只看最近 100 项问题；显式时间范围仍保留完整分页。
  const [riskWindowHours, setRiskWindowHours] = useState<number>(() => riskWindowFromSearch(searchParams.get('window_hours'), searchType === 'occurrences' ? 0 : 24 * 90))
  const [alertPage, setAlertPage] = useState(1)
  const alertPageSize = searchType === 'occurrences' ? 10 : 20
  const isAccessRetentionDetail = selectedSessionRisk?._source === ACCESS_RETENTION_SOURCE
  const linkedRiskStart = searchParams.get('start_time'), linkedRiskEnd = searchParams.get('end_time')
  const riskTimeWindow = useMemo(() => {
    const from = linkedRiskStart, to = linkedRiskEnd
    if (from && to && Number.isFinite(Date.parse(from)) && Number.isFinite(Date.parse(to)) && Date.parse(from)<Date.parse(to)) return {from,to}
    return boundedTimeWindowParams(riskWindowHours || 24 * 90)
  }, [riskWindowHours, linkedRiskStart, linkedRiskEnd])

  const rawAccessMembers = useMemo(() => {
    const ids = Array.isArray(selectedSessionRisk?.member_request_ids)
      ? selectedSessionRisk.member_request_ids
      : []
    return ids.map((id: any) => String(id || '').trim()).filter(Boolean)
  }, [selectedSessionRisk])
  const alertListParams = useMemo<ContentAuditListParams>(() => ({
    limit: alertPageSize,
    offset: (alertPage - 1) * alertPageSize,
    alert_only: true,
    user_id: userId || undefined,
    keyword: canReadContent ? keyword || undefined : undefined,
    category: riskCategoryFilter.length > 0 ? riskCategoryFilter.join(',') : undefined,
    severity: riskSeverityFilter,
    ...riskTimeWindow,
  }), [alertPage, alertPageSize, canReadContent, keyword, riskCategoryFilter, riskSeverityFilter, riskTimeWindow, userId])
  const laneParam = searchParams.get('lane')
  const alertLane: 'action' | 'watch' | 'eval' = laneParam === 'watch' || laneParam === 'eval' ? laneParam : 'action'
  const linkedEventID = searchParams.get('event_id')?.trim() || ''
  const exactOccurrenceQuery = searchType === 'occurrences' && Boolean(linkedEventID || linkedRequestId)
  const occurrenceParams = useMemo<AlertOccurrenceParams>(() => ({
    include_dev: searchParams.get('include_dev') === 'true',
    case_id: searchParams.get('case_id') || undefined,
    event_id: linkedEventID || undefined,
    session_id: searchParams.get('session_id')?.trim() || undefined,
    limit: alertPageSize,
    offset: (alertPage - 1) * alertPageSize,
    user_id: userId || undefined,
    project_id: projectId || undefined,
    request_id: linkedRequestId || undefined,
    category: riskCategoryFilter.length ? riskCategoryFilter.join(',') : undefined,
    severity: riskSeverityFilter,
    recent_limit: linkedEventID ? undefined : riskWindowHours === 0 ? 100 : undefined,
    start_time: linkedEventID ? undefined : riskWindowHours === 0 ? undefined : riskTimeWindow.from,
    end_time: linkedEventID ? undefined : riskTimeWindow.to,
    include_raw: false,
  }), [alertPage, alertPageSize, userId, projectId, linkedRequestId, riskCategoryFilter, riskSeverityFilter, riskTimeWindow, riskWindowHours, searchParams, linkedEventID])

  useEffect(() => {
    setRiskCategoryFilter(linkedRiskCategories)
  }, [linkedRiskCategories, searchType])

  useEffect(() => {
    setProjectIdInput(projectId)
  }, [projectId])

  useEffect(() => {
    setDrawerOpen(false)
    setSelectedSession(null)
    setSelectedSessionRisk(null)
    setLinkedOccurrence(null)
  }, [auditIdentity])

  useEffect(() => {
    setRiskWindowHours(riskWindowFromSearch(searchParams.get('window_hours'), searchType === 'occurrences' ? 0 : 24 * 90))
  }, [searchParams, searchType])

  useEffect(() => {
    if (canReadContent) return
    setSearchType('occurrences')
    setKeywordInput('')
    setKeyword('')
    setDrawerOpen(false)
    setSelectedSession(null)
    setSelectedSessionRisk(null)
    setLinkedOccurrence(null)
  }, [canReadContent])

  // Native alert links stay on exact alert occurrences even when they include a session_id.
  useEffect(() => {
    const eventIdParam = searchParams.get('event_id')?.trim()
    if (eventIdParam) {
      setSearchType('occurrences')
      setSessionIdInput('')
      setSessionId('')
      return
    }
    const sessionIdParam = searchParams.get('session_id')?.trim()
    if (sessionIdParam && canReadContent) {
      setSearchType('session')
      setSessionIdInput(sessionIdParam)
      setSessionId(sessionIdParam)
    }
  }, [canReadContent, searchParams])

  // Queries
  const usersQ = useInfiniteQuery({
    queryKey: ['content-audit', auditIdentity, 'user-selector', userSearch],
    initialPageParam: { cursor: undefined as string | undefined, offset: 0 },
    queryFn: ({ pageParam, signal }) => contentAuditApi.listUsers({
      q: userSearch || undefined,
      limit: 50,
      cursor: pageParam.cursor,
      offset: pageParam.cursor ? undefined : pageParam.offset,
      signal,
    }),
    getNextPageParam: (lastPage) => {
      if (!lastPage.data.has_more) return undefined
      return lastPage.data.next_cursor
        ? { cursor: lastPage.data.next_cursor, offset: 0 }
        : { cursor: undefined, offset: lastPage.data.offset + lastPage.data.limit }
    },
    enabled: searchType !== 'session',
    staleTime: 5 * 60 * 1000,
  })
  const sessionsQ = useQuery({
    queryKey: ['content-audit', auditIdentity, 'alerts', alertListParams],
    queryFn: ({ signal }) => contentAuditApi.list({
      ...alertListParams,
      signal,
    }),
    enabled: searchType === 'sessions',
    staleTime: 5 * 60 * 1000,
    refetchOnWindowFocus: false,
    placeholderData: (previousData) => previousData,
  })
  const linkedAccessRecordQ = useQuery({
    queryKey: ['content-audit', auditIdentity, 'linked-access-record', linkedRequestId, riskTimeWindow],
    queryFn: ({ signal }) => accessRetentionApi.list({ request_id: linkedRequestId, content_only: true, limit: 10, skip_summary: true, skip_total: true, ...riskTimeWindow, signal }),
    enabled: canReadContent && searchType === 'sessions' && linkedRequestId !== '',
    staleTime: 5 * 60 * 1000,
    refetchOnWindowFocus: false,
  })
  const applyKeywordSearch = (value: string) => {
    const next = value.trim()
    if (!next) {
      setKeywordInput('')
      setKeyword('')
      setAlertPage(1)
      return
    }
    const runeCount = Array.from(next).length
    const minimum = minimumKeywordLength(next)
    if (runeCount < minimum || runeCount > 128) {
      message.warning('中文关键词至少 2 个字符、英文至少 3 个字符，最多 128 个字符')
      return
    }
    setKeywordInput(next)
    setKeyword(next)
    setAlertPage(1)
  }
  const sessionLogsQ = useQuery({
    queryKey: ['content-audit', auditIdentity, 'session', sessionId, riskTimeWindow],
    queryFn: ({ signal }) => contentAuditApi.list({ session_id: sessionId, ...riskTimeWindow, signal }),
    enabled: canReadContent && searchType === 'session' && sessionId !== '',
  })
  const applySessionSearch = (value: string) => {
    const next = value.trim()
    setSessionIdInput(next)
    setSessionId(next)
  }
  const detailQ = useInfiniteQuery({
    queryKey: ['content-audit', auditIdentity, 'detail', 'manager', selectedSession, riskTimeWindow],
    initialPageParam: 0,
    queryFn: ({ pageParam, signal }) => contentAuditApi.getSession(selectedSession!, {
      view: 'manager',
      limit: CONTENT_DETAIL_PAGE_SIZE,
      offset: pageParam,
      ...riskTimeWindow,
      signal,
    }),
    getNextPageParam: (lastPage) => {
      const page = parseContentAuditSessionPage(lastPage, CONTENT_DETAIL_PAGE_SIZE)
      return page.hasMore ? page.offset + page.limit : undefined
    },
    enabled: canReadContent && selectedSession !== null && drawerOpen && !isAccessRetentionDetail,
  })
  const rawDetailQ = useQuery({
    queryKey: ['content-audit', auditIdentity, 'detail', 'all', selectedSession, rawPageOffset, riskTimeWindow],
    queryFn: ({ signal }) => contentAuditApi.getSession(selectedSession!, { view: 'all', limit: CONTENT_DETAIL_PAGE_SIZE, offset: rawPageOffset, ...riskTimeWindow, signal }),
    enabled: canReadContent && selectedSession !== null && drawerOpen && !isAccessRetentionDetail && detailView === 'all',
  })
  const sessionEventsQ = useInfiniteQuery({
    queryKey: ['content-audit', auditIdentity, 'detail-events', selectedSession, riskTimeWindow],
    initialPageParam: 0,
    queryFn: ({ pageParam, signal }) => contentAuditApi.getSessionEvents(selectedSession!, {
      limit: CONTENT_DETAIL_PAGE_SIZE,
      offset: pageParam,
      ...riskTimeWindow,
      signal,
    }),
    getNextPageParam: (lastPage) => {
      const payload = lastPage.data as any
      const logs = asEventArray(payload)
      const offset = Number(payload?.offset) || 0
      const limit = Number(payload?.limit) || CONTENT_DETAIL_PAGE_SIZE
      const total = Number(payload?.total) || logs.length
      const hasMore = typeof payload?.has_more === 'boolean'
        ? payload.has_more
        : offset + logs.length < total
      return hasMore ? offset + limit : undefined
    },
    enabled: canReadContent && selectedSession !== null && drawerOpen && !isAccessRetentionDetail && detailQ.isSuccess,
  })
  const accessDetailQ = useQuery({
    queryKey: ['content-audit', auditIdentity, 'access-retention-detail', selectedSession, riskTimeWindow],
    queryFn: ({ signal }) => accessRetentionApi.getContent(selectedSession!, undefined, { ...riskTimeWindow, signal }),
    enabled: canReadContent && selectedSession !== null && drawerOpen && isAccessRetentionDetail,
    retry: false,
  })
  const auditDetailQ = useQuery({
    queryKey: ['content-audit', auditIdentity, 'access-request-detail', selectedSession, riskTimeWindow],
    queryFn: ({ signal }) => auditApi.getRequestDetail(selectedSession!, { events_only: true, ...riskTimeWindow, signal }),
    enabled: canReadContent && selectedSession !== null && drawerOpen && isAccessRetentionDetail,
    retry: false,
  })

  const rawAccessDetailQ = useQuery({
    queryKey: ['content-audit', auditIdentity, 'access-retention-raw', selectedSession, rawAccessMembers, riskTimeWindow],
    queryFn: ({ signal }) => accessRetentionApi.getRawContent(selectedSession!, { members: rawAccessMembers, ...riskTimeWindow, signal }),
    // 责任主体里的工具调用块需要这份元数据，所以留证会话一开抽屉就取，不等到切「全部原文」。
    enabled: canReadContent && isAccessRetentionDetail && drawerOpen,
    retry: false,
  })
  const users = useMemo(() => {
    const byID = new Map<string, ContentAuditUserOption>()
    if (selectedUser) byID.set(selectedUser.id, selectedUser)
    usersQ.data?.pages.forEach((page) => {
      page.data.data.forEach((user) => byID.set(user.id, user))
    })
    return [...byID.values()]
  }, [selectedUser, usersQ.data?.pages])
  const _sessionsRaw = sessionsQ.data?.data
  const contentSessions = toResponseArray(_sessionsRaw)
  const contentRiskSessions = contentSessions.filter(hasContentRiskSignal)
  const alertTotal = Number((_sessionsRaw as any)?.total ?? (sessionsQ.data as any)?.data?.total) || 0
  const alertHasMore = Boolean((_sessionsRaw as any)?.has_more)
  const alertPaginationTotal = alertHasMore
    ? Math.max(alertTotal, alertPage * alertPageSize + 1)
    : Math.max(alertTotal, (alertPage - 1) * alertPageSize + contentSessions.length)
  const retainedAccessRecords = uniqueRecordsByRequest([
    ...toResponseArray(linkedAccessRecordQ.data?.data),
  ])
  const retainedAccessSessions = retainedAccessRecords.map(buildRetainedAccessSession).filter((item: any) => item.session_id)
  const linkedRetainedSessions = retainedAccessSessions.filter((record: any) => (
    linkedRequestId && String(record?.request_id || record?.session_id || '') === linkedRequestId
  ))
  const allRiskSessions = uniqueRecordsByRequest([
    ...contentRiskSessions,
    ...retainedAccessSessions.filter(hasContentRiskSignal),
    ...linkedRetainedSessions,
  ]).sort((left, right) => recordOccurrenceTime(right) - recordOccurrenceTime(left))

  useEffect(() => {
    const linkedOpenKey = `${linkedRequestId}|${linkedRiskCategory}`
    if (searchType !== 'sessions' || !linkedRequestId || openedLinkedRequestRef.current === linkedOpenKey) return
    const linkedRecord = allRiskSessions.find((record: any) =>
      String(record?.request_id || record?.session_id || '') === linkedRequestId,
    )
    if (!linkedRecord) return

    const recordCategories = actionableRiskCategories(linkedRecord)
    const linkedActionableCategory = linkedRiskCategory && !isLowRiskAgentSignal(linkedRiskCategory)
      ? linkedRiskCategory
      : ''
    const autoLockCategory = linkedActionableCategory
      || recordCategories.find((category: string) => !isLowRiskAgentSignal(category))
      || ''
    openedLinkedRequestRef.current = linkedOpenKey
    setDetailView('manager')
    setRawPageOffset(0)
    setSelectedRiskCategory(autoLockCategory || null)
    setSelectedSessionRisk(linkedRecord)
    setLinkedOccurrence(null)
    setSelectedSession(linkedRecord.session_id)
    setDrawerOpen(true)
  }, [allRiskSessions, linkedRequestId, linkedRiskCategory, searchType])
  const riskCategoryOptions = useMemo(() => Object.keys(RISK_CATEGORY_LABELS)
    .filter((category) => !isLowRiskAgentSignal(category))
    .map((value) => ({ value, label: searchType === 'occurrences' ? getFindingCategoryLabel(value) : getRiskCategoryLabel(value) }))
    .sort((left, right) => left.label.localeCompare(right.label, 'zh-CN')), [searchType])
  const updateRiskCategoryFilter = (values: string[]) => {
    const nextValues = [...new Set(values.map((value) => value.trim()).filter(Boolean))]
    setRiskCategoryFilter(nextValues)
    setAlertPage(1)
    const nextParams = new URLSearchParams(searchParams)
    if (nextValues.length > 0) nextParams.set('risk_category', nextValues.join(','))
    else nextParams.delete('risk_category')
    setSearchParams(nextParams, { replace: true })
  }
  const updateRiskWindow = (value: number) => {
    setRiskWindowHours(value)
    setAlertPage(1)
    const nextParams = new URLSearchParams(searchParams)
    nextParams.set('window_hours', String(value))
    nextParams.delete('start_time'); nextParams.delete('end_time')
    setSearchParams(nextParams, { replace: true })
  }
  const sessions = allRiskSessions
  const _sessLogsRaw = sessionLogsQ.data?.data
  const logs = searchType === 'session' ? toResponseArray(_sessLogsRaw) : []
  const managerDetailPages = detailQ.data?.pages.map((page) => parseContentAuditSessionPage(page, CONTENT_DETAIL_PAGE_SIZE)) || []
  const rawDetailPage = parseContentAuditSessionPage(rawDetailQ.data, CONTENT_DETAIL_PAGE_SIZE)
  const managerDetailLogs = uniqueBy(
    managerDetailPages.flatMap((page) => page.logs),
    (log) => String(log.id || [log.request_id, log.message_index, log.created_at, log.role].join('|')),
  )
  const managerDetailTotal = managerDetailPages.reduce((total, page) => Math.max(total, page.total), managerDetailLogs.length)
  const rawDetailLogs = rawDetailPage.logs
  const accessDetailLogs = isAccessRetentionDetail && selectedSession
    ? buildRetainedAccessLogs(selectedSession, accessDetailQ.data?.data, selectedSessionRisk)
    : []
  const detailLogs = isAccessRetentionDetail
    ? accessDetailLogs
    : detailView === 'all' ? rawDetailLogs : managerDetailLogs
  const evidenceContextLogs = isAccessRetentionDetail ? accessDetailLogs : managerDetailLogs
  const managerOverview = buildSessionOverview(isAccessRetentionDetail ? accessDetailLogs : managerDetailLogs)
  const sessionMessageCount = Number(selectedSessionRisk?.message_count)
  const totalMessageCount = Number.isFinite(sessionMessageCount) && sessionMessageCount >= 0
    ? sessionMessageCount
    : managerDetailTotal
  const hiddenNoiseCount = isAccessRetentionDetail
    ? managerOverview.hiddenCount
    : managerOverview.hiddenCount + Math.max(0, totalMessageCount - managerDetailTotal)
  const sessionMessageTotal = isAccessRetentionDetail
    ? accessDetailLogs.length
    : detailView === 'all' ? rawDetailPage.total : managerDetailTotal
  const sessionEvents = isAccessRetentionDetail
    ? asEventArray(auditDetailQ.data?.data?.security_events)
    : sessionEventsQ.data?.pages.flatMap((page) => asEventArray(page.data)) || []
  const ruleEvidences = buildRuleEvidences(sessionEvents)
  const effectiveRuleEvidences = ruleEvidences.filter((item) => item.countsAsSecurityFinding && !isAgentInventoryEvidence(item))
  const detectedAgentType = String(selectedSessionRisk?.agent_type || '').trim()
    || ruleEvidences.map((item) => agentTypeFromSignal(item.category) || agentTypeFromSignal(item.ruleId)).find(Boolean)
    || ''
  const sessionUsername = String(selectedSessionRisk?.username || '').trim()
  const sessionDepartment = String(selectedSessionRisk?.department_name || '').trim()
  const sessionConversationId = String(selectedSessionRisk?.conversation_id || selectedSession || '').trim()
  const sessionUpstreamLabel = upstreamPrincipalLabel(selectedSessionRisk?.principal_key)
  const sessionRetentionRequestId = String(selectedSessionRisk?.request_id || '').trim()
  const sessionSourceIp = String(selectedSessionRisk?.source_ip || selectedSessionRisk?.client_ip || '').trim()
  const sessionSourceIpText = sessionSourceIp
    ? ATTRIBUTION_SOURCE_IP_PREFIX + sessionSourceIp + (selectedSessionRisk?.principal_proxy_nat ? NAT_SOURCE_NOTE : '')
    : ''
  const sessionToolCalls: any[] = Array.isArray(rawAccessDetailQ.data?.data?.tool_calls)
    ? rawAccessDetailQ.data.data.tool_calls
    : []
  // 留存内容在访问留存页才有逐请求钻取；反代会话就地切到本抽屉的全部原文。
  const openRetentionDetail = () => {
    if (!isAccessRetentionDetail && sessionRetentionRequestId) {
      navigate('/audit/access-retention?request_id=' + encodeURIComponent(sessionRetentionRequestId))
      return
    }
    setDetailView('all')
  }
  const selectedRuleEvidences = useMemo(
    () => selectedRiskCategory ? effectiveRuleEvidences.filter((item) => evidenceMatchesCategory(item, selectedRiskCategory)) : [],
    [effectiveRuleEvidences, selectedRiskCategory],
  )
  const primaryEvidence = selectedRiskCategory && selectedRuleEvidences.length === 1 ? selectedRuleEvidences[0] : undefined
  useEffect(() => {
    if (!selectedRiskCategory || !detailQ.hasNextPage || detailQ.isFetchingNextPage) return
    const missingContext = selectedRuleEvidences.some((evidence) => findRelatedLogs(evidence, managerDetailLogs).length === 0)
    if (missingContext) void detailQ.fetchNextPage()
  }, [detailQ, managerDetailLogs, selectedRiskCategory, selectedRuleEvidences])
  const selectedRiskLabel = selectedRiskCategory ? getFindingCategoryLabel(selectedRiskCategory) : ''
  const scopedSessionRisk = useMemo(() => {
    if (!selectedRiskCategory || !selectedSessionRisk) return selectedSessionRisk
    return {
      ...selectedSessionRisk,
      highest_severity: '',
      risk_categories: [selectedRiskCategory],
      matched_rule_count: selectedRuleEvidences.length,
      security_event_count: selectedRuleEvidences.length,
    }
  }, [selectedRiskCategory, selectedSessionRisk, selectedRuleEvidences])
  const sessionOverview = {
    ...buildSessionOverview(detailLogs),
    hiddenCount: hiddenNoiseCount,
  }
  const conversationRiskSummary = getContentRiskSummary(selectedSessionRisk, ruleEvidences)
  const contentRiskSummary = selectedRiskCategory ? getContentRiskSummary(scopedSessionRisk, selectedRuleEvidences) : conversationRiskSummary
  const retainedBodyMissing = isAccessRetentionDetail && (accessDetailQ.error as any)?.response?.status === 404
  const gatewayBlocked = ['block', 'deny'].includes(String(selectedSessionRisk?.action_taken || ''))
  const detectionIssue = sessionEvents.find((event: any) => event.event_type === 'security_check_failed' || event.event_type === 'security_output_check_failed')
  const gatewayOutcome = gatewayBlocked ? {
    type: 'warning' as const,
    title: detectionIssue ? '检测异常，请求已拦截' : '请求已拦截',
    description: detectionIssue ? '网关未能完成安全检测，本次请求未向上游转发。这是检测运行异常，不代表检出了攻击。' : '网关记录了拦截动作；具体发生在请求输入还是响应输出阶段，请查看下方命中证据。',
  } : selectedSessionRisk?.action_taken === 'audit' ? {
    type: 'info' as const, title: '仅记录告警，未拦截', description: '网关记录了检测结果；这条告警不表示请求已被拦截。',
  } : null
  const selectedEvidenceLoading = isAccessRetentionDetail ? auditDetailQ.isLoading : sessionEventsQ.isLoading
  const shouldRenderSelectedEvidence = Boolean(selectedRiskCategory && (!isAccessRetentionDetail || !auditDetailQ.isLoading || selectedRuleEvidences.length > 0))

  const openOccurrenceConversation = (occurrence: AlertOccurrence) => {
    if (!canReadContent) return
    setLinkedOccurrence(occurrence)
    setSelectedRiskCategory(null)
    setDetailView('manager')
    setRawPageOffset(0)
    setSelectedSession(occurrence.session_id || occurrence.request_id)
    setSelectedSessionRisk({
      _source: occurrence.session_id ? 'content_audit' : ACCESS_RETENTION_SOURCE,
      session_id: occurrence.session_id,
      request_id: occurrence.request_id,
      conversation_id: occurrence.conversation_id,
      username: occurrence.actor_name,
      user_id: occurrence.actor_user_id,
      department_name: occurrence.actor_department_name,
      agent_type: occurrence.agent_type,
      client_id: occurrence.credential_id,
      client_name: occurrence.credential_name,
      source_ip: occurrence.source_ip,
      start_time: occurrence.created_at,
      principal_key: occurrence.principal_key,
    })
    setDrawerOpen(true)
  }

  const handleExport = async (sid: string, format: 'json' | 'text') => {
    try {
      const response = await contentAuditApi.export(sid, format, riskTimeWindow)
      const blob = new Blob([response.data], { type: format === 'json' ? 'application/json' : 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `session_${sid}.${format === 'json' ? 'json' : 'txt'}`
      a.click()
      URL.revokeObjectURL(url)
      message.success('导出成功')
    } catch {
      message.error('导出失败')
    }
  }

  return (
    <div className={searchType === 'occurrences' ? 'alert-workbench-page' : undefined}>
      <EnterprisePageHeader
        eyebrow="安全护栏"
        title="安全告警"
        description={exactOccurrenceQuery ? "按阻断编号或请求 ID 定位关联命中，每条证据都能追溯到对应的原请求留存。" : "按问题处理风险；重复命中合并展示，每条证据都能追溯到对应的原请求留存。"}
        actions={(
          <Space size={16} wrap>
            <a href="/security/agents">配置智能体告警策略</a>
            <a href="/security/policies?section=sensitive-data">配置内容与数据策略</a>
          </Space>
        )}
      />
      {searchParams.get('case_id') ? <Alert type="info" showIcon message="已定位到留痕关联的风险问题" action={<Button onClick={() => { const next = new URLSearchParams(searchParams); next.delete('case_id'); setSearchParams(next, { replace: true }) }}>返回问题列表</Button>} style={{ marginBottom: 12 }} /> : null}
      <div className="audit-context-line">
        <strong>安全告警记录</strong>
        <span>按告警查看风险证据、内容来源和处置结果；可单独打开关联对话。</span>
      </div>

      {/* Full-tenant roles may inspect retained content; department managers only receive scoped metadata. */}
      {canReadContent && searchType !== 'occurrences' ? <Card className="audit-search-bar" style={{ marginBottom: 16 }}>
        <Space wrap>
          <Select
            aria-label="告警视图"
            style={{ width: 180 }}
            value={searchType}
            onChange={(value) => {
              setSearchType(value)
              setAlertPage(1)
              setDrawerOpen(false)
              setLinkedOccurrence(null)
              const next = new URLSearchParams(searchParams)
              if (value === 'sessions') next.set('view', 'conversations')
              else next.delete('view')
              next.delete('session_id')
              setSearchParams(next, { replace: true })
            }}
            options={[
              { value: 'occurrences', label: '风险问题' },
              { value: 'sessions', label: '关联会话视图' },
              { value: 'session', label: '指定请求/会话ID' },
            ]}
          />
          {searchType === 'session' && (
            <Input.Search
              style={{ width: 300 }}
              placeholder="输入请求或会话 ID"
              enterButton="查询"
              allowClear
              value={sessionIdInput}
              onChange={(e) => {
                setSessionIdInput(e.target.value)
                if (!e.target.value) setSessionId('')
              }}
              onSearch={applySessionSearch}
            />
          )}
        </Space>
      </Card> : null}

      {/* Session list view */}
      {searchType !== 'session' && (
        <SectionPanel
          title="安全告警明细"
          extra={(
            <CollapsibleFilters
              id="content-audit-advanced-filters"
              advancedActiveCount={[riskCategoryFilter.length > 0 ? 'category' : '', riskSeverityFilter, searchType === 'occurrences' ? projectId : ''].filter(Boolean).length}
              primary={(
                <>
                  <Select
                    aria-label={searchType === 'occurrences' ? '用户筛选' : 'Key 归属筛选'}
                    allowClear
                    showSearch
                    filterOption={false}
                    placeholder={searchType === 'occurrences' ? '选择关联用户' : '选择 Key 归属'}
                    style={{ width: 220 }}
                    value={userId || undefined}
                    searchValue={userSearchInput}
                    onSearch={setUserSearchInput}
                    onInputKeyDown={(event) => {
                      if (event.key === 'Enter' && !event.nativeEvent.isComposing) {
                        event.preventDefault()
                        event.stopPropagation()
                        setUserSearch(userSearchInput.trim())
                      }
                    }}
                    onOpenChange={(open) => {
                      if (!open) {
                        setUserSearchInput('')
                        setUserSearch('')
                      }
                    }}
                    onChange={(value, option) => {
                      const nextID = value || ''
                      setUserId(nextID)
                      setSelectedUser(nextID ? users.find((user) => user.id === nextID) || {
                        id: nextID,
                        username: String((option as { label?: unknown })?.label || nextID),
                        identity_kind: 'key_owner',
                      } : null)
                      setAlertPage(1)
                    }}
                    onClear={() => {
                      setUserSearchInput('')
                      setUserSearch('')
                    }}
                    onPopupScroll={(event) => {
                      const target = event.currentTarget
                      if (target.scrollTop + target.clientHeight >= target.scrollHeight - 24 && usersQ.hasNextPage && !usersQ.isFetchingNextPage) {
                        void usersQ.fetchNextPage()
                      }
                    }}
                    loading={usersQ.isLoading || usersQ.isFetchingNextPage}
                    options={users.map((user) => ({
                      value: user.id,
                      label: user.department_name ? `${user.username} · ${user.department_name}` : user.username,
                    }))}
                    notFoundContent={usersQ.isLoading ? '加载中' : '未找到有权限查看的 Key 归属'}
                  />
                  {canReadContent && searchType === 'sessions' ? (
                    <div className="content-audit-keyword-search">
                      <Input.Search
                        allowClear
                        enterButton="搜索"
                        placeholder="搜索告警留证正文"
                        prefix={<SearchOutlined />}
                        style={{ width: '100%' }}
                        value={keywordInput}
                        onChange={(event) => {
                          const next = event.target.value
                          setKeywordInput(next)
                          if (!next) {
                            setKeyword('')
                            setAlertPage(1)
                          }
                        }}
                        onSearch={applyKeywordSearch}
                      />
                    </div>
                  ) : null}
                  {exactOccurrenceQuery ? <Text type="secondary">编号精确查询，时间筛选不限制查询范围</Text> : <Select
                    aria-label="告警时间范围"
                    style={{ width: 130 }}
                    value={riskWindowHours}
                    onChange={updateRiskWindow}
                    options={[
                      ...(searchType === 'occurrences' ? [{ value: 0, label: '最近 100 条' }] : []),
                      { value: 24, label: '近 24 小时' },
                      { value: 24 * 7, label: '近 7 天' },
                      { value: 24 * 30, label: '近 30 天' },
                      { value: 24 * 90, label: '近 90 天' },
                      { value: 24 * 180, label: '近 180 天' },
                    ]}
                  />}
                </>
              )}
              advanced={(
                <>
                  <Select
                    mode="multiple"
                    allowClear
                    aria-label="风险类型"
                    placeholder="风险类型"
                    style={{ minWidth: 180 }}
                    value={riskCategoryFilter}
                    onChange={(value: string | string[] | undefined) => updateRiskCategoryFilter(Array.isArray(value) ? value : value ? [value] : [])}
                    options={riskCategoryOptions}
                  />
                  <Select
                    allowClear
                    placeholder="风险等级"
                    style={{ width: 130 }}
                    value={riskSeverityFilter}
                    onChange={(value) => {
                      setRiskSeverityFilter(value)
                      setAlertPage(1)
                    }}
                    options={severityOptions()}
                  />
                  {searchType === 'occurrences' ? <Input.Search
                    aria-label="项目 ID 筛选"
                    placeholder="项目 ID"
                    value={projectIdInput}
                    allowClear
                    style={{ width: 220 }}
                    onChange={(event) => {
                      setProjectIdInput(event.target.value)
                      if (!event.target.value) {
                        const next = new URLSearchParams(searchParams)
                        next.delete('project_id')
                        setSearchParams(next, { replace: true })
                        setAlertPage(1)
                      }
                    }}
                    onSearch={(value) => {
                      const next = new URLSearchParams(searchParams)
                      if (value.trim()) next.set('project_id', value.trim())
                      else next.delete('project_id')
                      setSearchParams(next, { replace: true })
                      setAlertPage(1)
                    }}
                  /> : null}
                </>
              )}
            />
          )}
        >
          {riskCategoryFilter.length > 0 ? (
            <Alert
              type="info"
              showIcon
              message={`已按 ${riskCategoryFilter.map((category) => searchType === 'occurrences' ? getFindingCategoryLabel(category) : getRiskCategoryLabel(category)).join('、')} 筛选`}
              description={(
                <Space wrap>
                  <span data-testid="content-audit-filtered-stats">筛选已在服务端分页前应用</span>
                  <Button type="link" size="small" onClick={() => updateRiskCategoryFilter([])}>清除筛选</Button>
                </Space>
              )}
              style={{ marginBottom: 12 }}
            />
          ) : null}
          {searchType === 'occurrences' ? <AlertOccurrences
            key={auditIdentity}
            params={occurrenceParams}
            onIncludeDevChange={include => { const next = new URLSearchParams(searchParams); if (include) next.set('include_dev', 'true'); else next.delete('include_dev'); setSearchParams(next, { replace: true }) }}
            lane={alertLane}
            onLaneChange={(next) => { const q = new URLSearchParams(searchParams); if (next === 'action') q.delete('lane'); else q.set('lane', next); setSearchParams(q, { replace: true }); setAlertPage(1) }}
            page={alertPage}
            onPageChange={setAlertPage}
            canReadContent={canReadContent}
            onOpenConversation={openOccurrenceConversation}
          /> : <ResizableTable
            columnStorageKey="content-audit-session-columns"
            minColumnWidth={90}
            maxColumnWidth={720}
            dataSource={sessions}
            rowKey="session_id"
            loading={sessionsQ.isLoading || sessionsQ.isFetching}
            locale={{ emptyText: '暂无安全告警' }}
            pagination={{ current: alertPage, pageSize: alertPageSize, total: alertPaginationTotal, showSizeChanger: false, onChange: setAlertPage }}
            columns={[
                { title: '请求/会话', dataIndex: 'session_id', width: 185, ellipsis: true, render: (value: string) => <Text copyable={{ text: value }}>{shortSessionId(value)}</Text> },
                { title: '责任主体', dataIndex: 'source_ip', width: 190, ellipsis: true, render: (v: string, r: any) => {
                    const actor = responsibilityDisplay({ username: r.username, userId: r.user_id, clientName: r.client_name, sourceIp: v || r.client_ip, direction: r.access_direction, credentialType: r.credential_type, principalKey: r.principal_key, proxyNat: r.principal_proxy_nat })
                    return <Space direction="vertical" size={0}><Text strong style={{ fontSize: 12 }}>{actor.primary}</Text><Text type="secondary" style={{ fontSize: 12 }}>{actor.secondary}</Text></Space>
                  } },
                { title: '服务', dataIndex: 'provider', width: 130, ellipsis: true, render: (v: string) => v || '-' },
                { title: '目标', dataIndex: 'target_host', width: 180, ellipsis: true, render: (v: string) => v || '-' },
                { title: '时间', dataIndex: 'start_time', render: (v: string) => v ? new Date(v).toLocaleString() : '-', width: 175 },
                {
                  title: '风险结论',
                  dataIndex: 'highest_severity',
                  width: 220,
                  render: (v: string, r: any) => v ? (
                    <Space size={4}>
                      <Tag color={SEVERITY_COLORS[v] || 'default'}>{SEVERITY_LABELS[v] || v}</Tag>
                      {actionableRiskCategories(r).slice(0, 2).map((category: string) => (
                        <Tag key={category} color="purple">{getRiskCategoryLabel(category)}</Tag>
                      ))}
                    </Space>
                  ) : <Tag>未发现</Tag>,
                },
                {
                  title: '命中情况',
                  key: 'hit_summary',
                  width: 150,
                  render: (_: unknown, r: any) => `${recordActionableAlertCount(r)} 次告警 · ${Number(r.matched_rule_count) || 0} 条规则`,
                },
                { title: '网关动作', dataIndex: 'action_taken', width: 110, render: (v: string) => <Tag color={ACTION_COLORS[v] || 'blue'}>{ACTION_LABELS[v] || '未记录'}</Tag> },
                {
                  title: '操作',
                  key: 'actions',
                  width: 150,
                  render: (_, r: any) => (
                    canReadContent ? <Space>
                      <Button size="small" icon={<EyeOutlined />} onClick={() => { setLinkedOccurrence(null); setDetailView('manager'); setRawPageOffset(0); setSelectedRiskCategory(null); setSelectedSessionRisk(r); setSelectedSession(r.session_id); setDrawerOpen(true) }}>查看</Button>
                      {r._source === ACCESS_RETENTION_SOURCE ? null : <Button size="small" icon={<ExportOutlined />} onClick={() => handleExport(r.session_id, 'json')}>导出</Button>}
                    </Space> : <Text type="secondary">仅元数据</Text>
                  )
                },
              ]}
          />}
        </SectionPanel>
      )}

      {/* Message list view */}
      {searchType === 'session' && logs.length > 0 && (
        <Spin spinning={sessionLogsQ.isLoading}>
          <Card title="对话记录">
            <List
              dataSource={logs}
              renderItem={(item: any) => (
                <List.Item>
                  <List.Item.Meta
                    avatar={<Tag color={ROLE_COLORS[item.role] || 'default'}>{item.role === 'user' ? '用户' : item.role === 'assistant' ? 'AI' : '系统'}</Tag>}
                    title={<Text strong>{item.role === 'user' ? '用户' : item.role === 'assistant' ? 'AI' : '系统'} ({new Date(item.created_at).toLocaleString()})</Text>}
                    description={
                      <Text style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxWidth: '100%', display: 'block' }}>
                        {item.content.length > 500 ? item.content.slice(0, 500) + '...' : item.content}
                      </Text>
                    }
                  />
                </List.Item>
              )}
            />
          </Card>
        </Spin>
      )}

      {/* Empty state for message view */}
      {searchType === 'session' && !logs.length && !sessionLogsQ.isLoading && (
        <Card>
          <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-secondary)' }}>
            {sessionId === '' ? '请输入会话 ID' : '暂无数据'}
          </div>
        </Card>
      )}

      {/* Session detail drawer */}
      <Drawer
        rootClassName="content-audit-drawer"
        title={`${linkedOccurrence ? '关联对话' : isAccessRetentionDetail ? '留存详情' : '会话详情'}: ${selectedSession || ''}`}
        open={drawerOpen && canReadContent}
        onClose={() => { setDrawerOpen(false); setLinkedOccurrence(null); setSelectedSession(null); setSelectedSessionRisk(null); setSelectedRiskCategory(null); setDetailView('manager'); setRawPageOffset(0) }}
        width="min(860px, 100vw)"
        extra={isAccessRetentionDetail ? null : (
          <Space wrap className="content-audit-drawer-actions">
            <Button icon={<ExportOutlined />} onClick={() => handleExport(selectedSession!, 'text')}>导出 TXT</Button>
            <Button icon={<ExportOutlined />} onClick={() => handleExport(selectedSession!, 'json')}>导出 JSON</Button>
          </Space>
        )}
      >
        <Spin spinning={isAccessRetentionDetail ? accessDetailQ.isLoading || (detailView === 'all' && rawAccessDetailQ.isLoading) : detailQ.isLoading || (detailView === 'all' && rawDetailQ.isLoading)}>
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            {linkedOccurrence ? <AlertOccurrenceSummary occurrence={linkedOccurrence} /> : null}
            {retainedBodyMissing ? (
              <Alert type="info" showIcon message="该请求未留存正文" description="可查看请求和安全事件记录；没有正文不代表检测通过。" />
            ) : isAccessRetentionDetail && accessDetailQ.isError ? (
              <Alert type="error" showIcon message="留存内容加载失败" action={<Button size="small" aria-label="重试留存内容" onClick={() => void accessDetailQ.refetch()}>重试</Button>} />
            ) : null}
            {isAccessRetentionDetail && auditDetailQ.isError ? (
              <Alert type="warning" showIcon message="安全事件补充信息加载失败，留存内容仍可查看" />
            ) : null}
            <Card size="small" title="会话概览">
              <Descriptions
                size="small"
                column={1}
                items={[
                  { label: isAccessRetentionDetail ? '业务输入摘要' : '用户真实输入', children: retainedBodyMissing ? '该请求未留存正文' : sessionOverview.primaryUserText },
                  { label: '模型输出摘要', children: retainedBodyMissing ? (gatewayBlocked ? '请求已拦截，无上游模型回复' : '未留存模型回复') : sessionOverview.assistantText },
                  {
                    label: '内容处理',
                    children: retainedBodyMissing ? '无正文可供分析。' : sessionOverview.hiddenCount > 0
                      ? `已默认隐藏 ${sessionOverview.hiddenCount} 条系统或代理运行噪音，可切换“全部原文”查看完整证据。`
                      : '未发现需要隐藏的系统或代理运行噪音。',
                  },
                ]}
              />
              <Space wrap style={{ marginTop: 12 }}>
                <Tag color="blue">消息 {sessionMessageTotal}</Tag>
                <Tag color="green">输出 Token {formatTokenUsage(sessionOverview.totalTokens)}</Tag>
                <Tag color={sessionOverview.hiddenCount > 0 ? 'orange' : 'default'}>隐藏噪音 {sessionOverview.hiddenCount}</Tag>
              </Space>
            </Card>

            {!linkedOccurrence ? <Card size="small" title="责任与证据链">
              <Descriptions
                size="small"
                column={1}
                items={[
                  {
                    label: '发生时间',
                    children: primaryEvidence?.createdAt || selectedSessionRisk?.start_time
                      ? new Date(primaryEvidence?.createdAt || selectedSessionRisk?.start_time).toLocaleString()
                      : '-',
                  },
                  {
                    label: ATTRIBUTION_USER_LABEL,
                    children: (
                      <Space size={6} wrap>
                        <Text strong>{sessionUsername || ATTRIBUTION_UNLINKED_USER}</Text>
                        {sessionDepartment ? <Tag color="blue">{ATTRIBUTION_DEPARTMENT_PREFIX + sessionDepartment}</Tag> : null}
                        {selectedSessionRisk?.user_id ? <Text copyable={{ text: selectedSessionRisk.user_id }} type="secondary">{'用户 ID: ' + selectedSessionRisk.user_id}</Text> : null}
                      </Space>
                    ),
                  },
                  { label: ATTRIBUTION_AGENT_LABEL, children: detectedAgentType ? formatAgentType(detectedAgentType) : '未识别' },
                  {
                    label: ATTRIBUTION_CREDENTIAL_LABEL,
                    children: (
                      <Space size={6} wrap>
                        <Text>{sessionUpstreamLabel || selectedSessionRisk?.client_name || ATTRIBUTION_NO_CREDENTIAL}</Text>
                        {selectedSessionRisk?.client_id ? <Text copyable={{ text: selectedSessionRisk.client_id }} type="secondary">{'Key ID: ' + selectedSessionRisk.client_id}</Text> : null}
                        {sessionSourceIpText ? <Text type="secondary">{sessionSourceIpText}</Text> : null}
                      </Space>
                    ),
                  },
                  {
                    label: ATTRIBUTION_CONVERSATION_LABEL,
                    children: (
                      <Space size={6} wrap>
                        {sessionConversationId
                          ? <Text copyable={{ text: sessionConversationId }}>{sessionConversationId}</Text>
                          : <Text type="secondary">{ATTRIBUTION_NOT_RECORDED}</Text>}
                        <Button size="small" type="link" onClick={openRetentionDetail}>{ATTRIBUTION_VIEW_RETENTION}</Button>
                      </Space>
                    ),
                  },
                  {
                    label: '访问目标',
                    children: [selectedSessionRisk?.provider, selectedSessionRisk?.target_host].filter(Boolean).join(' / ') || '未记录',
                  },
                  {
                    label: '请求/会话 ID',
                    children: selectedSession ? <Text copyable={{ text: selectedSession }}>{selectedSession}</Text> : '-',
                  },
                  {
                    label: '被告警行为',
                    children: primaryEvidence
                      ? primaryEvidence.ruleName + '：' + (primaryEvidence.preview || primaryEvidence.summary || formatEvidenceLocation(primaryEvidence))
                      : effectiveRuleEvidences.length > 0 ? '选择风险类型后逐条查看命中证据' : auditDetailQ.isLoading ? '安全事件正在加载' : detectionIssue ? '检测运行异常，未检出安全风险证据' : '未提供具体命中证据',
                  },
                ]}
              />
            </Card> : null}

            {isAccessRetentionDetail && detailView === 'manager' ? <Card size="small" title={ATTRIBUTION_TOOL_CALLS_TITLE} style={{ marginTop: 12 }}>
              {sessionToolCalls.length > 0
                ? <AccessRetentionRawToolCallList calls={sessionToolCalls} />
                : <Text type="secondary">{ATTRIBUTION_NO_TOOL_DETAILS}</Text>}
            </Card> : null}

            {!linkedOccurrence ? <Card size="small" title="网关处理结果">
              <Alert
                type={gatewayOutcome?.type || contentRiskSummary.alertType}
                showIcon
                message={gatewayOutcome?.title || contentRiskSummary.title}
                description={gatewayOutcome?.description || contentRiskSummary.description}
                style={{ marginBottom: 12 }}
              />
              <Descriptions
                size="small"
                column={1}
                items={[
                  {
                    label: !selectedRiskCategory ? '会话最高风险等级' : selectedRuleEvidences.length > 1 ? '所选类型最高等级' : '风险等级',
                    children: contentRiskSummary.severity
                      ? <Tag color={SEVERITY_COLORS[contentRiskSummary.severity] || 'default'}>{SEVERITY_LABELS[contentRiskSummary.severity] || contentRiskSummary.severity}</Tag>
                      : <Tag>未发现</Tag>,
                  },
                  {
                    label: '风险类型',
                    children: conversationRiskSummary.categoryItems.length > 0
                      ? (
                        <Space size={6} wrap>
                          {conversationRiskSummary.categoryItems.map((item) => {
                            const count = effectiveRuleEvidences.filter((evidence) => evidenceMatchesCategory(evidence, item.value)).length
                            return (
                              <Button
                                key={item.value}
                                size="small"
                                type={selectedRiskCategory === item.value ? 'primary' : 'default'}
                                aria-label={`查看 ${item.label}命中证据`}
                                onClick={() => setSelectedRiskCategory(item.value)}
                              >
                                {item.label}{count > 0 ? ` ${count}` : ''}
                              </Button>
                            )
                          })}
                        </Space>
                      )
                      : '未命中安全风险分类',
                  },
                  ...(hasDirectApiCallLabel(sessionEvents) ? [{
                    label: '调用方式',
                    children: <Tag>直接调用</Tag>,
                  }] : []),
                  {
                    label: '命中规模',
                    children: `命中 ${contentRiskSummary.matchedRuleCount} 条规则，产生 ${contentRiskSummary.securityEventCount} 条安全事件`,
                  },
                  {
                    label: '建议处置',
                    children: contentRiskSummary.advice,
                  },
                ]}
              />
            </Card> : null}

            {!linkedOccurrence && shouldRenderSelectedEvidence ? (
              <Card
                size="small"
                title="命中证据"
                extra={<Button size="small" onClick={() => setSelectedRiskCategory(null)}>收起</Button>}
              >
                <Spin spinning={selectedEvidenceLoading}>
                  <Space direction="vertical" size={12} style={{ width: '100%' }}>
                    <Alert
                      type={selectedRuleEvidences.length > 0 ? 'info' : 'warning'}
                      showIcon
                      message={`${selectedRiskLabel}命中证据`}
                      description={selectedRuleEvidences.length > 0
                        ? `已找到 ${selectedRuleEvidences.length} 条规则命中记录。`
                        : '当前会话有风险分类，但没有查到可定位的规则证据；请查看全部原文或安全事件。'}
                    />
                    <List
                      dataSource={selectedRuleEvidences}
                      locale={{ emptyText: '暂无命中证据' }}
                      renderItem={(evidence: RuleEvidence) => {
                        const relatedLogs = findRelatedLogs(evidence, evidenceContextLogs)
                        const evidencePreview = recoverEvidencePreview(evidence, relatedLogs)
                        return (
                          <List.Item style={{ display: 'block', border: '1px solid var(--border-color)', borderRadius: 8, padding: 12, marginBottom: 12 }}>
                            <Space size={8} wrap style={{ marginBottom: 10 }}>
                              <Tag color={SEVERITY_COLORS[evidence.severity || ''] || 'default'}>严重度：{SEVERITY_LABELS[evidence.severity || ''] || evidence.severity || '未分级'}</Tag>
                              <Tag color={ACTION_COLORS[evidence.action || ''] || 'blue'}>{ACTION_LABELS[evidence.action || ''] || evidence.action || '已记录'}</Tag>
                              <Tag color="purple">{evidence.categoryLabel}</Tag>
                              {evidence.confidence ? <Tag color="cyan">置信度 {Math.round(evidence.confidence * 100)}%</Tag> : null}
                            </Space>
                            <Alert
                              type={evidencePreview.text ? 'warning' : 'error'}
                              showIcon
                              message="检测到的危险内容"
                              description={evidencePreview.text
                                ? evidencePreview.text + (evidence.hasRawEvidence && evidence.rawTruncated && !evidencePreview.recovered ? RAW_EVIDENCE_TRUNCATED_SUFFIX : '')
                                : evidence.rawOmitted
                                  ? RAW_EVIDENCE_OMITTED_TEXT
                                  : '告警事件未保存命中片段，且无法从当前内容留存恢复。请检查安全事件写入链路。'}
                              style={{ marginBottom: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}
                              action={evidencePreview.recovered
                                ? <Tag color="gold">由命中位置恢复</Tag>
                                : evidence.hasRawEvidence
                                  ? <Tag color="green">原始命中</Tag>
                                  : <Tag color="blue">历史命中预览</Tag>}
                            />
                            <Descriptions
                              size="small"
                              column={1}
                              items={[
                                { label: '危险类型', children: evidence.categoryLabel },
                                { label: '危险位置', children: formatEvidenceLocation(evidence) },
                                { label: '处置结果', children: ACTION_LABELS[evidence.action || ''] || evidence.action || '已记录' },
                                { label: '检测规则', children: evidence.ruleName },
                                { label: '规则 ID', children: evidence.ruleId || '-' },
                                {
                                  label: '语义复核',
                                  children: evidence.triageVerdict
                                    ? `${evidence.triageVerdict}${evidence.triageReason ? `：${evidence.triageReason}` : ''}`
                                    : evidence.semanticStatus === 'completed'
                                      ? '已执行；本规则没有获得可降级结论'
                                      : evidence.semanticStatus === 'incomplete'
                                        ? `未完成${evidence.semanticReason ? `：${evidence.semanticReason}` : ''}`
                                        : '本条未执行语义复核',
                                },
                              ]}
                            />
                            <div style={{ marginTop: 12 }}>
                              <Text strong>危险内容上下文</Text>
                              {relatedLogs.length > 0 ? (
                                <List
                                  size="small"
                                  dataSource={relatedLogs}
                                  renderItem={(log: ContentAuditLog) => (
                                    <List.Item style={{ display: 'block', padding: '10px 0' }}>
                                      <Space size={8} wrap style={{ marginBottom: 6 }}>
                                        <Tag color={ROLE_COLORS[log.role] || 'default'}>{getRoleLabel(log.role)}</Tag>
                                        <Text type="secondary">{new Date(log.created_at).toLocaleString()}</Text>
                                      </Space>
                                      <Paragraph style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', marginBottom: 0 }} ellipsis={{ rows: 7, expandable: true, symbol: '展开完整上下文' }}>
                                        {renderEvidenceContext(log.content, evidence)}
                                      </Paragraph>
                                    </List.Item>
                                  )}
                                />
                              ) : evidence.evidenceContext?.trim() ? (
                                <Alert
                                  style={{ marginTop: 8 }}
                                  type="info"
                                  showIcon
                                  message="安全事件独立留证"
                                  description={(
                                    <Paragraph
                                      style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', margin: 0 }}
                                      ellipsis={{ rows: 10, expandable: true, symbol: '展开完整上下文' }}
                                    >
                                      {renderEvidenceContext(evidence.evidenceContext, evidence)}
                                    </Paragraph>
                                  )}
                                />
                              ) : evidencePreview.text ? (
                                <Alert
                                  style={{ marginTop: 8 }}
                                  type="error"
                                  showIcon
                                  message="证据链校验失败（不可交付）"
                                  description="该事件未能关联到对应原文，不满足客户告警交付条件。请修复 request_id、消息序号或留存关联后再交付。"
                                />
                              ) : (
                                <Alert style={{ marginTop: 8 }} type="error" showIcon message="证据链不完整" description="安全事件既缺少可展示片段，也无法关联内容留存；请检查 matched_location、request_id 与内容留存是否完整写入。" />
                              )}
                            </div>
                          </List.Item>
                        )
                      }}
                    />
                    {!isAccessRetentionDetail && sessionEventsQ.hasNextPage ? (
                      <Button
                        loading={sessionEventsQ.isFetchingNextPage}
                        onClick={() => { void sessionEventsQ.fetchNextPage() }}
                      >
                        加载更多风险证据
                      </Button>
                    ) : null}
                  </Space>
                </Spin>
              </Card>
            ) : null}

            <Segmented
              value={detailView}
              onChange={(value) => {
                const nextView = value as 'manager' | 'all'
                if (nextView === 'all' && detailView !== 'all') setRawPageOffset(0)
                setDetailView(nextView)
              }}
              options={[
                { label: '摘要视图', value: 'manager' },
                { label: '全部原文', value: 'all' },
              ]}
            />

            {detailView === 'manager' ? (
              <Card size="small" title="对话轮次">
                {sessionOverview.turns.length > 0 ? (
                  <>
                    <List
                      dataSource={sessionOverview.turns}
                      renderItem={(turn: ConversationTurn) => (
                        <List.Item style={{ borderLeft: '3px solid var(--brand-blue)', paddingLeft: 12, marginBottom: 12 }}>
                        <div style={{ width: '100%' }}>
                          <Space wrap style={{ marginBottom: 12 }}>
                            <Tag color="blue">第 {turn.index} 轮</Tag>
                            {turn.startedAt && <Text type="secondary">{new Date(turn.startedAt).toLocaleString()}</Text>}
                            <Text type="secondary">输出 Token: {formatTokenUsage(turn.tokens)}</Text>
                          </Space>
                          <div style={{ marginBottom: 12 }}>
                            <Text strong>用户问题</Text>
                            <Paragraph style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', marginTop: 6, marginBottom: 0 }} ellipsis={{ rows: 5, expandable: true, symbol: '展开原文' }}>
                              {turn.user?.content || '无用户输入'}
                            </Paragraph>
                          </div>
                          <div>
                            <Text strong>模型回复</Text>
                            {turn.assistants.length > 0 ? (
                              turn.assistants.map((assistantLog) => (
                                <Paragraph key={assistantLog.id || assistantLog.created_at} style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', marginTop: 6, marginBottom: 0 }} ellipsis={{ rows: 6, expandable: true, symbol: '展开原文' }}>
                                  {assistantLog.content}
                                </Paragraph>
                              ))
                            ) : (
                              <div style={{ marginTop: 6 }}>
                                <Text type="secondary">暂无模型回复</Text>
                              </div>
                            )}
                          </div>
                        </div>
                        </List.Item>
                      )}
                    />
                  </>
                ) : (
                  <Alert
                    type="info"
                    showIcon
                    message="当前摘要视图没有业务对话内容"
                    description="这条记录主要由系统消息或代理运行噪音组成，客户视图已默认隐藏。可切换到全部原文查看完整审计证据，或导出 JSON 交给安全人员核查。"
                    action={<Button size="small" onClick={() => { setRawPageOffset(0); setDetailView('all') }}>查看全部原文</Button>}
                  />
                )}
                {detailQ.hasNextPage ? (
                  <Button
                    loading={detailQ.isFetchingNextPage}
                    onClick={() => { void detailQ.fetchNextPage() }}
                  >
                    加载更多对话
                  </Button>
                ) : null}
              </Card>
            ) : isAccessRetentionDetail ? (
              <AccessRetentionRawPanel query={rawAccessDetailQ} />
            ) : (
              <div style={{ width: '100%' }}>
                <List
                  dataSource={detailLogs}
                  locale={{ emptyText: '暂无数据' }}
                  renderItem={(item: ContentAuditLog) => {
                    const relatedEvidence = selectedRuleEvidences.find((evidence) =>
                      findRelatedLogs(evidence, detailLogs).some((log) =>
                        log === item || (Boolean(log.id) && log.id === item.id),
                      ),
                    )
                    return (
                      <List.Item style={{ borderLeft: `3px solid ${item.role === 'user' ? 'var(--brand-blue)' : item.role === 'assistant' ? 'var(--status-ok)' : 'var(--chart-2)'}`, paddingLeft: 12, marginBottom: 12 }}>
                        <div style={{ width: '100%' }}>
                          <div style={{ marginBottom: 8 }}>
                            <Tag color={ROLE_COLORS[item.role] || 'default'}>{getRoleLabel(item.role)}</Tag>
                            <Text type="secondary">{new Date(item.created_at).toLocaleString()}</Text>
                            <Text type="secondary" style={{ marginLeft: 8 }}>输出 Token: {formatTokenUsage(item.tokens)}</Text>
                          </div>
                          <Paragraph data-testid={`content-audit-raw-${item.id || item.message_index || item.created_at}`} style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', marginBottom: 0 }} ellipsis={{ rows: 8, expandable: true, symbol: '展开原文' }}>
                            {relatedEvidence ? renderEvidenceContext(item.content, relatedEvidence) : item.content}
                          </Paragraph>
                          {item.content_truncated ? (
                            <Text type="secondary" style={{ display: 'block', marginTop: 8 }}>
                              内容过长，当前显示预览；完整原文请通过导出获取。
                            </Text>
                          ) : null}
                        </div>
                      </List.Item>
                    )
                  }}
                />
                {!isAccessRetentionDetail && rawDetailPage.total > 0 ? (
                  <Space
                    wrap
                    role="group"
                    aria-label="原文分页"
                    className="content-audit-detail-pagination"
                    align="center"
                    style={{ marginTop: 12 }}
                  >
                    <Button
                      icon={<LeftOutlined />}
                      aria-label="上一页原文"
                      disabled={rawDetailPage.offset <= 0}
                      onClick={() => setRawPageOffset(Math.max(0, rawDetailPage.offset - rawDetailPage.limit))}
                    >
                      上一页原文
                    </Button>
                    <Text type="secondary" className="content-audit-detail-page-label">
                      第 {Math.floor(rawDetailPage.offset / rawDetailPage.limit) + 1} / {Math.max(1, Math.ceil(rawDetailPage.total / rawDetailPage.limit))} 页，共 {rawDetailPage.total} 条
                    </Text>
                    <Button
                      icon={<RightOutlined />}
                      aria-label="下一页原文"
                      disabled={!rawDetailPage.hasMore}
                      onClick={() => setRawPageOffset(rawDetailPage.offset + rawDetailPage.limit)}
                    >
                      下一页原文
                    </Button>
                  </Space>
                ) : null}
              </div>
            )}
          </Space>
        </Spin>
      </Drawer>
    </div>
  )
}

export default ContentAudit

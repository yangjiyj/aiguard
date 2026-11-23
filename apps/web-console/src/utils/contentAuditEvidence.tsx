import { findingEvidence } from './alertEvidence'
import { formatRuleLabel } from './risk'
import { getFindingCategoryLabel } from './alertOccurrenceDisplay'

export type ContentAuditLog = {
  id?: string
  request_id?: string
  role: string
  content: string
  tokens?: number
  content_truncated?: boolean
  created_at: string
  message_index?: number
  // access-retention stores a whole request/response segment without a
  // per-message index. Only explicitly marked segments may use that fallback.
  whole_segment?: boolean
}

export type ContentSecurityEvent = {
  id: string
  request_id?: string
  event_type?: string
  severity?: string
  rule_id?: string
  rule_name?: string
  rule_type?: string
  action_taken?: string
  matched_summary?: Record<string, any>
  evidence_ref?: string
  created_at?: string
}

export type RuleEvidence = {
  key: string
  eventId: string
  requestId?: string
  category: string
  categoryLabel: string
  ruleName: string
  ruleId?: string
  ruleType?: string
  severity?: string
  action?: string
  location?: string
  preview?: string
  evidenceContext?: string
  confidence?: number
  summary?: string
  createdAt?: string
  messageIndex?: number
  messageRole?: string
  attachmentIndex?: number
  countsAsSecurityFinding: boolean
  hasRawEvidence: boolean
  rawTruncated?: boolean
  rawOmitted?: boolean
  semanticStatus?: string
  semanticReason?: string
  triageVerdict?: string
  triageReason?: string
}

const normalizeEvidenceText = (value?: string) => String(value || '').replace(/\s+/g, '').toLowerCase()

const uniqueBy = <T,>(items: T[], getKey: (item: T) => string) => {
  const seen = new Set<string>()
  return items.filter((item) => {
    const key = getKey(item)
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

const getEventFindings = (event: ContentSecurityEvent) => {
  const summary = event.matched_summary || {}
  if (Array.isArray(summary.findings) && summary.findings.length > 0) return summary.findings
  return [{
    category: summary.category || event.rule_type || event.event_type,
    rule_id: event.rule_id,
    rule_name: event.rule_name,
    rule_type: event.rule_type,
    severity: event.severity,
    action: event.action_taken,
    matched_text_preview: summary.summary,
  }]
}

const optionalIndex = (value: unknown) => {
  if (value == null || typeof value === 'boolean' || (typeof value === 'string' && !value.trim())) return undefined
  const index = typeof value === 'number' ? value : Number(value)
  return Number.isInteger(index) && index >= 0 ? index : undefined
}

// WorkBuddy / Codex 等 Agent 会在 user 角色里塞协议级元数据包（带属性的 <system-reminder…>）。
// 这里的模式表与阈值是「元消息判定」的单一来源，页面隐藏与证据关联都走它，避免两处口径漂移。
export const AGENT_META_USER_PATTERNS = [
  /^The user stepped away and is coming back/i,
  /^Recap in under \d+ words/i,
  /^<system-reminder\b[^>]*>/i,
  /^You are an expert AI programming assistant, working with a user in the VS Code editor/i,
  /Your name is GitHub Copilot/i,
]

export const isAgentMetaText = (content?: string) =>
  AGENT_META_USER_PATTERNS.some((pattern) => pattern.test(String(content || '').trim()))

export const isAgentMetaUserMessage = (log?: ContentAuditLog) => {
  if (!log || log.role !== 'user') return false
  return isAgentMetaText(log.content)
}

const countsAsSecurityFinding = (finding: any) => {
  const counts = finding?.counts_as_security_finding
  return typeof counts === 'string' ? counts.toLowerCase() !== 'false' : counts !== false
}

const isRuntimeTelemetryFinding = (finding: any) =>
  String(finding?.type || '').toLowerCase() === 'semantic_telemetry'

// 「直接 API 调用」是请求识别标签，不是命中：新事件放在 matched_summary.request_labels，
// 存量事件里是一条不计入安全发现的 finding。
const DIRECT_API_CALL_LABEL = 'agent_direct_api_call'

export const hasDirectApiCallLabel = (events: ContentSecurityEvent[]) => events.some((event) => {
  const summary = event.matched_summary || {}
  const labels = Array.isArray(summary.request_labels) ? summary.request_labels : []
  if (labels.some((label: unknown) => String(label || '').toLowerCase() === DIRECT_API_CALL_LABEL)) return true
  const findings = Array.isArray(summary.findings) ? summary.findings : []
  return findings.some((finding: any) => String(finding?.category || '').toLowerCase() === DIRECT_API_CALL_LABEL)
})

export const buildRuleEvidences = (events: ContentSecurityEvent[]) => events.flatMap((event) => {
  const summary = event.matched_summary || {}
  const hasFindings = Array.isArray(summary.findings) && summary.findings.length > 0
  return getEventFindings(event)
    .filter((finding: any) => countsAsSecurityFinding(finding) && !isRuntimeTelemetryFinding(finding))
    .map((finding: any, index: number): RuleEvidence => {
    const category = String(finding?.category || finding?.type || event.rule_type || summary.category || event.event_type || 'security_check')
    const ruleId = String(finding?.rule_id || event.rule_id || '')
    const ruleName = String(finding?.rule_name || event.rule_name || formatRuleLabel(ruleId, category))
    return {
      key: `${event.id || event.request_id || 'event'}-${ruleId || category}-${index}`,
      eventId: event.id,
      requestId: event.request_id,
      category,
      categoryLabel: getFindingCategoryLabel(category),
      ruleName,
      ruleId: ruleId || undefined,
      ruleType: String(finding?.rule_type || event.rule_type || ''),
      severity: String(finding?.effective_severity || finding?.severity || (hasFindings ? '' : event.severity) || ''),
      action: String(event.action_taken || summary.action_taken || ''),
      location: String(finding?.matched_location || ''),
      preview: findingEvidence(finding),
      evidenceContext: String(finding?.evidence_context || ''),
      confidence: Number(finding?.confidence) || undefined,
      summary: String(finding?.reason || finding?.summary || (hasFindings ? '' : summary.summary) || ''),
      createdAt: event.created_at,
      messageIndex: optionalIndex(finding?.message_index),
      messageRole: String(finding?.message_role || ''),
      attachmentIndex: optionalIndex(finding?.attachment_index),
      countsAsSecurityFinding: finding?.counts_as_security_finding !== false
        && String(finding?.counts_as_security_finding || '').toLowerCase() !== 'false',
      hasRawEvidence: Boolean(String(finding?.raw_evidence || '').trim()),
      rawTruncated: finding?.raw_evidence_truncated === true,
      rawOmitted: finding?.raw_evidence_omitted === true,
      semanticStatus: String(summary.semantic_status || ''),
      semanticReason: String(summary.semantic_reason || ''),
      triageVerdict: String(finding?.triage?.verdict || finding?.triage?.review_state || ''),
      triageReason: String(finding?.triage?.reason || finding?.triage?.explanation || ''),
    }
  })
})

const getLocationRole = (location?: string) => {
  const normalized = String(location || '').toLowerCase()
  if (/tool|工具/.test(normalized)) return 'tool'
  if (/assistant|模型输出|模型回复|ai消息/.test(normalized)) return 'assistant'
  if (/system|系统/.test(normalized)) return 'system'
  if (/user|用户输入|用户消息/.test(normalized)) return 'user'
  return ''
}

const getLocationMessageIndex = (location?: string) => {
  const matched = String(location || '').match(/第\s*(\d+)\s*条[^/]*(?:消息|message)/i)
  if (!matched) return undefined
  const index = Number(matched[1]) - 1
  return Number.isInteger(index) && index >= 0 ? index : undefined
}

const getLocationContentRange = (location?: string) => {
  const matched = String(location || '').match(/content\[(\d+)\s*:\s*(\d+)\]/i)
  if (!matched) return undefined
  const start = Number(matched[1])
  const end = Number(matched[2])
  return Number.isInteger(start) && Number.isInteger(end) && start >= 0 && end > start
    ? { start, end }
    : undefined
}

export const findRelatedLogs = (evidence: RuleEvidence, logs: ContentAuditLog[]) => {
  // 协议级元数据包不是用户正文：不得把证据关联到这类 user 消息上。
  logs = logs.filter((log) => !isAgentMetaUserMessage(log))
  const locationRole = getLocationRole(evidence.location)
  const expectedRole = evidence.messageRole || locationRole
  const requestMatched = evidence.requestId ? logs.filter((log) => log.request_id === evidence.requestId) : []

  if (evidence.messageIndex !== undefined) {
    if (!evidence.requestId || !expectedRole) return []
    const indexMatched = requestMatched.filter((log) =>
      log.message_index === evidence.messageIndex
      && log.role === expectedRole
    )
    if (indexMatched.length > 0) return indexMatched
    // Per-message logs must keep strict anchors. Whole retained segments may
    // fall back to request and role so existing raw evidence remains usable.
    const wholeSegmentLogs = requestMatched.filter((log) => log.whole_segment && log.message_index === undefined)
    if (wholeSegmentLogs.length === 0) return []
    const roleMatched = wholeSegmentLogs.filter((log) => log.role === expectedRole)
    const fallback = roleMatched.length > 0 ? roleMatched : wholeSegmentLogs
    return uniqueBy(fallback, (log) => log.id || `${log.role}-${log.created_at}`)
  }

  const locationMessageIndex = getLocationMessageIndex(evidence.location)
  if (locationMessageIndex !== undefined) {
    const requestIds = [...new Set(logs.map((log) => log.request_id).filter(Boolean))]
    const locationRequestId = evidence.requestId || (requestIds.length === 1 ? requestIds[0] : undefined)
    if (!locationRequestId || !locationRole) return []
    const locationRequestLogs = logs.filter((log) => log.request_id === locationRequestId)
    const indexedMessage = locationRequestLogs.find((log) => log.message_index === locationMessageIndex)
      || (locationRequestLogs.every((log) => log.message_index === undefined) ? locationRequestLogs[locationMessageIndex] : undefined)
    return indexedMessage?.role === locationRole ? [indexedMessage] : []
  }

  const candidateLogs = evidence.requestId
    ? logs.filter((log) => !log.request_id || log.request_id === evidence.requestId)
    : logs
  const roleConstrainedLogs = expectedRole
    ? candidateLogs.filter((log) => log.role === expectedRole)
    : candidateLogs
  const snippets = [evidence.preview, evidence.summary].map((item) => normalizeEvidenceText(item)).filter((item) => item.length >= 3)
  const snippetMatched = snippets.length > 0
    ? roleConstrainedLogs.filter((log) => snippets.some((snippet) => normalizeEvidenceText(log.content).includes(snippet)))
    : []
  if (snippetMatched.length > 0) return uniqueBy(snippetMatched, (log) => log.id || `${log.role}-${log.created_at}`)

  const range = getLocationContentRange(evidence.location)
  if (range) {
    const rangeCandidates = expectedRole ? roleConstrainedLogs : requestMatched
    return rangeCandidates.length === 1 ? rangeCandidates : []
  }

  const roleMatched = expectedRole ? roleConstrainedLogs : []
  return uniqueBy([...requestMatched, ...roleMatched], (log) => log.id || `${log.role}-${log.created_at}`)
}

const isSensitiveEvidence = (evidence: RuleEvidence) =>
  /secret|credential|password|token|api[_ -]?key|config|env|密钥|凭据|口令/i.test(
    [evidence.category, evidence.ruleType, evidence.ruleId, evidence.ruleName].filter(Boolean).join(' '),
  )

export const recoverEvidencePreview = (evidence: RuleEvidence, relatedLogs: ContentAuditLog[]) => {
  if (evidence.preview?.trim()) return { text: evidence.preview.trim(), recovered: false }
  const range = getLocationContentRange(evidence.location)
  const source = relatedLogs.find((log) => {
    if (!range) return false
    return String(log.content || '').length >= range.end
  }) || relatedLogs[0]
  const content = String(source?.content || '').trim()
  if (!content) return { text: '', recovered: false }

  if (range && content.length >= range.end) {
    const contextStart = Math.max(0, range.start - 100)
    const contextEnd = Math.min(content.length, range.end + 100)
    const prefix = contextStart > 0 ? '…' : ''
    const suffix = contextEnd < content.length ? '…' : ''
    return { text: `${prefix}${content.slice(contextStart, contextEnd)}${suffix}`, recovered: true }
  }

  if (isSensitiveEvidence(evidence)) {
    return {
      text: '已定位到相关消息，但事件未提供命中片段或精确字符区间；请在下方受控上下文中复核。',
      recovered: true,
    }
  }

  return {
    text: content.length > 320 ? `${content.slice(0, 320)}…` : content,
    recovered: true,
  }
}

const renderHighlightedContent = (content: string, preview?: string) => {
  const snippet = String(preview || '').trim()
  if (!snippet) return content
  const index = content.toLowerCase().indexOf(snippet.toLowerCase())
  if (index < 0) return content
  return <>{content.slice(0, index)}<mark style={{ background: '#ffe58f', color: 'inherit', padding: '0 2px', borderRadius: 2 }}>{content.slice(index, index + snippet.length)}</mark>{content.slice(index + snippet.length)}</>
}

export const renderEvidenceContext = (content: string, evidence: RuleEvidence) => {
  const range = getLocationContentRange(evidence.location)
  if (range && content.length >= range.end) {
    return <>{content.slice(0, range.start)}<mark style={{ background: '#ffe58f', color: 'inherit', padding: '0 2px', borderRadius: 2 }}>{content.slice(range.start, range.end)}</mark>{content.slice(range.end)}</>
  }
  return renderHighlightedContent(content, evidence.preview)
}

export const formatEvidenceLocation = (evidence: RuleEvidence) => {
  const anchors: string[] = []
  if (evidence.messageIndex !== undefined) {
    anchors.push(`第 ${evidence.messageIndex + 1} 条${evidence.messageRole ? ` ${evidence.messageRole}` : ''}消息`)
  }
  if (evidence.attachmentIndex !== undefined) anchors.push(`附件 ${evidence.attachmentIndex + 1}`)
  if (evidence.location) anchors.push(evidence.location)
  return anchors.join(' / ') || '未标注'
}

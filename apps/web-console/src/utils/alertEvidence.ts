import type {
  AuditContentEvidenceInfo,
  AuditSecurityEventInfo,
  AuditToolCallLogInfo,
} from '../services/api'

type Finding = Record<string, unknown>

const text = (value: unknown) => typeof value === 'string' ? value.trim() : ''
const normalized = (value: unknown) => text(value).toLowerCase()

const findings = (event: AuditSecurityEventInfo): Finding[] => {
  const raw = event.matched_summary?.findings
  if (!Array.isArray(raw)) return []
  return raw.filter((item): item is Finding => !!item && typeof item === 'object' && !Array.isArray(item))
}

const countsAsSecurityFinding = (finding: Finding) => {
  const value = finding.counts_as_security_finding
  if (typeof value === 'boolean') return value
  if (typeof value === 'string') return value.toLowerCase() === 'true'
  return true
}

const severityWeight = (value: unknown) => {
  switch (normalized(value)) {
    case 'critical': return 60
    case 'high': return 45
    case 'medium': return 20
    case 'low': return 5
    default: return 0
  }
}

const isBlockedAction = (value: unknown) => {
  const action = normalized(value)
  return action === 'block'
    || action === 'blocked'
    || action === 'reply'
    || action === 'mask'
    || action === 'quarantine'
    || action.includes('blocked')
}

const isAuditAction = (value: unknown) => {
  const action = normalized(value)
  return action === 'audit' || action.includes('audit')
}

export type FindingEvidenceKind = 'literal' | 'semantic' | 'contextual' | 'runtime'

export type FindingEvidenceDetail = {
  kind: FindingEvidenceKind
  raw: string
  display: string
  location: string
  source: string
  reason: string
  historicalMissing: boolean
}

export const findingEvidenceDetail = (finding: Finding): FindingEvidenceDetail => {
  const raw = text(finding.raw_evidence)
  const display = raw
    || text(finding.redacted_evidence)
    || text(finding.matched_text_preview)
    || text(finding.matched_preview)
    || text(finding.evidence_preview)
  const explicitKind = normalized(finding.evidence_kind)
  const type = normalized(finding.type)
  const ruleType = normalized(finding.rule_type)
  let kind: FindingEvidenceKind = 'contextual'
  if (explicitKind === 'literal' || explicitKind === 'semantic' || explicitKind === 'contextual' || explicitKind === 'runtime') {
    kind = explicitKind
  } else if (type === 'semantic_attack' || ruleType === 'semantic') {
    kind = type === 'semantic_telemetry' ? 'runtime' : 'semantic'
  } else if (type === 'semantic_telemetry' || type === 'engine_runtime') {
    kind = 'runtime'
  } else if (raw) {
    kind = 'literal'
  }
  return {
    kind,
    raw,
    display,
    location: text(finding.matched_location),
    source: text(finding.content_source),
    reason: text(finding.evidence_reason) || text((finding.triage as Finding | undefined)?.reason),
    historicalMissing: !raw && Boolean(display),
  }
}

// 命中原文超过数据面上限（4096 字）被截断时，在原文后面标出。
export const RAW_EVIDENCE_TRUNCATED_SUFFIX = '（已截断）'

// 原文加截断标记；没有原文时返回空串。
export const rawEvidenceDisplay = (raw?: string | null, truncated?: boolean | null) =>
  raw && raw.trim() ? raw + (truncated ? RAW_EVIDENCE_TRUNCATED_SUFFIX : '') : ''

export const RAW_EVIDENCE_OMITTED_TEXT = '命中原文超出单个事件的保存上限，未随事件保存，请在内容留存中查看。'

export const findingEvidence = (finding: Finding) => {
  const detail = findingEvidenceDetail(finding)
  // 原文优先；历史事件没存原文时显示当时的打码片段。
  return detail.raw || detail.display
}

const eventEvidencePriority = (event: AuditSecurityEventInfo) => {
  const eventFindings = findings(event)
  const actionableFindings = eventFindings.filter(countsAsSecurityFinding)
  const strongestFinding = actionableFindings.reduce(
    (weight, finding) => Math.max(weight, severityWeight(finding.severity)),
    0,
  )
  let score = 0
  if (isBlockedAction(event.action_taken)) score += 1000
  // An event-level severity can be inherited from an observation finding. Only
  // actionable findings or an enforcement action may contribute risk weight.
  if (actionableFindings.length > 0 || isBlockedAction(event.action_taken)) {
    score += Math.max(severityWeight(event.severity), strongestFinding) * 10
  }
  if (actionableFindings.length > 0) score += 200
  if (actionableFindings.some((finding) => findingEvidence(finding))) score += 80
  if (event.rule_id || event.rule_name || event.rule_type) score += 30
  if (normalized(event.event_type) === 'agentguard_tool_decision' && eventFindings.length === 0) score -= 100
  return score
}

export const selectPrimaryEvidenceEvent = (events: AuditSecurityEventInfo[]) =>
  [...events].sort((left, right) =>
    eventEvidencePriority(right) - eventEvidencePriority(left)
    || Date.parse(right.created_at) - Date.parse(left.created_at)
  )[0]

export const isPipelineIssueEvent = (event: AuditSecurityEventInfo) => {
  const eventFindings = findings(event)
  const hasPipelineIssue = eventFindings.some((finding) =>
    normalized(finding.category || finding.type) === 'semantic_unavailable'
    && !countsAsSecurityFinding(finding)
  )
  const hasAttackEvidence = eventFindings.some((finding) => countsAsSecurityFinding(finding))
  return hasPipelineIssue && !hasAttackEvidence
}

export const isAuditOnlyDetail = (
  recordAction: string | undefined,
  recordBlocked: boolean,
  events: AuditSecurityEventInfo[],
  tools: AuditToolCallLogInfo[],
) => {
  if (recordBlocked) return false
  if (events.some((event) => isBlockedAction(event.action_taken) || normalized(event.event_type).includes('blocked'))) {
    return false
  }
  if (tools.some((tool) =>
    (normalized(tool.event_kind) === 'execution_forwarded' || tool.execution_observed)
    && (isBlockedAction(tool.status) || isBlockedAction(tool.matched_action))
  )) {
    return false
  }
  return isAuditAction(recordAction) || events.some((event) => isAuditAction(event.action_taken))
}

export const contentEvidenceLabel = (evidence?: AuditContentEvidenceInfo) => {
  switch (normalized(evidence?.status)) {
    case 'available': return '已有原始内容留证（管理员可见）'
    case 'not_collected': return '本次请求未采集内容'
    case 'expired': return '内容留证已过期'
    case 'unavailable': return '内容留证暂时读取失败'
    default: return '内容留证状态未记录'
  }
}

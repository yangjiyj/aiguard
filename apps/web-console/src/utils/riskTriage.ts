import { getEventEvidenceSummary, getEventMatchedRules, getEventRiskCategories, getToolMatchReason, CORE_SEVERITY_LABELS } from './risk'

export type TriageLevel = 'action_required' | 'review' | 'audit'

export type RiskTriage = {
  level: TriageLevel
  label: string
  color: string
  category: string
  reason: string
  advice: string
  score: number
}

export type RiskConversationGroup = {
  id: string
  conversationId?: string
  sessionId: string
  primaryRequestId: string
  requestIds: string[]
  events: any[]
  eventCount: number
  requestCount: number
  triage: RiskTriage
  categories: string[]
  ruleNames: string[]
  startedAt?: string
  endedAt?: string
}

const TRIAGE_META: Record<TriageLevel, Pick<RiskTriage, 'label' | 'color'>> = {
  action_required: { label: '待处置', color: 'red' },
  review: { label: '需复核', color: 'orange' },
  audit: { label: '仅审计', color: 'blue' },
}

const SENSITIVE_PATTERN = /(\.env|id_rsa|private[_ -]?key|api[_ -]?key|secret|token|password|passwd|credential|kubeconfig|authorized_keys|AKIA|sk-[a-z0-9])/i
const EXFIL_PATTERN = /(curl|wget|fetch|websocket|POST|PUT|upload|--data|-d\s|@\.env|http:\/\/|https:\/\/)/i
const DESTRUCTIVE_PATTERN = /(rm\s+-rf|DROP\s+TABLE|DELETE\s+FROM|TRUNCATE|chmod\s+777|mkfs|dd\s+if=|shutdown|reboot)/i
const PERSISTENCE_PATTERN = /(crontab|systemd|authorized_keys|\/etc\/profile|\.bashrc|launchctl|schtasks|startup)/i
const RECON_PATTERN = /(nmap|masscan|169\.254\.169\.254|metadata\.google|metadata\.aliyun|docker\.sock|kubectl|get\s+secrets)/i
const NORMAL_DEV_COMMAND_PATTERN = /^(npm|pnpm|yarn|go|git|rg|grep|sed|awk|ls|pwd|cat|head|tail|find|wc|docker compose ps|docker ps|curl -s -o \/dev\/null)/i

const stringify = (value: unknown) => {
  if (value === undefined || value === null) return ''
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

const makeTriage = (level: TriageLevel, category: string, reason: string, advice: string, score: number): RiskTriage => ({
  level,
  ...TRIAGE_META[level],
  category,
  reason,
  advice,
  score,
})

const severityScore = (severity?: string) => {
  if (severity === 'critical') return 90
  if (severity === 'high') return 70
  if (severity === 'medium') return 45
  if (severity === 'low') return 20
  return 10
}

const hasSensitiveAccess = (text: string) => SENSITIVE_PATTERN.test(text)
const hasOutboundExfil = (text: string) => EXFIL_PATTERN.test(text)
const hasDestructiveAction = (text: string) => DESTRUCTIVE_PATTERN.test(text)
const hasPersistenceChange = (text: string) => PERSISTENCE_PATTERN.test(text)
const hasReconBehavior = (text: string) => RECON_PATTERN.test(text)

export const getToolTriage = (tool: any): RiskTriage => {
  const text = [tool?.tool_name, tool?.tool_type, tool?.risk_level, stringify(tool?.parameters), stringify(tool?.result), getToolMatchReason(tool)]
    .filter(Boolean)
    .join(' ')
  const command = stringify(tool?.parameters?.command || tool?.parameters?.cmd || tool?.parameters?.input || tool?.parameters)
  const normalizedCommand = command.trim()

  if (hasSensitiveAccess(text) && hasOutboundExfil(text)) {
    return makeTriage('action_required', '数据外传链路', '同时出现敏感对象和外联/上传行为', '立即复核请求详情，确认是否存在敏感数据外传。', 96)
  }
  if (hasSensitiveAccess(text)) {
    return makeTriage('action_required', '敏感数据读取', '访问了敏感密钥、Token、配置文件或凭据类对象', '确认访问是否获得授权，必要时轮换相关密钥。', 90)
  }
  if (hasDestructiveAction(text)) {
    return makeTriage('action_required', '破坏性操作', '包含删除、清空、批量修改或高破坏性命令', '核对操作对象和执行结果，确认是否造成业务影响。', 88)
  }
  if (hasPersistenceChange(text)) {
    return makeTriage('action_required', '权限与持久化', '涉及自启动、授权文件、系统服务或登录脚本变更', '复核主机持久化项，确认是否存在越权驻留。', 86)
  }
  if (hasReconBehavior(text)) {
    return makeTriage('review', '内网探测', '出现内网探测、元数据地址或基础设施接口访问特征', '确认是否为授权诊断，关注是否伴随后续外联或凭据读取。', 72)
  }
  const effectiveDecision = String(tool?.effective_decision ?? '').trim().toLowerCase()
  const status = String(tool?.status ?? '').trim().toLowerCase()
  if (effectiveDecision === 'block' || effectiveDecision === 'confirm' || status === 'blocked' || status === 'denied') {
    const reason = effectiveDecision === 'confirm'
      ? '该调用处于待确认状态，需要复核策略决定和会话上下文；该状态本身不证明调用恶意。'
      : '该调用已被策略阻断或拒绝，需要复核策略命中依据和会话上下文；阻断本身不证明调用恶意。'
    return makeTriage('review', '策略阻断或待确认', reason, '查看工具参数、策略结果和同一会话上下文，再决定是否需要后续处置。', 55)
  }
  if (normalizedCommand && NORMAL_DEV_COMMAND_PATTERN.test(normalizedCommand) && !hasSensitiveAccess(normalizedCommand)) {
    return makeTriage('audit', '正常开发操作', '正常开发、测试、构建或代码检索行为，默认只记录', '无需处理；如同一会话后续出现敏感读取或外联，再升级复核。', 18)
  }
  if (tool?.risk_level === 'critical' || tool?.risk_level === 'high') {
    return makeTriage('review', '高风险工具调用', '工具本身权限较高，但未看到敏感对象、外传或破坏性动作', '复核参数和会话上下文，确认是否符合授权范围。', severityScore(tool?.risk_level))
  }
  if (tool?.tool_type === 'network' || tool?.tool_type === 'database' || tool?.tool_type === 'mcp') {
    return makeTriage('review', '工具风险线索', '涉及网络、数据库或 MCP 能力，需要结合上下文判断', '检查目标地址、查询对象和 MCP 来源可信度。', 55)
  }
  return makeTriage('audit', '审计记录', '未发现需要处置的高风险上下文', '保留记录用于追溯，无需单独处理。', 10)
}

const eventEffectiveSeverity = (event: any) => {
  const summary = event?.matched_summary
  return String(event?.effective_severity || summary?.effective_severity || event?.severity || '').toLowerCase()
}

const eventReviewState = (event: any) => {
  const summary = event?.matched_summary
  if (summary?.review_state) return String(summary.review_state).toLowerCase()
  const findings = Array.isArray(summary?.findings) ? summary.findings : []
  const triage = findings.find((finding: any) => finding?.triage)?.triage
  return String(triage?.review_state || triage?.verdict || '').toLowerCase()
}

const eventContentSource = (event: any) => {
  const summary = event?.matched_summary
  return String(event?.content_source || summary?.content_source || '').toLowerCase()
}

const verifiedContentTriage = (event: any, categories: string[]): RiskTriage | null => {
  const source = eventContentSource(event)
  if (source !== 'verified_user_input' && source !== 'verified_final_output') return null

  const state = eventReviewState(event)
  const severity = eventEffectiveSeverity(event)
  if (state === 'likely_false_positive' || state === 'audit_evidence') {
    return makeTriage('audit', categories[0] || '\u4EC5\u5BA1\u8BA1\u7559\u8BC1', '\u5DF2\u9A8C\u8BC1\u5185\u5BB9\u88AB\u5224\u5B9A\u4E3A\u4EC5\u5BA1\u8BA1\u7559\u8BC1\u3002', '\u4FDD\u7559\u8BB0\u5F55\u7528\u4E8E\u8FFD\u6EAF\uFF0C\u65E0\u9700\u5904\u7F6E\u3002', severityScore('low'))
  }
  if (state === 'review_pending' || state === 'unavailable' || state === 'needs_review') {
    const reason = state === 'unavailable' ? '\u8BED\u4E49\u88C1\u5224\u4E0D\u53EF\u7528\uFF0C\u8BE5\u5019\u9009\u5DF2\u4FDD\u7559\u4EBA\u5DE5\u590D\u6838\u3002' : '\u5DF2\u9A8C\u8BC1\u5185\u5BB9\u547D\u4E2D\u786E\u5B9A\u6027\u89C4\u5219\uFF0C\u6B63\u5728\u7B49\u5F85\u8BED\u4E49\u590D\u6838\u3002'
    return makeTriage('review', categories[0] || '\u5F85\u8BED\u4E49\u590D\u6838', reason, '\u4EC5\u590D\u6838\u6700\u540E\u7528\u6237\u8F93\u5165\u6216\u6700\u7EC8\u6A21\u578B\u8F93\u51FA\uFF0C\u4E0D\u8981\u4F9D\u636E\u539F\u59CB\u534F\u8BAE\u5C01\u5957\u5904\u7F6E\u3002', severityScore('medium'))
  }
  if (state === 'confirmed_risk') {
    return makeTriage('action_required', categories[0] || '\u786E\u8BA4\u98CE\u9669', '\u5DF2\u9A8C\u8BC1\u5185\u5BB9\u5DF2\u786E\u8BA4\u4E3A\u5B9E\u8D28\u98CE\u9669\u3002', '\u590D\u6838\u5DF2\u9A8C\u8BC1\u7684\u7528\u6237\u8F93\u5165\u6216\u6A21\u578B\u6700\u7EC8\u56DE\u7B54\u5E76\u91C7\u53D6\u5904\u7F6E\u3002', severityScore(severity))
  }
  return makeTriage('review', categories[0] || '\u5F85\u8BED\u4E49\u590D\u6838', '\u5DF2\u9A8C\u8BC1\u5185\u5BB9\u5C1A\u65E0\u6700\u7EC8\u7814\u5224\u7ED3\u8BBA\u3002', '\u5B8C\u6210\u8BED\u4E49\u590D\u6838\u524D\u4E0D\u8981\u91C7\u53D6\u5904\u7F6E\u3002', severityScore('medium'))
}


export const getEventTriage = (event: any): RiskTriage => {
  const categories = getEventRiskCategories(event)
  const rules = getEventMatchedRules(event)
  const text = [
    event?.event_type,
    event?.severity,
    event?.action_taken,
    event?.rule_id,
    event?.rule_name,
    event?.rule_type,
    categories.join(' '),
    rules.join(' '),
    getEventEvidenceSummary(event),
    stringify(event?.matched_summary),
  ].filter(Boolean).join(' ')

  if (event?.action_taken === 'block') {
    return makeTriage('action_required', '已阻断风险', '策略已经触发阻断，说明风险达到强处置条件', '查看请求详情，确认是否需要通知业务或调整策略。', 92)
  }
  const effectiveSeverity = eventEffectiveSeverity(event)
  const verifiedTriage = verifiedContentTriage(event, categories)
  if (verifiedTriage) return verifiedTriage
  if (hasSensitiveAccess(text) && hasOutboundExfil(text)) {
    return makeTriage('action_required', '数据外传链路', '规则证据同时包含敏感对象和外联/上传特征', '立即复核会话和工具调用链路。', 95)
  }
  if (hasSensitiveAccess(text)) {
    return makeTriage('action_required', '敏感数据读取', '规则证据包含敏感凭据、密钥、Token 或配置文件风险', '确认是否授权访问，必要时轮换相关凭据。', 88)
  }
  if (hasDestructiveAction(text) || hasPersistenceChange(text)) {
    return makeTriage('action_required', '高危系统行为', '规则证据包含破坏性操作或持久化变更', '复核执行结果和主机状态。', 86)
  }
  if (effectiveSeverity === 'critical') {
    return makeTriage('action_required', categories[0] || CORE_SEVERITY_LABELS.critical, '严重级别风险线索，需要优先确认', '打开请求详情查看命中内容和上下文。', 82)
  }
  if (effectiveSeverity === 'high' || effectiveSeverity === 'medium') {
    return makeTriage('review', categories[0] || '\u98CE\u9669\u7EBF\u7D22', '\u5F53\u524D\u6709\u6548\u98CE\u9669\u7B49\u7EA7\u9700\u8981\u4EBA\u5DE5\u590D\u6838\u3002', '\u5148\u67E5\u770B\u4E8B\u4EF6\u8BC1\u636E\uFF0C\u518D\u51B3\u5B9A\u662F\u5426\u5904\u7F6E\u3002', severityScore(effectiveSeverity))
  }
  if (event?.severity === 'high' || event?.severity === 'medium') {
    return makeTriage('review', categories[0] || '风险线索', '规则已命中，但未达到直接处置条件', '结合请求详情复核；若多次重复误报，可下调规则展示级别。', severityScore(event?.severity))
  }
  return makeTriage('audit', categories[0] || '审计记录', '低危或信息性命中，默认只作为审计证据', '无需处理，保留记录用于追溯。', severityScore(event?.severity))
}

export const summarizeTriage = (items: Array<Pick<RiskTriage, 'level'>>) => ({
  actionRequired: items.filter((item) => item.level === 'action_required').length,
  review: items.filter((item) => item.level === 'review').length,
  audit: items.filter((item) => item.level === 'audit').length,
})

export const sortByTriage = <T extends { triage: RiskTriage }>(items: T[]) =>
  [...items].sort((a, b) => b.triage.score - a.triage.score)

export const groupEventsByConversation = (
  events: any[],
  requests: Array<{ request_id?: string; session_id?: string; conversation_id?: string; created_at?: string }> = [],
): RiskConversationGroup[] => {
  const requestById = new Map(requests.filter((request) => request.request_id).map((request) => [request.request_id, request]))
  const groupMap = new Map<string, RiskConversationGroup>()

  events.forEach((event) => {
    const request = requestById.get(event?.request_id)
    const conversationId = event?.conversation_id || request?.conversation_id
    const sessionId = event?.session_id || request?.session_id || event?.request_id || event?.id || 'unknown'
    const key = conversationId || sessionId || event?.request_id || event?.id
    const triage = event?.triage || getEventTriage(event)
    const createdAt = event?.created_at || request?.created_at
    const existing = groupMap.get(key)
    const group: RiskConversationGroup = existing || {
      id: key,
      conversationId,
      sessionId,
      primaryRequestId: event?.request_id || '',
      requestIds: [],
      events: [],
      eventCount: 0,
      requestCount: 0,
      triage,
      categories: [],
      ruleNames: [],
      startedAt: createdAt,
      endedAt: createdAt,
    }

    group.events.push({ ...event, triage })
    group.eventCount = group.events.length
    if (event?.request_id && !group.requestIds.includes(event.request_id)) {
      group.requestIds.push(event.request_id)
    }
    group.requestCount = group.requestIds.length
    if (!group.primaryRequestId || triage.score > group.triage.score) {
      group.primaryRequestId = event?.request_id || group.primaryRequestId
    }
    if (triage.score > group.triage.score) {
      group.triage = triage
    }

    getEventRiskCategories(event).forEach((category) => {
      if (!group.categories.includes(category)) group.categories.push(category)
    })
    getEventMatchedRules(event).forEach((rule) => {
      if (!group.ruleNames.includes(rule)) group.ruleNames.push(rule)
    })

    if (createdAt) {
      if (!group.startedAt || new Date(createdAt).getTime() < new Date(group.startedAt).getTime()) group.startedAt = createdAt
      if (!group.endedAt || new Date(createdAt).getTime() > new Date(group.endedAt).getTime()) group.endedAt = createdAt
    }

    groupMap.set(key, group)
  })

  return sortByTriage(Array.from(groupMap.values()))
}

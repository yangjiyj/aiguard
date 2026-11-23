import { CORE_SEVERITY_LABELS } from './risk'
import { alertActionResult, isKnownAlertAction } from './alertReadable'

// 消息中心展示辅助：严重度 / 来源 / 风险域中文映射与 normalizeInboxItem。
// 从 pages/AlertInbox.tsx 原样抽出（页面文件只能导出组件，否则 react-refresh lint 告警；
// 折叠视图与批量已读弹窗也要共用这些映射），逻辑未改。

export const SEVERITY_CONFIG: Record<string, { color: string; label: string }> = {
  critical: { color: 'red', label: CORE_SEVERITY_LABELS.critical },
  high: { color: 'orange', label: CORE_SEVERITY_LABELS.high },
  medium: { color: 'gold', label: CORE_SEVERITY_LABELS.medium },
  low: { color: 'blue', label: CORE_SEVERITY_LABELS.low },
  warning: { color: 'gold', label: '提醒' },
  info: { color: 'blue', label: '提示' },
}

// 来源 / 处置 / event_type 中文标签：消息中心面向客户，不外露原始英文枚举或技术 id。
// 处置叫法以 alertActionResult 为准；控制面 secevent_bridge.go 的 actionLabelsCN 逐键对齐，由 Go 测试读 alertReadable.ts 比对。
export const SOURCE_LABELS: Record<string, string> = {
  security_event: '安全事件',
  runtime_fault: '运行故障',
  access_governance: '访问治理',
  security_event_daily_summary: '安全事件日聚合',
  governor: '预算管控',
  budget: '预算超限',
  cost_anomaly: '成本异常',
  anomaly: '异常检测',
  quota: '额度控制',
  // 计费与审计链运维告警（后端 opsalert 包，类型与中文名一一对应）。
  billing_budget_exhausted: '预算用尽断流',
  billing_unpriced_rejected: '未定价模型被拒',
  billing_budget_unavailable: '额度状态无法确认被拒',
  billing_wallet_overdraft: '钱包透支',
  billing_finalize_failed: '计费结算失败',
  billing_reservation_leak: '预占泄漏清理',
  billing_proxy_usage_unknown: '正向代理用量未知',
  billing_budget_threshold_80: '预算已用 80%',
  billing_budget_threshold_100: '预算已用尽 100%',
  audit_chain_record_dropped: '审计记录丢失',
  audit_chain_write_failed: '关键审计写入失败',
  audit_chain_verify_failed: '审计链完整性校验失败',
  audit_chain_hmac_default_key: '审计签名密钥未配置',
  local_identity_cleanup_exhausted: '本地身份清理失败',
}
const EVENT_TYPE_LABELS: Record<string, string> = {
  security_check_failed: '检测未完成',
  security_check: '安全检测', data_security: '数据安全', file_security: '文件安全',
  prompt_injection: '提示词注入', prompt_guard: '提示词防护', eval_content_safety: '内容安全测评',
  tool_audit_only: '工具风险', tool_risk: '工具风险', tool_call_risk: '工具风险',
  tool_execution_risk: '工具执行风险', tool_attempt_blocked: '工具尝试已阻断',
  tool_destructive_intent: '破坏性操作意图',
  skill_invocation_risk: 'Skill 调用风险', skill_admission_changed: 'Skill 准入变更',
  mcp_policy_hit: 'MCP 策略命中', mcp_redline_hit: 'MCP 红线命中', mcp_confirmation_required: 'MCP 待人工确认',
  model_policy: '模型策略', quota: '额度控制', semantic_attack: '语义攻击检测',
}

// 风险域维度（与后端 secevent_bridge.go alertDomainForSecurityEvent 同口径）。
// 新告警的 domain 由后端写入 body；存量行在前端按 event_type 前缀兜底推导。
export const DOMAIN_CONFIG: Record<string, { color: string; label: string }> = {
  content: { color: 'blue', label: '内容安全' },
  tool: { color: 'orange', label: '工具与智能体' },
  skill: { color: 'purple', label: 'Skill' },
  mcp: { color: 'geekblue', label: 'MCP' },
  access: { color: 'cyan', label: '访问治理' },
  system: { color: 'default', label: '系统' },
}

// 访问与额度治理类消息：现网实测 type 为 'alert'（旧版为 governor.*），额度准入另有 quota.admission.* 两种。
const GOVERNANCE_SOURCE_LABEL = '访问与额度治理'
function isGovernanceType(type: string): boolean {
  const t = type.toLowerCase()
  return t === 'alert' || t.startsWith('governor.') || t.startsWith('quota.admission.')
}

// 消息类别中文名（管理员「批量标为已读」的类别下拉用）。billing_* 等复用 SOURCE_LABELS；未知类别显示「其它类别」。
export const INBOX_TYPE_LABELS: Record<string, string> = {
  alert: '访问与额度治理事件',
  'quota.admission.reservation_overrun': '额度预占超出',
  'quota.admission.runtime_fault': '额度观测故障',
  model_route_degraded: '模型线路退化（仅剩一条健康线路）',
  model_route_circuit_opened: '上游线路已熔断',
  model_route_unavailable: '模型无可用线路',
  model_route_recovered: '上游线路已恢复',
  runtime_fault: '运行告警',
  security_event: '安全事件',
  security_event_daily_summary: '安全事件日聚合',
}

export function inboxTypeLabel(type: string): { label: string; known: boolean } {
  const key = (type || '').toLowerCase()
  if (INBOX_TYPE_LABELS[key]) return { label: INBOX_TYPE_LABELS[key], known: true }
  if (key.startsWith('governor.')) return { label: INBOX_TYPE_LABELS.alert, known: true }
  if (SOURCE_LABELS[key]) return { label: SOURCE_LABELS[key], known: true }
  return { label: '其它类别', known: false }
}

const MODEL_ROUTE_TITLES: Record<string, string> = {
  model_route_degraded: '模型仅剩一条健康线路',
  model_route_circuit_opened: '上游线路已熔断',
  model_route_unavailable: '模型无可用线路',
  model_route_recovered: '上游线路已恢复',
}

// 消息中心客户可见处不得露英文：含任何英文字母的后端文案一律视为不可信，改用前端中文兜底。
function cleanText(value: string): string {
  return /[A-Za-z]/.test(value) ? '' : value
}

// 前端有专门中文处理的 type；其余 type 统一走「其它事件」兜底。
const KNOWN_INBOX_TYPES = new Set([
  'security_event', 'runtime_fault', 'access_governance', 'security_event_daily_summary', 'security_mode_changed',
])
function isKnownInboxType(type: string): boolean {
  return KNOWN_INBOX_TYPES.has(type) || Boolean(SOURCE_LABELS[type.toLowerCase()]) || type.startsWith('model_route_') || isGovernanceType(type)
}

// 工具连续失败是运行状况，网关把它写成 matched.findings 里 category=agent_tool_failure_loop 的一条，证据是“<工具> 在窗口内失败 N 次”。
const TOOL_FAILURE_LOOP_CATEGORY = 'agent_tool_failure_loop'
// 控制面把主命中写在 body.category 与 body.primary_finding；matched.findings 遍历作兜底。
function toolFailureLoopFinding(body: Record<string, any>): Record<string, any> | null {
  if (body?.primary_finding?.category === TOOL_FAILURE_LOOP_CATEGORY) return body.primary_finding
  const findings = body?.matched?.findings ?? body?.findings
  const found = Array.isArray(findings) ? findings.find((item) => item && item.category === TOOL_FAILURE_LOOP_CATEGORY) : null
  if (found) return found
  return body?.category === TOOL_FAILURE_LOOP_CATEGORY ? {} : null
}

// 访问与额度治理类按 reason 重建中文标题/详情，不回显后端英文 reason 或 "governor 事件：xxx" 标题。
function governanceCopy(type: string, body: Record<string, any>): { title: string; detail: string } {
  const reason = pickString(body, 'reason').toLowerCase()
  if (reason === 'model not allowed for team') {
    return { title: '模型访问策略通知', detail: body.alert_only === true ? '当前团队模型策略仅告警，未阻断请求' : '当前团队不允许使用该模型' }
  }
  if (reason.startsWith('fail-open')) {
    return reason.includes('timeout')
      ? { title: '额度检查超时，已放行请求', detail: '额度检查超时，请求按放行处理' }
      : { title: '额度检查异常，已放行请求', detail: '额度检查未能完成，请求按放行处理' }
  }
  if (type === 'quota.admission.reservation_overrun' || reason.includes('exceeded the conservative reservation')) {
    return { title: '额度预占不足通知', detail: '实际用量超过了预占额度（仅告警，未阻断）' }
  }
  if (type === 'quota.admission.runtime_fault') {
    return { title: '额度观测不可用', detail: '额度观测暂不可用，请检查额度服务运行状态' }
  }
  return { title: '访问与额度治理通知', detail: '' }
}

const ACCESS_DOMAIN_EVENT_TYPES = new Set(['access_denied', 'model_policy', 'quota', 'proxy_auth_denied', 'proxy_access_denied'])
const SYSTEM_DOMAIN_EVENT_TYPES = new Set(['security_check_failed', 'security_output_check_failed', 'security_mode_changed'])

function deriveAlertDomain(body: Record<string, any>, type?: string, source?: string): string {
  const stored = pickString(body, 'domain')
  if (stored && DOMAIN_CONFIG[stored]) return stored
  const eventType = pickString(body, 'event_type').toLowerCase()
  const t = (type || '').toLowerCase()
  const src = (source || '').toLowerCase()
  if (eventType.startsWith('skill_')) return 'skill'
  if (eventType.startsWith('mcp_') || pickString(body, 'mcp_server_id') || pickString(body, 'server_id') || pickString(body, 'source') === 'gateway_mcp') return 'mcp'
  if (eventType.startsWith('tool_')) return 'tool'
  if (ACCESS_DOMAIN_EVENT_TYPES.has(eventType)) return 'access'
  // 存量运维/治理通知没有 body.domain，按行类型与来源归类，避免全部落进内容安全。
  if (isGovernanceType(t) || isGovernanceType(src)) return 'access'
  if (t.startsWith('model_route_') || t.startsWith('quota.') || t === 'runtime_fault' || t === 'security_mode_changed' || SYSTEM_DOMAIN_EVENT_TYPES.has(eventType)) return 'system'
  return 'content'
}

export function sourceLabel(v?: string): string {
  if (!v) return ''
  if (v.startsWith('model_route_')) return '运行故障'
  if (isGovernanceType(v)) return GOVERNANCE_SOURCE_LABEL
  return SOURCE_LABELS[v.toLowerCase()] || '其它来源'
}
export function notificationActionLabel(a?: string): string {
  if (!a) return '未记录'
  return alertActionResult(a)
}
// 处置值不在字典里时整段省略，不写“其他处置”。
function actionSuffix(a?: string): string {
  return isKnownAlertAction(a) ? ` · 处置：${notificationActionLabel(a)}` : ''
}
export function severityLabel(v?: string): string {
  return SEVERITY_CONFIG[(v || '').toLowerCase()]?.label || '未分级'
}
function eventTypeLabel(t?: string): string {
  if (!t) return ''
  const key = t.toLowerCase()
  if (EVENT_TYPE_LABELS[key]) return EVENT_TYPE_LABELS[key]
  if (key.startsWith('proxy_')) {
    const parts = key.split('_')
    if (parts.length === 3) {
      const stage = ({ input: '输入', output: '输出' } as Record<string, string>)[parts[1]]
      const act = ({ audit: '审计', block: '拦截', mask: '脱敏' } as Record<string, string>)[parts[2]]
      if (stage && act) return `代理${stage}${act}`
    }
  }
  return '其它事件'
}

export function pickString(obj: Record<string, any> | null | undefined, ...keys: string[]): string {
  if (!obj) return ''
  for (const key of keys) {
    const value = obj[key]
    if (typeof value === 'string' && value.trim() !== '') return value
    if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  }
  return ''
}

// 日聚合卡的聚合维度中文映射：未知维度直接不显示，绝不回显原始英文枚举。
const DAILY_SUMMARY_DIMENSION_LABELS: Record<string, string> = {
  rule: '按规则',
  rule_id: '按规则',
  rule_name: '按规则',
  source_ip: '按来源 IP',
  source: '按来源',
  tenant: '按租户',
  project: '按应用',
  user: '按用户',
  event_type: '按事件类型',
}

export function normalizeInboxItem(raw: Record<string, any>) {
  const body = raw.body_json || raw.BodyJSON || {}
  const readAt = pickString(raw, 'read_at', 'ReadAt')
  const type = pickString(raw, 'type', 'Type')
  const storedTitle = pickString(raw, 'title', 'Title', 'message')
  const eventType = pickString(body, 'event_type')
  let title = storedTitle
  let detail = pickString(raw, 'detail', 'Detail') || pickString(body, 'summary', 'rule_name', 'matched') || eventTypeLabel(eventType)
  const loop = toolFailureLoopFinding(body)
  if (loop) {
    // 工具连续失败是运行状况：不论消息类型（含发版前写成安全事件的历史消息），都用同一标题与证据原文。
    title = '智能体工具连续失败'
    detail = pickString(loop, 'redacted_evidence', 'rule_name')
  } else if (type === 'security_event' && eventType) {
    // 安全事件类:用 body 的枚举重建中文标题,兼容历史存量行里残留的英文标题。
    title = `安全事件【${severityLabel(pickString(body, 'severity') || pickString(raw, 'severity'))}】${[eventTypeLabel(eventType), pickString(body, 'rule_name')].filter(Boolean).join(' · ')}${actionSuffix(pickString(body, 'action'))}`
    // 去重折叠的告警把累计次数带出来:一条未读背后可能折叠了多次同类命中。
    const counts = [
      ['occurrence_count', '命中记录', ' 条'],
      ['distinct_occurrences', '独立事发/会话', ''],
      ['affected_users', '涉及主体', ''],
    ].flatMap(([key, label, suffix]) => {
      const rawCount = pickString(body, key)
      const count = Number(rawCount)
      return rawCount !== '' && Number.isInteger(count) && count >= 0 ? [`${label} ${count}${suffix}`] : []
    })
    if (counts.length) detail = [detail, ...counts].filter(Boolean).join(' · ')
  } else if (isGovernanceType(type)) {
    const copy = governanceCopy(type, body)
    title = copy.title
    detail = copy.detail
  } else if (type.startsWith('model_route_')) {
    // 模型线路类：标题优先用后端中文标题，英文/缺失则用前端兜底；详情带上模型名（provider_ref 等技术 id 不展示）。
    title = cleanText(storedTitle) || MODEL_ROUTE_TITLES[type] || '模型线路通知'
    const modelName = pickString(body, 'model_name')
    detail = modelName ? `模型：${modelName}` : cleanText(detail)
  } else if (type === 'runtime_fault') {
    title = `检测运行故障${actionSuffix(pickString(body, 'action'))}`
    const reasons: Record<string, string> = {
    file_unknown_type: '文件类型无法检视，按文件策略保护',
    retention_unavailable: '日志留存不可用',
    mcp_policy_unavailable: 'MCP 策略读取失败',
    custom_regex_timeout: '脱敏规则检测超时，保持失败关闭',
    custom_scan_incomplete: '脱敏扫描未完成，保持失败关闭', inspection_retry_exhausted: '补检重试已耗尽，请检查检测服务容量', inspection_queue_unavailable: '补检任务未能保存，请求未获准转发', inspection_queued: '检测任务已保存，正在自动补检', request_body_limit_exceeded: '请求体超过检测容量限制，检测未完成', tier1_timeout: '初筛超时', judge_timeout: '语义复核超时', judge_unavailable: '语义复核不可用', tier1_unavailable: '初筛不可用', breaker_open: '检测服务暂时熔断', parse_failed: '请求解析未完成' }
    const reason = pickString(body, 'semantic_reason', 'inspection_reason') || pickString(body.matched, 'semantic_reason', 'inspection_reason')
    detail = reasons[reason] || '检测未完成，请查看运行状态'
  } else if (body.ops_alert === true) {
    // 计费/审计链运维告警：标题由后端按中文类型名生成，详情给处置建议。
    title = storedTitle || SOURCE_LABELS[type] || '运维告警'
    const count = Number(pickString(body, 'count'))
    detail = [Number.isInteger(count) && count > 1 ? `本次 ${count} 次` : '', pickString(body, 'suggestion')].filter(Boolean).join(' · ')
  } else if (type === 'access_governance') {
    title = storedTitle || '访问治理通知'
  } else if (type === 'security_event_daily_summary') {
    // 规则日聚合卡:同规则当日多次命中折叠为一张摘要卡;标题/摘要全部用 body 重建中文,不信任存量英文标题。
    // 后端契约字段为 daily_count/dimension/date(见 secevent_bridge 日聚合测试),其余键名作防御性兜底。
    const ruleName = pickString(body, 'rule_name') || eventTypeLabel(eventType) || '安全规则'
    const count = pickString(body, 'daily_count', 'count', 'total', 'total_count', 'occurrence_count', 'event_count')
    const date = pickString(body, 'date', 'summary_date', 'day')
    // dimension 可能是维度类型也可能是维度取值(如具体规则 id):映射不到就不显示,绝不露原始英文。
    const dimensionLabel = DAILY_SUMMARY_DIMENSION_LABELS[pickString(body, 'dimension', 'group_by', 'dimension_type').toLowerCase()] || ''
    title = `规则日聚合：${ruleName}${count ? ` · 当日累计 ${count} 条` : ''}`
    detail = `${date ? `${date} ` : ''}当日同规则告警已折叠为一条摘要${dimensionLabel ? `（聚合维度：${dimensionLabel}）` : ''}`
  }
  if (!isKnownInboxType(type)) {
    // 未识别的 type：后端中文标题可留；含英文（如 "governor 事件：xxx"）统一显示「其它事件」，详情同理。
    title = cleanText(storedTitle) || '其它事件'
    detail = cleanText(detail)
  }
  const resolvedSource = pickString(raw, 'source', 'Source') || type
  return {
    ...raw,
    id: pickString(raw, 'id', 'ID'),
    severity: pickString(raw, 'severity', 'Severity') || 'info',
    type,
    domain: deriveAlertDomain(body || {}, type, resolvedSource),
    title,
    message: pickString(raw, 'message', 'title', 'Title'),
    detail,
    source: resolvedSource,
    created_at: pickString(raw, 'created_at', 'CreatedAt'),
    read_at: readAt,
    read: typeof raw.read === 'boolean' ? raw.read : typeof raw.Read === 'boolean' ? raw.Read : Boolean(readAt),
  }
}

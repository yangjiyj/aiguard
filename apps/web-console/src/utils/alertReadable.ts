import type { AlertOccurrence } from '../services/alertOccurrences'
import { getFindingCategoryLabel } from './alertOccurrenceDisplay'
import { DECISION_LABELS, RISK_CATEGORY_LABELS, getSpecificRiskCategoryLabel } from './risk'
import { RECORD_MODE_PASS_LABEL } from './ws8ActionLabels'
import { DESTRUCTIVE_SUBCATEGORY_LABELS, GATEWAY_CODE_LIKE, GATEWAY_REASON_LABELS, translateGatewayReason } from './gatewayReasonLabels'

export { DESTRUCTIVE_SUBCATEGORY_LABELS, GATEWAY_REASON_LABELS }

// 告警文案的唯一来源：标题、命中内容、处置结果、原因码都在这里翻译，卡片、详情、消息中心、阻断记录只调用它。

type TitleFields = Pick<AlertOccurrence, 'type' | 'category' | 'rule_name' | 'rule_name_count'> & Partial<Pick<AlertOccurrence, 'policy_link'>>
type EvidenceFields = Pick<AlertOccurrence, 'redacted_evidence' | 'evidence_status'> & Partial<Pick<AlertOccurrence, 'raw_evidence'>>

// 规则名为工具名或泛称时，标题退回类别名。
const GENERIC_RULE_NAMES = new Set(['自定义', '策略中心托管规则'])
const TOOL_EVENT_TYPES = new Set(['tool_destructive_intent', 'tool_failure_loop', 'tool_execution_risk', 'tool_policy_alert', 'coverage_gap'])
// 网关把工具名写进 rule_name 的几类告警，标题不能用工具名。
// tool_attempt_blocked 不在其中：它的规则名来自阻断原因（“删除与破坏”“受限文件”等），不是工具名。
const TOOL_NAMED_CATEGORIES = new Set(['agent_behavior_policy', 'restricted_file_access', 'agentguard_confirmation', 'agent_permission_governance'])
const SUSPECTED_TYPES = new Set(['semantic_attack', 'catalog_policy'])
// block_model_egress、disable_mcp、rule_9f3a1c 这类内部编号不是给人看的名字。
const INTERNAL_RULE_ID = /^[a-z][a-z0-9]*(_[a-z0-9]+)+$/

// 处置结果一律用完成态；“拦截/阻断”只说“阻断”。
const BLOCKED = '已阻断'
const MASKED = '已脱敏'
const REPLIED = '安全代答'
const RECORDED = '仅记录'
const ACTION_RESULTS: Record<string, string> = {
  block: BLOCKED, blocked: BLOCKED, deny: BLOCKED, security_blocked: BLOCKED, stream_blocked: BLOCKED,
  tool_attempt_blocked: BLOCKED, tool_blocked: BLOCKED, mcp_tool_result_blocked: BLOCKED, mcp_server_request_blocked: BLOCKED,
  quarantine: '已隔离',
  mask: MASKED, redact: MASKED, security_masked: MASKED,
  reply: REPLIED, security_replied: REPLIED,
  rewrite: '已改写',
  confirm: '要求人工确认',
  alert: '告警放行', mcp_server_request_alerted: '告警放行', mcp_tool_result_alerted: '告警放行', mcp_tools_list_alerted: '告警放行',
  flag: '告警放行', flagged: '告警放行',
  audit: RECORDED, security_audit: RECORDED, tool_audited: RECORDED, tool_audit_only: RECORDED,
  allow: '已放行',
  security_audit_only: RECORD_MODE_PASS_LABEL,
  security_check_failed: '检测异常', security_output_check_failed: '输出检测异常',
  mcp_tools_list_filtered: '已过滤工具列表',
  agentguard_policy_load_failed: '策略加载失败',
}
const SUMMARY_TAIL = /^([a-z][a-z0-9_]*):(\d+-targets|target-incomplete)$/
const SEPARATOR = ' · '

const translateSummary = (text: string) => {
  const match = SUMMARY_TAIL.exec(text)
  if (!match) return text
  const operation = DESTRUCTIVE_SUBCATEGORY_LABELS[match[1]] || '破坏性操作'
  return match[2] === 'target-incomplete' ? `${operation}（目标未解析）` : `${operation}（${match[2].split('-')[0]} 个目标）`
}

// 命中内容：只翻译“工具名 · 子类:目标”里的后半段，其余原样保留。
export const readableHitText = (value?: string | null) => {
  const text = String(value ?? '').trim()
  const cut = text.indexOf(SEPARATOR)
  if (cut > 0) return `${text.slice(0, cut)}${SEPARATOR}${translateSummary(text.slice(cut + SEPARATOR.length))}`
  return translateSummary(text)
}

// 原因码：查唯一字典；不认识的码返回空串（页面不显示，与控制面“未收录的不展示”一致），非码文本原样返回。
export const readableReasonCode = (value?: string | null) => {
  const text = String(value ?? '').trim()
  if (!text) return ''
  const translated = translateGatewayReason(text)
  if (translated) return translated
  // 不认识的码不显示，宁缺毋滥；“按工具安全策略命中”只留在工具审计页。
  return GATEWAY_CODE_LIKE.test(text) ? '' : text
}

// 引擎会在检测理由末尾追加“策略级别：…；告警级别：…（降级原因）”，2.9.16 的旧格式是“策略基准：…；本次风险：…”。
// 详情首屏的“告警级别”行已经显示，理由里只去掉这一段，其余原因保留。
const SEVERITY_EXPLANATION_TAIL = /(?:^|；\s*)(?:(?:策略级别：[^；]*；\s*)?告警级别：|策略基准：[^；]*；\s*本次风险：).*$/s
export const stripSeverityExplanation = (value?: string | null) => String(value ?? '').replace(SEVERITY_EXPLANATION_TAIL, '').trim()

export const categoryTitle = (value?: string) => {
  const label = getFindingCategoryLabel(value)
  if (label.startsWith('其他风险（')) return '其他风险'
  // 未收录的 agent_* / semantic_* 类别，getRiskCategoryLabel 会拼出“智能体：xxx · yyy”，标题层不显示拼接英文。
  if (value && /^(agent|semantic)_/.test(value) && !RISK_CATEGORY_LABELS[value] && label === getSpecificRiskCategoryLabel(value)) return '其他风险'
  return label
}

// 只做两项清洗：去泛称、去内部编号形状。阻断记录的规则名已是可读名，用这个；告警在此之上还要去工具名。
export const cleanRuleName = (value?: string | null) => {
  const name = String(value ?? '').trim()
  return name && !GENERIC_RULE_NAMES.has(name) && !INTERNAL_RULE_ID.test(name) ? name : ''
}

// 规则名能给人看吗：工具类告警的 rule_name 是工具名，不行。
const usableRuleName = (item: TitleFields) =>
  !TOOL_EVENT_TYPES.has(item.type) && !TOOL_NAMED_CATEGORIES.has(item.category) ? cleanRuleName(item.rule_name) : ''

export const alertCaseTitle = (item: TitleFields) => {
  const name = usableRuleName(item)
  const suspected = SUSPECTED_TYPES.has(item.type) || (item.category || '').startsWith('semantic_') ? '疑似' : ''
  if (name) {
    const count = item.rule_name_count || 1
    return `${suspected}${count > 1 ? `${name} 等 ${count} 条` : name}`
  }
  return `${suspected}${categoryTitle(item.category || item.type)}`
}

// 规则名清洗：清洗后的规则名 → 策略链接标签（泛称、内部编号同样不要）；都没有返回空串。
const alertRuleNameOrLink = (item: TitleFields) => {
  return usableRuleName(item) || cleanRuleName(item.policy_link?.label)
}

// 命中规则的显示名：规则名清洗结果，没有则用类别名。
export const alertRuleDisplayName = (item: TitleFields) =>
  alertRuleNameOrLink(item) || categoryTitle(item.category || item.type)

const hitSummary = (item: EvidenceFields, max: number) => {
  if (item.evidence_status === 'restricted') return '无权查看命中内容'
  // 命中原文整段返回，不截头尾；超长由显示处折叠。只有打码片段时才按长度截断。
  const raw = (item.raw_evidence || '').trim()
  if (raw) return raw
  const text = readableHitText(item.redacted_evidence)
  const chars = Array.from(text)
  return chars.length > max ? `${chars.slice(0, max).join('')}…` : text
}

// 命中内容：没有可显示的内容时返回空串。
export const alertHitText = (item: EvidenceFields, max = 60) => hitSummary(item, max)
export const alertEvidenceSummary = (item: EvidenceFields, max = 60) => hitSummary(item, max) || '未记录命中内容'

// 处置结果已记录时返回完成态说法，没记录返回空串（调用方自己决定写“未记录”还是省略）。
export const alertActionResultIfRecorded = (action?: string | null) => {
  const key = String(action ?? '').trim().toLowerCase()
  return key && key !== 'unknown' ? alertActionResult(key) : ''
}

// 处置值是否在字典里（“unknown”算已知，会显示“未记录处置结果”）。
export const isKnownAlertAction = (action?: string | null) => {
  const key = String(action ?? '').trim().toLowerCase()
  return !key || key === 'unknown' || Object.prototype.hasOwnProperty.call(ACTION_RESULTS, key)
}

export const alertActionResult = (action?: string | null) => {
  const key = String(action ?? '').trim().toLowerCase()
  if (!key || key === 'unknown') return '未记录处置结果'
  return ACTION_RESULTS[key] || '其他处置'
}

// 规则配置动作（action_taken）的叫法：说“规则要怎么处理”，不说已经发生的结果。
const RULE_ACTION_LABELS: Record<string, string> = {
  ...DECISION_LABELS,
  blocked: '阻断', deny: '阻断', mask: '脱敏', redact: '脱敏',
  security_audit: '仅记录', alert: '告警放行', flag: '告警放行',
  reply: '安全代答', rewrite: '改写',
}
// 智能体工具类告警（rule_type 为 agentguard）的 audit 既指“仅记录”也指“告警放行”配置，写出来会和实际处置矛盾，所以不显示。
const AGENT_TOOL_RULE_TYPE = 'agentguard'
export const alertRuleActionLabel = (action?: string | null, ruleType?: string | null) => {
  const key = String(action ?? '').trim().toLowerCase()
  if (key === 'audit' && String(ruleType ?? '').trim().toLowerCase() === AGENT_TOOL_RULE_TYPE) return ''
  return RULE_ACTION_LABELS[key] || ''
}

// 实际处置的完成态说法 → 规则动作说法，用于判断“规则建议”和实际处置是不是一回事。
const RESULT_AS_RULE_LABEL: Record<string, string> = {
  [BLOCKED]: '阻断', [MASKED]: '脱敏', [REPLIED]: '安全代答', [RECORDED]: '仅记录', [RECORD_MODE_PASS_LABEL]: '仅记录',
  '告警放行': '告警放行', '已放行': '放行', '要求人工确认': '人工确认', '已改写': '改写',
}
export const alertRuleActionDiffers = (ruleAction?: string | null, actualAction?: string | null, ruleType?: string | null) => {
  const rule = alertRuleActionLabel(ruleAction, ruleType)
  if (!rule) return false
  const actual = alertActionResult(actualAction)
  return rule !== (RESULT_AS_RULE_LABEL[actual] || actual)
}

// 消息来源统一取法：来源 → 命中位置推断 → 消息角色；都认不出来返回空串。位置推断排在角色之前。
// 角色兜底只认 assistant、tool、system：Claude Messages 协议下工具返回的原始角色是 user，
// 没有来源字段和命中位置时不能把 user 断定为“用户输入”。
const ROLE_FALLBACK = new Set(['assistant', 'tool', 'system'])
export const alertCaseSource = (item: Pick<AlertOccurrence, 'content_source' | 'matched_location'> & Partial<Pick<AlertOccurrence, 'message_role'>>) => {
  const role = String(item.message_role ?? '')
  return alertSourceLabel(item.content_source) || locationSource(item.matched_location) || (ROLE_FALLBACK.has(role) ? alertSourceLabel(role) : '')
}

export const STAGE_LABELS: Record<string, string> = { input: '输入检测', output: '输出检测', tool: '工具检测' }
// 消息来源：卡片、详情、告警列表共用这一份；不认识的值返回空串，由调用方决定怎么回退。
export const ALERT_SOURCE_LABELS: Record<string, string> = {
  verified_user_input: '用户输入', user_input: '用户输入', unverified_user_input: '用户输入（未验证）', user: '用户输入',
  user_history: '用户历史消息',
  verified_final_output: '模型输出', model_output: '模型输出', assistant_output: '模型输出', assistant: '模型输出', final_output: '模型输出',
  builtin_context: '内置上下文', system_prompt: '内置上下文', developer_prompt: '内置上下文',
  system_context: '内置上下文', developer_context: '内置上下文', agent_context: '内置上下文',
  agent_runtime_context: '内置上下文', system: '内置上下文', developer: '内置上下文',
  builtin_system: '内置上下文', builtin_developer: '内置上下文', developer_instruction: '内置上下文',
  tool_call: '工具调用', assistant_tool_call: '工具调用',
  tool_result: '工具返回', tool_output: '工具返回', tool: '工具返回',
  tool_def: '工具定义', tool_definition: '工具定义',
  rag_context: 'RAG 检索内容', retrieved_context: 'RAG 检索内容', retrieval_context: 'RAG 检索内容', rag: 'RAG 检索内容',
  retrieval: 'RAG 检索内容', retrieval_result: 'RAG 检索内容',
  file_attachment: '文件附件',
  agent_analysis_context: '智能体分析上下文', assistant_history: '模型历史上下文',
  project_instruction: '项目指令上下文', project_instruction_file: '项目指令文件', instruction_file: '指令文件',
  external_web: '外部网页', external_webpage: '外部网页', web: '外部网页', web_content: '外部网页',
}
export const alertSourceLabel = (value?: string | null) => ALERT_SOURCE_LABELS[String(value ?? '')] || ''

// 注意两处 tool 含义不同：content_source / message_role 里的 tool 指工具返回的内容；
// matched_location 里的 tool（如 tool_call[0]）指工具调用本身，只有 tool_result 开头才是工具返回。
const locationSource = (location?: string | null) => {
  const text = String(location ?? '')
  if (text.startsWith('tool_result')) return '工具返回'
  return text.startsWith('tool') ? '工具调用' : ''
}

// 卡片第二行：命中内容 · 处置结果 · 来源 · 阶段。哪段没有就省略，不写“未记录”；全空返回空串。
export const alertCaseLine = (item: EvidenceFields & Pick<AlertOccurrence, 'event_action_taken' | 'content_source' | 'stage' | 'matched_location'> & Partial<Pick<AlertOccurrence, 'message_role'>>) => {
  return [
    hitSummary(item, 60),
    alertActionResultIfRecorded(item.event_action_taken),
    alertCaseSource(item),
    STAGE_LABELS[item.stage] || '',
  ].filter(Boolean).join(' · ')
}

import { apiClient } from './api'
import type { PolicyLink } from './api'

export type AgentEndpointLocalDecision = {
  source?: string
  mode?: string
  effective_decision?: string
  decision?: string
  raw_decision?: string
  rule_id?: string
  matched_rule_id?: string
  policy_version?: string | number
  policy_checksum?: string
  risk_level?: string
}

export type AgentEndpointEvidence = {
  status: 'matched' | 'unmatched'
  agent_event_id?: string
  endpoint_id?: string
  session_id?: string
  event_type?: string
  tool_use_id?: string
  tool_name?: string
  tool_type?: string
  local_decision?: AgentEndpointLocalDecision
}

export type AlertLane = 'action' | 'watch' | 'eval'

export type AlertOccurrence = {
  // 处理车道：需行动 / 观察 / 测评流量。老后端无此字段，调用方按 action 兜底，不能漏显示。
  lane?: AlertLane
  detection_method?: string
  confidence_kind?: string
  validation_status?: string
  credential_validity?: string
  model_review_status?: string
  risk_basis?: string
  semantic_status?: string
  semantic_reason?: string
  raw_evidence_sha256?: string
  // 该请求在原文留证里的条数；大于 0 且角色有权限时显示“查看原文”。
  raw_evidence_count?: number
  evidence_context_sha256?: string
  evidence_recovered?: boolean
  case_id?: string
  occurred_at?: string
  time_known?: boolean
  first_seen?: string
  last_seen?: string
  last_detected_at?: string
  hit_count?: number
  request_count?: number
  blocked_count?: number
  grouping_basis?: 'conversation' | 'identity_target_day'
  target_host?: string
  model_name?: string
  model_id?: string
  delivery_outcome?: string
  request_status?: string
  id: string
  event_id: string
  request_id: string
  project_id: string
  created_at: string
  finding_index: number | null
  duplicate_count: number
  rule_ids: string[]
  type: string
  category: string
  severity: string
  rule_id: string
  rule_name: string
  rule_type?: string
  policy_code?: string
  rule_name_count?: number
  severity_downgrade_reason?: string
  policy_link?: PolicyLink | null
  action_taken: string
  event_action_taken: string
  suppressed: boolean
  suppression_reason: string
  review_state: string
  disposition_status: string
  alert_group_id: string
  message_index: number | null
  attachment_index: number | null
  message_role: string
  content_source: string
  stage: string
  matched_location: string
  location_status: 'available' | 'missing'
  reason: string
  reason_status: 'available' | 'missing' | 'restricted'
  evidence_kind: string
  redacted_evidence: string
  evidence_status: 'available' | 'missing' | 'restricted'
  raw_evidence?: string
  // 原文超过 4096 字被截断
  raw_evidence_truncated?: boolean
  // 事件原文总量超限，这条命中没随事件存原文（可从内容留存回捞）
  raw_evidence_omitted?: boolean
  matched_text_preview?: string
  evidence_context?: string
  raw_evidence_status: 'available' | 'missing' | 'restricted' | 'not_requested'
  actor_user_id: string
  actor_name: string
  actor_department_id: string
  actor_department_name: string
  key_owner_user_id: string
  key_owner_name: string
  department_id: string
  department_name: string
  agent_type: string
  credential_id: string
  credential_name: string
  principal_key: string
  identity_source: string
  identity_reliability: string
  source_ip: string
  access_type?: string
  client_product?: string
  access_direction: string
  conversation_key: string
  conversation_id: string
  session_id: string
  agent_session_id?: string
  agent_endpoint_evidence?: AgentEndpointEvidence
  conversation_source: string
  conversation_reliability: string
}

export type AlertOccurrenceParams = {
  include_dev?: boolean
  // 传 lane 即打开车道分流（'all' 为不过滤）；缺省保持全局口径。仅 grouping=cases 有效。
  lane?: AlertLane | 'all'
  recent_limit?: number
  grouping?: 'cases' | 'hits'
  case_id?: string
  event_id?: string
  disposition?: 'pending' | 'all' | 'handled' | 'false_positive'
  limit?: number
  offset?: number
  severity?: string
  category?: string
  request_id?: string
  conversation_key?: string
  session_id?: string
  user_id?: string
  project_id?: string
  start_time?: string
  end_time?: string
  include_suppressed?: boolean
  include_raw?: boolean
  signal?: AbortSignal
}

export type AlertOccurrenceCounts = Record<'total' | 'active' | 'suppressed' | 'critical' | 'high' | 'medium' | 'low', number> & {
  // 待处置：未闭环（无处置记录或 disposition_status='open'）且未抑制，随查询范围走。
  // 老版本后端无此字段；调用方必须降级而不是拿范围总量充数。
  raw_hits?: number
  delayed_24h?: number
  unknown_time?: number
  pending?: number
  handled?: number
  false_positive?: number
  last_24h?: number
  previous_24h?: number
  blocked_24h?: number
  pending_high?: number
  pending_medium?: number
  pending_low?: number
  // 车道页签计数：同一范围内按车道分别统计，不随当前选中的车道变化。老后端无此字段。
  lane_action?: number
  lane_watch?: number
  lane_eval?: number
}

export type AlertOccurrencePage = {
  // 本次读的账号有没有内容证据权限（后端判定）；老后端没有此字段
  evidence_readable?: boolean
  folded_development_groups?: number
  count_unit?: 'triage_cases' | 'findings'
  items: AlertOccurrence[]
  total: number
  limit: number
  offset: number
  counts: AlertOccurrenceCounts
  operational?: { count_known?: boolean; event_count: number; count_unit: 'security_events'; list_url?: string }
}

export type AlertOperationalEvent = {
  remediation_status?: 'partial_rechecked' | 'retained_content_unavailable' | 'recheck_incomplete' | 'retry_pending' | 'retry_exhausted' | 'rechecked_complete' | 'retry_not_saved'
  remediation_at?: string
  event_id: string
  request_id: string
  project_id: string
  event_type: string
  action_taken: string
  stage: string
  reason: string
  blocked: boolean
  classification: 'operational_gap'
  created_at: string
}

export type AlertOperationalPage = {
  items: AlertOperationalEvent[]
  total: number
  limit: number
  offset: number
  count_unit: 'security_events'
}

export type AlertOperationalReasonCount = {
  reason: string
  event_count: number
  last_24h_count: number
  blocked_count: number
}

// Coverage gaps inside the same scope/time range as the alert list. Counted in
// security_events; never added to attack occurrences.
export type AlertOperationalBreakdown = {
  count_unit: 'security_events'
  event_count: number
  last_24h_count: number
  blocked_count: number
  latest_at: string | null
  reasons: AlertOperationalReasonCount[]
}

const OPERATIONAL_LIST_PATH = '/admin/v1/security/alert-occurrences/operational'
const OPERATIONAL_SUMMARY_PATH = '/admin/v1/security/alert-occurrences/operational/summary'

// The API supplies the scoped metadata URL. Keep it on the known admin
// endpoint so the authenticated client cannot forward credentials elsewhere.
const scopedOperationalQuery = (listUrl: string) => {
  const [path, query = ''] = listUrl.split('?')
  if (path !== OPERATIONAL_LIST_PATH) throw new Error('运行异常列表链接无效')
  return query
}

const list = (params: AlertOccurrenceParams) => {
  const { signal, ...query } = params
  return apiClient.get<AlertOccurrencePage>('/security/alert-occurrences', { params: query, signal })
}

export const alertOccurrencesApi = {
  summary: (params: AlertOccurrenceParams) => {
    const { signal, ...query } = params
    return apiClient.get<{count_unit: string; total: number; categories: {category: string; count: number}[]}>('/security/alert-occurrences/summary', {params: query, signal})
  },
  list,
  listOperational: async (listUrl: string, params: { limit?: number; offset?: number; reason?: string; signal?: AbortSignal } = {}) => {
    const query = scopedOperationalQuery(listUrl)
    const { signal, reason, ...pagination } = params
    const scoped = reason ? { ...pagination, reason } : pagination
    return apiClient.get<AlertOperationalPage>(OPERATIONAL_LIST_PATH.slice('/admin/v1'.length) + (query ? `?${query}` : ''), { params: scoped, signal })
  },
  summarizeOperational: async (listUrl: string, params: { signal?: AbortSignal } = {}) => {
    const query = scopedOperationalQuery(listUrl)
    return apiClient.get<AlertOperationalBreakdown>(OPERATIONAL_SUMMARY_PATH.slice('/admin/v1'.length) + (query ? `?${query}` : ''), { signal: params.signal })
  },
  // The collection endpoint is also the permission-checked evidence reader.
  // Never take the first finding in a request as the selected occurrence.
  getEvidence: async (selected: AlertOccurrence, params: AlertOccurrenceParams) => {
    let offset = 0
    const limit = 100
    let total = 1
    while (offset < total) {
      const { data } = await list({
        ...params, disposition: undefined, grouping: 'hits', case_id: undefined, recent_limit: undefined,
        severity: undefined, category: undefined, start_time: undefined, end_time: undefined, conversation_key: undefined, session_id: undefined,
        event_id: selected.event_id,
        request_id: selected.request_id || params.request_id,
        include_raw: true,
        include_suppressed: true,
        limit,
        offset,
      })
      const match = data.items.find((item) => item.id === selected.id
        && item.event_id === selected.event_id
        && item.request_id === selected.request_id
        && item.finding_index === selected.finding_index)
      if (match) return match
      if (!data.items.length || offset + data.items.length >= data.total) return null
      total = data.total
      offset += limit
    }
    return null
  },
}

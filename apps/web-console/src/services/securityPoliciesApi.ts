import api, { type ProtectionAction } from './api'

export type SecurityPolicyRedaction = { replacement: string; restore_response: boolean }

export type SecurityPolicyAction = 'allow' | 'audit' | 'mask' | 'block'
/** 策略「智能分析命中时」：只作用于语义裁判（智能分析）结论；缺省 audit。 */
export type SecurityPolicySemanticAction = 'audit' | 'block' | 'observe'
export type SecurityPolicySeverity = 'low' | 'medium' | 'high' | 'critical'
export type SecurityPolicySource = 'system' | 'tenant'
export type SecurityPolicyOwnership = 'platform' | 'organization'
export type SecurityPolicyOrigin = 'preloaded' | 'organization_created'
export type SecurityPolicyBindingMode = 'any' | 'all'
export type SecurityPolicyMatcherType = 'regex' | 'keyword' | 'field_name'

export type SecurityPolicyCapability = {
  category: string
  name: string
  kind: 'static' | 'dynamic'
  enabled: boolean
  binding_mode?: SecurityPolicyBindingMode
  supported_stages: string[]
  allowed_actions: SecurityPolicyAction[]
  mask_capable: boolean
  /** 由智能分析（语义裁判）执行：拦不拦由策略 semantic_action 决定。 */
  semantic_judge?: boolean
  bound_policy_count?: number
  /** 检测能力说明目录里的内容；这四项只在能力列表接口的返回里有，策略的 capabilities 里没有；没有说明的能力也缺省。 */
  matches?: string
  hit_examples?: string[]
  miss_examples?: string[]
  judged_by_ai?: boolean
}

export type SecurityPolicyMatcherConfig = {
  regex?: string
  keywords?: string[]
  field_names?: string[]
}

export type SecurityPolicyMatcher = {
  type?: SecurityPolicyMatcherType
  config?: SecurityPolicyMatcherConfig
  regex?: string
  keywords?: string[]
  field_names?: string[]
}

export type SecurityPolicySubjectBinding = {
  tenant_ids?: string[]
  actor_user_ids?: string[]
  key_owner_user_ids?: string[]
  personnel_department_ids?: string[]
  personnel_department_include_children?: boolean
  project_ids?: string[]
  application_department_ids?: string[]
  key_ids?: string[]
  protocols?: string[]
  entry_points?: string[]
}

export type SecurityPolicy = {
  redaction?: SecurityPolicyRedaction
  semantic_action?: SecurityPolicySemanticAction
  id: string
  name: string
  description: string
  scene: string
  severity: SecurityPolicySeverity
  action: SecurityPolicyAction
  enabled: boolean
  source: SecurityPolicySource
  ownership: SecurityPolicyOwnership
  origin: SecurityPolicyOrigin
  industry?: string
  default_severity?: string
  severity_overridden?: boolean
  detection_basis: 'matcher' | 'capability' | 'conflict' | 'none'
  detection_configured: boolean
  detection_ready: boolean
  runtime_active: boolean
  detection_issue?: string
  unavailable_capability_count?: number
  capabilities: SecurityPolicyCapability[]
  matcher?: SecurityPolicyMatcher
  authoring?: DlpNumberAuthoring
  subject_binding?: SecurityPolicySubjectBinding
}

export type SecurityPoliciesResponse = {
  data: SecurityPolicy[]
  total: number
  configured_count: number
  ready_count: number
  active_count: number
  enabled_count: number
  pending_count: number
  unconfigured_count: number
  runtime_verified?: boolean
  runtime_status?: string
}

export type SecurityCapabilitiesResponse = {
  data: SecurityPolicyCapability[]
  total: number
  builtin_total: number
  extension_total: number
}

export type SecurityPolicyMatcherInput = {
  type: SecurityPolicyMatcherType
  config: SecurityPolicyMatcherConfig
}

export type SecurityPolicyWrite = {
  redaction?: SecurityPolicyRedaction
  semantic_action?: SecurityPolicySemanticAction
  name: string
  description: string
  scene: string
  severity: SecurityPolicySeverity
  action: SecurityPolicyAction
  enabled: boolean
  matcher?: SecurityPolicyMatcherInput
  authoring?: DlpNumberAuthoring
  authoring_proof?: string
  clear_matcher?: boolean
  capability_categories: string[]
  binding_mode: SecurityPolicyBindingMode
  subject_binding?: SecurityPolicySubjectBinding
  clear_subject_binding?: boolean
}

export type SecurityPolicyPatch = Partial<SecurityPolicyWrite>

// 行为卡片动作与防护项动作是同一套取值。
export type PolicyCenterAgentBehaviorAction = ProtectionAction

// 受限文件作用范围：工具调用、用户输入、代理输出；缺省三项全选。
export type RestrictedFileScope = 'tool_call' | 'user_mention' | 'proxy_output'

// confirm 只在该项的 allowed_actions 里有它时才算可写（2.9.22 起“删除与破坏”可选人工确认）；
// 其余卡片上的 confirm 仍是高级规则带来的、不可在卡片里保存的值。
export function isBasicAction(action: string, allowedActions?: readonly string[]): action is PolicyCenterAgentBehaviorAction {
  if (action === 'confirm') return (allowedActions ?? []).includes('confirm')
  return action === 'record' || action === 'alert_allow' || action === 'block'
}

export type PolicyCenterAgentBehavior = {
  key: string
  label: string
  description: string
  configured_action: string
  current_action: string
  raw_configured_action?: string
  health: 'ok' | 'error'
  health_message?: string
  allowed_actions: PolicyCenterAgentBehaviorAction[]
  has_advanced_overrides: boolean
  configured: boolean
  version: string
  match_scope?: string
  match_pattern?: string
  evaluation_stage?: string
  // 仅 sensitive_resource（敏感资源访问）返回：受限文件模式配置。
  restricted_file_patterns?: string[]
  restricted_file_action?: 'record' | 'alert_allow' | 'block'
  restricted_file_scopes?: RestrictedFileScope[]
  builtin_patterns_summary?: string
}

export type PolicyCenterAgentBehaviorsResponse = {
  items: PolicyCenterAgentBehavior[]
}

export type SecurityPolicyBatchUpdate = {
  redaction?: SecurityPolicyRedaction
  id: string
  action?: SecurityPolicyAction
  enabled?: boolean
}

export type SecurityPolicyPreviewInput = {
  stage: 'input' | 'agent' | 'output'
  application_id?: string
  key_id?: string
  protocol?: string
  entry_point?: string
}

export type SecurityPolicyPreviewBindingDetail = {
  dimension: keyof SecurityPolicySubjectBinding
  configured_values: string[]
  matched: boolean
  reason: 'matched' | 'principal_missing' | 'actor_not_authenticated' | 'principal_value_missing' | 'no_configured_value_matched'
  include_children: boolean
}

export type SecurityPolicyPreviewItem = {
  policy_code: string
  policy_id: string
  policy_name: string
  policy_version: string
  enabled: boolean
  matched: boolean
  subject_matched: boolean
  stage: 'input' | 'agent' | 'output'
  stage_supported: boolean
  configured_action: Exclude<SecurityPolicyAction, 'allow'>
  effective_action: Exclude<SecurityPolicyAction, 'allow'> | null
  conditional_action: Exclude<SecurityPolicyAction, 'allow'> | null
  requires_finding: boolean
  action_basis: 'finding_required' | 'policy_disabled' | 'subject_not_matched' | 'stage_not_supported'
  capability_categories: string[]
  stage_capability_categories: string[]
  matcher_rule_id: string
  binding_details: SecurityPolicyPreviewBindingDetail[]
}

export type SecurityPolicyPreviewResponse = {
  stage: 'input' | 'agent' | 'output'
  identity_version: string
  desired_version: string
  engine_rule_pack_version: string
  content_evaluated: false
  published_policy_ids: string[]
  nodes: {
    status: string
    node_count: number
    fresh_count: number
    converged_count: number
    fresh_converged_count: number
    stale_count: number
    all_converged: boolean
  }
  policies: SecurityPolicyPreviewItem[]
}

export type DlpNumberSegment = {
  kind: 'fixed' | 'digits' | 'letters'
  value?: string
  length?: number
}

export type DlpNumberAuthoring = {
  version: 1
  kind: 'number'
  matcher_pattern: string
  segments: DlpNumberSegment[]
}

export type DlpGenerateInput = {
  kind: 'number'
  positive_samples: string[]
  segments?: DlpNumberSegment[]
  policy_id?: string
  request_version?: string
}

export type DlpGenerateResponse = {
  matcher: SecurityPolicyMatcherInput
  segments: DlpNumberSegment[]
  explanation: string
  authoring_proof: string
  request_version?: string
}

export type DlpPreviewInput = {
  matcher: SecurityPolicyMatcherInput
  samples: string[]
  request_version?: string
}

export type DlpPreviewResponse = {
  matches: Array<{ sample_index: number; matched: boolean; location: string | null; redacted_evidence: string | null }>
  warnings: string[]
  request_version?: string
}

export const securityPoliciesApi = {
  list: () => api.get<SecurityPoliciesResponse>('/security/policies'),
  capabilities: () => api.get<SecurityCapabilitiesResponse>('/security/policies/capabilities'),
  create: (input: SecurityPolicyWrite) => api.post<SecurityPolicy>('/security/policies', input),
  generateDlp: (input: DlpGenerateInput) =>
    api.post<DlpGenerateResponse>('/security/policies/quick-create/generate', input),
  previewDlp: (input: DlpPreviewInput) =>
    api.post<DlpPreviewResponse>('/security/policies/quick-create/preview', input),
  update: (id: string, input: SecurityPolicyPatch) =>
    api.patch<SecurityPolicy>(`/security/policies/${id}`, input),
  batch: (updates: SecurityPolicyBatchUpdate[]) =>
    api.post('/security/policies/batch', { updates }),
  remove: (id: string) => api.delete(`/security/policies/${encodeURIComponent(id)}`),
  preview: (input: SecurityPolicyPreviewInput) =>
    api.post<SecurityPolicyPreviewResponse>('/security/policies/preview', input),
  agentBehaviors: () => api.get<PolicyCenterAgentBehaviorsResponse>('/policy-center/agent-behaviors'),
  updateAgentBehavior: (key: string, input: {
    action: PolicyCenterAgentBehaviorAction
    version: string
    restricted_file_patterns?: string[]
    restricted_file_action?: 'record' | 'alert_allow' | 'block'
    restricted_file_scopes?: RestrictedFileScope[]
  }) =>
    api.put<PolicyCenterAgentBehavior>('/policy-center/agent-behaviors/' + encodeURIComponent(key), input),
}

// W5 5.5: sensitive-read -> egress sequence rule on the network_egress category.
export type AgentGuardSequenceRuleUpdate = {
  action: PolicyCenterAgentBehaviorAction
  version: string
  sensitive_read_egress_window_seconds: number
}

export const agentGuardSequenceRuleApi = {
  update: (input: AgentGuardSequenceRuleUpdate) =>
    api.put<PolicyCenterAgentBehavior & { sensitive_read_egress_window_seconds?: number }>(
      '/policy-center/agent-behaviors/network_egress',
      input,
    ),
}

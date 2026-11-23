import type {
  SecurityPolicy,
  SecurityPolicyAction,
  SecurityPolicyCapability,
} from '../../services/securityPoliciesApi'

export type PolicyCenterSectionKey =
  | 'overview'
  | 'prompt-injection'
  | 'content-safety'
  | 'sensitive-data'
  | 'all'

export type PolicyCenterStatusKey = 'recording' | 'protecting' | 'disabled' | 'syncing' | 'error'

export type PolicyCenterScene = {
  key: Exclude<PolicyCenterSectionKey, 'overview' | 'all'>
  label: string
  description: string
  policyScenes: string[]
}

export type PolicyCenterStatus = {
  key: PolicyCenterStatusKey
  label: string
  reason: string
  currentAction: string
}

export const POLICY_CENTER_SCENES: PolicyCenterScene[] = [
  {
    key: 'prompt-injection',
    label: 'Prompt 注入',
    description: '识别绕过安全边界、覆写指令和提示词泄露风险。',
    policyScenes: ['prompt_injection', 'prompt_leak'],
  },
  {
    key: 'content-safety',
    label: '内容安全',
    description: '处理政治、色情、暴恐、诈骗和自伤等内容风险。',
    policyScenes: ['content_safety'],
  },
  {
    key: 'sensitive-data',
    label: '敏感数据外发',
    description: '统一配置文字和文件中的身份、凭据、财务及企业敏感信息。',
    policyScenes: ['data_leak', 'pii', 'secret'],
  },
]

export const POLICY_CENTER_NAV_ITEMS: Array<{
  key: PolicyCenterSectionKey
  label: string
}> = [
  { key: 'overview', label: '总览' },
  ...POLICY_CENTER_SCENES.map(({ key, label }) => ({ key, label })),
  { key: 'all', label: '全部策略' },
]

export type ContentSafetyCategoryKey =
  | 'political_safety'
  | 'adult_content'
  | 'violence_and_terror'
  | 'discrimination_and_harassment'
  | 'illegal_and_self_harm'

export type ContentSafetyItem = {
  key: string
  label: string
  policyNames: string[]
  capabilityCategories: string[]
}

export type ContentSafetyCategory = {
  key: ContentSafetyCategoryKey
  label: string
  description: string
  defaultAction: SecurityPolicyAction
  items: ContentSafetyItem[]
}

// 这些是 security-engine 当前真实暴露的内容安全能力及其预置策略名称。
// policyNames 用于让没有完成能力绑定的历史预置项也能在页面被看见；
// 这类项目会被标记为“未接入运行检测”，不会被前端伪装成可生效策略。
export const CONTENT_SAFETY_CATEGORIES: ContentSafetyCategory[] = [
  {
    key: 'political_safety',
    label: '政治与公共安全',
    description: '政治敏感事件、领土主权、历史虚无主义及敏感人物/组织内容。',
    defaultAction: 'block',
    items: [
      { key: 'political_sensitive_event', label: '敏感政治事件', policyNames: ['敏感政治事件'], capabilityCategories: ['political_sensitive_event'] },
      { key: 'political_territory', label: '领土主权', policyNames: ['领土主权检测'], capabilityCategories: ['political_territory_taiwan', 'political_territory_split'] },
      { key: 'political_history', label: '历史虚无主义', policyNames: ['历史虚无主义'], capabilityCategories: ['political_historical_nihilism'] },
      { key: 'political_leader', label: '敏感人物/组织', policyNames: ['领导人负面讨论', '敏感人物/组织'], capabilityCategories: ['political_leader_name'] },
      { key: 'political_ethnic', label: '民族宗教敏感内容', policyNames: ['民族宗教问题'], capabilityCategories: ['political_ethnic_separatism'] },
      { key: 'cult_propaganda', label: '邪教与颠覆宣传', policyNames: ['邪教宣传内容', '煽动颠覆内容'], capabilityCategories: [] },
    ],
  },
  {
    key: 'adult_content',
    label: '色情低俗',
    description: '色情、低俗和性暗示内容，默认高风险阻断。',
    defaultAction: 'block',
    items: [
      { key: 'pornography', label: '色情低俗内容', policyNames: ['色情低俗内容'], capabilityCategories: ['illegal_pornography'] },
      { key: 'sexual_violence', label: '性暴力内容', policyNames: ['性暴力内容'], capabilityCategories: [] },
    ],
  },
  {
    key: 'violence_and_terror',
    label: '暴力与暴恐',
    description: '暴力、恐怖主义、武器及对他人实施伤害的指导。',
    defaultAction: 'block',
    items: [
      { key: 'violence_terror', label: '暴力恐怖内容', policyNames: ['暴力恐怖内容', '恐怖主义宣传'], capabilityCategories: ['illegal_violence_terror'] },
      { key: 'weapon_guidance', label: '武器/爆炸物制作指导', policyNames: ['武器制作指导'], capabilityCategories: [] },
      { key: 'personal_attack', label: '人身攻击指导', policyNames: ['人身攻击指导'], capabilityCategories: [] },
    ],
  },
  {
    key: 'discrimination_and_harassment',
    label: '歧视、仇恨与骚扰',
    description: '种族、地域、性别歧视，仇恨言论、霸凌和网络暴力。',
    defaultAction: 'block',
    items: [
      { key: 'discrimination', label: '歧视内容', policyNames: ['歧视内容'], capabilityCategories: ['discrimination_racial_discrimination', 'discrimination_regional_discrimination', 'discrimination_gender_discrimination'] },
      { key: 'hate_speech', label: '仇恨言论', policyNames: ['仇恨言论'], capabilityCategories: [] },
      { key: 'harassment', label: '骚扰/霸凌与网络暴力', policyNames: ['骚扰/霸凌内容', '网络暴力内容', '校园暴力内容', '家庭暴力内容'], capabilityCategories: [] },
      { key: 'profanity', label: '辱骂脏话', policyNames: ['辱骂脏话'], capabilityCategories: ['content_profanity_abuse', 'harassment_profanity_cn'] },
      { key: 'doxxing', label: '人肉搜索与个人攻击', policyNames: ['人肉搜索指导', '人身攻击指导'], capabilityCategories: [] },
    ],
  },
  {
    key: 'illegal_and_self_harm',
    label: '违法、有害与自伤',
    description: '毒品、网络攻击、赌博诈骗、自伤自杀及未成年人保护相关内容。',
    defaultAction: 'block',
    items: [
      { key: 'drugs', label: '毒品相关内容', policyNames: ['毒品制作指导', '药品滥用指导'], capabilityCategories: ['illegal_drugs'] },
      { key: 'cyber_attack', label: '网络攻击教程', policyNames: ['网络攻击教程'], capabilityCategories: ['illegal_cyber_attack'] },
      { key: 'gambling_fraud', label: '赌博/诈骗内容', policyNames: ['赌博/诈骗内容'], capabilityCategories: ['illegal_gambling', 'illegal_fraud'] },
      { key: 'self_harm', label: '自伤自杀内容', policyNames: ['自杀方法指导', '自残/自杀内容'], capabilityCategories: ['self_harm_actionable_guidance'] },
      { key: 'minors', label: '未成年人保护', policyNames: ['未成年人保护'], capabilityCategories: [] },
      { key: 'other_harmful', label: '违禁品、谣言与公共安全', policyNames: ['违禁品检测', '虚假信息/谣言', '环境污染指导', '食品安全违规', '医疗欺诈内容'], capabilityCategories: [] },
      { key: 'animal_abuse', label: '虐待动物', policyNames: ['虐待动物内容'], capabilityCategories: [] },
    ],
  },
]

export type AgentBehaviorRelation = {
  key: string
  controlObject: string
  source: string
}

export const AGENT_BEHAVIOR_RELATIONS: AgentBehaviorRelation[] = [
  {
    key: 'destructive_operation',
    controlObject: '删除、覆盖、清空等不可逆操作',
    source: '删除与破坏策略',
  },
  {
    key: 'system_command',
    controlObject: 'Shell、系统命令和进程工具',
    source: 'AgentGuard 系统命令规则',
  },
  {
    key: 'sensitive_resource',
    controlObject: '敏感文件、目录和资源读取',
    source: 'AgentGuard 资源访问规则',
  },
  {
    key: 'network_egress',
    controlObject: '网络请求、上传和外部地址访问',
    source: 'AgentGuard 网络外联规则',
  },
  {
    key: 'database_change',
    controlObject: '写库、删库和结构变更工具',
    source: 'AgentGuard 数据库规则',
  },
  {
    key: 'external_tool',
    controlObject: '租户已接入的 MCP 服务和工具',
    source: 'MCP 权限策略',
  },
]

export function getAgentBehaviorRelation(key: string): AgentBehaviorRelation {
  return AGENT_BEHAVIOR_RELATIONS.find((relation) => relation.key === key) ?? {
    key,
    controlObject: '该行为类别的工具调用',
    source: '现有行为策略',
  }
}

const ERROR_RUNTIME_STATUSES = new Set([
  'degraded',
  'error',
  'pending',
  'applied_with_stale_nodes',
])

const ACTION_LABELS: Record<SecurityPolicy['action'], string> = {
  allow: '放行',
  audit: '告警并发送',
  mask: '脱敏后发送',
  block: '阻止发送',
}

export function filterCustomerVisiblePolicies(policies: SecurityPolicy[]): SecurityPolicy[] {
  // The API response is already tenant-scoped. Hiding preloaded policies that
  // do not yet have a detector binding made the policy center lie by omission:
  // administrators could neither see nor finish configuring shipped assets.
  return [...policies]
}

export type SecurityCapabilityCoverage = {
  capability: SecurityPolicyCapability
  policies: SecurityPolicy[]
}

export function buildSecurityCapabilityCoverage(
  capabilities: SecurityPolicyCapability[],
  policies: SecurityPolicy[],
): SecurityCapabilityCoverage[] {
  const policiesByCategory = new Map<string, SecurityPolicy[]>()
  policies.forEach((policy) => {
    policy.capabilities.forEach((capability) => {
      const current = policiesByCategory.get(capability.category) ?? []
      if (!current.some((item) => item.id === policy.id)) {
        policiesByCategory.set(capability.category, [...current, policy])
      }
    })
  })
  return capabilities.map((capability) => ({
    capability,
    policies: (policiesByCategory.get(capability.category) ?? [])
      .sort((left, right) => left.name.localeCompare(right.name, 'zh-CN')),
  }))
}

export function getPolicyCenterScene(key: PolicyCenterSectionKey): PolicyCenterScene | undefined {
  return POLICY_CENTER_SCENES.find((scene) => scene.key === key)
}

export function policiesForScene(
  policies: SecurityPolicy[],
  scene: PolicyCenterScene,
): SecurityPolicy[] {
  return policies.filter((policy) => scene.policyScenes.includes(policy.scene))
}

export function hasHealthyRuntimeReceipt(
  runtimeVerified: boolean | undefined,
  runtimeStatus: string | undefined,
): boolean {
  return runtimeVerified === true && !ERROR_RUNTIME_STATUSES.has(runtimeStatus ?? '')
}

export function isRuntimeSyncPending(
  runtimeVerified: boolean | undefined,
  runtimeStatus: string | undefined,
): boolean {
  return runtimeVerified === false && ['pending', 'partially_applied'].includes(runtimeStatus ?? '')
}

export function getPolicyActionLabel(action: SecurityPolicy['action']): string {
  return ACTION_LABELS[action]
}

export function aggregatePolicyCenterStatus({
  policies,
  auditOnly,
  runtimeVerified,
  runtimeStatus,
}: {
  policies: SecurityPolicy[]
  auditOnly: boolean | undefined
  runtimeVerified: boolean | undefined
  runtimeStatus: string | undefined
}): PolicyCenterStatus {
  const enabledPolicies = policies.filter((policy) => policy.enabled)
  if (enabledPolicies.length === 0) {
    return {
      key: 'disabled',
      label: '已停用',
      reason: '当前没有启用的客户策略，基础审计日志仍可保留。',
      currentAction: '无客户策略执行',
    }
  }

  if (isRuntimeSyncPending(runtimeVerified, runtimeStatus)) {
    return {
      key: 'syncing',
      label: '新配置同步中',
      reason: '新动作已保存，正在等待安全引擎回执；安全引擎继续使用最近一次成功加载的配置。',
      currentAction: '原配置继续运行',
    }
  }

  if (!hasHealthyRuntimeReceipt(runtimeVerified, runtimeStatus)) {
    return {
      key: 'error',
      label: '运行异常',
      reason: '运行回执尚未确认或当前节点配置异常，请检查策略运行状态。',
      currentAction: '仅展示已保存配置，实际处理待确认',
    }
  }

  if (enabledPolicies.some((policy) => (
    !policy.detection_configured
    || !policy.detection_ready
    || !policy.runtime_active
  ))) {
    return {
      key: 'error',
      label: '运行异常',
      reason: '有启用策略尚未完成识别配置或运行绑定，请处理后再启用保护。',
      currentAction: '实际处理待确认',
    }
  }

  if (auditOnly === undefined) {
    return {
      key: 'error',
      label: '运行异常',
      reason: '全局执行模式尚未取得权威配置，无法确认实际处理动作。',
      currentAction: '实际处理待确认',
    }
  }

  if (auditOnly) {
    return {
      key: 'recording',
      label: '记录中',
      reason: '当前为记录模式：策略命中只留痕，不会因命中执行脱敏或阻断。',
      currentAction: '仅记录',
    }
  }

  return {
    key: 'protecting',
    label: '保护中',
    reason: '当前为保护模式，场景按已保存动作执行告警、脱敏或阻断。',
    currentAction: getPolicyActionLabel(enabledPolicies[0].action),
  }
}

export type SensitiveDataCategoryKey =
  | 'identity_documents'
  | 'contact_location'
  | 'credentials'
  | 'financial'
  | 'health_biometrics'
  | 'enterprise_sensitive'

export type SensitiveDataItem = {
  key: string
  label: string
  policyNames?: string[]
  capabilityCategories: string[]
  allowMultiplePolicies?: boolean
}

export type SensitiveDataCategory = {
  key: SensitiveDataCategoryKey
  label: string
  description: string
  defaultAction: SecurityPolicyAction
  items: SensitiveDataItem[]
}

export const SENSITIVE_DATA_CATEGORIES: SensitiveDataCategory[] = [
  {
    key: 'identity_documents',
    label: '身份与证件',
    description: '手机号、身份证、护照、港澳台证件、军官证、驾驶证和社保卡。',
    defaultAction: 'mask',
    items: [
      { key: 'phone', label: '手机号', policyNames: ['手机号检测'], capabilityCategories: ['phone_cn'] },
      { key: 'id_card', label: '身份证号', policyNames: ['身份证号检测'], capabilityCategories: ['id_card_cn'] },
      { key: 'passport', label: '护照号', policyNames: ['护照号检测'], capabilityCategories: ['passport_cn'] },
      { key: 'hk_macao_taiwan_id', label: '港澳台证件', policyNames: ['港澳台证件检测'], capabilityCategories: ['hk_macao_taiwan_id'] },
      { key: 'officer_id', label: '军官证/警官证', policyNames: ['军官证检测'], capabilityCategories: ['officer_id_cn'] },
      { key: 'driver_license', label: '驾驶证', policyNames: ['驾驶证检测'], capabilityCategories: ['driver_license_cn'] },
      { key: 'social_security_card', label: '社保卡号', policyNames: ['社保卡号检测'], capabilityCategories: ['social_security_cn'] },
    ],
  },
  {
    key: 'contact_location',
    label: '联系方式与位置',
    description: '邮箱、家庭地址、IP、出生日期、通信记录和位置/GPS 数据。',
    defaultAction: 'mask',
    items: [
      { key: 'email', label: '邮箱地址', policyNames: ['邮箱地址检测'], capabilityCategories: ['email'] },
      { key: 'home_address', label: '家庭地址', policyNames: ['家庭地址检测'], capabilityCategories: ['home_address_cn'] },
      { key: 'ip_address', label: 'IP 地址', policyNames: ['IP 地址检测'], capabilityCategories: ['ip_address'] },
      { key: 'birth_date', label: '出生日期', policyNames: ['出生日期检测'], capabilityCategories: ['birth_date'] },
      { key: 'communications', label: '通信记录', policyNames: ['通信记录检测'], capabilityCategories: ['communication_record'] },
      { key: 'location', label: '位置/GPS 数据', policyNames: ['位置/GPS 数据'], capabilityCategories: ['gps_location'] },
    ],
  },
  {
    key: 'credentials',
    label: '账号与凭据',
    description: 'API Key、密码、JWT/Token、证书/私钥、云凭据和数据库连接串。',
    defaultAction: 'block',
    items: [
      { key: 'api_key', label: 'API Key', policyNames: ['API Key 检测'], capabilityCategories: ['generic_api_key', 'openai_key', 'anthropic_key', 'github_token'] },
      { key: 'plain_password', label: '密码明文', policyNames: ['密码明文检测'], capabilityCategories: ['plain_password', 'code_leak_password_in_code'] },
      { key: 'jwt_token', label: 'JWT/Token', policyNames: ['JWT/Token 检测'], capabilityCategories: ['jwt_token'] },
      {
        key: 'certificate_private_key',
        label: '证书/私钥',
        policyNames: ['证书/私钥检测', 'SSH 密钥检测'],
        capabilityCategories: ['ssh_private_key', 'openssh_private_key'],
        allowMultiplePolicies: true,
      },
      { key: 'cloud_credentials', label: '云厂商凭据', policyNames: ['AWS/GCP 凭据检测'], capabilityCategories: ['cloud_credential', 'aws_access_key', 'aws_secret_key', 'code_leak_cloud_credential'] },
      { key: 'database_connection', label: '数据库连接串', policyNames: ['数据库连接串检测'], capabilityCategories: ['code_leak_database_url'] },
    ],
  },
  {
    key: 'financial',
    label: '财务与保险',
    description: '银行卡、信用卡安全码、银行流水和保险信息。',
    defaultAction: 'block',
    items: [
      { key: 'bank_card', label: '银行卡号', policyNames: ['银行卡号检测'], capabilityCategories: ['bank_card_cn'] },
      { key: 'credit_card_cvv', label: '信用卡 CVV/CVC', policyNames: ['信用卡CVV检测'], capabilityCategories: ['credit_card_cvv'] },
      { key: 'bank_statement', label: '银行流水', policyNames: ['银行流水检测'], capabilityCategories: ['bank_statement'] },
      { key: 'insurance', label: '保险信息', policyNames: ['保险信息检测'], capabilityCategories: ['insurance_info'] },
    ],
  },
  {
    key: 'health_biometrics',
    label: '医疗与生物特征',
    description: '医疗记录、基因数据、指纹/虹膜/人脸等生物特征。',
    defaultAction: 'block',
    items: [
      { key: 'medical_records', label: '医疗记录/病历', policyNames: ['医疗记录检测'], capabilityCategories: ['medical_record'] },
      { key: 'genetic_data', label: '基因数据', policyNames: ['基因数据检测'], capabilityCategories: ['genetic_data'] },
      { key: 'biometrics', label: '生物特征', policyNames: ['生物特征检测'], capabilityCategories: ['biometric_data'] },
    ],
  },
  {
    key: 'enterprise_sensitive',
    label: '企业敏感信息',
    description: '涉密文件、内部项目代号、敏感代码和高风险人员信息。',
    defaultAction: 'audit',
    items: [
      { key: 'classified_file', label: '涉密文件标记', policyNames: ['涉密文件标记检测'], capabilityCategories: ['classified_classified_cn', 'classified_classified_en'] },
      { key: 'internal_project_code', label: '内部项目代号', policyNames: ['内部项目代号检测'], capabilityCategories: ['internal_project_code'] },
      { key: 'sensitive_code', label: '敏感代码片段', policyNames: ['敏感代码片段检测'], capabilityCategories: ['sensitive_code'] },
      { key: 'education', label: '教育背景', policyNames: ['教育背景检测'], capabilityCategories: ['education_background'] },
      { key: 'criminal_record', label: '犯罪记录', policyNames: ['犯罪记录检测'], capabilityCategories: ['criminal_record'] },
    ],
  },
]

const SENSITIVE_POLICY_SCENES = new Set(['data_leak', 'pii', 'secret'])
const CONTENT_POLICY_SCENES = new Set(['content_safety'])
const SENSITIVE_ACTION_ORDER: SecurityPolicyAction[] = ['audit', 'mask', 'block']

type PolicyCenterCatalogItem = {
  policyNames?: string[]
  capabilityCategories: string[]
}

function findCatalogItemPolicies(
  policies: SecurityPolicy[],
  item: PolicyCenterCatalogItem,
  scenes: Set<string>,
  includeUnconfigured: boolean,
): SecurityPolicy[] {
  const required = [...new Set(item.capabilityCategories)].sort()
  return policies.filter((policy) => {
    if (!scenes.has(policy.scene)) return false
    if (!includeUnconfigured && !policy.detection_configured) return false
    if (item.policyNames?.includes(policy.name)) return true
    if (required.length === 0) return false
    const categories = [...new Set(policy.capabilities.map((capability) => capability.category))].sort()
    return categories.length === required.length
      && categories.every((category, index) => category === required[index])
  })
}

export function findContentItemPolicies(
  policies: SecurityPolicy[],
  item: ContentSafetyItem,
  includeUnconfigured = false,
): SecurityPolicy[] {
  return findCatalogItemPolicies(policies, item, CONTENT_POLICY_SCENES, includeUnconfigured)
}

export function findSensitiveItemPolicies(
  policies: SecurityPolicy[],
  item: SensitiveDataItem,
  includeUnconfigured = false,
): SecurityPolicy[] {
  return findCatalogItemPolicies(policies, item, SENSITIVE_POLICY_SCENES, includeUnconfigured)
}

export function getSensitiveDataActions(policies: SecurityPolicy[]): SecurityPolicyAction[] {
  if (policies.length === 0) return []
  return SENSITIVE_ACTION_ORDER.filter((action) => policies.every((policy) => (
    policy.capabilities.length > 0
    && policy.capabilities.every((capability) => (
      capability.enabled
      && capability.allowed_actions.includes(action)
      && (action !== 'mask' || capability.mask_capable)
    ))
  )))
}

export function getEffectivePolicyActionLabel(
  action: SecurityPolicyAction,
  auditOnly: boolean | undefined,
): string {
  if (auditOnly === true) return '仅记录'
  if (auditOnly === undefined) return '实际处理待确认'
  return getPolicyActionLabel(action)
}

// 级别和动作明显矛盾时给出一句提示；其余组合由管理员自行决定，不提示。
export function severityActionMismatch(policy: { severity: string; action: string }): string {
  if (policy.severity === 'critical' && policy.action === 'audit') return '严重级别的策略只记录不阻断'
  if (policy.severity === 'low' && policy.action === 'block') return '低危级别的策略会阻断请求'
  return ''
}

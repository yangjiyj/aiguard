import type {
  SecurityPolicy,
  SecurityPolicyCapability,
  SecurityPolicySemanticAction,
  SecurityPoliciesResponse,
} from '../../services/securityPoliciesApi'
import { getStaticCapabilityLabel } from '../../utils/securityCapabilityLabels'
import { isRuntimeSyncPending } from './policyCenterModel'

export type EnterpriseSceneKey =
  | 'sensitive-data'
  | 'file-security'
  | 'content-safety'
  | 'prompt-security'
  | 'agent-tools'
  | 'model-access'
  | 'other'

export type EnterpriseSceneDefinition = {
  key: EnterpriseSceneKey
  label: string
  description: string
  subject: string
}

export const ENTERPRISE_SCENES: EnterpriseSceneDefinition[] = [
  {
    key: 'sensitive-data',
    label: '敏感数据外发',
    description: '识别身份、凭据、财务、医疗及企业敏感信息外发。',
    subject: '当前租户的文字与结构化数据流量',
  },
  {
    key: 'file-security',
    label: '文件与附件安全',
    description: '管控上传类型、文件正文、压缩包和无法解析的附件。',
    subject: '经过网关上传的文件与附件',
  },
  {
    key: 'content-safety',
    label: '内容合规安全',
    description: '识别违法违规、有害内容和行业合规风险。',
    subject: '当前租户的模型输入与输出',
  },
  {
    key: 'prompt-security',
    label: '提示注入与语义攻击',
    description: '识别指令覆写、提示词泄露、编码绕过和语义攻击。',
    subject: '当前租户的模型输入与智能体指令',
  },
  {
    key: 'agent-tools',
    label: '智能体与工具行为',
    description: '约束工具调用、命令执行、网络外联和破坏性操作。',
    subject: '当前租户的 Agent、MCP 与工具调用',
  },
  {
    key: 'model-access',
    label: '模型访问与使用范围',
    description: '管理模型、应用、API Key 和外部服务的访问范围。',
    subject: '当前租户的模型访问入口',
  },
]

export const CUSTOMER_SECURITY_SCENES = ENTERPRISE_SCENES.filter((scene) => scene.key !== 'model-access')

export const OTHER_SCENE: EnterpriseSceneDefinition = {
  key: 'other',
  label: '其他 / 待归类',
  description: '保留尚未映射到标准业务场景的策略，便于管理员核对。',
  subject: '以策略原始场景为准',
}

const SCENE_HINTS: Array<{ key: EnterpriseSceneKey; hints: string[] }> = [
  { key: 'file-security', hints: ['file', 'attachment', 'upload', 'archive', 'zip', 'document'] },
  { key: 'sensitive-data', hints: ['data_leak', 'data_security', 'pii', 'secret', 'credential', 'dlp', 'classified', 'privacy', 'phone', 'card', 'email', 'token', 'key'] },
  { key: 'content-safety', hints: ['content_safety', 'political', 'illegal', 'porn', 'violence', 'terror', 'hate', 'harass', 'self_harm', 'fraud', 'gambling'] },
  { key: 'prompt-security', hints: ['prompt', 'injection', 'jailbreak', 'semantic', 'steganography', 'encoding', 'obfuscation', 'instruction'] },
  { key: 'agent-tools', hints: ['agent', 'tool', 'mcp', 'command', 'shell', 'ssrf', 'metadata', 'network', 'destructive', 'database'] },
  { key: 'model-access', hints: ['model_access', 'model_scope', 'provider_access', 'service_access', 'api_key_scope', 'application_scope', 'egress_target'] },
]

function normalizedPolicyHints(policy: Pick<SecurityPolicy, 'scene' | 'capabilities'>): string {
  return [policy.scene, ...policy.capabilities.map((capability) => capability.category)]
    .join(' ')
    .trim()
    .toLowerCase()
}

export function classifyPolicyScene(policy: Pick<SecurityPolicy, 'scene' | 'capabilities'>): EnterpriseSceneKey {
  const value = normalizedPolicyHints(policy)
  return SCENE_HINTS.find(({ hints }) => hints.some((hint) => value.includes(hint)))?.key ?? 'other'
}

export function getEnterpriseScene(key: EnterpriseSceneKey): EnterpriseSceneDefinition {
  return ENTERPRISE_SCENES.find((scene) => scene.key === key) ?? OTHER_SCENE
}

const ACTION_LABELS: Record<string, string> = {
  allow: '放行',
  audit: '记录并告警',
  mask: '脱敏后发送',
  confirm: '人工确认',
  block: '阻断',
}

export function policyActionLabel(action?: string): string {
  if (!action) return '待确认'
  return ACTION_LABELS[action] ?? `未知动作（${action}）`
}

export function modeCustomerLabel(mode?: string): string {
  if (mode === 'record' || mode === 'observe') return '观察留痕'
  if (mode === 'audit') return '告警运营'
  if (mode === 'protect' || mode === 'strict') return '防护阻断'
  return mode ? `未知模式（${mode}）` : '待确认'
}

export type EffectiveActionDisplay = {
  configuredLabel: string
  effectiveAction?: string
  effectiveLabel: string
  explanation: string
  clamped: boolean
  preview: boolean
  source: 'runtime' | 'global-ceiling' | 'policy' | 'unknown'
}

export function describeEffectiveAction({
  configuredAction,
  globalMode,
  auditOnly = false,
  enabled = true,
  backendEffectiveAction,
}: {
  configuredAction?: string
  globalMode?: string
  auditOnly?: boolean
  enabled?: boolean
  backendEffectiveAction?: string
}): EffectiveActionDisplay {
  const configuredLabel = policyActionLabel(configuredAction)
  if (!enabled) {
    return {
      configuredLabel,
      effectiveLabel: '已停用',
      explanation: '策略当前不参与运行时决策。',
      clamped: false,
      preview: false,
      source: 'policy',
    }
  }

  if (auditOnly) {
    return {
      configuredLabel,
      effectiveAction: 'audit',
      effectiveLabel: configuredAction === 'audit' || configuredAction === 'allow'
        ? policyActionLabel(configuredAction)
        : '当前仅记录并告警',
      explanation: '系统审计总开关已将主动处置钳制为记录并告警。',
      clamped: !['allow', 'audit'].includes(configuredAction ?? ''),
      preview: false,
      source: 'global-ceiling',
    }
  }

  if (backendEffectiveAction) {
    return {
      configuredLabel,
      effectiveAction: backendEffectiveAction,
      effectiveLabel: policyActionLabel(backendEffectiveAction),
      explanation: backendEffectiveAction === configuredAction
        ? '来自运行时返回的有效动作。'
        : `运行时有效动作与配置动作不同，当前以运行时返回的${policyActionLabel(backendEffectiveAction)}为准。`,
      clamped: backendEffectiveAction !== configuredAction,
      preview: false,
      source: 'runtime',
    }
  }

  if (!globalMode) {
    return {
      configuredLabel,
      effectiveLabel: '待运行时确认',
      explanation: '尚未取得全局运行模式，不能推断实际处置。',
      clamped: false,
      preview: false,
      source: 'unknown',
    }
  }

  if (globalMode === 'record' || globalMode === 'observe') {
    return {
      configuredLabel,
      effectiveAction: 'audit',
      effectiveLabel: configuredAction === 'allow' ? '放行' : '当前仅留痕',
      explanation: '全局观察留痕模式不执行主动处置。',
      clamped: !['allow', 'audit'].includes(configuredAction ?? ''),
      preview: false,
      source: 'global-ceiling',
    }
  }

  if (globalMode === 'audit') {
    return {
      configuredLabel,
      effectiveAction: 'audit',
      effectiveLabel: configuredAction === 'allow' ? '放行' : '当前记录并告警',
      explanation: '全局告警运营模式不会自动确认、脱敏或阻断。',
      clamped: !['allow', 'audit'].includes(configuredAction ?? ''),
      preview: false,
      source: 'global-ceiling',
    }
  }

  if (globalMode === 'protect' || globalMode === 'strict') {
    if (!configuredAction || !ACTION_LABELS[configuredAction]) {
      return {
        configuredLabel,
        effectiveLabel: '待运行时确认',
        explanation: '配置动作无法识别，最终动作以运行时决策为准。',
        clamped: false,
        preview: false,
        source: 'unknown',
      }
    }
    return {
      configuredLabel,
      effectiveAction: configuredAction,
      effectiveLabel: `预计${policyActionLabel(configuredAction)}`,
      explanation: '后端未返回逐策略有效动作；此处仅按全局上限预览，最终以运行时决策为准。',
      clamped: false,
      preview: true,
      source: 'policy',
    }
  }

  return {
    configuredLabel,
    effectiveLabel: '待运行时确认',
    explanation: `无法识别全局模式 ${globalMode}，最终动作以运行时决策为准。`,
    clamped: false,
    preview: false,
    source: 'unknown',
  }
}

const ACTION_WEIGHT: Record<string, number> = { allow: 0, audit: 1, mask: 2, confirm: 3, block: 4 }

export function primaryEffectiveAction(
  policies: SecurityPolicy[],
  mode?: string,
  auditOnly = false,
): EffectiveActionDisplay {
  const enabled = policies.filter((policy) => policy.enabled)
  if (enabled.length === 0) {
    return describeEffectiveAction({ configuredAction: 'audit', globalMode: mode, auditOnly, enabled: false })
  }
  const strictest = [...enabled].sort((left, right) => (
    (ACTION_WEIGHT[right.action] ?? -1) - (ACTION_WEIGHT[left.action] ?? -1)
  ))[0]
  return describeEffectiveAction({
    configuredAction: strictest.action,
    globalMode: mode,
    auditOnly,
    enabled: strictest.enabled,
  })
}

export function detectionStageLabel(stage: string): string {
  const labels: Record<string, string> = {
    input: '输入',
    output: '输出',
    file: '文件',
    upload: '文件上传',
    tool: '工具调用',
    agent: '智能体',
    request: '请求',
    response: '响应',
  }
  return labels[stage] ?? `其他（${stage}）`
}

export function policyDetectionSummary(policy: SecurityPolicy): string {
  if (policy.capabilities.length > 0) {
    const names = policy.capabilities.map(capabilityDisplayName)
    return names.slice(0, 2).join('、') + (names.length > 2 ? ` 等 ${names.length} 项` : '')
  }
  if (policy.matcher?.type === 'regex') return '企业自定义正则条件'
  if (policy.matcher?.type === 'keyword') return '企业自定义关键词条件'
  if (policy.matcher?.type === 'field_name') return '企业自定义字段条件'
  if (policy.detection_configured) return '已配置识别条件'
  return '尚未配置识别条件'
}

export function capabilityDisplayName(capability: SecurityPolicyCapability): string {
  const staticLabel = getStaticCapabilityLabel(capability.category)
  if (capability.kind === 'static' && staticLabel !== capability.category) return staticLabel
  const name = capability.name?.trim()
  return name && name !== capability.category ? name : staticLabel
}

export function policyRuntimeRefetchInterval(
  response?: Pick<SecurityPoliciesResponse, 'runtime_verified' | 'runtime_status'>,
): 2000 | false {
  return isRuntimeSyncPending(response?.runtime_verified, response?.runtime_status) ? 2000 : false
}

export function capabilityRiskCategory(capability: SecurityPolicyCapability): string {
  const mockPolicy = { scene: '', capabilities: [capability] } as Pick<SecurityPolicy, 'scene' | 'capabilities'>
  return getEnterpriseScene(classifyPolicyScene(mockPolicy)).label
}

export function policiesUsingCapability(
  policies: SecurityPolicy[],
  capability: SecurityPolicyCapability,
): SecurityPolicy[] {
  return policies.filter((policy) => policy.capabilities.some((item) => item.category === capability.category))
}

export const SEMANTIC_ACTION_OPTIONS: Array<{ value: SecurityPolicySemanticAction; label: string }> = [
  { value: 'block', label: '拦截' },
  { value: 'audit', label: '记录并告警' },
  { value: 'observe', label: '仅记录' },
]

const SEMANTIC_ACTION_LABELS: Record<SecurityPolicySemanticAction, string> = {
  block: '拦截',
  audit: '记录并告警',
  observe: '仅记录',
}

export const SEMANTIC_BLOCK_HINT = '高置信时拦截、分析不可用时放行'

/** 策略是否绑定了由智能分析（语义裁判）执行的检测能力。 */
export function policyHasSemanticJudge(policy: Pick<SecurityPolicy, 'capabilities'> | undefined): boolean {
  return Boolean(policy?.capabilities.some((capability) => capability.semantic_judge))
}

export type SemanticEffectiveDisplay = {
  label: string
  explanation: string
  blocking: boolean
}

/**
 * 智能分析命中的有效处置：由策略「智能分析命中时」决定，与策略处置动作分开显示。
 * 选拦截时只在防护模式下生效，且只拦高置信结论；分析不可用一律放行。
 */
export function describeSemanticEffectiveAction({
  semanticAction,
  globalMode,
  auditOnly = false,
  enabled = true,
}: {
  semanticAction?: SecurityPolicySemanticAction
  globalMode?: string
  auditOnly?: boolean
  enabled?: boolean
}): SemanticEffectiveDisplay | undefined {
  if (!enabled) return undefined
  const action = semanticAction ?? 'audit'
  if (action !== 'block') {
    return {
      label: `智能分析：${SEMANTIC_ACTION_LABELS[action]}`,
      explanation: action === 'observe'
        ? '智能分析命中只留存证据，不计为安全告警。'
        : '智能分析命中记录并告警，不拦截请求。',
      blocking: false,
    }
  }
  const protect = !auditOnly && (globalMode === 'protect' || globalMode === 'strict')
  if (!protect) {
    return {
      label: '智能分析：当前仅记录并告警',
      explanation: '已配置智能分析拦截，但当前不是防护模式，命中只记录并告警。',
      blocking: false,
    }
  }
  return {
    label: `智能分析：拦截（${SEMANTIC_BLOCK_HINT}）`,
    explanation: '输入侧智能分析完整完成且置信度达到「智能分析 → 语义设置」中的拦截阈值时拦截；分析超时、不可用或容量饱和时放行，并在事件中写明原因。',
    blocking: true,
  }
}

/** 上下文裁判（jjdguard-context-judge-v1）的结论类别：只判攻击/正常，不细分类型。 */
export const SEMANTIC_CONTEXT_CAPABILITY = 'prompt_input_semantic_risk'
export const SEMANTIC_CONTEXT_COVERAGE_HINT = '上下文裁判不区分攻击类型，绑定任一智能分析能力即覆盖全部'

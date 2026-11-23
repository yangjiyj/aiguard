import { SEVERITY_LABELS, severityOptions } from '../utils/risk'
import SemanticConsole from './SemanticConsole'
import axios from 'axios'
import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Alert,
  Button,
  Checkbox,
  Collapse,
  Drawer,
  Empty,
  Input,
  Modal,
  Pagination,
  Popconfirm,
  Select,
  Switch,
  Tabs,
  Tag,
  Tooltip,
  message,
} from 'antd'
import {
  AppstoreOutlined,
  ArrowLeftOutlined,
  DatabaseOutlined,
  ExclamationCircleOutlined,
  EyeOutlined,
  InfoCircleOutlined,
  PlusOutlined,
  SearchOutlined,
  SettingOutlined,
} from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { EnterprisePageHeader, StatusPill } from '../components/EnterpriseUI'
import CapabilityMatchDocs, { CurrentHit } from '../components/CapabilityMatchDocs'
import SecurityExecutionModeCard from '../components/SecurityExecutionModeCard'
import { keyApi, orgApi, projectApi } from '../services/api'
import { useSecurityExecutionMode } from '../hooks/useSecurityExecutionMode'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import {
  securityPoliciesApi,
  type DlpNumberSegment,
  type DlpPreviewResponse,
  type SecurityPolicy,
  type SecurityPolicyAction,
  type SecurityPolicyBindingMode,
  type SecurityPolicyCapability,
  type SecurityPolicyMatcherConfig,
  type SecurityPolicyMatcherType,
  type SecurityPolicyPatch,
  type SecurityPolicySeverity,
  type SecurityPolicySubjectBinding,
  type SecurityPolicyPreviewInput,
  type SecurityPolicySemanticAction,
  type SecurityPolicyWrite,
} from '../services/securityPoliciesApi'
import { alertOccurrencesApi } from '../services/alertOccurrences'
import { useAuthStore } from '../stores/auth'
import { canAccessPath } from '../utils/access'
import { alertHitText } from '../utils/alertReadable'
import {
  batchActionAvailability,
  partitionPoliciesForBatchChange,
  type BatchPolicyAction,
  type BatchSkipReason,
} from '../utils/securityPolicyBatch'
import FilePolicySettings from './security-policy/FilePolicySettings'
import SensitiveDataPolicy from './security-policy/SensitiveDataPolicy'
import SecurityReplySettings from './security-policy/SecurityReplySettings'
import { canManageSecurityPolicy } from '../utils/access'
import {
  capabilityDisplayName,
  capabilityRiskCategory,
  classifyPolicyScene,
  describeEffectiveAction,
  describeSemanticEffectiveAction,
  policyHasSemanticJudge,
  SEMANTIC_ACTION_OPTIONS,
  SEMANTIC_CONTEXT_CAPABILITY,
  SEMANTIC_CONTEXT_COVERAGE_HINT,
  CUSTOMER_SECURITY_SCENES,
  detectionStageLabel,
  ENTERPRISE_SCENES,
  getEnterpriseScene,
  policiesUsingCapability,
  policyActionLabel,
  policyDetectionSummary,
  policyRuntimeRefetchInterval,
  primaryEffectiveAction,
  type EnterpriseSceneKey,
} from './security-policy/policyCenterEnterpriseModel'
import { isRuntimeSyncPending, severityActionMismatch } from './security-policy/policyCenterModel'

import RedactionConfigFields from './security-policy/RedactionConfigFields'

type CenterTab = 'scenarios' | 'runtime' | 'detection'
type AdvancedTab = 'capabilities' | 'catalog'
type PolicyDraft = {
  name: string
  description: string
  scene: string
  severity: SecurityPolicySeverity
  action: SecurityPolicyAction
  enabled: boolean
  detectionMethod: '' | 'capability' | 'matcher'
  matcherType: '' | SecurityPolicyMatcherType
  matcherText: string
  assistedEntries: string
  manualMatcherType: '' | SecurityPolicyMatcherType
  manualMatcherText: string
  generatedNumberRegex: string
  matcherMode: 'assisted' | 'manual'
  assistedKind: 'entries' | 'number'
  numberSamples: string
  numberSegments: DlpNumberSegment[]
  numberExplanation: string
  numberAuthoringProof: string
  capabilityCategories: string[]
  bindingMode: SecurityPolicyBindingMode
  subjectBinding: SecurityPolicySubjectBinding
  redaction: { replacement: string; restore_response: boolean }
  semanticAction: SecurityPolicySemanticAction
}
type PolicyPreviewDraft = SecurityPolicyPreviewInput
type ScopeProject = { id: string; name: string; status?: string }
type ScopeTeam = { id: string; name: string }
type ScopeKey = { id: string; project_id: string; name?: string; key_prefix?: string; status?: string }
type ScopeDirectory = {
  projects: ScopeProject[]
  teams: ScopeTeam[]
  keys: ScopeKey[]
}
type BatchEnabledDraft = '' | 'enabled' | 'disabled'
type BatchMutationRequest = {
  updates: Parameters<typeof securityPoliciesApi.batch>[0]
  skippedCount: number
  skippedSummary: string
}

const POLICY_QUERY_KEY = ['security', 'policies'] as const
const CAPABILITY_QUERY_KEY = ['security', 'policy-capabilities'] as const
const VALID_TABS = new Set<CenterTab>(['scenarios', 'runtime', 'detection'])
const PAGE_SIZE = 10
const MAX_CAPABILITIES_PER_POLICY = 32
const PROTOCOL_OPTIONS = [
  { value: 'chat', label: 'Chat Completions' },
  { value: 'messages', label: 'Anthropic Messages' },
  { value: 'responses', label: 'Responses' },
  { value: 'embeddings', label: 'Embeddings' },
  { value: 'images', label: 'Images' },
  { value: 'mcp', label: 'MCP' },
  { value: 'openai', label: '正/反向代理 OpenAI' },
  { value: 'anthropic', label: '正/反向代理 Anthropic' },
] as const
const ENTRY_POINT_OPTIONS = [
  { value: 'gateway_api', label: 'API 网关' },
  { value: 'mcp_gateway', label: 'MCP 网关' },
  { value: 'forward_proxy', label: '正向代理' },
  { value: 'reverse_proxy', label: '反向代理' },
] as const

function previewProtocolOptions(entryPoint?: string) {
  if (entryPoint === 'gateway_api') return PROTOCOL_OPTIONS.filter((item) => ['chat', 'messages', 'responses', 'embeddings', 'images'].includes(item.value))
  if (entryPoint === 'mcp_gateway') return PROTOCOL_OPTIONS.filter((item) => item.value === 'mcp')
  if (entryPoint === 'forward_proxy' || entryPoint === 'reverse_proxy') return PROTOCOL_OPTIONS.filter((item) => ['openai', 'anthropic'].includes(item.value))
  return [...PROTOCOL_OPTIONS]
}
const ACTION_OPTIONS: Array<{ value: SecurityPolicyAction; label: string }> = [
  { value: 'audit', label: '记录并告警' },
  { value: 'mask', label: '脱敏后发送' },
  { value: 'block', label: '阻断' },
]
const SCENE_BACKEND_VALUES: Record<Exclude<EnterpriseSceneKey, 'other'>, string> = {
  'sensitive-data': 'data_leak',
  'file-security': 'file_security',
  'content-safety': 'content_safety',
  'prompt-security': 'prompt_injection',
  'agent-tools': 'agent_detect',
  'model-access': 'model_access',
}

function normalizedMatcher(policy?: SecurityPolicy): { type: '' | SecurityPolicyMatcherType; config: SecurityPolicyMatcherConfig } {
  const raw = policy?.matcher
  if (!raw) return { type: '', config: {} }
  const config = raw.config ?? raw
  if (raw.type === 'regex' || config.regex !== undefined) return { type: 'regex', config }
  if (raw.type === 'keyword' || config.keywords !== undefined) return { type: 'keyword', config }
  if (raw.type === 'field_name' || config.field_names !== undefined) return { type: 'field_name', config }
  return { type: '', config: {} }
}

function matcherDraftText(type: '' | SecurityPolicyMatcherType, config: SecurityPolicyMatcherConfig): string {
  if (type === 'regex') return config.regex ?? ''
  if (type === 'keyword') return (config.keywords ?? []).join('\n')
  if (type === 'field_name') return (config.field_names ?? []).join('\n')
  return ''
}

function cloneSubjectBinding(binding?: SecurityPolicySubjectBinding): SecurityPolicySubjectBinding {
  return {
    tenant_ids: [...(binding?.tenant_ids ?? [])],
    actor_user_ids: [...(binding?.actor_user_ids ?? [])],
    key_owner_user_ids: [...(binding?.key_owner_user_ids ?? [])],
    personnel_department_ids: [...(binding?.personnel_department_ids ?? [])],
    personnel_department_include_children: binding?.personnel_department_include_children === true,
    project_ids: [...(binding?.project_ids ?? [])],
    application_department_ids: [...(binding?.application_department_ids ?? [])],
    key_ids: [...(binding?.key_ids ?? [])],
    protocols: [...(binding?.protocols ?? [])],
    entry_points: [...(binding?.entry_points ?? [])],
  }
}

function normalizedSubjectBinding(binding: SecurityPolicySubjectBinding): SecurityPolicySubjectBinding | undefined {
  const normalized = cloneSubjectBinding(binding)
  const hasValues = Object.entries(normalized).some(([key, value]) => (
    key === 'personnel_department_include_children' ? value === true : Array.isArray(value) && value.length > 0
  ))
  return hasValues ? normalized : undefined
}

function responseItems<T>(response: unknown): T[] {
  if (Array.isArray(response)) return response as T[]
  if (!response || typeof response !== 'object') return []
  const data = (response as { data?: unknown }).data
  return Array.isArray(data) ? data as T[] : []
}

function bindingScopeSummary(policy: SecurityPolicy, directory: ScopeDirectory): { title: string; detail: string } {
  const binding = policy.subject_binding
  if (!binding) return { title: '当前组织全部请求', detail: '无附加主体条件' }
  const projectNames = new Map(directory.projects.map((item) => [item.id, item.name]))
  const teamNames = new Map(directory.teams.map((item) => [item.id, item.name]))
  const keyNames = new Map(directory.keys.map((item) => [item.id, item.name || item.key_prefix || item.id]))
  const parts: string[] = []
  if (binding.project_ids?.length) parts.push('应用：' + binding.project_ids.map((id) => projectNames.get(id) || id).join('、'))
  if (binding.application_department_ids?.length) parts.push('应用部门：' + binding.application_department_ids.map((id) => teamNames.get(id) || id).join('、'))
  if (binding.key_ids?.length) parts.push('Key：' + binding.key_ids.map((id) => keyNames.get(id) || id).join('、'))
  if (binding.protocols?.length) parts.push('协议：' + binding.protocols.join('、'))
  if (binding.entry_points?.length) parts.push('入口：' + binding.entry_points.join('、'))
  const hiddenCount = (binding.actor_user_ids?.length ?? 0)
    + (binding.key_owner_user_ids?.length ?? 0)
    + (binding.personnel_department_ids?.length ?? 0)
  if (hiddenCount > 0) parts.push('含只读人员条件')
  return {
    title: parts[0] || '当前组织',
    detail: parts.slice(1).join('；') || '显式组织范围',
  }
}

function hasUnavailableActorBinding(binding?: SecurityPolicySubjectBinding): boolean {
  return Boolean(
    binding?.actor_user_ids?.length
    || binding?.personnel_department_ids?.length,
  )
}

const PREVIEW_DIMENSION_LABELS: Record<string, string> = {
  tenant_ids: '组织',
  actor_user_ids: '实际人员',
  key_owner_user_ids: 'Key 所有人',
  personnel_department_ids: '人员部门',
  project_ids: '应用',
  application_department_ids: '应用所属部门',
  key_ids: '稳定 Key',
  protocols: '协议',
  entry_points: '入口',
}

const PREVIEW_REASON_LABELS: Record<string, string> = {
  matched: '匹配',
  principal_missing: '缺少运行身份',
  actor_not_authenticated: '实际人员身份未知',
  principal_value_missing: '当前预览未选择该维度',
  no_configured_value_matched: '所选对象不在策略范围内',
}

function nonEmptyLines(text: string) {
  return text.split(/\r?\n/).map((value) => value.trim()).filter(Boolean)
}

function buildMatcher(type: '' | SecurityPolicyMatcherType, text: string) {
  const normalized = text.trim()
  if (!type || !normalized) return undefined
  if (type === 'regex') return { type, config: { regex: normalized } }
  const values = nonEmptyLines(text)
  return type === 'keyword'
    ? { type, config: { keywords: [...new Map(values.map((value) => [value.toLocaleLowerCase(), value])).values()] } }
    : { type, config: { field_names: values } }
}

function draftForPolicy(policy?: SecurityPolicy, sceneKey: EnterpriseSceneKey = 'sensitive-data', presetCapability?: string): PolicyDraft {
  const matcher = normalizedMatcher(policy)
  const matcherText = matcherDraftText(matcher.type, matcher.config)
  const numberSegments = matcher.type === 'regex' && policy?.authoring?.version === 1
    && policy.authoring.kind === 'number' && policy.authoring.matcher_pattern === matcherText
    ? policy.authoring.segments : null
  return {
    name: policy?.name ?? '',
    description: policy?.description ?? '',
    scene: policy?.scene ?? (sceneKey === 'other' ? 'custom_rules' : SCENE_BACKEND_VALUES[sceneKey]),
    severity: policy?.severity ?? 'high',
    action: policy?.action === 'allow' ? 'audit' : policy?.action ?? 'audit',
    enabled: policy?.enabled ?? false,
    detectionMethod: matcher.type ? 'matcher' : policy?.capabilities.length || presetCapability ? 'capability' : '',
    matcherType: matcher.type,
    matcherText,
    assistedEntries: matcher.type === 'keyword' ? matcherText : '',
    manualMatcherType: numberSegments || matcher.type === 'keyword' ? '' : matcher.type,
    manualMatcherText: numberSegments || matcher.type === 'keyword' ? '' : matcherText,
    generatedNumberRegex: numberSegments ? matcherText : '',
    matcherMode: numberSegments || matcher.type === 'keyword' || !matcher.type ? 'assisted' : 'manual',
    assistedKind: numberSegments ? 'number' : 'entries',
    numberSamples: '',
    numberSegments: numberSegments ?? [],
    numberExplanation: numberSegments ? '已从保存的编号规则恢复结构；调整分段后请重新生成规则。' : '',
    numberAuthoringProof: '',
    capabilityCategories: policy?.capabilities.map((capability) => capability.category) ?? (presetCapability ? [presetCapability] : []),
    bindingMode: policy?.capabilities[0]?.binding_mode ?? 'any',
    subjectBinding: cloneSubjectBinding(policy?.subject_binding),
    redaction: policy?.redaction ?? { replacement: '<MASKED>', restore_response: false },
    semanticAction: policy?.semantic_action ?? 'audit',
  }
}

function policyWriteFromDraft(draft: PolicyDraft, previous?: SecurityPolicy): SecurityPolicyWrite | SecurityPolicyPatch {
  const matcher = draft.detectionMethod === 'matcher' ? buildMatcher(draft.matcherType, draft.matcherText) : undefined
  const payload: SecurityPolicyWrite = {
    name: draft.name.trim(),
    description: draft.description.trim(),
    scene: draft.scene,
    severity: draft.severity,
    action: draft.action,
    enabled: draft.enabled,
    capability_categories: draft.detectionMethod === 'capability' ? draft.capabilityCategories : [],
    binding_mode: draft.bindingMode,
    redaction: draft.redaction,
  }
  // 「智能分析命中时」只对能力策略有意义；未绑定智能分析能力时编辑器会把它复位为 audit。
  if (draft.detectionMethod === 'capability') payload.semantic_action = draft.semanticAction
  if (matcher) {
    payload.matcher = matcher
    if (draft.matcherMode === 'assisted' && draft.assistedKind === 'number' && draft.numberExplanation
      && matcher.type === 'regex' && matcher.config.regex === draft.generatedNumberRegex && draft.numberSegments.length
      && draft.numberAuthoringProof) {
      payload.authoring = { version: 1, kind: 'number', matcher_pattern: matcher.config.regex, segments: draft.numberSegments }
      payload.authoring_proof = draft.numberAuthoringProof
    }
  }
  if (previous?.authoring && !draft.numberAuthoringProof && matcher?.type === 'regex'
    && matcher.config.regex === previous.authoring.matcher_pattern
    && draft.matcherMode === 'assisted' && draft.assistedKind === 'number'
    && JSON.stringify(draft.numberSegments) === JSON.stringify(previous.authoring.segments)) {
    delete payload.matcher
  }
  if (draft.detectionMethod !== 'matcher' && normalizedMatcher(previous).type) payload.clear_matcher = true
  const subjectBinding = normalizedSubjectBinding(draft.subjectBinding)
  if (subjectBinding) payload.subject_binding = subjectBinding
  else if (previous?.subject_binding) payload.clear_subject_binding = true
  return payload
}

function policyWritesForCreation(draft: PolicyDraft): SecurityPolicyWrite[] {
  const payload = policyWriteFromDraft(draft) as SecurityPolicyWrite
  if (draft.detectionMethod !== 'capability' || payload.capability_categories.length <= MAX_CAPABILITIES_PER_POLICY) return [payload]
  const chunks: string[][] = []
  for (let offset = 0; offset < payload.capability_categories.length; offset += MAX_CAPABILITIES_PER_POLICY) {
    chunks.push(payload.capability_categories.slice(offset, offset + MAX_CAPABILITIES_PER_POLICY))
  }
  const suffixLength = Array.from(`（${chunks.length}/${chunks.length}）`).length
  const nameBase = Array.from(payload.name).slice(0, 255 - suffixLength).join('')
  return chunks.map((capabilityCategories, index) => ({
    ...payload,
    name: `${nameBase}（${index + 1}/${chunks.length}）`,
    capability_categories: capabilityCategories,
  }))
}

function policyStatus(policy: SecurityPolicy, runtimeVerified: boolean, runtimeStatus?: string) {
  if (!policy.enabled) return { label: '已停用', tone: 'gray' as const }
  if (!policy.detection_configured) return { label: '识别条件未配置', tone: 'orange' as const }
  if (!policy.detection_ready) return { label: '识别配置待确认', tone: 'orange' as const }
  if (isRuntimeSyncPending(runtimeVerified, runtimeStatus)) return { label: '新配置同步中', tone: 'orange' as const }
  if (!runtimeVerified || !policy.runtime_active) return { label: '运行异常', tone: 'red' as const }
  return { label: '已启用', tone: 'green' as const }
}

function stageValues(policy: SecurityPolicy): string[] {
  return [...new Set(policy.capabilities.flatMap((capability) => capability.supported_stages))]
}

function previewDraftForPolicy(policy: SecurityPolicy, keys: ScopeKey[]): PolicyPreviewDraft {
  const keyID = policy.subject_binding?.key_ids?.[0]
  const keyProjectID = keys.find((item) => item.id === keyID)?.project_id
  return {
    stage: (stageValues(policy)[0] as PolicyPreviewDraft['stage']) || 'input',
    application_id: keyProjectID || policy.subject_binding?.project_ids?.[0],
    key_id: keyID,
    protocol: policy.subject_binding?.protocols?.[0],
    entry_point: policy.subject_binding?.entry_points?.[0],
  }
}

function matchesPolicyFilters(policy: SecurityPolicy, params: URLSearchParams, mode?: string): boolean {
  const query = (params.get('q') ?? '').trim().toLocaleLowerCase('zh-CN')
  if (query && !`${policy.name} ${policy.description} ${policy.scene} ${policy.capabilities.map((item) => item.category).join(' ')}`.toLocaleLowerCase('zh-CN').includes(query)) return false
  const state = params.get('state') ?? 'all'
  if (state === 'enabled' && !policy.enabled) return false
  if (state === 'disabled' && policy.enabled) return false
  if (state === 'clamped' && !describeEffectiveAction({ configuredAction: policy.action, globalMode: mode, enabled: policy.enabled }).clamped) return false
  const action = params.get('action') ?? 'all'
  if (action !== 'all' && policy.action !== action) return false
  const severity = params.get('severity') ?? 'all'
  if (severity !== 'all' && policy.severity !== severity) return false
  const effective = params.get('effective') ?? 'all'
  const display = describeEffectiveAction({ configuredAction: policy.action, globalMode: mode, enabled: policy.enabled })
  if (effective !== 'all' && display.effectiveAction !== effective) return false
  const stage = params.get('stage') ?? 'all'
  if (stage !== 'all' && !stageValues(policy).includes(stage)) return false
  return true
}

function PolicyFilters({ params, setParam, stages }: {
  params: URLSearchParams
  setParam: (key: string, value?: string) => void
  stages: string[]
}) {
  return (
    <div className="enterprise-policy-filters" role="search" aria-label="策略筛选">
      <Input
        allowClear
        prefix={<SearchOutlined />}
        aria-label="搜索策略"
        placeholder="搜索名称、场景或识别能力"
        value={params.get('q') ?? ''}
        onChange={(event) => setParam('q', event.target.value || undefined)}
      />
      <Select aria-label="启用状态筛选" value={params.get('state') ?? 'all'} onChange={(value) => setParam('state', value === 'all' ? undefined : value)} options={[
        { value: 'all', label: '全部状态' },
        { value: 'enabled', label: '已启用' },
        { value: 'disabled', label: '已停用' },
        { value: 'clamped', label: '受全局模式钳制' },
      ]} />
      <Select aria-label="级别筛选" value={params.get('severity') ?? 'all'} onChange={(value) => setParam('severity', value === 'all' ? undefined : value)} options={[
        { value: 'all', label: '全部级别' },
        ...severityOptions(['low', 'medium', 'high', 'critical']),
      ]} />
      <Select aria-label="配置动作筛选" value={params.get('action') ?? 'all'} onChange={(value) => setParam('action', value === 'all' ? undefined : value)} options={[
        { value: 'all', label: '全部配置动作' },
        ...ACTION_OPTIONS,
      ]} />
      <Select aria-label="当前有效动作筛选" value={params.get('effective') ?? 'all'} onChange={(value) => setParam('effective', value === 'all' ? undefined : value)} options={[
        { value: 'all', label: '全部有效动作' },
        { value: 'audit', label: '记录并告警' },
        { value: 'mask', label: '脱敏后发送' },
        { value: 'block', label: '阻断' },
      ]} />
      <Select aria-label="检测阶段筛选" value={params.get('stage') ?? 'all'} onChange={(value) => setParam('stage', value === 'all' ? undefined : value)} options={[
        { value: 'all', label: '全部检测阶段' },
        ...stages.map((stage) => ({ value: stage, label: detectionStageLabel(stage) })),
      ]} />
    </div>
  )
}

function PolicyTable({ policies, mode, auditOnly, runtimeVerified, runtimeStatus, directory, onOpen, onDelete, deletingID, selectedIDs, onSelect, onSelectPage }: {
  policies: SecurityPolicy[]
  mode?: string
  auditOnly: boolean
  runtimeVerified: boolean
  runtimeStatus?: string
  directory: ScopeDirectory
  onOpen: (policy: SecurityPolicy) => void
  /** Only passed to users who may change policies; the row still shows it for organization-created policies only. */
  onDelete?: (policy: SecurityPolicy) => void
  deletingID?: string
  selectedIDs?: Set<string>
  onSelect?: (policy: SecurityPolicy, selected: boolean) => void
  onSelectPage?: (policies: SecurityPolicy[], selected: boolean) => void
}) {
  if (policies.length === 0) return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="没有符合当前条件的策略" />
  const selectable = Boolean(selectedIDs && onSelect && onSelectPage)
  const selected = selectedIDs ?? new Set<string>()
  const selectedOnPage = selectable ? policies.filter((policy) => selected.has(policy.id)).length : 0
  return (
    <div className="enterprise-policy-table-wrap">
      <table className={`enterprise-policy-table${selectable ? ' is-selectable' : ''}`}>
        <thead><tr>
          {selectable ? <th className="enterprise-policy-selection-cell"><Checkbox aria-label="选择当前页策略" checked={selectedOnPage === policies.length} indeterminate={selectedOnPage > 0 && selectedOnPage < policies.length} onChange={(event) => onSelectPage?.(policies, event.target.checked)} /></th> : null}
          <th>策略名称</th><th>级别</th><th>所属场景</th><th>适用范围</th><th>检测条件</th><th>配置动作</th><th>当前有效动作</th><th>状态</th><th className="enterprise-policy-actions-head">操作</th>
        </tr></thead>
        <tbody>{policies.map((policy) => {
          const effective = describeEffectiveAction({ configuredAction: policy.action, globalMode: mode, auditOnly, enabled: policy.enabled })
          const semantic = policyHasSemanticJudge(policy)
            ? describeSemanticEffectiveAction({ semanticAction: policy.semantic_action, globalMode: mode, auditOnly, enabled: policy.enabled })
            : undefined
          const status = policyStatus(policy, runtimeVerified, runtimeStatus)
          const scope = bindingScopeSummary(policy, directory)
          return <tr key={policy.id}>
            {selectable ? <td className="enterprise-policy-selection-cell"><Checkbox aria-label={`选择策略 ${policy.name}`} checked={selected.has(policy.id)} onChange={(event) => onSelect?.(policy, event.target.checked)} /></td> : null}
            <td><strong>{policy.name}</strong><small>{policy.description || '未填写策略说明'}</small></td>
            <td className="enterprise-policy-severity-cell">
              {SEVERITY_LABELS[policy.severity] ?? '未分级'}
              {severityActionMismatch(policy) ? (
                <Tooltip title={severityActionMismatch(policy)}>
                  <ExclamationCircleOutlined aria-label="级别与动作不配套" style={{ color: 'var(--brand-orange)', marginLeft: 6 }} />
                </Tooltip>
              ) : null}
            </td>
            <td>{getEnterpriseScene(classifyPolicyScene(policy)).label}</td>
            <td><strong>{scope.title}</strong><small>{scope.detail}</small></td>
            <td>{policyDetectionSummary(policy)}</td>
            <td>{policyActionLabel(policy.action)}</td>
            <td>
              <Tooltip title={effective.explanation}>
                <span className={effective.clamped ? 'is-clamped' : ''}>{effective.effectiveLabel}</span>
              </Tooltip>
              {semantic ? <Tooltip title={semantic.explanation}><small className="policy-semantic-effective">{semantic.label}</small></Tooltip> : null}
            </td>
            <td><StatusPill tone={status.tone}>{status.label}</StatusPill></td>
            <td className="enterprise-policy-actions-cell">
              <Button type="link" size="small" onClick={() => onOpen(policy)}>查看</Button>
              {onDelete && policy.origin === 'organization_created' ? (
                <Popconfirm title="删除这条策略？" okText="删除" cancelText="取消" okButtonProps={{ danger: true }} onConfirm={() => onDelete(policy)}>
                  <Button type="link" size="small" danger aria-label={`删除策略 ${policy.name}`} loading={deletingID === policy.id}>删除</Button>
                </Popconfirm>
              ) : null}
            </td>
          </tr>
        })}</tbody>
      </table>
    </div>
  )
}

function PolicyBatchToolbar({ selectedCount, filteredCount, totalCount, canManage, pending, batchAction, batchEnabled, availability, onSelectFiltered, onSelectAll, onActionChange, onEnabledChange, onApply, onClear }: {
  selectedCount: number
  filteredCount: number
  totalCount: number
  canManage: boolean
  pending: boolean
  batchAction: '' | BatchPolicyAction
  batchEnabled: BatchEnabledDraft
  availability: ReturnType<typeof batchActionAvailability>
  onSelectFiltered: () => void
  onSelectAll: () => void
  onActionChange: (action: '' | BatchPolicyAction) => void
  onEnabledChange: (enabled: BatchEnabledDraft) => void
  onApply: () => void
  onClear: () => void
}) {
  const changed = Boolean(batchAction || batchEnabled)
  return (
    <div className={`enterprise-policy-batch-toolbar${selectedCount > 0 ? ' is-active' : ''}`} aria-label="批量配置策略">
      <div className="enterprise-policy-batch-scope">
        <span>{selectedCount > 0 ? `已选 ${selectedCount} 条` : '先选择配置范围'}</span>
        <Button size="small" disabled={!canManage || filteredCount === 0 || pending} onClick={onSelectFiltered}>选择筛选结果（{filteredCount}）</Button>
        <Button size="small" disabled={!canManage || totalCount === 0 || pending} onClick={onSelectAll}>选择全部策略（{totalCount}）</Button>
      </div>
      {selectedCount > 0 ? <div className="enterprise-policy-batch-fields">
        <label>配置动作<Select aria-label="批量配置动作" value={batchAction || undefined} placeholder="保持原状" allowClear disabled={pending} onChange={(value) => onActionChange((value ?? '') as '' | BatchPolicyAction)} options={(['audit', 'mask', 'block'] as BatchPolicyAction[]).map((action) => ({ value: action, label: `${policyActionLabel(action)}${availability[action].unsupportedCount > 0 ? `（跳过 ${availability[action].unsupportedCount} 条）` : ''}`, disabled: !availability[action].available }))} /></label>
        <label>启用状态<Select aria-label="批量启用状态" value={batchEnabled || undefined} placeholder="保持原状" allowClear disabled={pending} onChange={(value) => onEnabledChange((value ?? '') as BatchEnabledDraft)} options={[{ value: 'enabled', label: '统一启用' }, { value: 'disabled', label: '统一停用' }]} /></label>
        <Button type="primary" disabled={!changed || pending} loading={pending} onClick={onApply}>应用设置</Button>
        <Button disabled={pending} onClick={onClear}>取消选择</Button>
      </div> : null}
    </div>
  )
}

function SecurityPolicyCenterContent({ auditIdentity }: { auditIdentity: string }) {
  const queryClient = useQueryClient()
  const currentUser = useAuthStore((state) => state.user)
  const canManage = canManageSecurityPolicy(currentUser?.role)
  // 全局执行模式写在系统设置里（后端仅系统管理员可写），保持只有平台管理员能改。
  const canManageMode = currentUser?.role === 'platform_admin'
  const [params, setParams] = useSearchParams()
  const { mode } = useSecurityExecutionMode()
  const [editorPolicy, setEditorPolicy] = useState<SecurityPolicy | null>(null)
  const [editorOpen, setEditorOpen] = useState(false)
  const [creating, setCreating] = useState(false)
  const [createSceneOpen, setCreateSceneOpen] = useState(false)
  const [draft, setDraft] = useState<PolicyDraft>(() => draftForPolicy())
  const [confirmSaveOpen, setConfirmSaveOpen] = useState(false)
  const [dlpPreviewText, setDlpPreviewText] = useState('')
  const [dlpPreviewResult, setDlpPreviewResult] = useState<DlpPreviewResponse | null>(null)
  const [dlpError, setDlpError] = useState('')
  const [dlpGenerating, setDlpGenerating] = useState(false)
  const [dlpPreviewing, setDlpPreviewing] = useState(false)
  const dlpRequestVersion = useRef(0)
  const [capabilityDrawer, setCapabilityDrawer] = useState<SecurityPolicyCapability | null>(null)
  const [resolvedPolicyParam, setResolvedPolicyParam] = useState<string | null>(null)
  const [restoreSeverity, setRestoreSeverity] = useState(false)
  const [capabilityPage, setCapabilityPage] = useState(1)
  const [catalogPage, setCatalogPage] = useState(1)
  const [selectedPolicyIDs, setSelectedPolicyIDs] = useState<Set<string>>(new Set())
  const [batchAction, setBatchAction] = useState<'' | BatchPolicyAction>('')
  const [batchEnabled, setBatchEnabled] = useState<BatchEnabledDraft>('')
  const [confirmBatchOpen, setConfirmBatchOpen] = useState(false)
  const [selectedCapabilityIDs, setSelectedCapabilityIDs] = useState<Set<string>>(new Set())
  const [previewDraft, setPreviewDraft] = useState<PolicyPreviewDraft>({ stage: 'input' })

  const policiesQuery = useQuery({
    queryKey: [...POLICY_QUERY_KEY, auditIdentity],
    queryFn: () => securityPoliciesApi.list(),
    refetchInterval: (query) => policyRuntimeRefetchInterval(query.state.data?.data),
  })
  const capabilitiesQuery = useQuery({ queryKey: [...CAPABILITY_QUERY_KEY, auditIdentity], queryFn: () => securityPoliciesApi.capabilities() })
  const projectsQuery = useQuery({ queryKey: ['security', 'policy-scope-projects', auditIdentity], queryFn: () => projectApi.list() })
  const teamsQuery = useQuery({ queryKey: ['security', 'policy-scope-teams', auditIdentity], queryFn: () => orgApi.listTeams() })
  const keysQuery = useQuery({ queryKey: ['security', 'policy-scope-keys', auditIdentity], queryFn: () => keyApi.list() })
  const response = policiesQuery.data?.data
  const policies = useMemo(() => response?.data ?? [], [response?.data])
  const capabilities = useMemo(() => capabilitiesQuery.data?.data?.data ?? [], [capabilitiesQuery.data?.data?.data])
  // 说明只在能力列表里有；列表没到时为空，“匹配什么”不显示。
  const matchDocCapabilities = useMemo(() => {
    if (!editorPolicy) return []
    const byCategory = new Map(capabilities.map((item) => [item.category, item]))
    return editorPolicy.capabilities.map((item) => byCategory.get(item.category) ?? item)
  }, [capabilities, editorPolicy])
  // 从告警或阻断记录跳来时的本次命中：命中内容只留在页面里；无权限或请求失败都静默。
  const hitEventId = params.get('event') ?? ''
  // 切换策略时网址参数晚于抽屉更新：policy 参数和抽屉里的策略对不上的那几帧，不发请求也不显示。
  const hitOpen = Boolean(hitEventId) && Boolean(editorPolicy) && params.get('policy') === editorPolicy?.id
  const canReadHit = canAccessPath(currentUser?.role, '/security/alerts')
  const hitQuery = useQuery({
    queryKey: ['policy-current-hit', auditIdentity, hitEventId],
    queryFn: ({ signal }) => alertOccurrencesApi.list({ event_id: hitEventId, grouping: 'hits', limit: 20, include_suppressed: true, signal }),
    enabled: hitOpen && canReadHit && editorOpen && !creating,
    retry: false,
  })
  const currentHitText = useMemo(() => {
    if (!hitOpen || !editorPolicy || creating) return ''
    const rows = hitQuery.data?.data?.items ?? []
    const row = rows.find((item) => item.rule_id === editorPolicy.id)
    return row ? alertHitText(row, 120) : ''
  }, [creating, editorPolicy, hitOpen, hitQuery.data])
  const projects = useMemo(() => responseItems<ScopeProject>(projectsQuery.data?.data), [projectsQuery.data?.data])
  const teams = useMemo(() => responseItems<ScopeTeam>(teamsQuery.data?.data), [teamsQuery.data?.data])
  const keys = useMemo(() => responseItems<ScopeKey>(keysQuery.data?.data).filter((item) => item.status === 'active'), [keysQuery.data?.data])
  const scopeDirectory = useMemo(() => ({ projects, teams, keys }), [keys, projects, teams])
  const runtimeVerified = response?.runtime_verified === true
  const runtimeStatus = response?.runtime_status
  const auditOnly = mode?.effective_mode === 'record'
  const requestedTab = params.get('tab')
  const activeTab = requestedTab === 'policies'
    ? 'runtime'
    : VALID_TABS.has(requestedTab as CenterTab) ? requestedTab as CenterTab : 'scenarios'
  const selectedScene = params.get('scene') as EnterpriseSceneKey | null
  const advancedTab: AdvancedTab | null = params.get('advanced') === 'catalog'
    ? 'catalog'
    : params.get('advanced') === 'capabilities' ? 'capabilities' : null

  useEffect(() => {
    const legacySection = params.get('section')
    if (!legacySection && requestedTab !== 'capabilities' && requestedTab !== 'policies') return
    const next = new URLSearchParams(params)
    next.delete('section')
    if (legacySection === 'sensitive') {
      next.set('tab', 'scenarios')
      next.set('scene', 'sensitive-data')
    } else if (legacySection === 'files') {
      next.set('tab', 'scenarios')
      next.set('scene', 'file-security')
    } else if (legacySection === 'all') {
      next.set('tab', 'runtime')
      next.set('advanced', 'catalog')
    } else if (legacySection === 'custom') {
      next.set('tab', 'runtime')
    } else if (requestedTab === 'capabilities') {
      next.delete('tab')
      next.set('advanced', 'capabilities')
    } else if (requestedTab === 'policies') {
      next.set('tab', 'runtime')
    } else {
      next.set('tab', 'scenarios')
    }
    setParams(next, { replace: true })
  }, [params, requestedTab, setParams])

  const setParam = (key: string, value?: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
  }
  const clearEventParam = () => setParams((current) => {
    if (!current.has('event')) return current
    const next = new URLSearchParams(current)
    next.delete('event')
    return next
  }, { replace: true })
  const changeTab = (tab: string) => {
    const next = new URLSearchParams()
    if (tab !== 'scenarios') next.set('tab', tab)
    setParams(next, { replace: true })
  }

  const stages = useMemo(() => [...new Set(capabilities.flatMap((capability) => capability.supported_stages))].sort(), [capabilities])
  const activeRuntimePolicies = useMemo(() => policies.filter((policy) => policy.runtime_active), [policies])
  const runtimePolicies = useMemo(() => policies.filter((policy) => (
    policy.runtime_active
    || policy.origin === 'organization_created'
    || (!runtimeVerified && policy.enabled && policy.detection_configured && policy.detection_ready)
  )), [policies, runtimeVerified])
  const filteredPolicies = useMemo(() => runtimePolicies.filter((policy) => matchesPolicyFilters(policy, params, mode?.effective_mode)), [mode?.effective_mode, params, runtimePolicies])
  const scenePolicies = useMemo(() => selectedScene
    ? filteredPolicies.filter((policy) => classifyPolicyScene(policy) === selectedScene)
    : [], [filteredPolicies, selectedScene])
  const blockingPolicyCount = activeRuntimePolicies.filter((policy) => ['mask', 'block'].includes(policy.action)).length
  const protectedSceneCount = CUSTOMER_SECURITY_SCENES.filter((scene) => activeRuntimePolicies.some((policy) => classifyPolicyScene(policy) === scene.key)).length
  const customerRuntimePolicyCount = activeRuntimePolicies.filter((policy) => (
    CUSTOMER_SECURITY_SCENES.some((scene) => classifyPolicyScene(policy) === scene.key)
  )).length
  const tenantPolicyCount = policies.filter((policy) => policy.origin === 'organization_created').length

  const invalidatePolicies = async () => queryClient.invalidateQueries({ queryKey: POLICY_QUERY_KEY })
  const saveMutation = useMutation({
    mutationFn: async () => {
      if (creating) {
        return Promise.all(policyWritesForCreation(draft).map((payload) => securityPoliciesApi.create(payload)))
      }
      if (!editorPolicy) throw new Error('policy is required')
      if (editorPolicy.origin === 'preloaded') {
        // 只提交真正改了的字段：只改级别时只带 severity，落到控制面“只改级别 / 仅记录+改级别”两条路径。
        const saved = draftForPolicy(editorPolicy)
        const payload: SecurityPolicyPatch = {}
        if (draft.action !== saved.action) payload.action = draft.action
        if (draft.enabled !== saved.enabled) payload.enabled = draft.enabled
        if (JSON.stringify(draft.redaction) !== JSON.stringify(saved.redaction)) payload.redaction = draft.redaction
        if (policyHasSemanticJudge(editorPolicy) && draft.semanticAction !== saved.semanticAction) payload.semantic_action = draft.semanticAction
        if (draft.severity !== editorPolicy.severity || (restoreSeverity && editorPolicy.default_severity)) payload.severity = draft.severity
        if (Object.keys(payload).length === 0) return null
        return securityPoliciesApi.update(editorPolicy.id, payload)
      }
      return securityPoliciesApi.update(editorPolicy.id, policyWriteFromDraft(draft, editorPolicy))
    },
    onSuccess: async (result) => {
      if (result === null) {
        message.info('没有改动')
        setConfirmSaveOpen(false)
        setEditorOpen(false)
        clearEventParam()
        return
      }
      const createdCount = creating ? policyWritesForCreation(draft).length : 1
      message.success(createdCount > 1 ? `${createdCount} 条策略已保存，正在回读服务端状态` : '策略配置已保存，正在回读服务端状态')
      await invalidatePolicies()
      if (creating) setSelectedCapabilityIDs(new Set())
      setConfirmSaveOpen(false)
      setEditorOpen(false)
      clearEventParam()
    },
    onError: async (error: unknown) => {
      await invalidatePolicies()
      if (axios.isAxiosError(error) && error.response?.status === 422 && error.response.data?.error?.code === 'invalid_authoring_proof') {
        message.error('编号规则生成凭证已过期或失效，请重新应用分段修改后保存')
        return
      }
      const createPolicyCount = creating ? policyWritesForCreation(draft).length : 1
      message.error(createPolicyCount > 1 ? '批量策略未全部创建成功，已回读服务端状态，请检查是否存在部分结果' : '策略保存失败，服务端原配置未改变')
    },
  })
  // Both the drawer and the table rows delete through here. Whatever the outcome, the list is read
  // back from the server; a policy that is already gone (404) is treated as deleted.
  const dropDeletedPolicy = (policy: SecurityPolicy) => {
    setSelectedPolicyIDs((current) => {
      if (!current.has(policy.id)) return current
      const next = new Set(current)
      next.delete(policy.id)
      return next
    })
    if (editorPolicy?.id !== policy.id) return
    setEditorOpen(false)
    setConfirmSaveOpen(false)
    const next = new URLSearchParams(params)
    next.delete('policy')
    next.delete('event')
    setParams(next, { replace: true })
  }
  const deleteMutation = useMutation({
    mutationFn: (policy: SecurityPolicy) => securityPoliciesApi.remove(policy.id),
    onSuccess: async (_, policy) => {
      message.success('策略已删除')
      await invalidatePolicies()
      dropDeletedPolicy(policy)
    },
    onError: async (error: unknown, policy) => {
      await invalidatePolicies()
      const status = axios.isAxiosError(error) ? error.response?.status : undefined
      if (status === 404) {
        message.info('策略已不存在')
        dropDeletedPolicy(policy)
        return
      }
      message.error(status === 409 ? '内置策略不能删除，可以改为停用' : '策略删除失败，服务端原配置未改变')
    },
  })
  const deletingPolicyID = deleteMutation.isPending ? deleteMutation.variables?.id : undefined
  const canDeletePolicy = canManage && !creating && editorPolicy?.origin === 'organization_created'
  const previewMutation = useMutation({
    mutationFn: (input: PolicyPreviewDraft) => securityPoliciesApi.preview(input),
    onError: () => message.error('生效预览暂时不可用'),
  })
  const resetPreview = previewMutation.reset
  const resetDlpPreview = () => {
    dlpRequestVersion.current++
    setDlpPreviewResult(null)
    setDlpError('')
    setDlpGenerating(false)
    setDlpPreviewing(false)
  }
  const resetDlpEditor = () => {
    resetDlpPreview()
    setDlpPreviewText('')
  }
  const changeDlpDraft = (change: (current: PolicyDraft) => PolicyDraft) => {
    resetDlpPreview()
    setDraft(change)
  }

  const openAdvanced = (tab: AdvancedTab) => {
    const next = new URLSearchParams(params)
    next.set('advanced', tab)
    next.delete('policy')
    next.delete('event')
    setParams(next, { replace: true })
  }
  const closeAdvanced = () => {
    const next = new URLSearchParams(params)
    next.delete('advanced')
    setParams(next, { replace: true })
  }

  const openPolicy = (policy: SecurityPolicy) => {
    setCreating(false)
    setEditorPolicy(policy)
    setDraft(draftForPolicy(policy))
    resetDlpEditor()
    setPreviewDraft(previewDraftForPolicy(policy, keys))
    resetPreview()
    setEditorOpen(true)
    setResolvedPolicyParam(policy.id)
    setCapabilityDrawer(null)
    const next = new URLSearchParams(params)
    next.delete('advanced')
    next.delete('event')
    next.set('policy', policy.id)
    setParams(next, { replace: true })
  }
  useEffect(() => { setRestoreSeverity(false) }, [editorOpen, editorPolicy?.id])
  useEffect(() => {
    const policyID = params.get('policy')
    if (!policyID) {
      if (resolvedPolicyParam !== null) setResolvedPolicyParam(null)
      return
    }
    if (policyID === resolvedPolicyParam || editorOpen || !policiesQuery.isSuccess) return
    const policy = policies.find((item) => item.id === policyID)
    if (!policy) {
      message.warning('该策略已删除')
      setResolvedPolicyParam(policyID)
      const next = new URLSearchParams(params)
      next.delete('policy')
      next.delete('event')
      setParams(next, { replace: true })
      return
    }
    setCreating(false)
    setEditorPolicy(policy)
    setDraft(draftForPolicy(policy))
    dlpRequestVersion.current++
    setDlpPreviewResult(null)
    setDlpError('')
    setDlpGenerating(false)
    setDlpPreviewing(false)
    setDlpPreviewText('')
    setPreviewDraft(previewDraftForPolicy(policy, keys))
    resetPreview()
    setEditorOpen(true)
    setResolvedPolicyParam(policyID)
  }, [editorOpen, keys, params, policies, resetPreview, resolvedPolicyParam, setParams, policiesQuery.isSuccess])
  useEffect(() => {
    if (!previewDraft.key_id) return
    const keyProjectID = keys.find((item) => item.id === previewDraft.key_id)?.project_id
    if (!keyProjectID || keyProjectID === previewDraft.application_id) return
    setPreviewDraft((current) => ({ ...current, application_id: keyProjectID }))
  }, [keys, previewDraft.application_id, previewDraft.key_id])
  const openCreator = (sceneKey: EnterpriseSceneKey, presetCapability?: string) => {
    setCreating(true)
    setEditorPolicy(null)
    setDraft(draftForPolicy(undefined, sceneKey, presetCapability))
    resetDlpEditor()
    setPreviewDraft({ stage: 'input' })
    resetPreview()
    setCreateSceneOpen(false)
    setCapabilityDrawer(null)
    setEditorOpen(true)
    const next = new URLSearchParams(params)
    next.delete('advanced')
    setParams(next, { replace: true })
  }
  const openAdvancedSensitiveCreator = () => {
    setCreating(true)
    setEditorPolicy(null)
    setDraft({
      ...draftForPolicy(undefined, 'sensitive-data'),
      name: '',
      description: '',
      scene: 'data_leak',
      severity: 'medium',
      action: 'audit',
      enabled: true,
      detectionMethod: 'matcher',
      matcherType: 'keyword',
      matcherText: '',
      matcherMode: 'assisted',
      assistedKind: 'entries',
    })
    resetDlpEditor()
    setPreviewDraft({ stage: 'input' })
    resetPreview()
    setEditorOpen(true)
    const next = new URLSearchParams(params)
    next.delete('advanced')
    setParams(next, { replace: true })
  }
  const openCapabilityBatchCreator = () => {
    const categories = capabilities
      .filter((capability) => capability.enabled && selectedCapabilityIDs.has(capability.category))
      .map((capability) => capability.category)
    if (categories.length === 0) return
    setCreating(true)
    setEditorPolicy(null)
    setDraft({
      ...draftForPolicy(undefined, 'other'),
      name: `检测组件统一告警（${categories.length}项）`,
      description: '批量关联检测组件；任一组件命中时记录证据并生成告警，不直接阻断业务请求。',
      action: 'audit',
      enabled: true,
      detectionMethod: 'capability',
      capabilityCategories: categories,
      bindingMode: 'any',
    })
    setPreviewDraft({ stage: 'input' })
    resetPreview()
    setCapabilityDrawer(null)
    setEditorOpen(true)
    const next = new URLSearchParams(params)
    next.delete('advanced')
    setParams(next, { replace: true })
  }
  const closeEditor = () => {
    if (saveMutation.isPending) return
    setResolvedPolicyParam(params.get('policy'))
    setEditorOpen(false)
    resetDlpPreview()
    setConfirmSaveOpen(false)
    const next = new URLSearchParams(params)
    next.delete('policy')
    next.delete('event')
    setParams(next, { replace: true })
  }
  const selectedCapabilities = capabilities.filter((capability) => draft.capabilityCategories.includes(capability.category))
  const capabilityActionAllowed = selectedCapabilities.length === 0 || selectedCapabilities.every((capability) => capability.allowed_actions.includes(draft.action) && (draft.action !== 'mask' || capability.mask_capable))
  const matcherActionAllowed = draft.detectionMethod !== 'matcher' || draft.action !== 'mask' || draft.matcherType === 'regex' || editorPolicy?.origin === 'preloaded'
  const selectedActionAllowed = capabilityActionAllowed && matcherActionAllowed
  const semanticSelected = draft.detectionMethod === 'capability' && (
    selectedCapabilities.some((capability) => capability.semantic_judge)
    || (editorPolicy?.origin === 'preloaded' && policyHasSemanticJudge(editorPolicy))
  )
  useEffect(() => {
    if (!semanticSelected && draft.semanticAction !== 'audit') setDraft((current) => ({ ...current, semanticAction: 'audit' }))
  }, [semanticSelected, draft.semanticAction])
  const existingMatcher = !creating && editorPolicy?.detection_basis === 'matcher'
  const canEditSubjects = canManage && editorPolicy?.origin !== 'preloaded'
  const updateSubjectBinding = <K extends keyof SecurityPolicySubjectBinding,>(
    key: K,
    value: SecurityPolicySubjectBinding[K],
  ) => setDraft((current) => ({
    ...current,
    subjectBinding: { ...current.subjectBinding, [key]: value },
  }))
  const matcherConfigured = draft.detectionMethod === 'matcher' && Boolean(buildMatcher(draft.matcherType, draft.matcherText))
  const numberNeedsGeneration = draft.detectionMethod === 'matcher' && draft.matcherMode === 'assisted' && draft.assistedKind === 'number'
    && (!draft.numberExplanation || !draft.matcherText
      || (!draft.numberAuthoringProof && (!editorPolicy?.authoring
        || draft.matcherText !== editorPolicy.authoring.matcher_pattern
        || JSON.stringify(draft.numberSegments) !== JSON.stringify(editorPolicy.authoring.segments))))
  const editingSavedNumber = Boolean(editorPolicy?.authoring && draft.matcherMode === 'assisted' && draft.assistedKind === 'number')
  const generateNumber = async (segments?: DlpNumberSegment[]) => {
    const version = ++dlpRequestVersion.current
    setDlpError('')
    setDlpGenerating(true)
    try {
      const result = (await securityPoliciesApi.generateDlp({
        kind: 'number', positive_samples: nonEmptyLines(draft.numberSamples),
        ...(segments ? { segments } : {}),
        ...(editorPolicy ? { policy_id: editorPolicy.id } : {}),
        request_version: String(version),
      })).data
      if (version !== dlpRequestVersion.current || !editorOpen) return
      setDraft((current) => ({ ...current,
        matcherType: 'regex', matcherText: result.matcher.config.regex || '', generatedNumberRegex: result.matcher.config.regex || '',
        numberSegments: result.segments, numberExplanation: result.explanation, numberAuthoringProof: result.authoring_proof,
      }))
      setDlpPreviewResult(null)
    } catch {
      if (version === dlpRequestVersion.current) setDlpError('编号规则生成失败，请检查结构段及样例是否一致；首次生成需至少两个不同样例。')
    } finally {
      if (version === dlpRequestVersion.current) setDlpGenerating(false)
    }
  }
  const previewDlp = async () => {
    const matcher = buildMatcher(draft.matcherType, draft.matcherText)
    if (!matcher || !nonEmptyLines(dlpPreviewText).length) return
    const version = ++dlpRequestVersion.current
    setDlpError('')
    setDlpPreviewing(true)
    try {
      const result = (await securityPoliciesApi.previewDlp({ matcher, samples: nonEmptyLines(dlpPreviewText), request_version: String(version) })).data
      if (version === dlpRequestVersion.current && editorOpen) setDlpPreviewResult(result)
    } catch {
      if (version === dlpRequestVersion.current) setDlpError('运行时预览暂不可用；请复核识别条件后再保存。')
    } finally {
      if (version === dlpRequestVersion.current) setDlpPreviewing(false)
    }
  }
  const capabilityConfigured = draft.detectionMethod === 'capability' && draft.capabilityCategories.length > 0
  const draftValid = draft.redaction.replacement.trim().length > 0 && !draft.redaction.replacement.includes('<JJD_') && draft.name.trim().length > 0 && selectedActionAllowed && !numberNeedsGeneration && (!draft.enabled || matcherConfigured || capabilityConfigured || existingMatcher)
  const createPolicyCount = creating ? policyWritesForCreation(draft).length : 1
  const draftMatchesSavedPolicy = Boolean(
    editorPolicy
    && JSON.stringify(policyWriteFromDraft(draft, editorPolicy)) === JSON.stringify(policyWriteFromDraft(draftForPolicy(editorPolicy), editorPolicy)),
  )
  const previewResponse = draftMatchesSavedPolicy ? previewMutation.data?.data : undefined
  const previewPolicy = editorPolicy
    ? previewResponse?.policies.find((item) => item.policy_id === editorPolicy.id)
    : undefined
  const previewPublished = Boolean(editorPolicy && previewResponse?.published_policy_ids.includes(editorPolicy.id))
  const previewNodesApplied = Boolean(
    previewPublished
    && previewResponse?.nodes.all_converged
    && previewResponse.engine_rule_pack_version === previewResponse.desired_version,
  )

  // 客户场景页只展示可直接配置的安全防护场景。
  // 访问治理和未归类项留在运行策略/高级维护，避免空场景与治理债务混入覆盖率。
  const scenarioCards = CUSTOMER_SECURITY_SCENES
  const capabilityUsage = (capability: SecurityPolicyCapability) => capability.bound_policy_count ?? policiesUsingCapability(policies.filter((policy) => policy.enabled), capability).length
  const capabilityTotal = capabilitiesQuery.data?.data?.total ?? capabilities.length
  const referencedCapabilityCount = capabilities.filter((item) => capabilityUsage(item) > 0).length
  const unreferencedCapabilityCount = Math.max(0, capabilityTotal - referencedCapabilityCount)
  const policyCatalogTotal = response?.total ?? policies.length
  const inactiveCatalogCount = Math.max(0, policyCatalogTotal - activeRuntimePolicies.length)
  const unconfiguredCatalogCount = policies.filter((policy) => !policy.runtime_active && !policy.detection_configured).length
  const nonCustomerRuntimePolicyCount = Math.max(0, activeRuntimePolicies.length - customerRuntimePolicyCount)
  const capabilityQuery = (params.get('capability_q') ?? '').trim().toLowerCase()
  const capabilityStage = params.get('capability_stage') ?? 'all'
  const capabilityUsageFilter = params.get('usage') ?? 'used'
  const visibleCapabilities = capabilities.filter((capability) => {
    if (capabilityQuery && !`${capability.name} ${capability.category}`.toLowerCase().includes(capabilityQuery)) return false
    if (capabilityStage !== 'all' && !capability.supported_stages.includes(capabilityStage)) return false
    if (capabilityUsageFilter === 'used' && capabilityUsage(capability) === 0) return false
    if (capabilityUsageFilter === 'unused' && capabilityUsage(capability) > 0) return false
    return true
  })
  const capabilityCurrentPage = Math.min(capabilityPage, Math.max(1, Math.ceil(visibleCapabilities.length / PAGE_SIZE)))
  const pagedCapabilities = visibleCapabilities.slice((capabilityCurrentPage - 1) * PAGE_SIZE, capabilityCurrentPage * PAGE_SIZE)
  const selectedCapabilityCount = capabilities.filter((capability) => selectedCapabilityIDs.has(capability.category)).length
  const selectedCapabilitiesOnPage = pagedCapabilities.filter((capability) => selectedCapabilityIDs.has(capability.category)).length
  const catalogQuery = (params.get('catalog_q') ?? '').trim().toLocaleLowerCase('zh-CN')
  const catalogState = params.get('catalog_state') ?? 'all'
  const filteredCatalog = policies.filter((policy) => {
    if (catalogQuery && !`${policy.name} ${policy.description} ${policy.scene} ${policy.id}`.toLocaleLowerCase('zh-CN').includes(catalogQuery)) return false
    if (catalogState === 'runtime' && !policy.runtime_active) return false
    if (catalogState === 'inactive' && policy.runtime_active) return false
    if (catalogState === 'unconfigured' && policy.detection_configured) return false
    if (catalogState === 'tenant' && policy.origin !== 'organization_created') return false
    return true
  })
  const catalogCurrentPage = Math.min(catalogPage, Math.max(1, Math.ceil(filteredCatalog.length / PAGE_SIZE)))
  const pagedCatalog = filteredCatalog.slice((catalogCurrentPage - 1) * PAGE_SIZE, catalogCurrentPage * PAGE_SIZE)
  const requestedRuntimePage = Number(params.get('page') ?? '1')
  const runtimePage = Number.isFinite(requestedRuntimePage) && requestedRuntimePage > 0 ? Math.floor(requestedRuntimePage) : 1
  const runtimeCurrentPage = Math.min(runtimePage, Math.max(1, Math.ceil(filteredPolicies.length / PAGE_SIZE)))
  const pagedRuntimePolicies = filteredPolicies.slice((runtimeCurrentPage - 1) * PAGE_SIZE, runtimeCurrentPage * PAGE_SIZE)
  const sceneAllPolicies = selectedScene
    ? runtimePolicies.filter((policy) => classifyPolicyScene(policy) === selectedScene)
    : runtimePolicies
  const batchAllPolicies = advancedTab === 'catalog' ? policies : sceneAllPolicies
  const selectedPolicies = useMemo(
    () => batchAllPolicies.filter((policy) => selectedPolicyIDs.has(policy.id)),
    [batchAllPolicies, selectedPolicyIDs],
  )
  const batchAvailability = useMemo(() => batchActionAvailability(selectedPolicies), [selectedPolicies])
  const batchPartition = useMemo(() => partitionPoliciesForBatchChange(selectedPolicies, {
    ...(batchAction ? { action: batchAction } : {}),
    ...(batchEnabled ? { enabled: batchEnabled === 'enabled' } : {}),
  }), [batchAction, batchEnabled, selectedPolicies])
  const batchApplicablePolicies = batchPartition.applicable
  const batchSkippedCount = batchPartition.skipped.length
  const batchSkippedSummary = useMemo(() => {
    const counts = batchPartition.skipped.reduce<Record<BatchSkipReason, number>>((result, item) => {
      result[item.reason] += 1
      return result
    }, { detection_not_ready: 0, action_unsupported: 0 })
    return [
      counts.detection_not_ready > 0 ? `检测配置未就绪 ${counts.detection_not_ready} 条` : '',
      counts.action_unsupported > 0 ? `不支持所选动作 ${counts.action_unsupported} 条` : '',
    ].filter(Boolean).join('，')
  }, [batchPartition.skipped])
  const batchMutation = useMutation({
    mutationFn: ({ updates }: BatchMutationRequest) => securityPoliciesApi.batch(updates),
    onSuccess: async (_, { updates, skippedCount, skippedSummary }) => {
      message.success(skippedCount > 0
        ? `已修改 ${updates.length} 条，自动跳过 ${skippedCount} 条${skippedSummary ? `（${skippedSummary}）` : ''}`
        : `已修改 ${updates.length} 条策略`)
      setSelectedPolicyIDs(new Set())
      setBatchAction('')
      setBatchEnabled('')
      setConfirmBatchOpen(false)
      await invalidatePolicies()
    },
    onError: () => message.error('批量配置失败，服务端原配置未改变'),
  })
  const selectPolicies = (items: SecurityPolicy[], selected: boolean) => {
    setSelectedPolicyIDs((current) => {
      const next = new Set(current)
      items.forEach((policy) => selected ? next.add(policy.id) : next.delete(policy.id))
      return next
    })
  }
  const selectPolicy = (policy: SecurityPolicy, selected: boolean) => selectPolicies([policy], selected)
  const replacePolicySelection = (items: SecurityPolicy[]) => setSelectedPolicyIDs(new Set(items.map((policy) => policy.id)))
  const clearPolicySelection = () => {
    setSelectedPolicyIDs(new Set())
    setBatchAction('')
    setBatchEnabled('')
  }
  const submitBatch = () => {
    if ((!batchAction && !batchEnabled) || batchApplicablePolicies.length === 0) return
    batchMutation.mutate({
      updates: batchApplicablePolicies.map((policy) => ({
        id: policy.id,
        ...(batchAction ? { action: batchAction } : {}),
        ...(batchEnabled ? { enabled: batchEnabled === 'enabled' } : {}),
      })),
      skippedCount: batchSkippedCount,
      skippedSummary: batchSkippedSummary,
    })
  }
  const selectCapabilities = (items: SecurityPolicyCapability[], selected: boolean) => {
    setSelectedCapabilityIDs((current) => {
      const next = new Set(current)
      items.filter((capability) => capability.enabled).forEach((capability) => selected ? next.add(capability.category) : next.delete(capability.category))
      return next
    })
  }
  const renderPolicyBatchToolbar = (filtered: SecurityPolicy[], all: SecurityPolicy[]) => canManage ? <PolicyBatchToolbar
    selectedCount={selectedPolicies.length}
    filteredCount={filtered.length}
    totalCount={all.length}
    canManage={canManage}
    pending={batchMutation.isPending}
    batchAction={batchAction}
    batchEnabled={batchEnabled}
    availability={batchAvailability}
    onSelectFiltered={() => replacePolicySelection(filtered)}
    onSelectAll={() => replacePolicySelection(all)}
    onActionChange={setBatchAction}
    onEnabledChange={setBatchEnabled}
    onApply={() => setConfirmBatchOpen(true)}
    onClear={clearPolicySelection}
  /> : null

  const renderScenarioContent = () => {
    if (!selectedScene) return (
      <div className="enterprise-scene-grid">
        {scenarioCards.map((scene) => {
          const items = activeRuntimePolicies.filter((policy) => classifyPolicyScene(policy) === scene.key)
          const effective = primaryEffectiveAction(items, mode?.effective_mode, auditOnly)
          return <article className="enterprise-scene-card" key={scene.key}>
            <div className="enterprise-scene-card-head"><h3>{scene.label}</h3><StatusPill tone={items.length > 0 ? 'green' : 'gray'}>{items.length > 0 ? '保护中' : '未启用'}</StatusPill></div>
            <p>{scene.description}</p>
            <dl><div><dt>运行策略项</dt><dd>{items.length}</dd></div><div><dt>当前主要动作</dt><dd className={effective.clamped ? 'is-clamped' : ''}>{effective.effectiveLabel}</dd></div></dl>
            <small>{scene.subject}</small>
            {items.some((policy) => describeEffectiveAction({ configuredAction: policy.action, globalMode: mode?.effective_mode, auditOnly, enabled: policy.enabled }).clamped)
              ? <small className="enterprise-scene-limit-note">主动处置当前受观察留痕上限约束</small> : null}
            <Button onClick={() => setParam('scene', scene.key)}>进入场景</Button>
          </article>
        })}
      </div>
    )
    const scene = getEnterpriseScene(selectedScene)
    return (
      <div className="enterprise-scene-detail">
        <div className="enterprise-scene-detail-head">
          <Button type="text" icon={<ArrowLeftOutlined />} aria-label="返回场景列表" onClick={() => setParam('scene', undefined)} />
          <div><h2>{scene.label}</h2><p>{scene.description}</p></div>
        </div>
        {selectedScene === 'sensitive-data' ? <SensitiveDataPolicy policies={policies} auditOnly={auditOnly} runtimeVerified={runtimeVerified} runtimeStatus={runtimeStatus} canManage={canManage} onSaved={invalidatePolicies} onCreateCustom={openAdvancedSensitiveCreator} onOpenPolicy={openPolicy} /> : null}
        {selectedScene === 'file-security' ? <FilePolicySettings canManage={canManage} /> : null}
        {selectedScene === 'content-safety' ? <SecurityReplySettings canManage={canManage} /> : null}
        {selectedScene !== 'file-security' && selectedScene !== 'sensitive-data' ? <>
          <PolicyFilters params={params} setParam={setParam} stages={stages} />
          {renderPolicyBatchToolbar(scenePolicies, sceneAllPolicies)}
          <PolicyTable policies={scenePolicies} directory={scopeDirectory} mode={mode?.effective_mode} auditOnly={auditOnly} runtimeVerified={runtimeVerified} runtimeStatus={runtimeStatus} onOpen={openPolicy} onDelete={canManage ? (policy) => deleteMutation.mutate(policy) : undefined} deletingID={deletingPolicyID} selectedIDs={canManage ? selectedPolicyIDs : undefined} onSelect={canManage ? selectPolicy : undefined} onSelectPage={canManage ? selectPolicies : undefined} />
        </> : null}
      </div>
    )
  }

  const loading = policiesQuery.isLoading
  const loadError = policiesQuery.isError

  return (
    <div className="enterprise-page enterprise-policy-center">
      <EnterprisePageHeader eyebrow="安全护栏" title="策略中心" description="按业务场景查看当前保护状态，并管理实际参与运行的策略。" />
      {selectedScene || activeTab === 'runtime' ? (
        <div className="enterprise-scene-mode-strip" aria-label="当前全局运行方式">
          <StatusPill tone={auditOnly ? 'orange' : 'green'}>{auditOnly ? '观察留痕' : '防护阻断'}</StatusPill>
          <span>{auditOnly ? '当前场景继续检测、告警和留证，不执行脱敏或阻断。' : '当前场景按各策略的配置动作执行。'}</span>
        </div>
      ) : (
        <SecurityExecutionModeCard
          canManage={canManageMode}
          protectedSceneCount={protectedSceneCount}
          totalSceneCount={CUSTOMER_SECURITY_SCENES.length}
          runtimePolicyCount={customerRuntimePolicyCount}
          tenantPolicyCount={tenantPolicyCount}
          blockingPolicyCount={blockingPolicyCount}
        />
      )}
      {!canManage ? <Alert type="info" showIcon message="当前为只读视图" description="你可以查看场景与运行策略，但不能修改运行模式或策略配置。" /> : null}
      <div className="enterprise-policy-primary-nav">
        <Tabs className="enterprise-policy-tabs" activeKey={activeTab} onChange={changeTab} items={[
          { key: 'scenarios', label: <span><AppstoreOutlined />场景策略</span>, children: null },
          { key: 'runtime', label: <span><SettingOutlined />运行策略</span>, children: null },
          { key: 'detection', label: '检测配置', children: null },
        ]} />
        {canManage ? <Button icon={<DatabaseOutlined />} onClick={() => openAdvanced('capabilities')}>高级维护</Button> : null}
      </div>

      {activeTab === 'detection' ? <SemanticConsole /> : null}
      {loading && activeTab !== 'detection' ? <div className="enterprise-policy-loading">正在读取运行策略...</div> : null}
      {loadError ? <Alert type="error" showIcon message="策略中心加载失败" description="未取得当前组织的运行策略，页面不会使用目录数量替代。" action={<Button onClick={() => void policiesQuery.refetch()}>重试</Button>} /> : null}
      {!loading && !loadError && activeTab === 'scenarios' ? renderScenarioContent() : null}
      {!loading && !loadError && activeTab === 'runtime' ? (
        <section className="enterprise-policy-section">
          <div className="enterprise-policy-section-head"><div><h2>运行策略</h2><p>仅展示已接入运行时的策略和组织自建策略；系统目录项不在此混排。</p></div>{canManage ? <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateSceneOpen(true)}>新建策略</Button> : null}</div>
          <PolicyFilters params={params} setParam={setParam} stages={stages} />
          {renderPolicyBatchToolbar(filteredPolicies, runtimePolicies)}
          <PolicyTable policies={pagedRuntimePolicies} directory={scopeDirectory} mode={mode?.effective_mode} auditOnly={auditOnly} runtimeVerified={runtimeVerified} runtimeStatus={runtimeStatus} onOpen={openPolicy} onDelete={canManage ? (policy) => deleteMutation.mutate(policy) : undefined} deletingID={deletingPolicyID} selectedIDs={canManage ? selectedPolicyIDs : undefined} onSelect={canManage ? selectPolicy : undefined} onSelectPage={canManage ? selectPolicies : undefined} />
          {filteredPolicies.length > PAGE_SIZE ? <Pagination className="enterprise-policy-pagination" current={runtimeCurrentPage} pageSize={PAGE_SIZE} total={filteredPolicies.length} showSizeChanger={false} showTotal={(total) => `共 ${total} 条运行策略`} onChange={(page) => setParam('page', String(page))} /> : null}
        </section>
      ) : null}

      <Drawer className="policy-advanced-drawer" width="min(1220px, 100vw)" open={canManage && advancedTab !== null} title="高级维护" destroyOnHidden onClose={closeAdvanced}>
        <Tabs activeKey={advancedTab ?? 'capabilities'} onChange={(key) => openAdvanced(key as AdvancedTab)} items={[
          {
            key: 'capabilities',
            label: '检测组件',
            children: capabilitiesQuery.isError ? <Alert type="error" showIcon message="检测组件读取失败" action={<Button onClick={() => void capabilitiesQuery.refetch()}>重试</Button>} /> : (
              <section className="enterprise-policy-section capability-library">
                <div className="enterprise-policy-section-head"><div><h2>检测组件</h2><p>平台维护视图。组件是可复用的检测能力，一个组件可以被多条策略引用，不与策略数量一一对应。</p></div></div>
                <div className="capability-summary" aria-label="检测能力统计">
                  <span><small>组件总数</small><strong>{capabilityTotal}</strong></span>
                  <span><small>已被策略引用</small><strong>{referencedCapabilityCount}</strong></span>
                  <span><small>未被策略引用 <Tooltip title="未被引用的组件是技术储备，不代表安全缺口。"><InfoCircleOutlined /></Tooltip></small><strong>{unreferencedCapabilityCount}</strong></span>
                </div>
                <Alert className="enterprise-policy-count-note" type="info" showIcon message={`口径关系：${capabilityTotal} 个组件 = ${referencedCapabilityCount} 个已被策略引用 + ${unreferencedCapabilityCount} 个未被引用。组件可被多条策略复用，因此组件数不等于策略数。`} />
                <div className="enterprise-policy-filters capability-filters" role="search" aria-label="检测能力筛选">
                  <Input allowClear prefix={<SearchOutlined />} aria-label="搜索检测能力" placeholder="搜索名称或内部标识" value={params.get('capability_q') ?? ''} onChange={(event) => { setCapabilityPage(1); setParam('capability_q', event.target.value || undefined) }} />
                  <Select aria-label="能力检测阶段筛选" value={capabilityStage} onChange={(value) => { setCapabilityPage(1); setParam('capability_stage', value === 'all' ? undefined : value) }} options={[{ value: 'all', label: '全部检测阶段' }, ...stages.map((stage) => ({ value: stage, label: detectionStageLabel(stage) }))]} />
                  <Select aria-label="能力使用状态筛选" value={capabilityUsageFilter} onChange={(value) => { setCapabilityPage(1); setParam('usage', value === 'used' ? undefined : value) }} options={[{ value: 'used', label: '正在使用' }, { value: 'unused', label: '可选未使用' }, { value: 'all', label: '全部组件' }]} />
                </div>
                <div className={`enterprise-policy-batch-toolbar${selectedCapabilityCount > 0 ? ' is-active' : ''}`} aria-label="批量配置检测组件">
                  <div className="enterprise-policy-batch-scope"><span>{selectedCapabilityCount > 0 ? `已选 ${selectedCapabilityCount} 个组件` : '选择要挂载的检测组件'}</span><Button size="small" disabled={visibleCapabilities.length === 0} onClick={() => setSelectedCapabilityIDs(new Set(visibleCapabilities.filter((capability) => capability.enabled).map((capability) => capability.category)))}>选择当前筛选结果（{visibleCapabilities.length}）</Button></div>
                  {selectedCapabilityCount > 0 ? <div className="enterprise-policy-batch-fields"><Button type="primary" onClick={openCapabilityBatchCreator}>配置为记录并告警策略</Button><Button onClick={() => setSelectedCapabilityIDs(new Set())}>取消选择</Button></div> : null}
                </div>
                <div className="enterprise-policy-table-wrap"><table className="enterprise-policy-table capability-table is-selectable"><thead><tr><th className="enterprise-policy-selection-cell"><Checkbox aria-label="选择当前页检测组件" checked={pagedCapabilities.length > 0 && selectedCapabilitiesOnPage === pagedCapabilities.length} indeterminate={selectedCapabilitiesOnPage > 0 && selectedCapabilitiesOnPage < pagedCapabilities.length} onChange={(event) => selectCapabilities(pagedCapabilities, event.target.checked)} /></th><th>检测组件</th><th>风险类别</th><th>阶段</th><th>状态</th><th>使用数</th><th>关联策略</th><th>操作</th></tr></thead>
                  <tbody>{pagedCapabilities.map((capability) => {
                    const related = policiesUsingCapability(policies, capability)
                    return <tr key={capability.category}>
                      <td className="enterprise-policy-selection-cell"><Checkbox aria-label={`选择检测组件 ${capability.name || capability.category}`} checked={selectedCapabilityIDs.has(capability.category)} disabled={!capability.enabled} onChange={(event) => selectCapabilities([capability], event.target.checked)} /></td>
                      <td><strong>{capability.name || capability.category}</strong><small>{capability.category}</small>{capability.category === SEMANTIC_CONTEXT_CAPABILITY ? <small>{SEMANTIC_CONTEXT_COVERAGE_HINT}</small> : null}</td>
                      <td>{capabilityRiskCategory(capability)}</td>
                      <td>{capability.supported_stages.map((stage) => <Tag key={stage}>{detectionStageLabel(stage)}</Tag>)}</td>
                      <td><StatusPill tone={capability.enabled ? 'green' : 'gray'}>{capability.enabled ? '可用' : '已停用'}</StatusPill></td>
                      <td>{capabilityUsage(capability)}</td>
                      <td>{related.length > 0 ? related.slice(0, 2).map((policy) => <span className="capability-policy-link" key={policy.id}>{policy.name} · {policyActionLabel(policy.action)}</span>) : '当前未关联'}</td>
                      <td><Button type="link" size="small" onClick={() => setCapabilityDrawer(capability)}>查看关联</Button></td>
                    </tr>
                  })}</tbody>
                </table></div>
                {visibleCapabilities.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="没有符合当前条件的检测组件" /> : null}
                {visibleCapabilities.length > PAGE_SIZE ? <Pagination className="enterprise-policy-pagination" current={capabilityCurrentPage} pageSize={PAGE_SIZE} total={visibleCapabilities.length} showSizeChanger={false} showTotal={(total) => `共 ${total} 个组件`} onChange={setCapabilityPage} /> : null}
              </section>
            ),
          },
          {
            key: 'catalog',
            label: '系统策略目录',
            children: (
              <section className="enterprise-policy-section">
                <div className="enterprise-policy-section-head"><div><h2>系统策略目录</h2><p>平台维护视图。目录项按是否实际参与运行拆分；“待接入”是未运行项中的配置子集。</p></div></div>
                <div className="capability-summary is-four-column" aria-label="系统策略目录统计">
                  <span><small>目录总数</small><strong>{policyCatalogTotal}</strong></span>
                  <span><small>参与运行</small><strong>{activeRuntimePolicies.length}</strong></span>
                  <span><small>未参与运行</small><strong>{inactiveCatalogCount}</strong></span>
                  <span><small>其中待接入</small><strong>{unconfiguredCatalogCount}</strong></span>
                </div>
                <Alert className="enterprise-policy-count-note" type="info" showIcon message={`目录关系：${policyCatalogTotal} 个目录项 = ${activeRuntimePolicies.length} 个参与运行 + ${inactiveCatalogCount} 个未参与运行；未运行项中 ${unconfiguredCatalogCount} 个尚待接入检测。运行中的 ${activeRuntimePolicies.length} 条 = ${customerRuntimePolicyCount} 条客户安全场景策略 + ${nonCustomerRuntimePolicyCount} 条访问治理或待归类策略。`} />
                <div className="enterprise-policy-filters catalog-filters" role="search" aria-label="系统策略目录筛选">
                  <Input allowClear prefix={<SearchOutlined />} aria-label="搜索系统策略目录" placeholder="搜索目录项名称、场景或 ID" value={params.get('catalog_q') ?? ''} onChange={(event) => { setCatalogPage(1); setParam('catalog_q', event.target.value || undefined) }} />
                  <Select aria-label="系统策略目录状态筛选" value={catalogState} onChange={(value) => { setCatalogPage(1); setParam('catalog_state', value === 'all' ? undefined : value) }} options={[{ value: 'all', label: '全部目录项' }, { value: 'runtime', label: '参与运行' }, { value: 'inactive', label: '未参与运行' }, { value: 'unconfigured', label: '其中待接入' }, { value: 'tenant', label: '组织自建' }]} />
                </div>
                {renderPolicyBatchToolbar(filteredCatalog, policies)}
                <PolicyTable policies={pagedCatalog} directory={scopeDirectory} mode={mode?.effective_mode} auditOnly={auditOnly} runtimeVerified={runtimeVerified} runtimeStatus={runtimeStatus} onOpen={openPolicy} onDelete={canManage ? (policy) => deleteMutation.mutate(policy) : undefined} deletingID={deletingPolicyID} selectedIDs={canManage ? selectedPolicyIDs : undefined} onSelect={canManage ? selectPolicy : undefined} onSelectPage={canManage ? selectPolicies : undefined} />
                {filteredCatalog.length > PAGE_SIZE ? <Pagination className="enterprise-policy-pagination" current={catalogCurrentPage} pageSize={PAGE_SIZE} total={filteredCatalog.length} showSizeChanger={false} showTotal={(total) => `共 ${total} 个目录项`} onChange={setCatalogPage} /> : null}
              </section>
            ),
          },
        ]} />
      </Drawer>


      <Modal open={createSceneOpen} title="选择策略场景" footer={null} onCancel={() => setCreateSceneOpen(false)}>
        <div className="policy-create-scene-list">{ENTERPRISE_SCENES.map((scene) => (
          <button key={scene.key} type="button" onClick={() => {
            if (scene.key === 'sensitive-data') {
              setCreateSceneOpen(false)
              openAdvancedSensitiveCreator()
              return
            }
            if (scene.key !== 'file-security') {
              openCreator(scene.key)
              return
            }
            setCreateSceneOpen(false)
            const next = new URLSearchParams()
            next.set('scene', 'file-security')
            setParams(next)
          }}>
            <strong>{scene.label}</strong><span>{scene.key === 'file-security' ? '进入真实文件发送配置' : scene.description}</span>
          </button>
        ))}</div>
      </Modal>

      <Drawer width="min(680px, 100vw)" open={editorOpen} title={creating ? draft.detectionMethod === 'matcher' ? '新建自定义敏感信息策略' : '新建策略' : editorPolicy?.name} destroyOnHidden onClose={closeEditor} footer={<div className="policy-drawer-footer">{canDeletePolicy ? <Popconfirm title="删除这条策略？" okText="删除" cancelText="取消" okButtonProps={{ danger: true }} onConfirm={() => { if (editorPolicy) deleteMutation.mutate(editorPolicy) }}><Button danger loading={deleteMutation.isPending} style={{ marginRight: 'auto' }}>删除策略</Button></Popconfirm> : null}<Button onClick={closeEditor}>取消</Button>{canManage ? <Button type="primary" disabled={!draftValid} onClick={() => setConfirmSaveOpen(true)}>保存并应用</Button> : null}</div>}>
        <div className="policy-detail-drawer">
          {!creating && editorPolicy ? <div className="policy-detail-summary">
            <span><small>所属场景</small><strong>{getEnterpriseScene(classifyPolicyScene(editorPolicy)).label}</strong></span>
            <span><small>适用对象</small><strong>{bindingScopeSummary(editorPolicy, scopeDirectory).title}</strong></span>
            <span><small>检测阶段</small><strong>{stageValues(editorPolicy).map(detectionStageLabel).join('、') || 'API 未提供'}</strong></span>
            <span><small>配置 / 有效动作</small><strong>{policyActionLabel(editorPolicy.action)} / {describeEffectiveAction({ configuredAction: editorPolicy.action, globalMode: mode?.effective_mode, auditOnly, enabled: editorPolicy.enabled }).effectiveLabel}</strong></span>
          </div> : null}
          {!creating ? <CurrentHit text={currentHitText} /> : null}
          <label>策略名称<Input aria-label="策略名称" value={draft.name} disabled={!canManage || editorPolicy?.origin === 'preloaded'} maxLength={255} onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))} /></label>
          <label>策略说明<Input.TextArea aria-label="策略说明" value={draft.description} disabled={!canManage || editorPolicy?.origin === 'preloaded'} maxLength={4096} rows={3} onChange={(event) => setDraft((current) => ({ ...current, description: event.target.value }))} /></label>
          <div className="policy-drawer-grid">
            <label>级别<Select aria-label="风险级别" value={draft.severity} disabled={!canManage} onChange={(severity) => { setRestoreSeverity(false); setDraft((current) => ({ ...current, severity })) }} options={severityOptions(['low', 'medium', 'high', 'critical'])} />
              {!creating && editorPolicy?.default_severity && editorPolicy.severity_overridden ? (
                <span className="policy-severity-custom">
                  <Tag>已自定义</Tag>
                  <Button type="link" size="small" disabled={!canManage || restoreSeverity} onClick={() => { setRestoreSeverity(true); setDraft((current) => ({ ...current, severity: (editorPolicy.default_severity ?? current.severity) as SecurityPolicySeverity })) }}>恢复默认</Button>
                </span>
              ) : null}
            </label>
            <label>配置动作<Select aria-label="配置动作" value={draft.action} disabled={!canManage} onChange={(action) => setDraft((current) => ({ ...current, action }))} options={ACTION_OPTIONS.map((option) => ({ ...option, disabled: selectedCapabilities.some((capability) => !capability.allowed_actions.includes(option.value) || (option.value === 'mask' && !capability.mask_capable)) }))} /></label>
          </div>
          {semanticSelected ? <div className="policy-semantic-action">
            <label>智能分析命中时<Select aria-label="智能分析命中时" value={draft.semanticAction} disabled={!canManage} onChange={(semanticAction) => setDraft((current) => ({ ...current, semanticAction }))} options={SEMANTIC_ACTION_OPTIONS} /></label>
            <p className="text-muted">智能分析（语义裁判）给出的是模型判断，单独决定处置，不随上方配置动作变化。选「拦截」后：仅输入侧、仅防护模式、分析完整完成且置信度达到「智能分析 → 语义设置」中的拦截阈值时才拦截；分析超时、不可用或容量饱和时一律放行，并在事件中写明原因。「仅记录」只留存证据，不产生告警。</p>
            <p className="text-muted">{SEMANTIC_CONTEXT_COVERAGE_HINT}</p>
          </div> : null}
          {draft.action === 'mask' ? <RedactionConfigFields value={draft.redaction} disabled={!canManage} onChange={(redaction) => setDraft((current) => ({ ...current, redaction }))} /> : null}
          <section className="policy-subject-editor" aria-label="策略适用对象">
            <div className="policy-subject-heading">
              <div><strong>适用对象</strong><small>当前组织为固定边界；已选择维度之间同时满足，同一维度内任一匹配。</small></div>
              <StatusPill tone="blue">当前组织</StatusPill>
            </div>
            <div className="policy-subject-grid">
              <label>应用<Select mode="multiple" maxTagCount="responsive" aria-label="适用应用" value={draft.subjectBinding.project_ids ?? []} disabled={!canEditSubjects} onChange={(value) => updateSubjectBinding('project_ids', value)} options={projects.map((item) => ({ value: item.id, label: item.name }))} /></label>
              <label>应用所属部门<Select mode="multiple" maxTagCount="responsive" aria-label="适用应用部门" value={draft.subjectBinding.application_department_ids ?? []} disabled={!canEditSubjects} onChange={(value) => updateSubjectBinding('application_department_ids', value)} options={teams.map((item) => ({ value: item.id, label: item.name }))} /></label>
              <label>稳定 Key<Select mode="multiple" maxTagCount="responsive" aria-label="适用 Key" value={draft.subjectBinding.key_ids ?? []} disabled={!canEditSubjects} onChange={(value) => updateSubjectBinding('key_ids', value)} options={keys.map((item) => ({ value: item.id, label: item.name || item.key_prefix || item.id }))} /></label>
              <label>协议<Select mode="multiple" maxTagCount="responsive" aria-label="适用协议" value={draft.subjectBinding.protocols ?? []} disabled={!canEditSubjects} onChange={(value) => updateSubjectBinding('protocols', value)} options={[...PROTOCOL_OPTIONS]} /></label>
              <label>入口<Select mode="multiple" maxTagCount="responsive" aria-label="适用入口" value={draft.subjectBinding.entry_points ?? []} disabled={!canEditSubjects} onChange={(value) => updateSubjectBinding('entry_points', value)} options={[...ENTRY_POINT_OPTIONS]} /></label>
            </div>
            <Alert type="info" showIcon message="人员主体暂不可配置" description="当前运行链没有可信 actor 来源。运行时身份未知时，人员及人员部门条件不会匹配。" />
            {hasUnavailableActorBinding(draft.subjectBinding) ? <Alert type="warning" showIcon message="该策略含只读人员条件" description="现有条件会原样保留；在可信 actor 来源接入前不会通过人员匹配。" /> : null}
          </section>
          {editorPolicy?.origin === 'preloaded' ? (
            <>
              <div className="policy-fixed-capabilities" aria-label="系统固定检测能力">
                <div><strong>检测能力由系统固定</strong><small>预置策略的识别逻辑由产品维护，客户只需选择处置动作和是否启用。</small></div>
                <div className="policy-fixed-capability-list">
                  {editorPolicy.capabilities.map((capability) => <Tag key={capability.category}>{capabilityDisplayName(capability)}</Tag>)}
                  {editorPolicy.capabilities.length === 0 && editorPolicy.detection_basis === 'matcher' ? <Tag>系统内置识别条件</Tag> : null}
                </div>
              </div>
              <CapabilityMatchDocs capabilities={matchDocCapabilities} />
            </>
          ) : (
            <>
              <label>识别方式<Select aria-label="识别方式" value={draft.detectionMethod || undefined} placeholder="暂不配置" allowClear disabled={!canManage} onChange={(value) => {
                const detectionMethod = (value ?? '') as PolicyDraft['detectionMethod']
                setDraft((current) => ({
                  ...current,
                  detectionMethod,
                  capabilityCategories: detectionMethod === 'capability' ? current.capabilityCategories : [],
                  matcherType: detectionMethod === 'matcher' ? (current.matcherType || 'keyword') : '',
                  matcherText: detectionMethod === 'matcher' ? current.matcherText : '',
                }))
              }} options={[{ value: 'capability', label: '系统检测组件' }, { value: 'matcher', label: '自定义敏感信息' }]} /></label>
              {draft.detectionMethod === 'capability' ? <>
                <label>关联检测能力<Select mode="multiple" showSearch optionFilterProp="label" aria-label="关联检测能力" value={draft.capabilityCategories} disabled={!canManage} onChange={(capabilityCategories) => setDraft((current) => ({ ...current, capabilityCategories }))} options={capabilities.map((capability) => ({ value: capability.category, label: capabilityDisplayName(capability), disabled: !capability.enabled }))} /></label>
                <label>检测组合方式<Select aria-label="检测组合方式" value={draft.bindingMode} disabled={!canManage} onChange={(bindingMode) => setDraft((current) => ({ ...current, bindingMode }))} options={[{ value: 'any', label: '任一能力命中' }, { value: 'all', label: '全部能力同时命中' }]} /></label>
                {createPolicyCount > 1 ? <Alert type="info" showIcon message={`将自动拆分为 ${createPolicyCount} 条策略`} description={`服务端每条策略最多关联 ${MAX_CAPABILITIES_PER_POLICY} 个检测组件；本次仍只需确认一次。`} /> : null}
              </> : null}
              {draft.detectionMethod === 'matcher' ? <div className="policy-custom-matcher-editor">
                <label>配置方式<Select aria-label="自定义配置方式" value={draft.matcherMode} disabled={!canManage} onChange={(matcherMode) => changeDlpDraft((current) => ({ ...current, matcherMode,
                  ...(matcherMode === 'manual' ? { matcherType: current.manualMatcherType, matcherText: current.manualMatcherText }
                    : current.assistedKind === 'number' ? { matcherType: 'regex', matcherText: current.generatedNumberRegex }
                      : { matcherType: 'keyword', matcherText: current.assistedEntries }),
                }))} options={[{ value: 'assisted', label: '辅助配置' }, { value: 'manual', label: '手动配置' }]} /></label>
                {draft.matcherMode === 'assisted' ? <>
                  <label>识别内容类型<Select aria-label="识别内容类型" value={draft.assistedKind} disabled={!canManage} onChange={(assistedKind) => changeDlpDraft((current) => ({ ...current, assistedKind,
                    matcherType: assistedKind === 'entries' ? 'keyword' : 'regex',
                    matcherText: assistedKind === 'entries' ? current.assistedEntries : current.generatedNumberRegex,
                  }))} options={[{ value: 'entries', label: '词条' }, { value: 'number', label: '编号格式' }]} /></label>
                  {draft.assistedKind === 'entries' ? <>
                    <label>词条（每行一项）<Input.TextArea aria-label="词条" rows={6} value={draft.assistedEntries} disabled={!canManage} placeholder="例如：A+B、a.b、[内部]；均按字面量包含匹配" onChange={(event) => changeDlpDraft((current) => ({ ...current, matcherType: 'keyword', matcherText: event.target.value, assistedEntries: event.target.value }))} /></label>
                    <p className="text-muted">忽略空行与重复词条，匹配时不区分大小写；词条不会被解释为正则表达式。不强制填写测试样例。</p>
                  </> : <>
                    <label>应识别的编号样例（首次生成至少两个，重开可直接修改结构）<Input.TextArea aria-label="编号样例" rows={4} value={draft.numberSamples} disabled={!canManage || editingSavedNumber} onChange={(event) => changeDlpDraft((current) => ({ ...current, numberSamples: event.target.value, numberExplanation: '', numberSegments: [], numberAuthoringProof: '' }))} /></label>
                    <Button disabled={!canManage || editingSavedNumber || new Set(nonEmptyLines(draft.numberSamples)).size < 2} loading={dlpGenerating} onClick={() => void generateNumber()}>根据样例生成结构</Button>
                    {draft.numberSegments.length > 0 ? <section aria-label="编号结构段" className="policy-number-segments">
                      <strong>编号结构（按顺序匹配）</strong>
                      {draft.numberSegments.map((segment, index) => <div className="policy-number-segment" key={index}>
                        <span>第 {index + 1} 段</span>
                        <Select aria-label={`编号第${index + 1}段类型`} value={segment.kind} disabled={!canManage} onChange={(kind) => changeDlpDraft((current) => ({ ...current, numberSegments: current.numberSegments.map((part, idx) => idx === index ? (kind === 'fixed' ? { kind, value: part.kind === 'fixed' ? part.value : '', length: part.kind === 'fixed' ? part.length : 0 } : { kind, length: part.length }) : part), numberExplanation: '', numberAuthoringProof: '' }))} options={[{ value: 'fixed', label: '固定内容' }, { value: 'digits', label: '数字' }, { value: 'letters', label: '字母' }]} />
                        {segment.kind === 'fixed' ? <Input aria-label={`编号第${index + 1}段内容`} value={segment.value || ''} disabled={!canManage} onChange={(event) => changeDlpDraft((current) => ({ ...current, numberSegments: current.numberSegments.map((part, idx) => idx === index ? { ...part, value: event.target.value, length: event.target.value.length } : part), numberExplanation: '', numberAuthoringProof: '' }))} /> : <Input type="number" min={1} max={18} aria-label={`编号第${index + 1}段位数`} value={segment.length} disabled={!canManage} onChange={(event) => changeDlpDraft((current) => ({ ...current, numberSegments: current.numberSegments.map((part, idx) => idx === index ? { ...part, length: Number(event.target.value) } : part), numberExplanation: '', numberAuthoringProof: '' }))} />}
                      </div>)}
                      <Button disabled={!canManage || draft.numberSegments.some((segment) => segment.kind === 'fixed' ? !segment.value : !segment.length || segment.length < 1 || segment.length > 18)} loading={dlpGenerating} onClick={() => void generateNumber(draft.numberSegments)}>应用分段修改</Button>
                    </section> : null}
                    {draft.numberExplanation ? <Alert type="info" showIcon message="识别规则说明" description={draft.numberExplanation} /> : null}
                    {!draft.numberExplanation ? <p className="text-muted">编号段有改动时需重新生成规则，之后即可保存并应用。固定段也可改成限定长度的数字段。</p> : null}
                  </>}
                </> : <>
                  <label>自定义识别方式<Select aria-label="自定义识别方式" value={draft.matcherType || undefined} disabled={!canManage} onChange={(matcherType) => changeDlpDraft((current) => ({ ...current, matcherType, matcherText: '', manualMatcherType: matcherType, manualMatcherText: '' }))} options={[{ value: 'keyword', label: '关键词' }, { value: 'field_name', label: '字段名称' }, { value: 'regex', label: '正则表达式' }]} /></label>
                  <label>识别内容<Input.TextArea aria-label="识别内容" rows={draft.matcherType === 'regex' ? 3 : 6} value={draft.matcherText} disabled={!canManage} placeholder={draft.matcherType === 'regex' ? '输入一个正则表达式' : '每行填写一项'} onChange={(event) => changeDlpDraft((current) => ({ ...current, matcherText: event.target.value, manualMatcherText: event.target.value }))} /></label>
                  <Alert type="info" showIcon message="自定义内容由当前组织维护" description="关键词和字段名称适合记录告警或阻断；需要脱敏时请使用能够精确定位内容的正则表达式。" />
                </>}
                <section aria-label="可选规则预览" className="policy-matcher-preview">
                  <label>试验内容（可选，每行一项）<Input.TextArea aria-label="试验内容" rows={3} value={dlpPreviewText} disabled={!canManage} onChange={(event) => { resetDlpPreview(); setDlpPreviewText(event.target.value) }} /></label>
                  <Button icon={<EyeOutlined />} disabled={!canManage || !matcherConfigured || numberNeedsGeneration || !nonEmptyLines(dlpPreviewText).length} loading={dlpPreviewing} onClick={() => void previewDlp()}>预览当前识别规则</Button>
                  {dlpPreviewResult ? <ul>{dlpPreviewResult.matches.map((item) => <li key={item.sample_index}>样例 {item.sample_index + 1}：{item.matched ? '命中' : '未命中'}{item.matched && item.location ? ` · 位置：${item.location}` : ''}</li>)}</ul> : null}
                  <small>试验内容未命中时仅作提示，不阻止保存；请用合成样例，勿填写真实敏感数据。</small>
                </section>
                {dlpError ? <Alert type="warning" showIcon message={dlpError} /> : null}
              </div> : null}
            </>
          )}
          <div className="policy-drawer-switch"><span><strong>启用策略</strong><small>启用前必须选择可用检测能力。</small></span><Switch aria-label="启用策略" checked={draft.enabled} disabled={!canManage} onChange={(enabled) => setDraft((current) => ({ ...current, enabled }))} /></div>
          {!selectedActionAllowed ? <Alert type="warning" showIcon message="所选检测能力不支持当前配置动作" /> : null}
          {draft.enabled && !matcherConfigured && !capabilityConfigured && !existingMatcher ? <Alert type="warning" showIcon message="未配置检测条件的策略只能保存为停用草稿" /> : null}
          {!creating && editorPolicy ? <>
            <Alert type={auditOnly && ['mask', 'block'].includes(editorPolicy.action) ? 'warning' : 'info'} showIcon message={describeEffectiveAction({ configuredAction: editorPolicy.action, globalMode: mode?.effective_mode, auditOnly, enabled: editorPolicy.enabled }).explanation} />
            <section className="policy-effective-preview" aria-label="生效预览">
              <div className="policy-subject-heading">
                <div><strong>当前已发布版本生效预览</strong><small>按引擎当前规则包检查主体绑定和检测阶段，不预演未保存草稿。</small></div>
                <Button icon={<EyeOutlined />} disabled={!draftMatchesSavedPolicy} loading={previewMutation.isPending} onClick={() => previewMutation.mutate(previewDraft)}>运行预览</Button>
              </div>
              {!draftMatchesSavedPolicy ? <Alert type="warning" showIcon message="存在未保存修改" description="请先保存并等待策略进入发布包，再预览节点当前实际持有的版本。" /> : null}
              <div className="policy-preview-selectors">
                <label>检测阶段<Select aria-label="预览检测阶段" value={previewDraft.stage} onChange={(stage) => setPreviewDraft((current) => ({ ...current, stage }))} options={[
                  { value: 'input', label: '输入' },
                  { value: 'agent', label: '智能体' },
                  { value: 'output', label: '输出' },
                ]} /></label>
                <label>应用<Select allowClear showSearch optionFilterProp="label" aria-label="预览应用" value={previewDraft.application_id} onChange={(application_id) => setPreviewDraft((current) => ({
                  ...current,
                  application_id,
                  key_id: current.key_id && keys.find((item) => item.id === current.key_id)?.project_id !== application_id ? undefined : current.key_id,
                }))} options={projects.map((item) => ({ value: item.id, label: item.name }))} /></label>
                <label>稳定 Key<Select allowClear showSearch optionFilterProp="label" aria-label="预览 Key" value={previewDraft.key_id} onChange={(key_id) => {
                  const selected = keys.find((item) => item.id === key_id)
                  setPreviewDraft((current) => ({ ...current, key_id, application_id: selected?.project_id || current.application_id }))
                }} options={keys.map((item) => ({ value: item.id, label: item.name || item.key_prefix || item.id }))} /></label>
                <label>协议<Select allowClear aria-label="预览协议" value={previewDraft.protocol} onChange={(protocol) => setPreviewDraft((current) => ({ ...current, protocol }))} options={previewProtocolOptions(previewDraft.entry_point)} /></label>
                <label>入口<Select allowClear aria-label="预览入口" value={previewDraft.entry_point} onChange={(entry_point) => setPreviewDraft((current) => {
                  const allowed = previewProtocolOptions(entry_point).some((item) => item.value === current.protocol)
                  return { ...current, entry_point, protocol: current.protocol && !allowed ? undefined : current.protocol }
                })} options={[...ENTRY_POINT_OPTIONS]} /></label>
              </div>
              {previewResponse ? <div className="policy-preview-result">
                <div className="policy-preview-delivery" aria-label="策略发布状态">
                  <span><small>保存</small><StatusPill tone="green">已保存</StatusPill></span>
                  <span><small>发布包</small><StatusPill tone={previewPublished ? 'green' : 'orange'}>{previewPublished ? '已发布' : '未进入当前发布包'}</StatusPill></span>
                  <span><small>节点</small><StatusPill tone={previewNodesApplied ? 'green' : 'orange'}>{previewNodesApplied ? '节点已应用' : '等待节点回执'}</StatusPill></span>
                </div>
                {previewPolicy ? <>
                  <Alert
                    type={previewPolicy.matched ? 'success' : 'warning'}
                    showIcon
                    message={previewPolicy.matched ? '主体与阶段满足策略条件' : '当前主体或阶段不满足策略条件'}
                    description={previewPolicy.requires_finding ? '未提供检测内容，不生成模拟 finding；最终动作需在真实 finding 命中后计算。' : '该策略不会参与当前预览上下文。'}
                  />
                  <dl className="policy-preview-facts">
                    <div><dt>配置动作</dt><dd>{policyActionLabel(previewPolicy.configured_action)}</dd></div>
                    <div><dt>命中后候选动作</dt><dd>{previewPolicy.conditional_action ? policyActionLabel(previewPolicy.conditional_action) : '不适用'}</dd></div>
                    <div><dt>实际有效动作</dt><dd>{previewPolicy.effective_action ? policyActionLabel(previewPolicy.effective_action) : '需实际 finding 计算'}</dd></div>
                    <div><dt>阶段覆盖</dt><dd>{previewPolicy.stage_supported ? '支持' : '不支持'}</dd></div>
                  </dl>
                  {previewPolicy.binding_details.length > 0 ? <ul className="policy-preview-dimensions">
                    {previewPolicy.binding_details.map((detail) => <li key={detail.dimension}>
                      <StatusPill tone={detail.matched ? 'green' : 'orange'}>{detail.matched ? '匹配' : '未匹配'}</StatusPill>
                      <span>{PREVIEW_DIMENSION_LABELS[detail.dimension] || detail.dimension}</span>
                      <small>{PREVIEW_REASON_LABELS[detail.reason] || detail.reason}</small>
                    </li>)}
                  </ul> : <p className="policy-preview-unbound">当前策略无附加主体条件。</p>}
                  <div className="policy-preview-versions">
                    <span>策略版本 <code>{previewPolicy.policy_version}</code></span>
                    <span>发布版本 <code>{previewResponse.desired_version || '无'}</code></span>
                    <span>引擎版本 <code>{previewResponse.engine_rule_pack_version || '无'}</code></span>
                    <span>身份版本 <code>{previewResponse.identity_version}</code></span>
                  </div>
                </> : <Alert type="warning" showIcon message="当前引擎版本尚未包含该策略" />}
              </div> : null}
            </section>
            <Collapse ghost items={[{ key: 'technical', label: '技术详情', children: <dl className="policy-technical-details"><div><dt>策略 ID</dt><dd>{editorPolicy.id}</dd></div><div><dt>原始场景</dt><dd>{editorPolicy.scene}</dd></div><div><dt>来源</dt><dd>{editorPolicy.origin}</dd></div><div><dt>识别依据</dt><dd>{editorPolicy.detection_basis}</dd></div><div><dt>运行状态</dt><dd>{runtimeStatus || '未返回'}</dd></div></dl> }]} />
          </> : null}
        </div>
      </Drawer>

      <Modal zIndex={1100} open={confirmSaveOpen} title={creating ? createPolicyCount > 1 ? `确认创建并应用 ${createPolicyCount} 条策略` : '确认创建并应用策略' : '确认保存并应用策略'} okText="确认保存并应用" cancelText="返回检查" confirmLoading={saveMutation.isPending} onCancel={() => setConfirmSaveOpen(false)} onOk={() => saveMutation.mutate()}>
        <div className="policy-save-confirm"><p><strong>{draft.name}</strong></p><p>配置动作：{policyActionLabel(draft.action)}；当前全局模式下：{describeEffectiveAction({ configuredAction: draft.action, globalMode: mode?.effective_mode, auditOnly, enabled: draft.enabled }).effectiveLabel}</p><Alert type={draft.action === 'block' ? 'warning' : 'info'} showIcon message="保存成功后将等待运行时回执，页面会重新读取服务端状态。" /></div>
      </Modal>

      <Modal zIndex={1100} open={confirmBatchOpen} title={`确认批量配置 ${batchApplicablePolicies.length} 条策略`} okText="确认应用" cancelText="返回检查" confirmLoading={batchMutation.isPending} okButtonProps={{ disabled: batchApplicablePolicies.length === 0 }} onCancel={() => setConfirmBatchOpen(false)} onOk={submitBatch}>
        {batchSkippedCount > 0 ? <p>实际修改 {batchApplicablePolicies.length} 条，自动跳过 {batchSkippedCount} 条。</p> : null}
        {batchSkippedSummary ? <p>跳过原因：{batchSkippedSummary}</p> : null}
        <p>配置动作：{batchAction ? `统一改为${policyActionLabel(batchAction)}` : '保持原状'}</p>
        <p>启用状态：{batchEnabled === 'enabled' ? '统一启用' : batchEnabled === 'disabled' ? '统一停用' : '保持原状'}</p>
        <Alert type="warning" showIcon message="检测条件不会改变；批量更新采用服务端事务，任意一条失败时全部保持原状。" />
      </Modal>

      <Drawer width="min(620px, 100vw)" open={capabilityDrawer !== null} title={capabilityDrawer?.name || capabilityDrawer?.category} destroyOnHidden onClose={() => setCapabilityDrawer(null)}>
        {capabilityDrawer ? <div className="capability-detail-drawer">
          <Alert type="info" showIcon message="检测能力本身不等于已生效策略" description="只有被启用策略调用后，它才会参与对应场景的检测与处置。" />
          {capabilityDrawer.category === SEMANTIC_CONTEXT_CAPABILITY ? <p className="text-muted">{SEMANTIC_CONTEXT_COVERAGE_HINT}</p> : null}
          <dl><div><dt>内部标识</dt><dd>{capabilityDrawer.category}</dd></div><div><dt>风险类别</dt><dd>{capabilityRiskCategory(capabilityDrawer)}</dd></div><div><dt>检测阶段</dt><dd>{capabilityDrawer.supported_stages.map(detectionStageLabel).join('、')}</dd></div><div><dt>启用策略使用数</dt><dd>{capabilityUsage(capabilityDrawer)}</dd></div></dl>
          <h3>关联策略</h3>
          {policiesUsingCapability(policies, capabilityDrawer).map((policy) => <button className="capability-related-policy" type="button" key={policy.id} onClick={() => openPolicy(policy)}><span><strong>{policy.name}</strong><small>{policy.enabled ? '已启用' : '已停用'} · {policyActionLabel(policy.action)}</small></span><span>查看</span></button>)}
          {policiesUsingCapability(policies, capabilityDrawer).length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前没有关联策略" /> : null}
          {canManage ? <Button type="primary" onClick={() => openCreator(classifyPolicyScene({ scene: '', capabilities: [capabilityDrawer] }), capabilityDrawer.category)}>配置策略</Button> : null}
        </div> : null}
      </Drawer>
    </div>
  )
}

function SecurityPolicyCenter() {
  const auditIdentity = useAuditQueryIdentity()
  return <SecurityPolicyCenterContent key={auditIdentity} auditIdentity={auditIdentity} />
}

export default SecurityPolicyCenter

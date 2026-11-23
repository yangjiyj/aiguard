import { useEffect, useMemo, useRef, useState } from 'react'
import { Alert, Button, Checkbox, Modal, Tag, Tooltip } from 'antd'
import { Link } from 'react-router-dom'
import {
  isBasicAction,
  securityPoliciesApi,
  type PolicyCenterAgentBehavior,
  type PolicyCenterAgentBehaviorAction,
  type RestrictedFileScope,
} from '../../services/securityPoliciesApi'
import { saveAgentBehaviorDrafts, type SaveItemResult } from './simpleConfigurationModel'
import AgentExceptionModal from '../../components/protection/AgentExceptionModal'
import { ACTION_LABELS as SHARED_ACTION_LABELS } from '../../utils/actionLabels'
import {
  SaveImpactDialog,
  SaveResultBanner,
  ScenarioActionRow,
  type SaveImpactChange,
} from './SimpleConfigurationUI'

const BEHAVIOR_ORDER = [
  'destructive_operation',
  'system_command',
  'sensitive_resource',
  'network_egress',
  'database_change',
  'external_tool',
] as const

// 动作用词取统一标签；行为卡片的“告警放行”只对实际高风险命中告警，这里保留“风险”二字说明这一点。
const ACTION_LABELS: Record<PolicyCenterAgentBehaviorAction, string> = {
  ...SHARED_ACTION_LABELS,
  alert_allow: '风险告警并放行',
}

const POLICY_COPY = {
  modePrefix: "当前全局模式下",
  baseline: "基线动作",
  noticeTitle: "策略与执行分开看",
  noticeBody: "基线规定默认动作；例外和高级规则可能覆盖基线；实际结果以调用记录为准。",
  coverageTitle: "配置不代表已经控制",
  coverageBody: "需要客户端或工具网关接入控制链路。未接入的本地工具无法被网关阻止，不应显示“全面保护”。",
  conflict: "配置已被其他人修改，请确认后重试",
  readFailed: "读取最新配置失败，请稍后重试",
  healthError: "该类行为状态异常，请稍后重试。",
  saveFailed: "保存失败，请稍后重试",
  saved: "已保存",
  unknown: "实际处理待确认",
  advanced: "按单独规则处理",
  mismatch: "当前配置不一致",
  confirm: "确认保存",
  cancel: "取消",
}

function actionLabel(action: string, behaviorKey?: string, allowedActions?: readonly string[]) {
  if (behaviorKey === 'external_tool') return action === 'block' ? '禁用' : action === 'record' || action === 'alert_allow' ? '允许' : action
  return isBasicAction(action, allowedActions) ? ACTION_LABELS[action] : action
}

// 批内自冲突判定：同批前序 PUT 成功会推进共享版本（agentguard 合并策略摘要），
// 但不会改变后续项的动作本身。只有动作/高级覆盖信号变化才算第三方真实修改。
function agentBehaviorExternallyChanged(
  before: PolicyCenterAgentBehavior,
  after: PolicyCenterAgentBehavior,
): boolean {
  return before.configured_action !== after.configured_action
    || before.has_advanced_overrides !== after.has_advanced_overrides
    || (before.raw_configured_action ?? '') !== (after.raw_configured_action ?? '')
}

const SCENARIOS: Record<string, { label: string; description: string; href?: string }> = {
  destructive_operation: {
    label: '删除与破坏',
    description: '删除、覆盖、清空等不可逆操作。',
    href: '/security/agent-operation-protection/advanced',
  },
  system_command: {
    label: '系统命令',
    description: '系统工具全类拟调用（含普通 Shell）',
  },
  sensitive_resource: {
    label: "文件工具访问",
    description: "文件工具全类拟调用（含普通读写）",
  },
  network_egress: {
    label: '访问外部网络',
    description: '网络请求、上传和外部地址访问。',
  },
  database_change: {
    label: "数据库工具调用",
    description: "数据库工具全类拟调用（读写均包括）",
  },
  external_tool: {
    label: '调用外部工具',
    description: '单位已接入的 MCP 服务和工具。',
    href: '/mcp-gateway/policies',
  },
}

type AgentBehaviorPolicyProps = {
  items: PolicyCenterAgentBehavior[]
  auditOnly: boolean | undefined
  canManage: boolean
  focusKey?: string
  restrictedFileFocused?: boolean
  loadItems: () => Promise<PolicyCenterAgentBehavior[]>
  onReload: () => void | Promise<void>
  isLoading?: boolean
  isError?: boolean
}

function AgentBehaviorPolicy({
  items,
  auditOnly,
  canManage,
  focusKey,
  restrictedFileFocused = false,
  loadItems,
  onReload,
  isLoading = false,
  isError = false,
}: AgentBehaviorPolicyProps) {
  const [drafts, setDrafts] = useState<Record<string, PolicyCenterAgentBehaviorAction>>({})
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const [results, setResults] = useState<SaveItemResult[]>([])
  const [retryKeys, setRetryKeys] = useState<Set<string> | null>(null)
  const [confirmedItems, setConfirmedItems] = useState<Map<string, PolicyCenterAgentBehavior> | null>(null)
  const [conflictNotice, setConflictNotice] = useState<string | undefined>()
  const previousItemsRef = useRef(new Map<string, PolicyCenterAgentBehavior>())
  const draftBasesRef = useRef<Record<string, PolicyCenterAgentBehavior>>({})
  const canSaveRef = useRef(false)
  canSaveRef.current = canManage && !isLoading && !isError
  const failedDraftsRef = useRef<Record<string, PolicyCenterAgentBehaviorAction>>({})

  useEffect(() => {
    const previousItems = previousItemsRef.current
    const failedDrafts = failedDraftsRef.current
    setDrafts((current) => Object.fromEntries(items.flatMap((item) => {
      const previous = previousItems.get(item.key)
      const dirty = previous && current[item.key] !== undefined && current[item.key] !== previous.configured_action
      const draft = failedDrafts[item.key] ?? (dirty ? current[item.key] : item.configured_action)
      return isBasicAction(draft, item.allowed_actions) ? [[item.key, draft]] : []
    })))
    previousItemsRef.current = new Map(items.map((item) => [item.key, item]))
    failedDraftsRef.current = {}
  }, [items])

  useEffect(() => {
    canSaveRef.current = canManage && !isLoading && !isError
    return () => { canSaveRef.current = false }
  }, [canManage, isLoading, isError])

  const itemByKey = useMemo(() => new Map(items.map((item) => [item.key, item])), [items])
  useEffect(() => {
    if (!focusKey || !itemByKey.has(focusKey) || restrictedFileFocused) return
    document.getElementById(`agent-behavior-${focusKey}`)?.scrollIntoView?.({ block: 'center' })
  }, [focusKey, itemByKey, restrictedFileFocused])
  const pendingKeys = BEHAVIOR_ORDER.filter((key) => {
    const item = itemByKey.get(key)
    return !isError && !isLoading && item && item.health !== 'error' && isBasicAction(item.configured_action, item.allowed_actions) && drafts[key] && drafts[key] !== item.configured_action
  })
  const selectedKeys = retryKeys ? pendingKeys.filter((key) => retryKeys.has(key)) : pendingKeys
  const changes: SaveImpactChange[] = selectedKeys.map((key) => {
    const item = confirmedItems?.get(key) ?? itemByKey.get(key)!
    return {
      key,
      label: SCENARIOS[key]?.label ?? item.label,
      from: actionLabel(item.configured_action, key, item.allowed_actions),
      to: actionLabel(drafts[key], key, item.allowed_actions),
    }
  })

  const save = async () => {
    if (!canSaveRef.current || saving || selectedKeys.length === 0) return
    setSaving(true)
    setConfirmOpen(false)
    let needsConfirmation = false
    try {
      const latestItems = await loadItems()
      if (!canSaveRef.current) return
      const latestByKey = new Map(latestItems.map((item) => [item.key, item]))
      const unavailableKeys = selectedKeys.filter((key) => {
        const latest = latestByKey.get(key)
        return !latest || latest.health !== 'ok' || !isBasicAction(latest.configured_action, latest.allowed_actions)
      })
      const availableKeys = selectedKeys.filter((key) => !unavailableKeys.includes(key))
      if (availableKeys.some((key) => {
        const latest = latestByKey.get(key)
        const expected = confirmedItems?.get(key) ?? draftBasesRef.current[key] ?? itemByKey.get(key)
        return latest && expected && latest.version !== expected.version
      })) {
        needsConfirmation = true
        setConfirmedItems(latestByKey)
        setConflictNotice(POLICY_COPY.conflict)
        setConfirmOpen(true)
        return
      }
      let firstLoad = true
      let loadedByKey = latestByKey
      const nextResults = await saveAgentBehaviorDrafts({
        order: availableKeys,
        drafts,
        load: async () => {
          if (firstLoad) {
            firstLoad = false
            return latestItems
          }
          const loadedItems = await loadItems()
          loadedByKey = new Map(loadedItems.map((item) => [item.key, item]))
          return loadedItems
        },
        save: (key, input) => {
          const loaded = loadedByKey.get(key)
          if (!canSaveRef.current || !loaded || loaded.health !== 'ok' || !isBasicAction(loaded.configured_action, loaded.allowed_actions)) {
            throw new Error(POLICY_COPY.healthError)
          }
          // input.version 必须来自刚完成的权威读取；每项保存前 saveAgentBehaviorDrafts
          // 都会重新 GET，因此这里用的是批内刷新后的服务器快照，而不是首轮冻结快照。
          if (input.version !== loadedByKey.get(key)?.version) {
            throw Object.assign(new Error(POLICY_COPY.conflict), { response: { status: 409 } })
          }
          // 版本变化若伴随动作/高级覆盖信号变化，是第三方真实修改；仅共享版本推进
          // （本批前序 PUT 造成的）不算冲突。最终防线仍是服务器端 version_conflict 409。
          const batchStart = latestByKey.get(key)
          if (batchStart && agentBehaviorExternallyChanged(batchStart, loaded)) {
            throw Object.assign(new Error(POLICY_COPY.conflict), { response: { status: 409 } })
          }
          return securityPoliciesApi.updateAgentBehavior(key, input)
        },
      })
      nextResults.push(...unavailableKeys.map((key): SaveItemResult => ({
        key,
        status: 'skipped',
        previousAction: latestByKey.get(key)?.configured_action ?? 'unknown',
        requestedAction: drafts[key],
        message: latestByKey.get(key)?.health_message || POLICY_COPY.healthError,
      })))
      const freshByKey = new Map((await loadItems()).map((item) => [item.key, item]))
      const verifiedResults = nextResults.map((result): SaveItemResult => {
        if (result.status !== 'saved') {
          return result.status === 'failed' && result.message !== POLICY_COPY.conflict
            ? { ...result, message: POLICY_COPY.saveFailed }
            : result
        }
        const fresh = freshByKey.get(result.key)
        return fresh?.health === 'ok' && fresh.configured_action === result.requestedAction
          ? result
          : { ...result, status: 'failed', message: POLICY_COPY.mismatch }
      })
      failedDraftsRef.current = Object.fromEntries(verifiedResults.flatMap((result) => (
        result.status !== 'saved' && drafts[result.key]
          ? [[result.key, drafts[result.key]]]
          : []
      )))
      await onReload()
      setResults(verifiedResults)
      for (const result of verifiedResults) {
        if (result.status === 'saved') delete draftBasesRef.current[result.key]
      }
      setConfirmedItems(null)
      setConflictNotice(undefined)
    } catch {
      setResults(selectedKeys.map((key) => ({
        key,
        status: 'failed',
        previousAction: itemByKey.get(key)?.configured_action ?? 'unknown',
        requestedAction: drafts[key],
        message: POLICY_COPY.readFailed,
      })))
    } finally {
      if (!needsConfirmation) setRetryKeys(null)
      setSaving(false)
    }
  }

  if (isLoading && items.length === 0) return <div className="policy-center-empty">正在读取智能体行为状态...</div>

  return (
    <section className="agent-behavior-simple-view" aria-label="智能体行为配置">
      {isError ? <Alert type="error" showIcon message="智能体行为状态读取失败" description="当前不能确认各类行为的实际处理，也不会使用默认值代替。" /> : null}
      {auditOnly === true ? (
        <div className="agent-behavior-override-note"><span>全局执行：仅记录</span><Link to="/audit/access-retention?view=requests">行为记录</Link></div>
      ) : null}
      {auditOnly === undefined ? (
        <Alert type="warning" showIcon message="全局执行模式待确认" />
      ) : null}

      <div className="agent-behavior-scenario-list">
        {BEHAVIOR_ORDER.map((key) => {
          const item = itemByKey.get(key)
          if (!item) return null
          const scenario = SCENARIOS[key]
          const configured = actionLabel(item.configured_action, key, item.allowed_actions)
          const supported = isBasicAction(item.configured_action, item.allowed_actions)
          const effective = isError || isLoading || item.health === 'error' || auditOnly === undefined
            ? POLICY_COPY.unknown
            : auditOnly === true ? ACTION_LABELS.record : item.has_advanced_overrides ? POLICY_COPY.advanced : isBasicAction(item.current_action, item.allowed_actions) ? actionLabel(item.current_action, key, item.allowed_actions) : POLICY_COPY.unknown
          return (
            <div key={key} id={`agent-behavior-${key}`} className={`agent-behavior-scenario-item${focusKey === key ? ' is-focused' : ''}`}>
              <ScenarioActionRow
                title={scenario.label}
                description={scenario.description}
                configuredLabel={configured}
                effectiveLabel={effective}
                configuredLabelPrefix={POLICY_COPY.baseline}
                effectiveLabelPrefix={POLICY_COPY.modePrefix}
                value={drafts[key] ?? item.configured_action}
                options={(key === 'external_tool'
                  ? item.allowed_actions.filter((action) => action !== 'record')
                  : item.allowed_actions
                ).map((action) => ({ value: action, label: actionLabel(action, key, item.allowed_actions) }))}
                recordHref="/audit/access-retention?view=requests"
                recordLinkLabel="查看行为记录"
                disabled={!canManage || saving || isLoading || isError || item.health === 'error' || !supported}
                onChange={(action) => {
                  if (!isBasicAction(action, item.allowed_actions)) return
                  if (!draftBasesRef.current[key]) draftBasesRef.current[key] = item
                  if (action === item.configured_action) delete draftBasesRef.current[key]
                  setDrafts((current) => ({ ...current, [key]: action }))
                  setConfirmedItems(null)
                  setConflictNotice(undefined)
                  setResults([])
                  setRetryKeys(null)
                }}
              />
              <SpaceScope item={item} behaviorKey={key} />
              {item.health === 'error' || !supported ? (
                <Alert type="warning" showIcon message="当前不可保存" description={item.health_message || '该类行为状态异常，请稍后重试。'} />
              ) : null}
              {item.has_advanced_overrides ? (
                <div className="agent-behavior-override-note">
                  <span>部分工具有单独处理方式</span>
                  {item.raw_configured_action && item.raw_configured_action !== item.configured_action ? <code>{item.raw_configured_action}</code> : null}
                  {scenario.href ? <Link to={scenario.href}>查看单独调整</Link> : null}
                </div>
              ) : null}
              {key === 'external_tool' ? (
                <div className="agent-behavior-override-note">
                  <span>MCP 处置：放行或阻断</span>
                </div>
              ) : null}
              {key === 'sensitive_resource' ? (
                <RestrictedFileSection
                  item={item}
                  canManage={canManage}
                  focused={restrictedFileFocused}
                  disabled={saving || isLoading || isError}
                  loadItems={loadItems}
                  onSaved={onReload}
                />
              ) : null}
            </div>
          )
        })}
      </div>

      {canManage && pendingKeys.length > 0 ? (
        <div className="simple-config-save-bar">
          <span>共 {pendingKeys.length} 类行为待保存。</span>
          <Button type="primary" loading={saving} onClick={() => { setRetryKeys(null); setConfirmedItems(null); setConflictNotice(undefined); setConfirmOpen(true) }}>保存全部调整</Button>
        </div>
      ) : null}

      <SaveResultBanner
        results={results}
        itemLabels={Object.fromEntries(BEHAVIOR_ORDER.map((key) => [key, SCENARIOS[key].label]))}
        onRetry={canManage && !isError && !isLoading ? (keys) => { setRetryKeys(new Set(keys)); setConfirmedItems(null); setConflictNotice(undefined); setConfirmOpen(true) } : undefined}
      />
      <SaveImpactDialog
        open={confirmOpen}
        changes={changes}
        impact="风险告警仅针对实际高风险命中；整类阻断包括该类普通拟调用。MCP 允许或禁用只改变基础准入。敏感目标、兜底判定和受限文件按各自设置处理，全局执行模式不变。"
        notice={conflictNotice}
        confirmLoading={saving}
        onConfirm={() => void save()}
        onCancel={() => { setConfirmOpen(false); setRetryKeys(null) }}
      />

      <div className="agent-behavior-page-links">
        <Link to="/security/agents/advanced">例外与确认</Link>
        <Link to="/security/alerts">查看安全告警</Link>
        <Link to="/security/blocks">查看阻断记录</Link>
      </div>
    </section>
  )
}

function SpaceScope({ item, behaviorKey }: { item: PolicyCenterAgentBehavior; behaviorKey: string }) {
  return <div className="agent-behavior-override-note">
    {['system_command', 'sensitive_resource', 'network_egress', 'database_change'].includes(behaviorKey) ? <Tooltip title="仅实际参数或行为命中高风险时告警；普通拟调用只记录"><Tag>风险命中才告警</Tag></Tooltip> : behaviorKey === 'external_tool' ? <Tooltip title="允许不承诺发告警；MCP 参数与供应链防护在 MCP 调用策略中设置"><Tag>MCP 基础准入</Tag></Tooltip> : <Tag>破坏性参数判定</Tag>}
    <Tag>阶段：{item.evaluation_stage === 'invocation_proposed' ? '拟调用' : '待核验'}</Tag>
    <Tag>匹配：{item.match_pattern || (behaviorKey === 'destructive_operation' ? '破坏性参数' : behaviorKey === 'external_tool' ? 'MCP 网关' : '全类工具')}</Tag>
  </div>
}

type RestrictedFileSectionProps = {
  item: PolicyCenterAgentBehavior
  canManage: boolean
  focused?: boolean
  disabled: boolean
  loadItems: () => Promise<PolicyCenterAgentBehavior[]>
  onSaved: () => void | Promise<void>
}

const RESTRICTED_FILE_SCOPES: Array<{ value: RestrictedFileScope; label: string }> = [
  { value: 'tool_call', label: '工具调用' },
  { value: 'user_mention', label: '用户输入' },
  { value: 'proxy_output', label: '代理输出' },
]
const ALL_RESTRICTED_FILE_SCOPES = RESTRICTED_FILE_SCOPES.map((scope) => scope.value)

function normalizeScopes(scopes: readonly string[] | undefined): RestrictedFileScope[] {
  const list = Array.isArray(scopes) ? scopes : ALL_RESTRICTED_FILE_SCOPES
  return ALL_RESTRICTED_FILE_SCOPES.filter((scope) => list.includes(scope))
}

function restrictedFileDraft(item: PolicyCenterAgentBehavior) {
  return {
    text: (item.restricted_file_patterns ?? []).join('\n'),
    action: item.restricted_file_action ?? 'block',
    scopes: normalizeScopes(item.restricted_file_scopes),
  }
}

function sameRestrictedFileConfig(left: PolicyCenterAgentBehavior, right: PolicyCenterAgentBehavior) {
  return left.version === right.version
    && left.configured_action === right.configured_action
    && restrictedFileDraft(left).text === restrictedFileDraft(right).text
    && restrictedFileDraft(left).action === restrictedFileDraft(right).action
    && restrictedFileDraft(left).scopes.join(',') === restrictedFileDraft(right).scopes.join(',')
}

function RestrictedFileSection({ item, canManage, focused = false, disabled, loadItems, onSaved }: RestrictedFileSectionProps) {
  const [open, setOpen] = useState(focused)
  const [exceptionOpen, setExceptionOpen] = useState(false)
  const [draft, setDraft] = useState(() => restrictedFileDraft(item))
  const { text, action, scopes } = draft
  const sectionRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!focused) return
    setOpen(true)
    sectionRef.current?.scrollIntoView?.({ block: 'center' })
  }, [focused])
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [savedTip, setSavedTip] = useState(false)
  const [conflictItem, setConflictItem] = useState<PolicyCenterAgentBehavior | null>(null)
  const baselineRef = useRef(item)
  const previousItemRef = useRef(item)
  const latestPropRef = useRef(item)
  latestPropRef.current = item
  const savingRef = useRef(false)
  const canSaveRef = useRef(false)
  canSaveRef.current = canManage && !disabled && item.health === 'ok' && isBasicAction(item.configured_action, item.allowed_actions) && isBasicAction(action)
  const controlsDisabled = !canSaveRef.current || saving

  useEffect(() => {
    if (previousItemRef.current === item) return
    previousItemRef.current = item
    const baseline = baselineRef.current
    const stored = restrictedFileDraft(baseline)
    if (text !== stored.text || action !== stored.action || scopes.join(',') !== stored.scopes.join(',') || savingRef.current) return
    baselineRef.current = item
    setDraft(restrictedFileDraft(item))
    if (!sameRestrictedFileConfig(baseline, item)) setSavedTip(false)
  }, [item, text, action, scopes])

  useEffect(() => {
    canSaveRef.current = canManage && !disabled && item.health === 'ok' && isBasicAction(item.configured_action, item.allowed_actions) && isBasicAction(action)
    return () => { canSaveRef.current = false }
  }, [canManage, disabled, item.health, item.configured_action, item.allowed_actions, action])

  const validate = (patterns: string[]): string | null => {
    if (patterns.length > 64) return '最多 64 行'
    for (const p of patterns) {
      if (p.length > 128) return `模式 ${p} 超过 128 字符`
      if (/\s/.test(p)) return `模式 ${p} 含空白字符`
      if (/^https?:\/\//i.test(p)) return `模式 ${p} 不能是 URL`
    }
    return null
  }

  const handleSave = async (confirmedItem?: PolicyCenterAgentBehavior) => {
    if (!canSaveRef.current || savingRef.current) return
    const patterns = text.split('\n').map((line) => line.trim()).filter(Boolean)
    const unique = Array.from(new Set(patterns))
    const validationError = validate(unique) ?? (scopes.length === 0 ? '至少选择一个作用范围' : null)
    if (validationError) {
      setError(validationError)
      return
    }
    savingRef.current = true
    setSaving(true)
    setError(null)
    setSavedTip(false)
    let stage: 'read' | 'write' = 'read'
    try {
      const latest = (await loadItems()).find((candidate) => candidate.key === 'sensitive_resource')
      if (!canSaveRef.current) return
      if (!latest || latest.health !== 'ok' || !isBasicAction(latest.configured_action, latest.allowed_actions)) {
        setError(latest?.health_message || POLICY_COPY.healthError)
        return
      }
      if (!sameRestrictedFileConfig(latest, confirmedItem ?? baselineRef.current)) {
        setConflictItem(latest)
        return
      }
      setConflictItem(null)
      stage = 'write'
      await securityPoliciesApi.updateAgentBehavior('sensitive_resource', {
        action: latest.configured_action,
        version: latest.version,
        restricted_file_patterns: unique,
        restricted_file_action: action,
        restricted_file_scopes: scopes,
      })
      stage = 'read'
      const fresh = (await loadItems()).find((candidate) => candidate.key === 'sensitive_resource')
      await onSaved()
      if (!fresh || fresh.health !== 'ok') {
        setError(fresh?.health_message || POLICY_COPY.readFailed)
        return
      }
      if (restrictedFileDraft(fresh).text !== unique.join('\n') || restrictedFileDraft(fresh).action !== action
        || (fresh.restricted_file_scopes !== undefined && restrictedFileDraft(fresh).scopes.join(',') !== scopes.join(','))) {
        setError(POLICY_COPY.mismatch)
        return
      }
      baselineRef.current = fresh
      previousItemRef.current = latestPropRef.current
      setDraft(restrictedFileDraft(fresh))
      setSavedTip(true)
    } catch (error) {
      const status = (error as { response?: { status?: number } })?.response?.status
      setError(status === 409 ? POLICY_COPY.conflict : stage === 'read' ? POLICY_COPY.readFailed : POLICY_COPY.saveFailed)
    } finally {
      savingRef.current = false
      setSaving(false)
    }
  }

  return (
    <div ref={sectionRef} id="protection-item-agent.restricted_file" className={`restricted-file-section${focused ? ' is-focused' : ''}`} data-testid="restricted-file-section">
      <button type="button" className="restricted-file-toggle" onClick={() => setOpen((v) => !v)}>
        {open ? '▾' : '▸'} 额外禁止访问的文件
      </button>
      {exceptionOpen ? (
        <AgentExceptionModal
          prefill={{ scope_type: 'tenant', rule_id: 'agent.restricted_file' }}
          targetKind="file"
          onClose={() => setExceptionOpen(false)}
        />
      ) : null}
      <Modal
        title={POLICY_COPY.conflict}
        open={conflictItem !== null}
        okText={POLICY_COPY.confirm}
        cancelText={POLICY_COPY.cancel}
        okButtonProps={{ disabled: controlsDisabled }}
        confirmLoading={saving}
        onOk={() => { if (conflictItem) void handleSave(conflictItem) }}
        onCancel={() => setConflictItem(null)}
      >
        <p>{POLICY_COPY.baseline}: {conflictItem ? actionLabel(conflictItem.configured_action) : ''}</p>
        <pre>{conflictItem ? restrictedFileDraft(conflictItem).text : ''}</pre>
        <p>{conflictItem ? actionLabel(restrictedFileDraft(conflictItem).action) : ''} -&gt; {actionLabel(action)}</p>
        <pre>{text}</pre>
      </Modal>
      {open ? (
        <div className="restricted-file-body">
          <textarea
            aria-label="受限文件模式"
            rows={5}
            value={text}
            disabled={controlsDisabled}
            onChange={(e) => { setDraft((current) => ({ ...current, text: e.target.value })); setSavedTip(false); setError(null); setConflictItem(null) }}
            placeholder="*.pdf&#10;*.docx&#10;contracts/**&#10;/srv/finance/"
          />
          <div className="restricted-file-hint">
            每行一个模式，例如 <code>*.pdf</code>、<code>*.docx</code>、<code>contracts/**</code>、<code>/srv/finance/</code>
          </div>
          {item.builtin_patterns_summary ? (
            <div className="restricted-file-builtin">内置：{item.builtin_patterns_summary}</div>
          ) : null}
          <div className="restricted-file-action" role="radiogroup" aria-label="命中后的处理动作">
            {(['record', 'alert_allow', 'block'] as const).map((a) => (
              <label key={a}>
                <input
                  type="radio"
                  name="restricted-file-action"
                  value={a}
                  checked={action === a}
                  disabled={controlsDisabled}
                  onChange={() => { setDraft((current) => ({ ...current, action: a })); setSavedTip(false); setError(null); setConflictItem(null) }}
                />
                {SHARED_ACTION_LABELS[a]}
              </label>
            ))}
          </div>
          <div className="restricted-file-scopes">
            <span>作用范围</span>
            <Checkbox.Group
              aria-label="受限文件作用范围"
              value={scopes}
              disabled={controlsDisabled}
              options={RESTRICTED_FILE_SCOPES}
              onChange={(next) => { setDraft((current) => ({ ...current, scopes: normalizeScopes(next as string[]) })); setSavedTip(false); setError(null); setConflictItem(null) }}
            />
          </div>
          <div className="restricted-file-audit-note">「阻断」只在防护模式下生效；全局处于记录模式时只记录不阻断。</div>
          {error ? <Alert type="error" showIcon message={error} /> : null}
          {savedTip ? <Alert type="success" showIcon message={POLICY_COPY.saved} /> : null}
          {canManage ? (
            <div className="restricted-file-buttons">
              <Button type="primary" size="small" disabled={controlsDisabled} loading={saving} onClick={() => void handleSave()}>
                保存受限文件配置
              </Button>
              <Button size="small" onClick={() => setExceptionOpen(true)}>加例外</Button>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}

export default AgentBehaviorPolicy

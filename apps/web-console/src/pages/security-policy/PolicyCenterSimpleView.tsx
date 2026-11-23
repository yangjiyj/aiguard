import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, Tabs } from 'antd'
import {
  securityPoliciesApi,
  type SecurityPolicy,
  type SecurityPolicyAction,
  type SecurityPolicyBatchUpdate,
} from '../../services/securityPoliciesApi'
import {
  aggregatePolicyCenterStatus,
  CONTENT_SAFETY_CATEGORIES,
  findContentItemPolicies,
  findSensitiveItemPolicies,
  getPolicyActionLabel,
  SENSITIVE_DATA_CATEGORIES,
} from './policyCenterModel'
import { changedPolicyUpdates, type SaveItemResult } from './simpleConfigurationModel'
import FilePolicySettings from './FilePolicySettings'
import {
  SaveImpactDialog,
  SaveResultBanner,
  ScenarioActionRow,
  type SaveImpactChange,
} from './SimpleConfigurationUI'

type PolicyCenterSimpleViewProps = {
  policies: SecurityPolicy[]
  auditOnly: boolean | undefined
  runtimeVerified?: boolean
  runtimeStatus?: string
  canManage: boolean
  isLoading?: boolean
  isError?: boolean
  activeTab?: string
  onTabChange?: (key: string) => void
  onReload: () => Promise<void>
}

const ACTION_OPTIONS: Array<{ value: SecurityPolicyAction; label: string }> = [
  { value: 'audit', label: '告警' },
  { value: 'mask', label: '脱敏' },
  { value: 'block', label: '阻止' },
]

function errorLabel(error: unknown): string {
  if ((error as { response?: { status?: number } } | undefined)?.response?.status === 409) {
    return '配置已被其他人修改，请确认后重试'
  }
  return '保存失败，原配置继续生效'
}

function configuredAction(policies: SecurityPolicy[], fallback: SecurityPolicyAction): SecurityPolicyAction {
  return policies[0]?.action ?? fallback
}

function securityAlertHref(categories: string[]): string {
  const values = [...new Set(categories.map((value) => value.trim()).filter(Boolean))]
  if (values.length === 0) return '/security/alerts'
  return '/security/alerts?risk_category=' + encodeURIComponent(values.join(','))
}

function groupEffectiveLabel(
  policies: SecurityPolicy[],
  auditOnly: boolean | undefined,
  runtimeVerified: boolean | undefined,
  runtimeStatus: string | undefined,
): string {
  if (policies.length === 0) return '当前未配置'
  const labels = new Set(policies.map((policy) => {
    const status = aggregatePolicyCenterStatus({ policies: [policy], auditOnly, runtimeVerified, runtimeStatus })
    return status.key === 'error' ? '实际处理待确认' : status.currentAction
  }))
  return labels.size === 1 ? [...labels][0] : '按各项配置执行'
}

function allowedOptions(policies: SecurityPolicy[]): Array<{ value: SecurityPolicyAction; label: string }> {
  if (policies.length === 0) return ACTION_OPTIONS
  return ACTION_OPTIONS.filter(({ value }) => policies.every((policy) => (
    policy.capabilities.length === 0
    || policy.capabilities.every((capability) => capability.allowed_actions.includes(value))
  )))
}

function PolicyCenterSimpleView({
  policies,
  auditOnly,
  runtimeVerified,
  runtimeStatus,
  canManage,
  isLoading = false,
  isError = false,
  activeTab,
  onTabChange,
  onReload,
}: PolicyCenterSimpleViewProps) {
  const [drafts, setDrafts] = useState<Record<string, SecurityPolicyAction>>({})
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const [results, setResults] = useState<SaveItemResult[]>([])
  const [retryKeys, setRetryKeys] = useState<Set<string> | null>(null)

  useEffect(() => {
    setDrafts(Object.fromEntries(policies.map((policy) => [policy.id, policy.action])))
  }, [policies])

  const managedPolicies = useMemo(
    () => policies.filter((policy) => policy.origin === 'preloaded' && policy.detection_configured),
    [policies],
  )
  const promptPolicies = useMemo(
    () => managedPolicies.filter((policy) => policy.scene === 'prompt_injection' || policy.scene === 'prompt_leak'),
    [managedPolicies],
  )
  const requestedPolicyUpdates = useMemo<SecurityPolicyBatchUpdate[]>(() => (
    managedPolicies.map((policy) => ({ id: policy.id, action: drafts[policy.id] ?? policy.action, enabled: true }))
  ), [drafts, managedPolicies])
  const pendingPolicyUpdates = useMemo(
    () => changedPolicyUpdates(managedPolicies, requestedPolicyUpdates),
    [managedPolicies, requestedPolicyUpdates],
  )
  const allChanges = useMemo<SaveImpactChange[]>(() => {
    const policyByID = new Map(managedPolicies.map((policy) => [policy.id, policy]))
    return pendingPolicyUpdates.map((update) => {
      const policy = policyByID.get(update.id)!
      return {
        key: `policy-${update.id}`,
        label: policy.name,
        from: getPolicyActionLabel(policy.action),
        to: getPolicyActionLabel(update.action ?? policy.action),
      }
    })
  }, [managedPolicies, pendingPolicyUpdates])
  const visibleChanges = retryKeys ? allChanges.filter((change) => retryKeys.has(change.key)) : allChanges
  const unavailable = isLoading || isError || auditOnly === undefined
  const status = aggregatePolicyCenterStatus({ policies: managedPolicies, auditOnly, runtimeVerified, runtimeStatus })

  const setGroupAction = (items: SecurityPolicy[], action: SecurityPolicyAction) => {
    setDrafts((current) => ({
      ...current,
      ...Object.fromEntries(items.map((policy) => [policy.id, action])),
    }))
    setResults([])
    setRetryKeys(null)
  }

  const save = async () => {
    if (!canManage || saving || visibleChanges.length === 0) return
    setSaving(true)
    setConfirmOpen(false)
    const nextResults: SaveItemResult[] = []
    const selected = (key: string) => !retryKeys || retryKeys.has(key)
    const selectedUpdates = pendingPolicyUpdates.filter((update) => selected(`policy-${update.id}`))

    if (selectedUpdates.length > 0) {
      try {
        await securityPoliciesApi.batch(selectedUpdates)
        selectedUpdates.forEach((update) => {
          const previous = managedPolicies.find((policy) => policy.id === update.id)!
          nextResults.push({
            key: `policy-${update.id}`,
            status: 'saved',
            previousAction: previous.action,
            requestedAction: update.action ?? previous.action,
          })
        })
      } catch (error) {
        selectedUpdates.forEach((update) => {
          const previous = managedPolicies.find((policy) => policy.id === update.id)!
          nextResults.push({
            key: `policy-${update.id}`,
            status: 'failed',
            previousAction: previous.action,
            requestedAction: update.action ?? previous.action,
            message: errorLabel(error),
          })
        })
      }
    }

    try {
      await onReload()
    } catch (error) {
      nextResults.push({
        key: 'refresh',
        status: 'failed',
        previousAction: 'unknown',
        requestedAction: 'verified',
        message: errorLabel(error),
      })
    }
    setResults(nextResults)
    setRetryKeys(null)
    setSaving(false)
  }

  const itemLabels = Object.fromEntries([
    ...managedPolicies.map((policy) => [`policy-${policy.id}`, policy.name]),
    ['refresh', '运行状态确认'],
  ])
  const settingsChildren = (
    <div className="policy-center-tab-content">
      {isError ? (
        <Alert type="error" showIcon message="策略配置读取失败" description="没有取得完整配置，页面不会使用默认值代替，也不会允许保存。" />
      ) : null}
      {auditOnly !== true && !unavailable ? (
        <Alert type={status.key === 'error' ? 'warning' : 'success'} showIcon message={status.key === 'error' ? '实际处理待确认' : '保护正在运行'} description={status.reason} />
      ) : null}
      <section className="simple-config-scenario-group" aria-label="提示词攻击配置">
        <ScenarioActionRow
          title="提示词攻击"
          description="识别绕过指令、提示词泄露和越权要求。"
          configuredLabel={getPolicyActionLabel(configuredAction(promptPolicies, 'audit'))}
          effectiveLabel={groupEffectiveLabel(promptPolicies, auditOnly, runtimeVerified, runtimeStatus)}
          recordHref={securityAlertHref(['prompt_injection', 'prompt_leak'])}
          value={configuredAction(promptPolicies.map((policy) => ({ ...policy, action: drafts[policy.id] ?? policy.action })), 'audit')}
          options={allowedOptions(promptPolicies).filter((option) => option.value !== 'mask')}
          disabled={!canManage || unavailable || promptPolicies.length === 0}
          onChange={(action) => setGroupAction(promptPolicies, action)}
        />
      </section>
      {CONTENT_SAFETY_CATEGORIES.map((category) => {
        const categoryPolicies = [...new Map(category.items.flatMap((item) => (
          findContentItemPolicies(managedPolicies, item)
        )).map((policy) => [policy.id, policy])).values()]
        if (categoryPolicies.length === 0) return null
        const recordCategories = [...new Set([
          ...category.items.flatMap((item) => item.capabilityCategories),
          ...categoryPolicies.flatMap((policy) => policy.capabilities.map((capability) => capability.category)),
          ...categoryPolicies.map((policy) => policy.scene),
        ])]
        const draftPolicies = categoryPolicies.map((policy) => ({ ...policy, action: drafts[policy.id] ?? policy.action }))
        return (
          <section key={category.key} className="simple-config-scenario-group" aria-label={`${category.label}配置`}>
            <ScenarioActionRow
              title={category.label}
              description={category.description}
              configuredLabel={getPolicyActionLabel(configuredAction(categoryPolicies, category.defaultAction))}
              effectiveLabel={groupEffectiveLabel(categoryPolicies, auditOnly, runtimeVerified, runtimeStatus)}
              recordHref={securityAlertHref(recordCategories)}
              value={configuredAction(draftPolicies, category.defaultAction)}
              options={allowedOptions(categoryPolicies).filter((option) => option.value !== 'mask')}
              disabled={!canManage || unavailable || categoryPolicies.length === 0}
              onChange={(action) => setGroupAction(categoryPolicies, action)}
            />
          </section>
        )
      })}
    </div>
  )
  const sensitiveChildren = (
    <section className="simple-config-scenario-group policy-center-tab-content" aria-labelledby="sensitive-scenario-title">
      <div className="policy-center-section-heading">
        <h2 id="sensitive-scenario-title">敏感数据外发</h2>
        <p>按数据类型选择告警、脱敏或阻止发送。</p>
      </div>
      {SENSITIVE_DATA_CATEGORIES.map((category) => {
        const categoryPolicies = [...new Map(category.items.flatMap((item) => (
          findSensitiveItemPolicies(managedPolicies, item)
        )).map((policy) => [policy.id, policy])).values()]
        if (categoryPolicies.length === 0) return null
        const recordCategories = [...new Set([
          ...category.items.flatMap((item) => item.capabilityCategories),
          ...categoryPolicies.flatMap((policy) => policy.capabilities.map((capability) => capability.category)),
          ...categoryPolicies.map((policy) => policy.scene),
        ])]
        const draftPolicies = categoryPolicies.map((policy) => ({ ...policy, action: drafts[policy.id] ?? policy.action }))
        return (
          <section key={category.key} className="simple-config-scenario-group" aria-label={`${category.label}配置`}>
            <ScenarioActionRow
              title={category.label}
              description={category.description}
              configuredLabel={getPolicyActionLabel(configuredAction(categoryPolicies, category.defaultAction))}
              effectiveLabel={groupEffectiveLabel(categoryPolicies, auditOnly, runtimeVerified, runtimeStatus)}
              recordHref={securityAlertHref(recordCategories)}
              value={configuredAction(draftPolicies, category.defaultAction)}
              options={allowedOptions(categoryPolicies)}
              disabled={!canManage || unavailable || categoryPolicies.length === 0}
              onChange={(action) => setGroupAction(categoryPolicies, action)}
            />
          </section>
        )
      })}
    </section>
  )
  const tabs = [
    { key: 'settings', label: '策略设置', children: settingsChildren },
    { key: 'sensitive', label: '敏感数据外发', children: sensitiveChildren },
    { key: 'files', label: '网页 AI 附件准入', children: <FilePolicySettings canManage={canManage} showExceptions={false} /> },
    { key: 'custom', label: '全部策略', children: null },
  ]

  return (
    <div className="policy-center-simple-view">
      <Tabs
        className="policy-center-tabs"
        activeKey={activeTab}
        defaultActiveKey={activeTab ? undefined : 'settings'}
        onChange={onTabChange}
        items={tabs}
      />
      {canManage && allChanges.length > 0 ? (
        <div className="simple-config-save-bar">
          <span>共 {allChanges.length} 项调整，保存前会再次确认影响。</span>
          <Button type="primary" loading={saving} onClick={() => { setRetryKeys(null); setConfirmOpen(true) }}>保存全部调整</Button>
        </div>
      ) : null}
      <SaveResultBanner
        results={results}
        itemLabels={itemLabels}
        onRetry={(keys) => {
          const retryable = keys.filter((key) => key.startsWith('policy-'))
          if (retryable.length > 0) {
            setRetryKeys(new Set(retryable))
            setConfirmOpen(true)
          }
        }}
      />
      <SaveImpactDialog
        open={confirmOpen}
        changes={visibleChanges}
        impact="阻止会中断高风险请求；告警和脱敏会保留相应处置记录。"
        confirmLoading={saving}
        onConfirm={() => void save()}
        onCancel={() => { setConfirmOpen(false); setRetryKeys(null) }}
      />
    </div>
  )
}

export default PolicyCenterSimpleView

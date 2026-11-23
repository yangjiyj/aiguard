import { useMemo, useState } from 'react'
import { Alert, Button, Drawer, Modal, Progress, Select, message } from 'antd'
import { PlusOutlined, SettingOutlined } from '@ant-design/icons'
import { StatusPill } from '../../components/EnterpriseUI'
import { securityPoliciesApi, type SecurityPolicy } from '../../services/securityPoliciesApi'
import {
  findSensitiveItemPolicies,
  getEffectivePolicyActionLabel,
  getPolicyActionLabel,
  getSensitiveDataActions,
  hasHealthyRuntimeReceipt,
  isRuntimeSyncPending,
  SENSITIVE_DATA_CATEGORIES,
  type SensitiveDataCategory,
  type SensitiveDataCategoryKey,
} from './policyCenterModel'
import FilePolicySettings from './FilePolicySettings'
import RedactionConfigFields from './RedactionConfigFields'
import ClassifiedOutputDisposition from './ClassifiedOutputDisposition'

type SensitiveDataPolicyProps = {
  policies: SecurityPolicy[]
  auditOnly: boolean | undefined
  runtimeVerified?: boolean
  runtimeStatus?: string
  canManage: boolean
  onSaved: () => void | Promise<void>
  onCreateCustom?: () => void
  onOpenPolicy?: (policy: SecurityPolicy) => void
}

type CategorySummary = {
  category: SensitiveDataCategory
  itemStates: Array<{
    item: SensitiveDataCategory['items'][number]
    policies: SecurityPolicy[]
  }>
  policies: SecurityPolicy[]
  configuredCount: number
  missingCount: number
  ambiguousCount: number
  configuredAction: '' | SecurityPolicy['action']
  supportedActions: SecurityPolicy['action'][]
}

function summarizeCategory(category: SensitiveDataCategory, policies: SecurityPolicy[]): CategorySummary {
  const itemStates = category.items.map((item) => ({
    item,
    policies: findSensitiveItemPolicies(policies, item),
  }))
  const categoryPolicies = [...new Map(itemStates.flatMap((state) => state.policies).map((policy) => [policy.id, policy])).values()]
  const supportedActions = getSensitiveDataActions(categoryPolicies)
  const configuredActions = [...new Set(categoryPolicies.map((policy) => policy.action))]
  return {
    category,
    itemStates,
    policies: categoryPolicies,
    configuredCount: itemStates.filter((state) => (
      state.policies.length === 1 || (state.item.allowMultiplePolicies === true && state.policies.length > 1)
    )).length,
    missingCount: itemStates.filter((state) => state.policies.length === 0).length,
    ambiguousCount: itemStates.filter((state) => (
      state.policies.length > 1 && state.item.allowMultiplePolicies !== true
    )).length,
    configuredAction: configuredActions.length === 1 && supportedActions.includes(configuredActions[0])
      ? configuredActions[0]
      : '',
    supportedActions,
  }
}

function summaryStatus(summary: CategorySummary, runtimeHealthy: boolean, runtimeSyncing: boolean) {
  if (summary.ambiguousCount > 0) return { tone: 'red' as const, label: '配置需检查' }
  if (summary.configuredCount === 0) return { tone: 'gray' as const, label: '目录待接入' }
  if (runtimeSyncing) return { tone: 'orange' as const, label: '新配置同步中' }
  if (!runtimeHealthy) return { tone: 'red' as const, label: '运行异常' }
  if (summary.missingCount > 0) return { tone: 'blue' as const, label: '部分保护' }
  return { tone: 'green' as const, label: '已保护' }
}

function SensitiveDataPolicy({
  policies,
  auditOnly,
  runtimeVerified,
  runtimeStatus,
  canManage,
  onSaved,
  onCreateCustom,
  onOpenPolicy,
}: SensitiveDataPolicyProps) {
  const [selectedKey, setSelectedKey] = useState<SensitiveDataCategoryKey | 'file' | null>(null)
  const [action, setAction] = useState<'' | SecurityPolicy['action']>('')
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [redaction, setRedaction] = useState({ replacement: '<MASKED>', restore_response: false })
  const [saving, setSaving] = useState(false)
  const runtimeHealthy = hasHealthyRuntimeReceipt(runtimeVerified, runtimeStatus)
  const runtimeSyncing = isRuntimeSyncPending(runtimeVerified, runtimeStatus)
  const summaries = useMemo(
    () => SENSITIVE_DATA_CATEGORIES.map((category) => summarizeCategory(category, policies)),
    [policies],
  )
  const customSensitivePolicies = useMemo(() => policies.filter((policy) => (
    policy.origin === 'organization_created'
    && policy.detection_basis === 'matcher'
    && (policy.scene === 'data_leak' || policy.scene === 'data_security' || policy.scene === 'custom_rules')
  )), [policies])
  const selected = selectedKey === 'file'
    ? undefined
    : summaries.find((summary) => summary.category.key === selectedKey)

  const openCategory = (summary: CategorySummary) => {
    setAction(summary.configuredAction)
    setRedaction(summary.policies[0]?.redaction ?? { replacement: '<MASKED>', restore_response: false })
    setConfirmOpen(false)
    setSelectedKey(summary.category.key)
  }

  const save = async () => {
    if (!canManage || !selected || !action || selected.policies.length === 0 || selected.ambiguousCount > 0 || saving) return
    setSaving(true)
    try {
      await securityPoliciesApi.batch(selected.policies.map((policy) => ({ id: policy.id, action, ...(action === 'mask' ? { redaction } : {}) })))
      message.success(`${selected.category.label}配置已保存`)
      await onSaved()
      setConfirmOpen(false)
      setSelectedKey(null)
    } catch {
      message.error('敏感数据配置保存失败，服务端原配置未改变')
    } finally {
      setSaving(false)
    }
  }

  return (
    <section className="sensitive-policy-summary" aria-label="敏感数据外发配置">
      <div className="sensitive-policy-summary-head">
        <div>
          <h3>分类保护策略</h3>
          <p>按业务数据类别查看当前保护状态；具体检测项仅在配置时展开。</p>
        </div>
        <span>共 {SENSITIVE_DATA_CATEGORIES.length + 1} 类</span>
      </div>

      <div className="sensitive-policy-summary-table" role="table" aria-label="敏感数据分类保护状态">
        <div className="sensitive-policy-summary-row is-header" role="row">
          <span>数据类别</span><span>保护项</span><span>配置动作</span><span>当前动作</span><span>状态</span><span>操作</span>
        </div>
        {summaries.map((summary) => {
          const status = summaryStatus(summary, runtimeHealthy, runtimeSyncing)
          const effective = runtimeSyncing
            ? '原配置继续运行'
            : !runtimeHealthy
              ? '运行异常'
            : summary.configuredAction
              ? getEffectivePolicyActionLabel(summary.configuredAction, auditOnly)
              : summary.configuredCount > 0 ? '按具体策略执行' : '尚未参与检测'
          const percent = Math.round((summary.configuredCount / summary.category.items.length) * 100)
          return (
            <div className="sensitive-policy-summary-row" role="row" key={summary.category.key}>
              <span className="sensitive-policy-category"><strong>{summary.category.label}</strong><small>{summary.category.description}</small></span>
              <span className="sensitive-policy-coverage"><strong>{summary.configuredCount} / {summary.category.items.length}</strong><Progress percent={percent} showInfo={false} size="small" /></span>
              <span>{summary.configuredAction ? getPolicyActionLabel(summary.configuredAction) : summary.configuredCount > 0 ? '按具体策略' : '尚未配置'}</span>
              <span>{effective}</span>
              <span><StatusPill tone={status.tone}>{status.label}</StatusPill></span>
              <span><Button size="small" icon={<SettingOutlined />} onClick={() => openCategory(summary)}>配置</Button></span>
            </div>
          )
        })}
        <div className="sensitive-policy-summary-row" role="row">
          <span className="sensitive-policy-category"><strong>文件与附件</strong><small>文件类型、正文检测、大小限制和内容例外。</small></span>
          <span>独立配置</span><span>按文件规则</span><span>以文件策略为准</span>
          <span><StatusPill tone="blue">独立管控</StatusPill></span>
          <span><Button size="small" icon={<SettingOutlined />} onClick={() => { setAction(''); setConfirmOpen(false); setSelectedKey('file') }}>配置</Button></span>
        </div>
      </div>

      <div className="custom-sensitive-policy-panel" aria-label="自定义敏感信息策略">
        <div>
          <h3>自定义敏感信息策略</h3>
          <p>用企业自己的关键词、字段名称或正则表达式识别专有数据；适合客户名称、项目代号、内部编号和业务术语。</p>
        </div>
        {canManage && onCreateCustom ? <Button type="primary" icon={<PlusOutlined />} onClick={onCreateCustom}>新建自定义敏感信息策略</Button> : null}
        <div className="custom-sensitive-policy-list">
          {customSensitivePolicies.map((policy) => <button type="button" key={policy.id} disabled={!onOpenPolicy} onClick={() => onOpenPolicy?.(policy)}><span><strong>{policy.name}</strong><small>{policy.enabled ? '已启用' : '已停用'} · {getPolicyActionLabel(policy.action)}</small></span><span>配置</span></button>)}
          {customSensitivePolicies.length === 0 ? <span className="custom-sensitive-policy-empty">当前还没有组织自定义敏感信息策略。</span> : null}
        </div>
      </div>

      <Drawer
        width="min(720px, 100vw)"
        open={selectedKey !== null}
        destroyOnHidden
        title={selectedKey === 'file' ? '文件与附件安全' : selected?.category.label}
        onClose={() => setSelectedKey(null)}
        footer={selectedKey === 'file' ? null : (
          <div className="policy-drawer-footer">
            <Button onClick={() => setSelectedKey(null)}>取消</Button>
            {canManage ? <Button type="primary" disabled={!selected || !action || selected.ambiguousCount > 0 || (action === 'mask' && (!redaction.replacement.trim() || redaction.replacement.includes('<JJD_')))} onClick={() => setConfirmOpen(true)}>保存并应用</Button> : null}
          </div>
        )}
      >
        {selectedKey === 'file' ? <FilePolicySettings canManage={canManage} /> : selected ? (
          <div className="sensitive-policy-drawer">
            <p>{selected.category.description}</p>
            {selected.ambiguousCount > 0 ? <Alert type="error" showIcon message="存在重复识别配置，暂不能批量保存" /> : null}
            {runtimeSyncing ? <Alert type="info" showIcon message="新配置同步中" description="新动作已保存，正在等待安全引擎回执；原配置继续运行。" /> : null}
            {!runtimeHealthy && !runtimeSyncing ? <Alert type="error" showIcon message="运行状态异常，请检查安全引擎回执。" /> : null}
            <label>
              类别处置动作
              <Select
                aria-label={`${selected.category.label}处置动作`}
                value={action || undefined}
                placeholder={selected.configuredCount > 0 ? '当前包含多种动作' : '当前没有可统一配置的策略'}
                disabled={!canManage || selected.supportedActions.length === 0}
                onChange={(value) => setAction(value)}
                options={selected.supportedActions.map((value) => ({ value, label: getPolicyActionLabel(value) }))}
              />
            </label>
            {action === 'mask' ? <RedactionConfigFields value={redaction} disabled={!canManage} onChange={setRedaction} /> : null}
            <div className="sensitive-policy-item-grid" aria-label={`${selected.category.label}检测项`}>
              {selected.itemStates.map(({ item, policies: matches }) => {
                const matched = matches[0]
                const ambiguous = matches.length > 1 && item.allowMultiplePolicies !== true
                const itemActions = [...new Set(matches.map((policy) => policy.action))]
                const configuredActionLabel = itemActions.length === 1
                  ? getPolicyActionLabel(itemActions[0])
                  : '按具体策略'
                const effectiveActionLabel = itemActions.length === 1
                  ? getEffectivePolicyActionLabel(itemActions[0], auditOnly)
                  : runtimeSyncing ? '原配置继续运行' : runtimeHealthy ? '按具体策略执行' : '运行异常'
                const status = ambiguous
                  ? { tone: 'red' as const, label: '配置需检查' }
                  : matched
                    ? { tone: 'green' as const, label: '已接入' }
                    : { tone: 'gray' as const, label: '目录待接入' }
                return (
                  <div key={item.key}>
                    <span><strong>{item.label}</strong><small>{matched ? `${configuredActionLabel} · ${effectiveActionLabel}` : '当前没有可执行识别条件'}</small></span>
                    <StatusPill tone={status.tone}>{status.label}</StatusPill>
                    {item.key === 'classified_file' ? <ClassifiedOutputDisposition canManage={canManage} /> : null}
                  </div>
                )
              })}
            </div>
            {selected.missingCount > 0 ? <p className="sensitive-policy-maintenance-note">另有 {selected.missingCount} 个目录项尚未接入运行检测，仅供平台后续维护，不影响已接入项目。</p> : null}
          </div>
        ) : null}
      </Drawer>

      <Modal
        zIndex={1100}
        open={confirmOpen}
        title={`确认保存${selected?.category.label ?? ''}配置`}
        okText="确认保存并应用"
        cancelText="返回检查"
        confirmLoading={saving}
        onCancel={() => setConfirmOpen(false)}
        onOk={() => void save()}
      >
        <p>将 {selected?.configuredCount ?? 0} 个已接入保护项统一调整为“{action ? getPolicyActionLabel(action) : '未选择'}”。目录待接入项不会被修改。</p>
      </Modal>
    </section>
  )
}

export default SensitiveDataPolicy

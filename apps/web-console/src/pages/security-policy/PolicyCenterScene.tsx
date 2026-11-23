import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, message } from 'antd'
import {
  getEffectivePolicyActionLabel,
  getPolicyActionLabel,
  getPolicyCenterScene,
  hasHealthyRuntimeReceipt,
  policiesForScene,
  type PolicyCenterSectionKey,
} from './policyCenterModel'
import { securityPoliciesApi, type SecurityPolicy } from '../../services/securityPoliciesApi'

type PolicyCenterSceneProps = {
  sceneKey: Extract<PolicyCenterSectionKey, 'prompt-injection' | 'content-safety'>
  policies: SecurityPolicy[]
  auditOnly: boolean | undefined
  runtimeVerified?: boolean
  runtimeStatus?: string
  canManage: boolean
  onSaved: () => void | Promise<void>
}

const ACTIONS: SecurityPolicy['action'][] = ['audit', 'block']

function actionLabel(action: SecurityPolicy['action'], sceneKey: PolicyCenterSceneProps['sceneKey']): string {
  if (action === 'block' && sceneKey === 'prompt-injection') return '阻止请求'
  return getPolicyActionLabel(action)
}

function PolicyCenterScene({
  sceneKey,
  policies,
  auditOnly,
  runtimeVerified,
  runtimeStatus,
  canManage,
  onSaved,
}: PolicyCenterSceneProps) {
  const scene = getPolicyCenterScene(sceneKey)
  const scenePolicies = useMemo(() => (
    scene
      ? policiesForScene(policies, scene).filter((policy) => policy.detection_configured)
      : []
  ), [policies, scene])

  const [action, setAction] = useState<'' | SecurityPolicy['action']>('')
  const [saving, setSaving] = useState(false)

  const enabledPolicies = scenePolicies.filter((policy) => policy.enabled)

  const configuredActions = [...new Set(scenePolicies.map((policy) => policy.action))]
  const configuredAction = configuredActions.length === 1 && ACTIONS.includes(configuredActions[0])
    ? configuredActions[0]
    : ''
  useEffect(() => {
    setAction(configuredAction)
  }, [configuredAction, sceneKey])

  const runtimeHealthy = hasHealthyRuntimeReceipt(runtimeVerified, runtimeStatus)
  const statusLabel = enabledPolicies.length === 0
    ? '已停用'
    : runtimeHealthy
      ? auditOnly === true ? '记录中' : auditOnly === false ? '保护中' : '运行异常'
      : '运行异常'

  const save = async () => {
    if (!canManage || !action || scenePolicies.length === 0 || saving) return
    setSaving(true)
    try {
      await securityPoliciesApi.batch(scenePolicies.map((policy) => ({ id: policy.id, action })))
      message.success('场景配置已保存')
      await onSaved()
    } catch {
      message.error('场景配置保存失败，当前配置未改变')
    } finally {
      setSaving(false)
    }
  }

  return (
    <section className="policy-center-scene" aria-label={(scene?.label ?? '场景') + '配置'}>
      <div className="policy-center-section-heading">
        <div>
          <h2>{scene?.label}</h2>
          <p>{scene?.description}</p>
        </div>
        <span className="policy-center-scene-status">{statusLabel}</span>
      </div>
      {!runtimeHealthy && scenePolicies.length > 0 ? (
        <Alert
          type="warning"
          showIcon
          message="运行异常"
          description="运行回执尚未确认，当前只展示已保存配置；请确认节点状态后再宣称保护已生效。"
        />
      ) : null}
      <div className="policy-center-simple-controls">
        <label htmlFor={sceneKey + '-action'}>
          场景处置动作
          <select
            id={sceneKey + '-action'}
            aria-label={(scene?.label ?? '场景') + '处置动作'}
            value={action}
            disabled={!canManage || scenePolicies.length === 0 || saving}
            onChange={(event) => setAction(event.target.value as '' | SecurityPolicy['action'])}
          >
            <option value="">当前配置不一致</option>
            {ACTIONS.map((item) => <option key={item} value={item}>{actionLabel(item, sceneKey)}</option>)}
          </select>
        </label>
        <Button
          type="primary"
          aria-label={'保存 ' + (scene?.label ?? '场景') + '配置'}
          disabled={!canManage || !action || scenePolicies.length === 0 || saving}
          loading={saving}
          onClick={save}
        >
          保存配置
        </Button>
      </div>
      <div className="policy-center-scene-list">
        {scenePolicies.length > 0 ? scenePolicies.map((policy) => (
          <div key={policy.id} className="policy-center-scene-item">
            <span>{policy.name}</span>
            <span>已配置：{actionLabel(policy.action, sceneKey)}</span>
            <span>当前实际处理：{runtimeHealthy ? getEffectivePolicyActionLabel(policy.action, auditOnly) : '实际处理待确认'}</span>
          </div>
        )) : <div className="policy-center-empty">当前没有可展示的客户策略。</div>}
      </div>
      <details className="policy-center-detection-details">
        <summary>检测内容</summary>
        {scenePolicies.length > 0 ? (
          <ul>
            {scenePolicies.map((policy) => <li key={policy.id}>{policy.name}</li>)}
          </ul>
        ) : <p>当前没有已配置的检测内容。</p>}
      </details>
    </section>
  )
}

export default PolicyCenterScene

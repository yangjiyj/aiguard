import { useEffect, useState } from 'react'
import { Alert, Button, InputNumber, Switch } from 'antd'
import {
  agentGuardSequenceRuleApi,
  isBasicAction,
  type PolicyCenterAgentBehavior,
} from '../../services/securityPoliciesApi'
import { SEQUENCE_DEFAULT_MINUTES, SEQUENCE_MAX_MINUTES, sequenceWindowSeconds } from './sequenceRule'

type NetworkBehavior = PolicyCenterAgentBehavior & { sensitive_read_egress_window_seconds?: number }

type Props = {
  item?: NetworkBehavior
  canManage: boolean
  onSaved: () => Promise<void> | void
}

export default function SequenceRuleSettings({ item, canManage, onSaved }: Props) {
  const storedSeconds = item?.sensitive_read_egress_window_seconds ?? 0
  const [enabled, setEnabled] = useState(storedSeconds > 0)
  const [minutes, setMinutes] = useState<number | null>(storedSeconds > 0 ? Math.round(storedSeconds / 60) : SEQUENCE_DEFAULT_MINUTES)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    setEnabled(storedSeconds > 0)
    setMinutes(storedSeconds > 0 ? Math.round(storedSeconds / 60) : SEQUENCE_DEFAULT_MINUTES)
  }, [storedSeconds])

  if (!item || item.health !== 'ok') return null
  const configuredAction = item.configured_action
  const supported = isBasicAction(configuredAction)
  const displayEnabled = supported ? enabled : storedSeconds > 0
  const displayMinutes = supported ? minutes : Math.round(storedSeconds / 60)
  const dirty = sequenceWindowSeconds(enabled, minutes) !== storedSeconds

  const save = async () => {
    if (!canManage || saving || item.health !== 'ok' || !isBasicAction(configuredAction)) return
    setSaving(true)
    setError('')
    try {
      await agentGuardSequenceRuleApi.update({
        action: configuredAction,
        version: item.version,
        sensitive_read_egress_window_seconds: sequenceWindowSeconds(enabled, minutes),
      })
      await onSaved()
    } catch {
      setError('保存失败，请刷新后重试')
    } finally {
      setSaving(false)
    }
  }

  return (
    <section className="agent-behavior-sequence-rule" data-testid="sequence-rule-settings" aria-label="敏感读取后外发">
      <div className="agent-behavior-sequence-rule-header">
        <strong>敏感读取后外发</strong>
        <Switch
          checked={displayEnabled}
          disabled={!canManage || !supported || saving}
          onChange={setEnabled}
          aria-label="启用敏感读取后外发检测"
        />
      </div>
      <p className="agent-behavior-sequence-rule-description">
        同一智能体读取敏感或受限文件后，在时间窗内发起网络外发（含 curl、scp 等命令）时要求人工确认；记录模式下只记录。
      </p>
      {displayEnabled && (
        <label className="agent-behavior-sequence-rule-window">
          时间窗（分钟）
          <InputNumber
            min={1}
            max={SEQUENCE_MAX_MINUTES}
            value={displayMinutes}
            disabled={!canManage || !supported || saving}
            onChange={(value) => setMinutes(typeof value === 'number' ? value : null)}
            aria-label="时间窗（分钟）"
          />
        </label>
      )}
      {error && <Alert type="error" showIcon message={error} />}
      {canManage && supported && (
        <Button type="primary" disabled={!dirty} loading={saving} onClick={save} data-testid="sequence-rule-save">
          保存
        </Button>
      )}
    </section>
  )
}

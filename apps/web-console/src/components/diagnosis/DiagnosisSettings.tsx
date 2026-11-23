import { useEffect, useState } from 'react'
import { Alert, Descriptions, Form, Modal, Select, Spin, Switch, message } from 'antd'
import { diagnosticsApi, type DiagnosisSettingsData } from '../../services/api'

export default function DiagnosisSettings({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [settings, setSettings] = useState<DiagnosisSettingsData | null>(null)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    if (!open) return
    let active = true
    setLoading(true)
    setSettings(null)
    setError('')
    diagnosticsApi.getSettings().then((response) => {
      if (!active) return
      setSettings(response.data)
    }).catch(() => { if (active) setError('诊断设置读取失败，请重新打开重试') }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [open])
  const save = async () => {
    if (!settings) return
    setSaving(true)
    setError('')
    try {
      await diagnosticsApi.putSettings({ ai_enabled: settings.ai_enabled, model_id: settings.model_id })
      message.success('诊断设置已保存')
      onClose()
    } catch { setError('诊断设置保存失败，请重试') }
    finally { setSaving(false) }
  }
  return <Modal title="诊断设置" open={open} onCancel={onClose} onOk={save} okText="保存" cancelText="取消" confirmLoading={saving} okButtonProps={{ disabled: loading || !settings }}>
    {error && <Alert type="error" message={error} />}
    <Spin spinning={loading}>
      {settings && <>
        <Form layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item label="AI 解读"><Switch aria-label="AI 解读" checked={settings.ai_enabled} onChange={(ai_enabled) => setSettings({ ...settings, ai_enabled })} /></Form.Item>
          <Form.Item label="模型"><Select aria-label="模型" allowClear placeholder={settings.effective_model_name ? `自动选择（当前：${settings.effective_model_name}）` : '自动选择'} style={{ width: '100%' }} options={settings.models.map((model) => ({ value: model.id, label: model.name }))} value={settings.model_id || undefined} onChange={(model_id) => setSettings({ ...settings, model_id: model_id || null })} /></Form.Item>
        </Form>
        <Descriptions size="small" column={1} items={[
          { key: 'check', label: '自检结果', children: settings.selfcheck ? `${settings.selfcheck.passed ? '通过' : '未通过'} · ${settings.selfcheck.score}/5 · ${settings.selfcheck.model_name ? `${settings.selfcheck.model_name} · ` : ''}${settings.selfcheck.tested_at ? new Date(settings.selfcheck.tested_at).toLocaleString('zh-CN') : '未记录时间'}` : '未自检' },
          { key: 'agent', label: '采集器状态', children: settings.agent_installed ? '已安装' : '未安装' },
          { key: 'seen', label: '最近上报时间', children: settings.agent_last_seen ? new Date(settings.agent_last_seen).toLocaleString('zh-CN') : '未上报' },
        ]} />
      </>}
    </Spin>
  </Modal>
}

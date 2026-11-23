import { useEffect, useState } from 'react'
import { Button, Form, Input, InputNumber, Switch, message } from 'antd'
import { consoleLoginSecurityApi, type ConsoleLoginSecuritySettings } from '../../services/api'
import { LOGIN_SECURITY_SETTINGS_TEXT as T } from './text'
import { loginSecuritySaveError } from './loginErrors'

// W3: console login security settings (lockout, password policy, session timeouts, admin TOTP, admin IP allowlist).
// Bounds mirror handler.consoleIntSettingBounds; the backend validates bounds and refuses an allowlist that would lock out the current administrator.

type NumericKey = Exclude<keyof ConsoleLoginSecuritySettings, 'admin_totp_required' | 'admin_ip_allowlist'>

const NUMERIC_FIELDS: Array<{ name: NumericKey; label: string; min: number; max: number }> = [
  { name: 'lockout_threshold', label: T.lockoutThreshold, min: 1, max: 100 },
  { name: 'lockout_minutes', label: T.lockoutMinutes, min: 1, max: 1440 },
  { name: 'password_min_length', label: T.passwordMinLength, min: 8, max: 128 },
  { name: 'password_min_classes', label: T.passwordMinClasses, min: 1, max: 4 },
  { name: 'password_history_count', label: T.passwordHistoryCount, min: 0, max: 24 },
  { name: 'password_max_age_days', label: T.passwordMaxAgeDays, min: 0, max: 3650 },
  { name: 'session_idle_minutes', label: T.sessionIdleMinutes, min: 5, max: 1440 },
  { name: 'session_absolute_hours', label: T.sessionAbsoluteHours, min: 1, max: 168 },
  { name: 'session_max_concurrent', label: T.sessionMaxConcurrent, min: 0, max: 100 },
]

function LoginSecuritySettings() {
  const [form] = Form.useForm<ConsoleLoginSecuritySettings>()
  const [loaded, setLoaded] = useState(false)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    let cancelled = false
    consoleLoginSecurityApi.getSettings()
      .then((response) => {
        if (cancelled) return
        form.setFieldsValue(response.data)
        setLoaded(true)
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [form])

  const onFinish = async (values: ConsoleLoginSecuritySettings) => {
    setSaving(true)
    try {
      const response = await consoleLoginSecurityApi.updateSettings({ ...values, admin_ip_allowlist: values.admin_ip_allowlist ?? '' })
      form.setFieldsValue(response.data)
      message.success(T.saved)
    } catch (error) {
      message.error(loginSecuritySaveError(error))
    } finally {
      setSaving(false)
    }
  }

  return (
    <section aria-label={T.title}>
      <h3>{T.title}</h3>
      <Form form={form} layout="vertical" onFinish={onFinish} disabled={!loaded}>
        {NUMERIC_FIELDS.map((field) => (
          <Form.Item key={field.name} name={field.name} label={field.label} rules={[{ required: true }]}>
            <InputNumber min={field.min} max={field.max} precision={0} style={{ width: 200 }} aria-label={field.label} />
          </Form.Item>
        ))}
        <Form.Item name="admin_totp_required" label={T.adminTotpRequired} valuePropName="checked">
          <Switch aria-label={T.adminTotpRequired} />
        </Form.Item>
        <Form.Item name="admin_ip_allowlist" label={T.adminIpAllowlist}>
          <Input aria-label={T.adminIpAllowlist} placeholder="10.0.0.0/8, 192.168.1.10" />
        </Form.Item>
        <Form.Item>
          <Button type="primary" htmlType="submit" loading={saving}>{T.save}</Button>
        </Form.Item>
      </Form>
    </section>
  )
}

export default LoginSecuritySettings

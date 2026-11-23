import { useEffect, useState } from 'react'
import { Alert, Button, Form, Input, Typography, message } from 'antd'
import { KeyOutlined } from '@ant-design/icons'
import { consoleLoginSecurityApi } from '../../services/api'
import { LOGIN_TEXT, TOTP_ENROLL_TEXT } from './text'

interface TotpEnrollProps {
  // Enrollment-only session token returned by login. It is not stored until enrollment succeeds.
  token: string
  onDone: () => void
}

interface EnrollSecret {
  secret: string
  otpauth_uri: string
}

function TotpEnroll({ token, onDone }: TotpEnrollProps) {
  const [secret, setSecret] = useState<EnrollSecret | null>(null)
  const [loadFailed, setLoadFailed] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    let cancelled = false
    consoleLoginSecurityApi.setupTOTP(token)
      .then((response) => {
        if (!cancelled) setSecret(response.data)
      })
      .catch(() => {
        if (!cancelled) setLoadFailed(true)
      })
    return () => {
      cancelled = true
    }
  }, [token])

  const onFinish = async (values: { code: string }) => {
    setSubmitting(true)
    try {
      await consoleLoginSecurityApi.enableTOTP(values.code, token)
      message.success(TOTP_ENROLL_TEXT.success)
      onDone()
    } catch {
      message.error(TOTP_ENROLL_TEXT.invalidCode)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="totp-enroll">
      <div className="login-panel-heading">
        <h2>{TOTP_ENROLL_TEXT.title}</h2>
        <p>{TOTP_ENROLL_TEXT.intro}</p>
      </div>
      {loadFailed && <Alert type="error" showIcon message={TOTP_ENROLL_TEXT.loadFailed} style={{ marginBottom: 16 }} />}
      {secret && (
        <>
          <Typography.Paragraph>
            <Typography.Text type="secondary">{TOTP_ENROLL_TEXT.secretLabel}</Typography.Text>
            <br />
            <Typography.Text code copyable data-testid="totp-secret">{secret.secret}</Typography.Text>
          </Typography.Paragraph>
          <Typography.Paragraph>
            <Typography.Text type="secondary">{TOTP_ENROLL_TEXT.uriLabel}</Typography.Text>
            <br />
            <Typography.Text copyable style={{ wordBreak: 'break-all' }}>{secret.otpauth_uri}</Typography.Text>
          </Typography.Paragraph>
          <Form onFinish={onFinish} layout="vertical" requiredMark={false}>
            <Form.Item
              label={LOGIN_TEXT.totpLabel}
              name="code"
              rules={[{ required: true, pattern: /^\d{6}$/, message: LOGIN_TEXT.totpRule }]}
            >
              <Input prefix={<KeyOutlined />} placeholder={LOGIN_TEXT.totpPlaceholder} size="large" maxLength={6} inputMode="numeric" autoComplete="one-time-code" />
            </Form.Item>
            <Form.Item className="login-submit-item">
              <Button type="primary" htmlType="submit" loading={submitting} block size="large">
                {TOTP_ENROLL_TEXT.confirm}
              </Button>
            </Form.Item>
          </Form>
        </>
      )}
    </div>
  )
}

export default TotpEnroll

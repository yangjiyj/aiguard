import { Form, Input, Button, Alert, message } from 'antd'
import { LockOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import { useMutation } from '@tanstack/react-query'
import { authApi } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { useNavigate } from 'react-router-dom'
import { openAuthenticatedChat } from '../utils/access'
import { PASSWORD_TEXT } from './login-security/text'
import { passwordCharClasses, passwordErrorMessage } from './login-security/loginErrors'

interface ChangePasswordForm {
  current_password: string
  new_password: string
  confirm_password: string
}

// Client-side checks mirror the default policy for instant feedback only; the backend enforces the configured policy.
const DEFAULT_MIN_LENGTH = 12
const DEFAULT_MIN_CLASSES = 3

function ChangePassword() {
  const navigate = useNavigate()
  const { user, setUser, logout } = useAuthStore()

  const mutation = useMutation({
    mutationFn: (data: ChangePasswordForm) => authApi.changePassword(data.current_password, data.new_password),
    onSuccess: (response) => {
      if (user?.role === 'chat_user') {
        // The password endpoint revokes this token with all other old sessions.
        // Its fresh ticket completes Chat login without resubmitting a password.
        logout()
        if (response.data?.chat_ticket) {
          message.success('密码修改成功')
          openAuthenticatedChat(response.data.chat_ticket)
        } else {
          message.error('密码已修改，Chat 登录交接未完成，请使用新密码重新登录。')
          navigate('/login', { replace: true })
        }
        return
      }
      if (user) {
        setUser({ ...user, password_change_required: false })
      }
      message.success('密码修改成功')
      navigate('/dashboard', { replace: true })
    },
    onError: (error: any) => {
      const code = error?.response?.data?.error?.code
      if (user?.role === 'chat_user' && ['chat_login_unavailable', 'chat_identity_not_ready',
        'authorization_denied', 'password_updated_session_revoke_failed'].includes(code)) {
        logout()
        message.error('密码已修改，Chat 登录交接未完成。请使用新密码重新登录或联系管理员检查账号。')
        navigate('/login', { replace: true })
        return
      }
      message.error(passwordErrorMessage(error, error?.response?.data?.error?.message || '密码修改失败'))
    },
  })

  const onFinish = (values: ChangePasswordForm) => {
    mutation.mutate(values)
  }

  return (
    <main className="login-page">
      <section className="login-shell" aria-labelledby="password-title">
        <header className="login-brand">
          <span className="login-brand-mark" aria-hidden="true"><SafetyCertificateOutlined /></span>
          <div>
            <h1 id="password-title">{PASSWORD_TEXT.title}</h1>
            <p>{PASSWORD_TEXT.subtitle}</p>
          </div>
        </header>

        <div className="login-panel">
          {user?.password_change_required && <Alert type="warning" showIcon message="完成改密前，系统仅开放账号信息和密码设置。" style={{ marginBottom: 12 }} />}
          <Alert type="info" showIcon message={PASSWORD_TEXT.hint} style={{ marginBottom: 20 }} />
          <Form onFinish={onFinish} layout="vertical" requiredMark={false}>
            <Form.Item name="current_password" label="当前密码" rules={[{ required: true, message: '请输入当前密码' }]}>
              <Input.Password prefix={<LockOutlined />} placeholder="当前密码" size="large" autoComplete="current-password" />
            </Form.Item>
            <Form.Item
              name="new_password"
              label="新密码"
              rules={[
                { required: true, message: '请输入新密码' },
                { min: DEFAULT_MIN_LENGTH, message: PASSWORD_TEXT.tooShort(DEFAULT_MIN_LENGTH) },
                () => ({
                  validator(_, value) {
                    if (!value || passwordCharClasses(value) >= DEFAULT_MIN_CLASSES) return Promise.resolve()
                    return Promise.reject(new Error(PASSWORD_TEXT.tooFewClasses(DEFAULT_MIN_CLASSES)))
                  },
                }),
                () => ({
                  validator(_, value) {
                    const username = user?.username?.trim().toLowerCase() ?? ''
                    if (!value || username.length < 3 || !String(value).toLowerCase().includes(username)) return Promise.resolve()
                    return Promise.reject(new Error(PASSWORD_TEXT.containsUsername))
                  },
                }),
              ]}
            >
              <Input.Password prefix={<LockOutlined />} placeholder="新密码" size="large" autoComplete="new-password" />
            </Form.Item>
            <Form.Item
              name="confirm_password"
              label="确认新密码"
              dependencies={['new_password']}
              rules={[
                { required: true, message: '请再次输入新密码' },
                ({ getFieldValue }) => ({
                  validator(_, value) {
                    if (!value || getFieldValue('new_password') === value) return Promise.resolve()
                    return Promise.reject(new Error('两次输入的新密码不一致'))
                  },
                }),
              ]}
            >
              <Input.Password prefix={<LockOutlined />} placeholder="再次输入新密码" size="large" autoComplete="new-password" />
            </Form.Item>
            <Form.Item className="login-submit-item">
              <Button type="primary" htmlType="submit" loading={mutation.isPending} block size="large">保存新密码</Button>
            </Form.Item>
          </Form>
        </div>
        <footer className="login-security-note">密码变更将记录至操作审计</footer>
      </section>
    </main>
  )
}

export default ChangePassword

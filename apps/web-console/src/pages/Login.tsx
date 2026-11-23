import { useCallback, useEffect, useState } from 'react'
import { Form, Input, Button, Tooltip, message } from 'antd'
import { UserOutlined, LockOutlined, ReloadOutlined, SafetyCertificateOutlined, KeyOutlined } from '@ant-design/icons'
import { useAuthStore } from '../stores/auth'
import { useMutation } from '@tanstack/react-query'
import { authApi, consoleLoginSecurityApi } from '../services/api'
import { useNavigate } from 'react-router-dom'
import { LOGIN_TEXT } from './login-security/text'
import { loginErrorMessage, isTotpRequired } from './login-security/loginErrors'
import TotpEnroll from './login-security/TotpEnroll'
import { roleHome } from '../utils/access'
import { isConsoleRole, CONSOLE_LOGIN_COPY } from '../utils/consoleAccess'
import { productCopy, useProductIdentity } from '../product/profiles'

interface LoginForm {
  username: string
  password: string
  captcha_code: string
  totp_code?: string
}

interface LoginResult {
  token: string
  user: Parameters<ReturnType<typeof useAuthStore.getState>['login']>[1]
  password_expired?: boolean
  totp_setup_required?: boolean
}

interface CaptchaChallenge {
  captcha_id: string
  image: string
  expires_in: number
}

interface PendingEnrollment {
  token: string
  user: any
}

function Login() {
  const navigate = useNavigate()
  const { login, logout } = useAuthStore()
  const product = useProductIdentity()
  const copy = productCopy[product.profile]
  const [form] = Form.useForm<LoginForm>()
  const [captcha, setCaptcha] = useState<CaptchaChallenge | null>(null)
  const [captchaLoading, setCaptchaLoading] = useState(false)
  const [totpStep, setTotpStep] = useState(false)
  const [enrollment, setEnrollment] = useState<PendingEnrollment | null>(null)

  const loadCaptcha = useCallback(async () => {
    setCaptchaLoading(true)
    try {
      const response = await authApi.captcha()
      setCaptcha(response.data)
      form.setFieldValue('captcha_code', '')
    } catch {
      setCaptcha(null)
      message.error('验证码加载失败，请刷新重试')
    } finally {
      setCaptchaLoading(false)
    }
  }, [form])

  useEffect(() => {
    void loadCaptcha()
  }, [loadCaptcha])

  const finishLogin = useCallback((token: string, user: any) => {
    if (!isConsoleRole(user?.role)) {
      logout()
      message.error(CONSOLE_LOGIN_COPY.employeeHint)
      return
    }
    login(token, user)
    message.success('登录成功')
    navigate(user?.password_change_required ? '/change-password' : roleHome(user?.role || ''))
  }, [login, logout, navigate])

  const mutation = useMutation({
    mutationFn: async (data: LoginForm): Promise<LoginResult> => {
      if (totpStep && data.totp_code) {
        const response = await consoleLoginSecurityApi.loginWithTOTP(
          data.username,
          data.password,
          captcha?.captcha_id ?? '',
          data.captcha_code,
          data.totp_code,
        )
        return response.data
      }
      const response = await authApi.login(
        data.username,
        data.password,
        captcha?.captcha_id ?? '',
        data.captcha_code,
      )
      return response.data
    },
    onSuccess: (result) => {
      const { token, user, password_expired: passwordExpired, totp_setup_required: totpSetupRequired } = result
      if (!isConsoleRole(user?.role)) {
        logout()
        message.error(CONSOLE_LOGIN_COPY.employeeHint)
        void loadCaptcha()
        return
      }
      if (passwordExpired) {
        message.warning(LOGIN_TEXT.passwordExpired)
      }
      if (totpSetupRequired) {
        // The session is restricted to two-factor enrollment until it is confirmed, so keep it out of the store.
        setEnrollment({ token, user })
        return
      }
      finishLogin(token, user)
    },
    onError: (error: any) => {
      if (isTotpRequired(error)) {
        setTotpStep(true)
        message.info(LOGIN_TEXT.totpRequired)
      } else {
        const code = error?.response?.data?.error?.code
        if (code === 'console_role_required') {
          message.error(CONSOLE_LOGIN_COPY.employeeHint)
        } else {
          message.error(loginErrorMessage(error, totpStep))
        }
      }
      void loadCaptcha()
    },
  })

  const onFinish = (values: LoginForm) => {
    if (!captcha) {
      message.error('请先刷新验证码')
      return
    }
    mutation.mutate(values)
  }

  if (enrollment) {
    return (
      <main className="login-page">
        <section className="login-shell" aria-labelledby="login-title">
          <header className="login-brand">
            <span className="login-brand-mark" aria-hidden="true"><SafetyCertificateOutlined /></span>
            <div>
              <h1 id="login-title">AI算力安全网关</h1>
              <p>统一接入、安全策略与审计控制台</p>
            </div>
          </header>
          <div className="login-panel">
            <TotpEnroll token={enrollment.token} onDone={() => finishLogin(enrollment.token, enrollment.user)} />
          </div>
          <footer className="login-security-note">登录行为将记录至操作审计</footer>
        </section>
      </main>
    )
  }

  return (
    <main className="login-page">
      <section className="login-shell" aria-labelledby="login-title">
        <header className="login-brand">
          <span className="login-brand-mark" aria-hidden="true"><SafetyCertificateOutlined /></span>
          <div>
            <h1 id="login-title">{product.profile === 'agent-platform' ? product.name : copy.title}</h1>
            <p>{copy.subtitle} · 统一接入、安全策略与审计控制台</p>
          </div>
        </header>

        <div className="login-panel">
          <div className="login-panel-heading">
            <h2>{CONSOLE_LOGIN_COPY.adminHeading}</h2>
            <p>请使用已授权的平台账号访问</p>
          </div>
          <Form form={form} onFinish={onFinish} layout="vertical" requiredMark={false}>
            <Form.Item label="用户名" name="username" rules={[{ required: true, message: '请输入用户名' }]}>
              <Input prefix={<UserOutlined />} placeholder="用户名" size="large" autoComplete="username" />
            </Form.Item>
            <Form.Item label="密码" name="password" rules={[{ required: true, message: '请输入密码' }]}>
              <Input.Password prefix={<LockOutlined />} placeholder="密码" size="large" autoComplete="current-password" />
            </Form.Item>
            <Form.Item label="验证码" required>
              <div className="login-captcha-row">
                <Form.Item name="captcha_code" rules={[{ required: true, message: '请输入验证码' }]} noStyle>
                  <Input placeholder="请输入验证码" size="large" maxLength={5} autoComplete="off" />
                </Form.Item>
                <img src={captcha?.image} alt="验证码" width={145} className="login-captcha-image" height={44} />
                <Tooltip title="刷新验证码">
                  <Button aria-label="刷新验证码" htmlType="button" icon={<ReloadOutlined />} loading={captchaLoading} onClick={() => void loadCaptcha()} size="large" />
                </Tooltip>
              </div>
            </Form.Item>
            {totpStep && (
              <Form.Item
                label={LOGIN_TEXT.totpLabel}
                name="totp_code"
                rules={[{ required: true, pattern: /^\d{6}$/, message: LOGIN_TEXT.totpRule }]}
              >
                <Input prefix={<KeyOutlined />} placeholder={LOGIN_TEXT.totpPlaceholder} size="large" maxLength={6} inputMode="numeric" autoComplete="one-time-code" />
              </Form.Item>
            )}
            <Form.Item className="login-submit-item">
              <Button type="primary" htmlType="submit" loading={mutation.isPending} disabled={!captcha || captchaLoading} block size="large">
                登录
              </Button>
            </Form.Item>
          </Form>

        </div>

        <footer className="login-security-note">登录行为将记录至操作审计</footer>
      </section>
    </main>
  )
}

export default Login

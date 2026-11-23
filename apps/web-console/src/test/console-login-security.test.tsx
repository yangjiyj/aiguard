import type { ReactElement } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, useLocation } from 'react-router-dom'
import Login from '../pages/Login'
import ChangePassword from '../pages/ChangePassword'
import * as api from '../services/api'
import { useAuthStore } from '../stores/auth'
import { message, notification } from 'antd'
import { AxiosHeaders } from 'axios'
import { LOGIN_SECURITY_SETTINGS_TEXT, LOGIN_TEXT, PASSWORD_TEXT, PORTAL_BASELINE_TEXT, TOTP_ENROLL_TEXT } from '../pages/login-security/text'
import LoginSecuritySettings from '../pages/login-security/LoginSecuritySettings'
import PortalBaselineNotice from '../pages/login-security/PortalBaselineNotice'
import { loginErrorMessage, loginSecuritySaveError, passwordCharClasses, passwordErrorMessage, safeSsoLoginUrl } from '../pages/login-security/loginErrors'

type NodeRequire = { (name: string): unknown; resolve(name: string): string }
const { createRequire } = await import('node:module' as string) as {
  createRequire(filename: string): NodeRequire
}
const requireFromAntd = createRequire(createRequire(import.meta.url).resolve('antd'))
const { animationEndName, transitionEndName } = requireFromAntd('rc-motion/lib/util/motion') as {
  animationEndName: string; transitionEndName: string
}

// W3 console login security (MLPS level 3): lockout copy, TOTP step, SSO button visibility, password policy errors.

const apiError = (status: number, code: string, details?: Record<string, unknown>, headers: Record<string, string> = {}) => ({
  response: { status, headers, data: { error: { code, message: code, details } } },
})

const queryClients = new Set<QueryClient>()

const destroyStaticNotices = async () => {
  const wrappers = '.ant-message-notice-wrapper, .ant-notification-notice-wrapper'
  await act(async () => {
    message.destroy()
    notification.destroy()
  })
  await waitFor(() => {
    expect(Array.from(document.querySelectorAll(wrappers)).every((node) => (
      Array.from(node.classList).some((name) => name.endsWith('-leave-active'))
    ))).toBe(true)
  })
  // jsdom does not emit CSS animation completion; finish the real leave lifecycle.
  await act(async () => {
    document.querySelectorAll(wrappers).forEach((node) => {
      fireEvent(node, new Event(animationEndName, { bubbles: true }))
      fireEvent(node, new Event(transitionEndName, { bubbles: true }))
    })
  })
  await waitFor(() => expect(document.querySelectorAll(wrappers)).toHaveLength(0))
}

const cleanupLoginTest = async () => {
  await act(async () => {
    cleanup()
    queryClients.forEach((client) => client.clear())
    queryClients.clear()
  })
  await destroyStaticNotices()
}

afterEach(async () => {
  await cleanupLoginTest()
  vi.restoreAllMocks()
})

const renderWithProviders = (node: ReactElement) => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  queryClients.add(queryClient)
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>{node}</QueryClientProvider>
    </MemoryRouter>,
  )
}

const fillCredentials = () => {
  fireEvent.change(screen.getByPlaceholderText('用户名'), { target: { value: 'admin' } })
  fireEvent.change(screen.getByPlaceholderText('密码'), { target: { value: 'secret' } })
  fireEvent.change(screen.getByPlaceholderText('请输入验证码'), { target: { value: 'A7BK2' } })
}

const submitLogin = () => fireEvent.click(screen.getByRole('button', { name: /登\s*录/ }))

describe('W3 login page', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    useAuthStore.getState().logout()
    vi.spyOn(api.authApi, 'captcha').mockResolvedValue({
      data: { captcha_id: 'captcha-1', image: 'data:image/svg+xml;base64,PHN2Zy8+', expires_in: 300 },
    } as any)
  })

  it('shows the lockout message with the remaining minutes', async () => {
    vi.spyOn(api.authApi, 'login').mockRejectedValue(apiError(423, 'account_locked', { retry_after_minutes: 17 }))
    renderWithProviders(<Login />)
    await screen.findByRole('img', { name: '验证码' })
    fillCredentials()
    submitLogin()
    expect(await screen.findByText(LOGIN_TEXT.locked(17))).toBeInTheDocument()
  })

  it('password expiration keeps the session restricted and opens /change-password', async () => {
    const user = { id: 'u1', username: 'admin', role: 'platform_admin', password_change_required: true }
    const response: Awaited<ReturnType<typeof api.authApi.login>> = {
      data: { token: 'local-token', user, password_expired: true },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: { headers: new AxiosHeaders() },
    }
    const localLogin = vi.spyOn(api.authApi, 'login').mockResolvedValue(response)
    const withTotp = vi.spyOn(api.consoleLoginSecurityApi, 'loginWithTOTP')
    const warning = vi.spyOn(message, 'warning')
    const LocationProbe = () => <span data-testid="login-result-path">{useLocation().pathname}</span>
    renderWithProviders(<><Login /><LocationProbe /></>)
    await waitFor(() => expect(api.authApi.captcha).toHaveBeenCalledTimes(1))
    fillCredentials()
    submitLogin()

    await waitFor(() => expect(localLogin).toHaveBeenCalledWith('admin', 'secret', 'captcha-1', 'A7BK2'))
    await waitFor(() => expect(useAuthStore.getState().token).toBe('local-token'))
    expect(useAuthStore.getState().user).toEqual(user)
    expect(warning).toHaveBeenCalledWith(LOGIN_TEXT.passwordExpired)
    await waitFor(() => expect(screen.getByTestId('login-result-path')).toHaveTextContent('/change-password'))
    expect(withTotp).not.toHaveBeenCalled()
  })

  it('asks for a TOTP code and resubmits with it', async () => {
    vi.spyOn(api.authApi, 'login').mockRejectedValue(apiError(401, 'totp_required'))
    const withTotp = vi.spyOn(api.consoleLoginSecurityApi, 'loginWithTOTP').mockResolvedValue({
      data: { token: 'token-2', user: { id: 'u1', username: 'admin', role: 'platform_admin' } },
    } as any)
    renderWithProviders(<Login />)
    await screen.findByRole('img', { name: '验证码' })
    fillCredentials()
    submitLogin()

    const totpInput = await screen.findByPlaceholderText(LOGIN_TEXT.totpPlaceholder)
    await waitFor(() => expect(api.authApi.captcha).toHaveBeenCalledTimes(2))
    fillCredentials()
    fireEvent.change(totpInput, { target: { value: '123456' } })
    submitLogin()

    await waitFor(() => expect(withTotp).toHaveBeenCalledWith('admin', 'secret', 'captcha-1', 'A7BK2', '123456'))
    await waitFor(() => expect(useAuthStore.getState().token).toBe('token-2'))
  })

  it('keeps the enrollment-only session out of the store until TOTP is confirmed', async () => {
    vi.spyOn(api.authApi, 'login').mockResolvedValue({
      data: { token: 'enroll-token', user: { id: 'u1', username: 'admin', role: 'platform_admin' }, totp_setup_required: true },
    } as any)
    const setup = vi.spyOn(api.consoleLoginSecurityApi, 'setupTOTP').mockResolvedValue({
      data: { secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/JJDGuard:admin?secret=JBSWY3DPEHPK3PXP' },
    } as any)
    const enable = vi.spyOn(api.consoleLoginSecurityApi, 'enableTOTP').mockResolvedValue({ data: { enabled: true } } as any)
    renderWithProviders(<Login />)
    await screen.findByRole('img', { name: '验证码' })
    fillCredentials()
    submitLogin()

    expect(await screen.findByText(TOTP_ENROLL_TEXT.title)).toBeInTheDocument()
    expect(setup).toHaveBeenCalledWith('enroll-token')
    expect(await screen.findByTestId('totp-secret')).toHaveTextContent('JBSWY3DPEHPK3PXP')
    expect(useAuthStore.getState().token).toBeNull()

    fireEvent.change(screen.getByPlaceholderText(LOGIN_TEXT.totpPlaceholder), { target: { value: '654321' } })
    fireEvent.click(screen.getByRole('button', { name: TOTP_ENROLL_TEXT.confirm }))
    await waitFor(() => expect(enable).toHaveBeenCalledWith('654321', 'enroll-token'))
    await waitFor(() => expect(useAuthStore.getState().token).toBe('enroll-token'))
  })

  it('console login exposes no SSO links or ticket exchange', async () => {
    renderWithProviders(<Login />)
    await waitFor(() => expect(api.authApi.captcha).toHaveBeenCalled())
    expect(screen.queryByRole('link')).not.toBeInTheDocument()
  })

})

describe('W3 change password page', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    useAuthStore.getState().login('token', { id: 'u1', username: 'operator', role: 'platform_admin', password_change_required: true })
  })

  const fillPasswords = (next: string) => {
    fireEvent.change(screen.getByPlaceholderText('当前密码'), { target: { value: 'Current-Pass-1' } })
    fireEvent.change(screen.getByPlaceholderText('新密码'), { target: { value: next } })
    fireEvent.change(screen.getByPlaceholderText('再次输入新密码'), { target: { value: next } })
    fireEvent.click(screen.getByRole('button', { name: /保存新密码/ }))
  }

  it('rejects passwords shorter than 12 characters before calling the backend', async () => {
    const change = vi.spyOn(api.authApi, 'changePassword')
    renderWithProviders(<ChangePassword />)
    expect(screen.getByText(PASSWORD_TEXT.hint)).toBeInTheDocument()
    fillPasswords('Ab1!short')
    expect(await screen.findByText(PASSWORD_TEXT.tooShort(12))).toBeInTheDocument()
    expect(change).not.toHaveBeenCalled()
  })

  it('maps the backend reuse error using the configured history count', async () => {
    vi.spyOn(api.authApi, 'changePassword').mockRejectedValue(apiError(400, 'password_reused', { min_length: 12, min_classes: 3, history_count: 7 }))
    renderWithProviders(<ChangePassword />)
    fillPasswords('Brand-New-Pass-2026')
    expect(await screen.findByText(PASSWORD_TEXT.reused(7))).toBeInTheDocument()
  })
})

describe('W3 login security helpers', () => {
  it('maps login errors without revealing account existence', () => {
    expect(loginErrorMessage(apiError(401, 'unauthorized'), false)).toBe(LOGIN_TEXT.genericFailure)
    expect(loginErrorMessage(apiError(401, 'unauthorized'), true)).toBe(LOGIN_TEXT.totpFailure)
    expect(loginErrorMessage(apiError(400, 'invalid_captcha'), false)).toBe(LOGIN_TEXT.invalidCaptcha)
    expect(loginErrorMessage(apiError(403, 'login_ip_not_allowed'), false)).toBe(LOGIN_TEXT.ipNotAllowed)
    expect(loginErrorMessage(apiError(423, 'account_locked', undefined, { 'retry-after': '90' }), false)).toBe(LOGIN_TEXT.locked(2))
  })

  it('maps password policy errors with configured limits', () => {
    expect(passwordErrorMessage(apiError(400, 'password_too_short', { min_length: 16 }), 'x')).toBe(PASSWORD_TEXT.tooShort(16))
    expect(passwordErrorMessage(apiError(400, 'password_too_few_classes', { min_classes: 4 }), 'x')).toBe(PASSWORD_TEXT.tooFewClasses(4))
    expect(passwordErrorMessage(apiError(400, 'password_contains_username'), 'x')).toBe(PASSWORD_TEXT.containsUsername)
    expect(passwordErrorMessage(apiError(403, 'invalid_password'), 'x')).toBe(PASSWORD_TEXT.wrongCurrent)
    expect(passwordErrorMessage(apiError(500, 'internal_error'), 'fallback')).toBe('fallback')
  })

  it('counts character classes like the backend', () => {
    expect(passwordCharClasses('abcdefghijkl')).toBe(1)
    expect(passwordCharClasses('Abcdefghijk1')).toBe(3)
    expect(passwordCharClasses('Abcdefghij1!')).toBe(4)
  })

  it('accepts only relative or http(s) SSO URLs', () => {
    expect(safeSsoLoginUrl('/admin/v1/auth/sso/login')).toBe('/admin/v1/auth/sso/login')
    expect(safeSsoLoginUrl('https://sso.example.com/login')).toBe('https://sso.example.com/login')
    expect(safeSsoLoginUrl('//evil.example.com')).toBeNull()
    expect(safeSsoLoginUrl('javascript:alert(1)')).toBeNull()
    expect(safeSsoLoginUrl(undefined)).toBeNull()
  })
})

describe('W3 portal baseline notice and settings', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('warns only when the portal realm is below the baseline', async () => {
    vi.spyOn(api.consoleLoginSecurityApi, 'portalBaseline').mockResolvedValue({
      data: {
        status: 'not_compliant',
        checked_at: '2026-09-30T00:00:00Z',
        apply_hint: 'portal-login-baseline.sh check',
        items: [
          { key: 'failureFactor', current: 30, target: 5, compliant: false },
          { key: 'sslRequired', current: 'external', target: 'external', compliant: true },
        ],
      },
    } as any)
    renderWithProviders(<PortalBaselineNotice />)
    expect(await screen.findByText(PORTAL_BASELINE_TEXT.notMet)).toBeInTheDocument()
    const gaps = screen.getByTestId('portal-baseline-gaps')
    expect(gaps).toHaveTextContent('failureFactor')
    expect(gaps).not.toHaveTextContent('sslRequired')
  })

  it('renders nothing when compliant or when the check is unavailable', async () => {
    for (const status of ['compliant', 'unavailable']) {
      const spy = vi.spyOn(api.consoleLoginSecurityApi, 'portalBaseline').mockResolvedValue({
        data: { status, checked_at: '2026-09-30T00:00:00Z' },
      } as any)
      const view = renderWithProviders(<PortalBaselineNotice />)
      await waitFor(() => expect(spy).toHaveBeenCalled())
      expect(screen.queryByText(PORTAL_BASELINE_TEXT.notMet)).not.toBeInTheDocument()
      view.unmount()
      spy.mockRestore()
    }
  })

  it('loads and saves login security settings', async () => {
    const settings = {
      lockout_threshold: 5, lockout_minutes: 30, password_min_length: 12, password_min_classes: 3,
      password_history_count: 5, password_max_age_days: 90, session_idle_minutes: 30, session_absolute_hours: 12,
      session_max_concurrent: 3, admin_totp_required: false, admin_ip_allowlist: '',
    }
    vi.spyOn(api.consoleLoginSecurityApi, 'getSettings').mockResolvedValue({ data: settings } as any)
    const update = vi.spyOn(api.consoleLoginSecurityApi, 'updateSettings').mockResolvedValue({ data: settings } as any)
    renderWithProviders(<LoginSecuritySettings />)
    const threshold = await screen.findByLabelText(LOGIN_SECURITY_SETTINGS_TEXT.lockoutThreshold)
    await waitFor(() => expect(threshold).toHaveValue('5'))
    fireEvent.click(screen.getByRole('button', { name: new RegExp(LOGIN_SECURITY_SETTINGS_TEXT.save.split('').join('\\s*')) }))
    await waitFor(() => expect(update).toHaveBeenCalledWith(settings))
  })

  it('explains the allowlist self-lockout guard', () => {
    expect(loginSecuritySaveError(apiError(400, 'allowlist_excludes_current_ip'))).toBe(LOGIN_SECURITY_SETTINGS_TEXT.excludesCurrentIp)
    expect(loginSecuritySaveError(apiError(400, 'invalid_login_security'))).toBe(LOGIN_SECURITY_SETTINGS_TEXT.invalid)
  })
})

describe('login test notification lifecycle', () => {
  it('removes real static notices and cancels their auto-close timers during teardown', async () => {
    await destroyStaticNotices()
    const setTimer = vi.spyOn(globalThis, 'setTimeout')
    const clearTimer = vi.spyOn(globalThis, 'clearTimeout')
    try {
      await act(async () => {
        message.open({ key: 'login-cleanup-message', content: 'login teardown message', duration: 60 })
        notification.open({ key: 'login-cleanup-notification', message: 'login teardown notification', duration: 60 })
      })
      expect(await screen.findByText('login teardown message')).toBeInTheDocument()
      expect(await screen.findByText('login teardown notification')).toBeInTheDocument()
      const noticeTimers = setTimer.mock.calls.flatMap(([, delay], index) => (
        delay === 60_000 && setTimer.mock.results[index]?.type === 'return'
          ? [setTimer.mock.results[index].value]
          : []
      )).filter((timer) => !clearTimer.mock.calls.some(([cleared]) => cleared === timer))
      expect(noticeTimers.length).toBeGreaterThanOrEqual(2)

      await cleanupLoginTest()

      expect(screen.queryByText('login teardown message')).not.toBeInTheDocument()
      expect(screen.queryByText('login teardown notification')).not.toBeInTheDocument()
      for (const timer of noticeTimers) {
        expect(clearTimer).toHaveBeenCalledWith(timer)
      }
    } finally {
      await destroyStaticNotices()
    }
  })
})

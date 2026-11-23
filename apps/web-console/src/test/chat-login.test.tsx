import { readFileSync } from 'node:fs'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import * as api from '../services/api'
import { useAuthStore } from '../stores/auth'
import Login from '../pages/Login'
import App from '../App'
import { isConsoleRole, CONSOLE_LOGIN_COPY as copy } from '../utils/consoleAccess'

vi.mock('../components/Layout', () => ({ default: () => <div data-testid="console-layout" /> }))
const source = readFileSync('src/pages/Login.tsx', 'utf8')
const placeholders = [...source.matchAll(/placeholder="([^"]+)"/g)].map(match => match[1])
const captchaAlt = source.match(/<img[^>]*alt="([^"]+)"/)![1]
let client: QueryClient
beforeEach(() => {
  vi.restoreAllMocks()
  useAuthStore.getState().logout()
  window.history.replaceState({}, '', '/login')
  client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  vi.spyOn(api.authApi, 'captcha').mockResolvedValue({ data: { captcha_id: 'c', image: 'data:image/svg+xml;base64,PHN2Zy8+', expires_in: 300 } } as any)
})
afterEach(() => { cleanup(); client.clear(); vi.restoreAllMocks() })
const showLogin = () => render(<MemoryRouter><QueryClientProvider client={client}><Login /></QueryClientProvider></MemoryRouter>)
const submit = async () => {
  await screen.findByRole('img', { name: captchaAlt })
  fireEvent.change(screen.getByPlaceholderText(placeholders[0]), { target: { value: 'alice' } })
  fireEvent.change(screen.getByPlaceholderText(placeholders[1]), { target: { value: 'secret' } })
  fireEvent.change(screen.getByPlaceholderText(placeholders[2]), { target: { value: 'ABCD' } })
  fireEvent.click(screen.getAllByRole('button').find(button => button.getAttribute('type') === 'submit')!)
}

describe('administrator console identity boundary', () => {
  it.each(['platform_admin', 'security_officer', 'auditor', 'tenant_admin', 'admin', 'tenant_owner'])('accepts the supported %s console role (three officers included)', async role => {
    vi.spyOn(api.authApi, 'login').mockResolvedValue({ data: { token: 'admin-session', user: { id: 'u', username: 'alice', role } } } as any)
    showLogin()
    await submit()
    await waitFor(() => expect(useAuthStore.getState().isAuthenticated).toBe(true))
    expect(useAuthStore.getState().user?.role).toBe(role)
  })
  it('rejects an employee reply before storing a token or mounting second-factor enrollment', async () => {
    vi.spyOn(api.authApi, 'login').mockResolvedValue({ data: { token: 'employee-token', chat_ticket: 'unused-ticket', totp_setup_required: true, user: { id: 'u', username: 'alice', role: 'chat_user' } } } as any)
    const exchange = vi.spyOn(api.authApi, 'chatLogin')
    showLogin()
    await submit()
    expect(await screen.findByText(copy.employeeHint)).toBeVisible()
    expect(useAuthStore.getState().isAuthenticated).toBe(false)
    expect(useAuthStore.getState().token).toBeNull()
    expect(exchange).not.toHaveBeenCalled()
  })
  it('maps the server role rejection to the employee Chat guidance', async () => {
    vi.spyOn(api.authApi, 'login').mockRejectedValue({ response: { status: 403, data: { error: { code: 'console_role_required' } } } })
    showLogin()
    await submit()
    expect(await screen.findByText(copy.employeeHint)).toBeVisible()
    expect(useAuthStore.getState().isAuthenticated).toBe(false)
  })
  it('ignores the retired from-chat display mode and keeps the administrator form', async () => {
    window.history.replaceState({}, '', '/login?from=chat')
    showLogin()
    expect(await screen.findByRole('heading', { name: copy.adminHeading })).toBeVisible()
    expect(document.querySelector('a[href*="sso"]')).toBeNull()
  })
  it.each(['chat_user', 'developer', 'viewer', 'dept_manager', 'operator'])('blocks persisted %s sessions before console or password-change routes mount', async role => {
    useAuthStore.getState().login('existing-non-admin-session', { id: 'u', username: 'alice', role, password_change_required: true })
    const exchange = vi.spyOn(api.authApi, 'chatLogin')
    render(<App />)
    expect(screen.getByText(copy.deniedHeading)).toBeVisible()
    expect(screen.queryByTestId('console-layout')).not.toBeInTheDocument()
    expect(exchange).not.toHaveBeenCalled()
    expect(isConsoleRole(role)).toBe(false)
  })
  it.each(['security_officer', 'auditor'])('lets persisted %s (a three-officer console role) reach the console', async role => {
    useAuthStore.getState().login('officer-session', { id: 'u', username: 'alice', role })
    render(<App />)
    expect(screen.queryByText(copy.deniedHeading)).not.toBeInTheDocument()
    expect(await screen.findByTestId('console-layout')).toBeInTheDocument()
    expect(isConsoleRole(role)).toBe(true)
  })
  it.each(['developer', 'viewer', 'dept_manager', 'operator'])('rejects a %s reply before storing a token', async role => {
    const login = vi.spyOn(api.authApi, 'login').mockResolvedValue({ data: { token: 'x-token', user: { id: 'u', username: 'alice', role } } } as any)
    showLogin()
    await submit()
    // 关心的是状态：被拒角色不得被存入 token、不得进入已登录态（提示文案由上面的员工用例覆盖）。
    await waitFor(() => expect(login).toHaveBeenCalled())
    await waitFor(() => expect(api.authApi.captcha).toHaveBeenCalledTimes(2)) // 被拒后会刷新验证码
    expect(useAuthStore.getState().isAuthenticated).toBe(false)
    expect(useAuthStore.getState().token).toBeNull()
  })
})

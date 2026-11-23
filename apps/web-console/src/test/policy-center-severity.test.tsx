import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { message } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import api from '../services/api'
import SecurityPolicyCenter from '../pages/SecurityPolicyCenter'
import { useAuthStore } from '../stores/auth'

const capability = {
  category: 'code_sql_injection_generation', name: 'SQL 注入代码生成', kind: 'static' as const, enabled: true, binding_mode: 'any' as const,
  supported_stages: ['input'], allowed_actions: ['audit', 'block'], mask_capable: false, bound_policy_count: 1,
}
const preloaded = {
  id: 'sql-policy', name: 'SQL 注入代码生成', description: '检测生成 SQL 注入攻击代码的请求', scene: 'code_security',
  severity: 'critical', action: 'audit', enabled: true, source: 'system', ownership: 'platform', origin: 'preloaded',
  detection_basis: 'capability', detection_configured: true, detection_ready: true, runtime_active: true, capabilities: [capability],
  default_severity: 'critical', severity_overridden: false,
}
const consistent = { ...preloaded, id: 'ok-policy', name: '一致的策略', severity: 'high', default_severity: 'high', action: 'block' }
// 管理员把默认“高危”改成了“低危”
const overridden = { ...preloaded, id: 'ov-policy', name: '被改过级别的策略', severity: 'low', default_severity: 'high', severity_overridden: true, action: 'audit' }
// 覆盖值恰好等于默认值
const overriddenEqual = { ...preloaded, id: 'eq-policy', name: '等值覆盖的策略', severity: 'high', default_severity: 'high', severity_overridden: true, action: 'audit' }
const unknownSeverity = { ...preloaded, id: 'unk-policy', name: '级别未知的策略', severity: 'unknown', default_severity: 'unknown', action: 'audit' }
const tenantOwned = {
  id: 'own-policy', name: '厂房关键词', description: '客户自定义', scene: 'data_leak', severity: 'medium', action: 'block', enabled: true,
  source: 'tenant', ownership: 'organization', origin: 'organization_created', detection_basis: 'matcher', detection_configured: true, detection_ready: true, runtime_active: true,
  matcher: { type: 'keyword', config: { keywords: ['厂房'] } }, capabilities: [], default_severity: '', severity_overridden: false,
}

function renderPage(search: string) {
  window.history.replaceState({}, '', `/security/policies${search}`)
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<BrowserRouter><QueryClientProvider client={queryClient}><SecurityPolicyCenter /></QueryClientProvider></BrowserRouter>)
}

let listed: unknown[] = []

describe('策略中心的级别', () => {
  beforeEach(() => {
    listed = [preloaded, consistent, overridden, overriddenEqual, tenantOwned, unknownSeverity]
    vi.restoreAllMocks()
    useAuthStore.setState({ token: 'token', user: { id: 'admin', username: 'admin', role: 'platform_admin', tenant_id: 'tenant-a' }, isAuthenticated: true } as never)
    vi.spyOn(api, 'get').mockImplementation(async (path) => {
      if (path === '/security/policies') return { data: { data: listed, total: listed.length, configured_count: listed.length, ready_count: listed.length, active_count: listed.length, enabled_count: listed.length, pending_count: 0, unconfigured_count: 0, runtime_verified: true, runtime_status: 'verified' } } as never
      if (path === '/security/policies/capabilities') return { data: { data: [capability], total: 1, builtin_total: 1, extension_total: 0 } } as never
      if (path === '/system/settings') return { data: { security_execution_mode: { effective_mode: 'protect', runtime_verified: true, runtime_status: 'verified' } } } as never
      if (path === '/projects') return { data: { data: [], total: 0 } } as never
      if (path === '/teams') return { data: { data: [] } } as never
      if (path === '/keys') return { data: { data: [], total: 0 } } as never
      throw new Error(`unexpected GET ${path}`)
    })
  })

  it('shows the severity column and flags only the contradictory pair', async () => {
    renderPage('?tab=runtime')
    const row = (await screen.findByText('SQL 注入代码生成', { selector: 'strong' })).closest('tr') as HTMLElement
    expect(within(row).getByText('严重')).toBeInTheDocument()
    expect(within(row).getByLabelText('级别与动作不配套')).toBeInTheDocument()
    const okRow = screen.getByText('一致的策略', { selector: 'strong' }).closest('tr') as HTMLElement
    expect(within(okRow).queryByLabelText('级别与动作不配套')).not.toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '级别' })).toBeInTheDocument()
  })

  it('filters the runtime table by severity', async () => {
    renderPage('?tab=runtime&severity=critical')
    expect(await screen.findByText('SQL 注入代码生成', { selector: 'strong' })).toBeInTheDocument()
    expect(screen.queryByText('一致的策略', { selector: 'strong' })).not.toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '级别筛选' })).toBeInTheDocument()
  })

  it('lets an administrator change the severity of a preloaded policy', async () => {
    renderPage('?tab=runtime&policy=sql-policy')
    expect(await screen.findByRole('combobox', { name: '风险级别' })).not.toBeDisabled()
  })

  it('opens the drawer for the policy named in ?policy=', async () => {
    renderPage('?tab=runtime&policy=ok-policy')
    expect(await screen.findByRole('dialog', { name: '一致的策略' })).toBeInTheDocument()
  })

  it('says so and clears the parameter when the linked policy no longer exists', async () => {
    const warn = vi.spyOn(message, 'warning')
    renderPage('?tab=runtime&policy=deleted-policy')
    await waitFor(() => expect(warn).toHaveBeenCalledWith('该策略已删除'))
    await waitFor(() => expect(window.location.search).not.toContain('policy='))
  })

  async function saveFromDrawer(user: ReturnType<typeof userEvent.setup>) {
    const drawer = await screen.findByRole('dialog')
    await user.click(within(drawer).getByRole('button', { name: '保存并应用' }))
    await user.click(await screen.findByRole('button', { name: '确认保存并应用' }))
  }

  const pick = async (user: ReturnType<typeof userEvent.setup>, name: string, option: string) => {
    await user.click(await screen.findByRole('combobox', { name }))
    await user.click(await screen.findByTitle(option))
  }

  it('sends only the severity when only the severity was changed', async () => {
    const patch = vi.spyOn(api, 'patch').mockResolvedValue({ data: {} } as never)
    const user = userEvent.setup()
    renderPage('?tab=runtime&policy=sql-policy')
    await pick(user, '风险级别', '高危')
    await saveFromDrawer(user)
    await waitFor(() => expect(patch).toHaveBeenCalled())
    expect(patch.mock.calls[0]).toEqual(['/security/policies/sql-policy', { severity: 'high' }])
  })

  it('sends action and severity when switching to record-only and changing the severity', async () => {
    const patch = vi.spyOn(api, 'patch').mockResolvedValue({ data: {} } as never)
    const user = userEvent.setup()
    renderPage('?tab=runtime&policy=ok-policy')
    await pick(user, '配置动作', '记录并告警')
    await pick(user, '风险级别', '低危')
    await saveFromDrawer(user)
    await waitFor(() => expect(patch).toHaveBeenCalled())
    expect(patch.mock.calls[0]).toEqual(['/security/policies/ok-policy', { action: 'audit', severity: 'low' }])
  })

  it('sends only the action when only the action was changed', async () => {
    const patch = vi.spyOn(api, 'patch').mockResolvedValue({ data: {} } as never)
    const user = userEvent.setup()
    renderPage('?tab=runtime&policy=ok-policy')
    await pick(user, '配置动作', '记录并告警')
    await saveFromDrawer(user)
    await waitFor(() => expect(patch).toHaveBeenCalled())
    expect(patch.mock.calls[0]).toEqual(['/security/policies/ok-policy', { action: 'audit' }])
  })

  it('sends no request when nothing was changed', async () => {
    const patch = vi.spyOn(api, 'patch').mockResolvedValue({ data: {} } as never)
    const info = vi.spyOn(message, 'info')
    const user = userEvent.setup()
    renderPage('?tab=runtime&policy=ov-policy')
    await screen.findByRole('combobox', { name: '风险级别' })
    await saveFromDrawer(user)
    await waitFor(() => expect(info).toHaveBeenCalledWith('没有改动'))
    expect(patch).not.toHaveBeenCalled()
  })

  it('shows 已自定义 and 恢复默认 only for an overridden preloaded policy', async () => {
    renderPage('?tab=runtime&policy=ov-policy')
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('已自定义')).toBeInTheDocument()
    expect(within(drawer).getByRole('button', { name: '恢复默认' })).toBeInTheDocument()
  })

  it('hides them for a preloaded policy that was never overridden and for tenant policies', async () => {
    const first = renderPage('?tab=runtime&policy=sql-policy')
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).queryByText('已自定义')).not.toBeInTheDocument()
    expect(within(drawer).queryByRole('button', { name: '恢复默认' })).not.toBeInTheDocument()
    first.unmount()
    renderPage('?tab=runtime&policy=own-policy')
    const own = await screen.findByRole('dialog', { name: '厂房关键词' })
    expect(within(own).queryByText('已自定义')).not.toBeInTheDocument()
    expect(within(own).queryByRole('button', { name: '恢复默认' })).not.toBeInTheDocument()
  })

  it('restore default submits the default severity', async () => {
    const patch = vi.spyOn(api, 'patch').mockResolvedValue({ data: {} } as never)
    const user = userEvent.setup()
    renderPage('?tab=runtime&policy=ov-policy')
    const drawer = await screen.findByRole('dialog')
    await user.click(within(drawer).getByRole('button', { name: '恢复默认' }))
    await saveFromDrawer(user)
    await waitFor(() => expect(patch).toHaveBeenCalled())
    expect(patch.mock.calls[0]).toEqual([expect.any(String), { severity: 'high' }])
  })

  it('restore default still submits when the override equals the default', async () => {
    const patch = vi.spyOn(api, 'patch').mockResolvedValue({ data: {} } as never)
    const user = userEvent.setup()
    renderPage('?tab=runtime&policy=eq-policy')
    const drawer = await screen.findByRole('dialog')
    await user.click(within(drawer).getByRole('button', { name: '恢复默认' }))
    await saveFromDrawer(user)
    await waitFor(() => expect(patch).toHaveBeenCalled())
    expect(patch.mock.calls[0]).toEqual([expect.any(String), { severity: 'high' }])
  })

  it('an untouched equal-valued override sends nothing on an ordinary save', async () => {
    const info = vi.spyOn(message, 'info')
    const patch = vi.spyOn(api, 'patch').mockResolvedValue({ data: {} } as never)
    const user = userEvent.setup()
    renderPage('?tab=runtime&policy=eq-policy')
    await screen.findByRole('combobox', { name: '风险级别' })
    await saveFromDrawer(user)
    await waitFor(() => expect(info).toHaveBeenCalledWith('没有改动'))
    expect(patch).not.toHaveBeenCalled()
  })

  it('shows 未分级 for a severity outside the dictionary', async () => {
    renderPage('?tab=runtime')
    const row = (await screen.findByText('级别未知的策略', { selector: 'strong' })).closest('tr') as HTMLElement
    expect(within(row).getByText('未分级')).toBeInTheDocument()
  })

  it('also says so when the tenant has no policies at all', async () => {
    listed = []
    const warn = vi.spyOn(message, 'warning')
    renderPage('?tab=runtime&policy=gone')
    await waitFor(() => expect(warn).toHaveBeenCalledWith('该策略已删除'))
    await waitFor(() => expect(window.location.search).not.toContain('policy='))
  })
})

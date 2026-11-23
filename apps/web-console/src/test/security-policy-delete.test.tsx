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
  category: 'phone_cn', name: '手机号检测', kind: 'static' as const, enabled: true, binding_mode: 'any' as const,
  supported_stages: ['input'], allowed_actions: ['audit', 'mask', 'block'], mask_capable: true, bound_policy_count: 1,
}

const builtin = {
  id: 'data-policy', name: '手机号外发', description: '识别手机号', scene: 'data_leak', severity: 'high', action: 'mask', enabled: true,
  source: 'system', ownership: 'platform', origin: 'preloaded', detection_basis: 'capability', detection_configured: true, detection_ready: true, runtime_active: true,
  capabilities: [capability],
}
const custom = {
  id: 'custom-1', name: '厂房关键词', description: '客户自定义', scene: 'data_leak', severity: 'medium', action: 'block', enabled: true,
  source: 'tenant', ownership: 'organization', origin: 'organization_created', detection_basis: 'matcher', detection_configured: true, detection_ready: true, runtime_active: true,
  matcher: { type: 'keyword', config: { keywords: ['厂房'] } }, capabilities: [],
}

// The mocked server owns the policy list, so a delete really changes what the next read returns.
let serverPolicies: Array<typeof builtin | typeof custom> = []

function policyResponse() {
  return {
    data: serverPolicies, total: serverPolicies.length, configured_count: serverPolicies.length, ready_count: serverPolicies.length,
    active_count: serverPolicies.length, enabled_count: serverPolicies.length,
    pending_count: 0, unconfigured_count: 0, runtime_verified: true, runtime_status: 'verified',
  }
}

function policyReads() {
  return vi.mocked(api.get).mock.calls.filter(([path]) => path === '/security/policies').length
}

function renderPage(search = '?tab=runtime') {
  window.history.replaceState({}, '', `/security/policies${search}`)
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<BrowserRouter><QueryClientProvider client={queryClient}><SecurityPolicyCenter /></QueryClientProvider></BrowserRouter>)
}

function httpError(status: number) {
  return Object.assign(new Error(`HTTP ${status}`), { isAxiosError: true, response: { status, data: {} } })
}

function signIn(role: string) {
  useAuthStore.setState({
    token: 'token',
    user: { id: 'admin', username: 'admin', role, tenant_id: 'tenant-a' },
    isAuthenticated: true,
  } as never)
}

describe('策略中心删除自定义策略', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    serverPolicies = [builtin, custom]
    signIn('platform_admin')
    vi.spyOn(api, 'get').mockImplementation(async (path) => {
      if (path === '/security/policies') return { data: policyResponse() } as never
      if (path === '/security/policies/capabilities') return { data: { data: [capability], total: 1, builtin_total: 1, extension_total: 0 } } as never
      if (path === '/system/settings') return { data: { security_execution_mode: { effective_mode: 'record', runtime_verified: true, runtime_status: 'verified' } } } as never
      if (path === '/projects') return { data: { data: [], total: 0 } } as never
      if (path === '/teams') return { data: { data: [] } } as never
      if (path === '/keys') return { data: { data: [], total: 0 } } as never
      throw new Error(`unexpected GET ${path}`)
    })
  })

  const deleteOnServer = () => vi.spyOn(api, 'delete').mockImplementation(async (path) => {
    serverPolicies = serverPolicies.filter((policy) => path !== `/security/policies/${policy.id}`)
    return { status: 204, data: '' } as never
  })

  it('组织自建策略的详情里有删除按钮，点确认后调用删除接口、关闭抽屉并回读列表', async () => {
    const remove = deleteOnServer()
    const success = vi.spyOn(message, 'success')
    const user = userEvent.setup()
    renderPage()
    await user.click(within((await screen.findByText('厂房关键词')).closest('tr')!).getByRole('button', { name: '查看' }))
    const drawer = await screen.findByRole('dialog', { name: '厂房关键词' })
    await user.click(within(drawer).getByRole('button', { name: '删除策略' }))
    expect(remove).not.toHaveBeenCalled()
    await user.click(await screen.findByRole('button', { name: '删 除' }))
    await waitFor(() => expect(remove).toHaveBeenCalledWith('/security/policies/custom-1'))
    await waitFor(() => expect(success).toHaveBeenCalledWith('策略已删除'))
    // the list is read back from the server after the delete, and the row is gone from it
    await waitFor(() => expect(policyReads()).toBeGreaterThanOrEqual(2))
    await waitFor(() => expect(screen.queryByText('厂房关键词')).not.toBeInTheDocument())
    expect(screen.getByText('手机号外发')).toBeInTheDocument()
    // the policy deep link must not stay behind in the address bar
    await waitFor(() => expect(window.location.search).not.toContain('policy='))
  })

  it('运行策略表的自建策略行内可以直接删除，内置策略行没有删除', async () => {
    const remove = deleteOnServer()
    const user = userEvent.setup()
    renderPage()
    const builtinRow = (await screen.findByText('手机号外发')).closest('tr')!
    expect(within(builtinRow).queryByRole('button', { name: /删除/ })).not.toBeInTheDocument()
    const customRow = screen.getByText('厂房关键词').closest('tr')!
    await user.click(within(customRow).getByRole('button', { name: '删除策略 厂房关键词' }))
    expect(remove).not.toHaveBeenCalled()
    await user.click(await screen.findByRole('button', { name: '删 除' }))
    await waitFor(() => expect(remove).toHaveBeenCalledWith('/security/policies/custom-1'))
    await waitFor(() => expect(screen.queryByText('厂房关键词')).not.toBeInTheDocument())
    expect(screen.getByText('手机号外发')).toBeInTheDocument()
  })

  it('场景页的组织自建策略计数在删除后同步减少', async () => {
    deleteOnServer()
    const user = userEvent.setup()
    renderPage('')
    const counter = async () => (await screen.findByText('组织自建策略')).closest('span')!.querySelector('strong')!
    await waitFor(async () => expect((await counter()).textContent).toBe('1'))
    // open the policy from the sensitive-data scene's custom list, then delete it there
    await user.click(screen.getAllByRole('button', { name: '进入场景' })[0])
    await user.click(await screen.findByRole('button', { name: /厂房关键词/ }))
    const drawer = await screen.findByRole('dialog', { name: '厂房关键词' })
    await user.click(within(drawer).getByRole('button', { name: '删除策略' }))
    await user.click(await screen.findByRole('button', { name: '删 除' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '厂房关键词' })).not.toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: '返回场景列表' }))
    await waitFor(async () => expect((await counter()).textContent).toBe('0'))
  })

  it('内置策略的详情里没有删除按钮', async () => {
    const remove = deleteOnServer()
    const user = userEvent.setup()
    renderPage()
    await user.click(within((await screen.findByText('手机号外发')).closest('tr')!).getByRole('button', { name: '查看' }))
    const drawer = await screen.findByRole('dialog', { name: '手机号外发' })
    expect(within(drawer).queryByRole('button', { name: '删除策略' })).not.toBeInTheDocument()
    expect(remove).not.toHaveBeenCalled()
  })

  it.each(['auditor', 'viewer', 'dept_manager'])('%s 在列表和详情里都看不到删除', async (role) => {
    signIn(role)
    deleteOnServer()
    const user = userEvent.setup()
    renderPage()
    const customRow = (await screen.findByText('厂房关键词')).closest('tr')!
    expect(within(customRow).queryByRole('button', { name: /删除/ })).not.toBeInTheDocument()
    await user.click(within(customRow).getByRole('button', { name: '查看' }))
    const drawer = await screen.findByRole('dialog', { name: '厂房关键词' })
    expect(within(drawer).queryByRole('button', { name: '删除策略' })).not.toBeInTheDocument()
  })

  it('服务端删除失败时给出提示、回读列表，策略和抽屉都保留', async () => {
    const remove = vi.spyOn(api, 'delete').mockRejectedValue(httpError(500))
    const failure = vi.spyOn(message, 'error')
    const user = userEvent.setup()
    renderPage()
    await user.click(within((await screen.findByText('厂房关键词')).closest('tr')!).getByRole('button', { name: '查看' }))
    const drawer = await screen.findByRole('dialog', { name: '厂房关键词' })
    const readsBefore = policyReads()
    await user.click(within(drawer).getByRole('button', { name: '删除策略' }))
    await user.click(await screen.findByRole('button', { name: '删 除' }))
    await waitFor(() => expect(remove).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(failure).toHaveBeenCalledWith('策略删除失败，服务端原配置未改变'))
    await waitFor(() => expect(policyReads()).toBeGreaterThan(readsBefore))
    expect(screen.getByRole('dialog', { name: '厂房关键词' })).toBeInTheDocument()
    expect(screen.getAllByText('厂房关键词').length).toBeGreaterThan(0)
  })

  it('策略已被别人删掉（404）时按已删除处理：关闭抽屉、列表去掉它', async () => {
    vi.spyOn(api, 'delete').mockImplementation(async () => {
      serverPolicies = [builtin]
      throw httpError(404)
    })
    const info = vi.spyOn(message, 'info')
    const failure = vi.spyOn(message, 'error')
    const user = userEvent.setup()
    renderPage()
    await user.click(within((await screen.findByText('厂房关键词')).closest('tr')!).getByRole('button', { name: '查看' }))
    const drawer = await screen.findByRole('dialog', { name: '厂房关键词' })
    await user.click(within(drawer).getByRole('button', { name: '删除策略' }))
    await user.click(await screen.findByRole('button', { name: '删 除' }))
    await waitFor(() => expect(info).toHaveBeenCalledWith('策略已不存在'))
    expect(failure).not.toHaveBeenCalled()
    await waitFor(() => expect(screen.queryByText('厂房关键词')).not.toBeInTheDocument())
  })
})

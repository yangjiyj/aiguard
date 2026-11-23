import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import RequireRole from '../components/RequireRole'
import PolicyRuleLink from '../components/PolicyRuleLink'
import SystemSettings from '../pages/SystemSettings'
import ProxySettings from '../pages/ProxySettings'
import api, { billingEmployeeApi, caApi, proxyApi } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { canAccessPath, canSeeMenuItem } from '../utils/access'
import { chooseOption } from './protectionTestUtils'

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() } }
})

function setUser(role: string, tenant_id: string) {
  useAuthStore.setState({ token: 't', user: { id: 'u1', username: 'u', role, tenant_id }, isAuthenticated: true })
}

function wrap(node: JSX.Element, entry = '/') {
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
        {node}
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

describe('平台级安全员进入系统设置与正向代理配置', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(api, 'get').mockResolvedValue({ data: { guardrail_fail_closed_enabled: 'false' } } as never)
    vi.spyOn(api, 'put').mockResolvedValue({ data: {} } as never)
    vi.spyOn(billingEmployeeApi, 'settings').mockResolvedValue({ data: { data: { currency: 'CNY' } } } as never)
    vi.spyOn(caApi, 'list').mockResolvedValue({ data: { data: [], total: 0 } } as never)
    vi.spyOn(proxyApi, 'getWhitelist').mockResolvedValue({ data: { data: [], total: 0 } } as never)
  })

  it('路由与菜单：平台级安全员可进，租户级安全员和审计员不行', () => {
    for (const path of ['/system/settings', '/connect/network']) {
      expect(canAccessPath('security_officer', path, 'tenant_default')).toBe(true)
      expect(canAccessPath('security_officer', path, 'tenant_system')).toBe(true)
      expect(canSeeMenuItem('security_officer', path, 'tenant_default')).toBe(true)
      expect(canAccessPath('security_officer', path, 'tenant-a')).toBe(false)
      expect(canSeeMenuItem('security_officer', path, 'tenant-a')).toBe(false)
      expect(canAccessPath('auditor', path, 'tenant_default')).toBe(false)
      expect(canSeeMenuItem('auditor', path, 'tenant_default')).toBe(false)
      expect(canAccessPath('platform_admin', path, 'tenant_default')).toBe(true)
    }
    // 其他系统页对安全员仍不开放。
    expect(canAccessPath('security_officer', '/system/license', 'tenant_default')).toBe(false)
  })

  it.each([
    ['security_officer', 'tenant_default', '系统设置页'],
    ['security_officer', 'tenant-a', '首页'],
    ['auditor', 'tenant_default', '首页'],
  ])('%s（%s）打开 /system/settings → %s', (role, tenant, expected) => {
    setUser(role, tenant)
    wrap(
      <Routes>
        <Route path="/system/settings" element={<RequireRole path="/system/settings"><div>系统设置页</div></RequireRole>} />
        <Route path="*" element={<div>首页</div>} />
      </Routes>,
      '/system/settings',
    )
    expect(screen.getByText(expected)).toBeInTheDocument()
  })

  it('系统设置：安全员只看到故障处理、检测执行，并能保存', async () => {
    setUser('security_officer', 'tenant_default')
    wrap(<SystemSettings />)
    const failure = await screen.findByRole('region', { name: '故障处理' })
    expect(screen.getByRole('region', { name: '检测执行' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /保存设置/ })).not.toBeInTheDocument()
    expect(screen.queryByText('货币设置')).not.toBeInTheDocument()
    expect(screen.queryByText(/查看币种/)).not.toBeInTheDocument()
    const guardrail = within(failure).getByRole('combobox', { name: '安全检测不可用' })
    await waitFor(() => expect(guardrail).toBeEnabled())
    await chooseOption(guardrail, '拦截')
    await userEvent.click(within(failure).getByRole('button', { name: '保存故障处理' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/security/system-settings', { guardrail_fail_closed_enabled: true }))
  })

  it('系统设置：系统管理员页面不变', async () => {
    setUser('platform_admin', 'tenant_default')
    wrap(<SystemSettings />)
    expect(await screen.findByRole('button', { name: /保存设置/ })).toBeInTheDocument()
    expect(screen.getByText('货币设置')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: '故障处理' })).toBeInTheDocument()
  })

  it('正向代理配置：安全员只看到出站限制，不读白名单，能保存', async () => {
    setUser('security_officer', 'tenant_default')
    const user = userEvent.setup()
    wrap(<ProxySettings />)
    const section = await screen.findByRole('region', { name: '出站限制' })
    expect(screen.queryByRole('region', { name: '出站白名单' })).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: /网关出网代理/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: /CA 管理/ })).not.toBeInTheDocument()
    expect(proxyApi.getWhitelist).not.toHaveBeenCalled()
    const output = within(section).getByRole('combobox', { name: '未登记目标' })
    await waitFor(() => expect(output).toBeEnabled())
    await chooseOption(output, '放行并审计')
    const confirm = (await screen.findAllByText('网关可被用来访问未登记的地址。')).pop()!.closest('.ant-modal') as HTMLElement
    await user.click(within(confirm).getByRole('button', { name: '确认放行' }))
    await user.click(within(section).getByRole('button', { name: '保存出站限制' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/security/system-settings', { forward_proxy_unlisted_action: 'allow_audit' }))
  })

  it('策略链接按租户判断能否打开', () => {
    setUser('security_officer', 'tenant_default')
    const { unmount } = wrap(<PolicyRuleLink link={{ kind: 'policy', path: '/connect/network', label: '出站限制' }} />)
    expect(screen.getByRole('link', { name: '出站限制' })).toBeInTheDocument()
    unmount()
    setUser('security_officer', 'tenant-a')
    wrap(<PolicyRuleLink link={{ kind: 'policy', path: '/connect/network', label: '出站限制' }} />)
    expect(screen.queryByRole('link', { name: '出站限制' })).not.toBeInTheDocument()
    expect(screen.getByText('出站限制')).toBeInTheDocument()
  })

  it('正向代理配置：系统管理员页面不变', async () => {
    setUser('platform_admin', 'tenant_default')
    wrap(<ProxySettings />)
    expect(await screen.findByRole('tab', { name: /网关出网代理/ })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /CA 管理/ })).toBeInTheDocument()
    expect(await screen.findByRole('region', { name: '出站白名单' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: '出站限制' })).toBeInTheDocument()
  })
})

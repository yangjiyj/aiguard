import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Modal } from 'antd'
import ReverseProxy from '../pages/ReverseProxy'
import { reverseProxyApi } from '../services/api'
import { useAuthStore } from '../stores/auth'

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }
})

const route = {
  id: 'rpr_1', tenant_id: 't', name: '内部接口', path_prefix: '/proxy/internal', target_url: 'https://api.corp.example',
  target_path_prefix: '', allow_private_egress: false, private_egress_cidrs: [], security_enabled: true, stats_enabled: true,
  status: 'active', description: '', created_at: '', updated_at: '',
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={client}><ReverseProxy /></QueryClientProvider>)
}

describe('反向代理规则：高级出站', () => {
  afterEach(() => Modal.destroyAll())
  beforeEach(() => {
    vi.restoreAllMocks()
    useAuthStore.setState({ token: 't', user: { id: 'u1', username: 'u', role: 'platform_admin', tenant_id: 'tenant_default' }, isAuthenticated: true })
    vi.spyOn(reverseProxyApi, 'list').mockResolvedValue({ data: { data: [route], total: 1 } } as never)
    vi.spyOn(reverseProxyApi, 'update').mockResolvedValue({ data: route } as never)
  })

  it('打开回环放行要二次确认，提交带上 egress_overrides', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('button', { name: /编辑/ }))
    const group = await screen.findByRole('group', { name: '高级出站' })
    expect(within(group).queryByRole('switch', { name: '跳过证书校验' })).not.toBeInTheDocument()
    const loopback = within(group).getByRole('switch', { name: '允许回环地址' })
    await user.click(loopback)
    expect(await screen.findByText('网关可被用来访问这些地址。')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '确认打开' }))
    await waitFor(() => expect(loopback).toBeChecked())

    const form = group.closest('form') as HTMLFormElement
    await user.click(within(form).getByRole('button', { name: /保\s*存|提\s*交|确\s*定/ }))
    await waitFor(() => expect(reverseProxyApi.update).toHaveBeenCalledWith('rpr_1', expect.objectContaining({
      egress_overrides: { allow_loopback: true, allow_link_local: false, allow_metadata: false, allow_internal_hostnames: false },
    })))
  })

  it('租户级角色只能关不能开', async () => {
    useAuthStore.setState({ token: 't', user: { id: 'u2', username: 'so', role: 'security_officer', tenant_id: 'tenant-a' }, isAuthenticated: true })
    vi.spyOn(reverseProxyApi, 'list').mockResolvedValue({ data: { data: [{ ...route, egress_overrides: { allow_metadata: true } }], total: 1 } } as never)
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('button', { name: /编辑/ }))
    const group = await screen.findByRole('group', { name: '高级出站' })
    expect(within(group).getByRole('switch', { name: '允许回环地址' })).toBeDisabled()
    // 允许私网回源同样只有平台级角色能打开。
    expect(screen.getByRole('switch', { name: '允许私网回源' })).toBeDisabled()
    const metadata = within(group).getByRole('switch', { name: '允许云元数据地址' })
    expect(metadata).toBeChecked()
    expect(metadata).toBeEnabled()
    await user.click(metadata)
    expect(metadata).not.toBeChecked()
  })

  it('平台级安全员可以打开', async () => {
    useAuthStore.setState({ token: 't', user: { id: 'u3', username: 'so', role: 'security_officer', tenant_id: 'tenant_default' }, isAuthenticated: true })
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('button', { name: /编辑/ }))
    const group = await screen.findByRole('group', { name: '高级出站' })
    expect(within(group).getByRole('switch', { name: '允许回环地址' })).toBeEnabled()
  })

  it('取消确认不打开', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('button', { name: /编辑/ }))
    const group = await screen.findByRole('group', { name: '高级出站' })
    const metadata = within(group).getByRole('switch', { name: '允许云元数据地址' })
    await user.click(metadata)
    const content = await screen.findAllByText('网关可被用来访问这些地址。')
    const confirm = content[content.length - 1].closest('.ant-modal') as HTMLElement
    await user.click(within(confirm).getByRole('button', { name: /取\s*消/ }))
    expect(metadata).not.toBeChecked()
  })
})

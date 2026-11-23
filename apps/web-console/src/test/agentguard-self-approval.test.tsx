import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Modal } from 'antd'
import AgentGuard from '../pages/AgentGuard'
import api from '../services/api'
import { useAuthStore } from '../stores/auth'
import { last } from './protectionTestUtils'

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return { ...actual, message: { success: vi.fn(), error: vi.fn() } }
})

let settings: Record<string, unknown> = {}

function renderPage(role = 'platform_admin', tenant_id = 'tenant_default') {
  useAuthStore.setState({ token: 't', user: { id: 'u1', username: 'u', role, tenant_id }, isAuthenticated: true })
  return render(
    <MemoryRouter initialEntries={['/security/agents/advanced?tab=confirmations']}>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
        <AgentGuard />
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

describe('工具确认与例外：允许本人批准', () => {
  afterEach(() => Modal.destroyAll())
  beforeEach(() => {
    vi.restoreAllMocks()
    settings = {}
    vi.spyOn(api, 'get').mockImplementation(async (url: string) => {
      if (url === '/system/settings') return { data: settings } as never
      return { data: { data: [] } } as never
    })
    vi.spyOn(api, 'put').mockResolvedValue({ data: {} } as never)
  })

  it('打开要二次确认，确认后写入系统设置', async () => {
    const user = userEvent.setup()
    renderPage()
    const toggle = await screen.findByRole('switch', { name: '允许本人批准' })
    await waitFor(() => expect(toggle).toBeEnabled())
    expect(toggle).not.toBeChecked()
    await user.click(toggle)
    expect(await screen.findByText('触发确认的人可以自己批准这次操作。')).toBeInTheDocument()
    expect(api.put).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: '确认打开' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/security/system-settings', { agentguard_allow_self_approval: true }))
  })

  it('取消确认不写入', async () => {
    const user = userEvent.setup()
    renderPage()
    const toggle = await screen.findByRole('switch', { name: '允许本人批准' })
    await waitFor(() => expect(toggle).toBeEnabled())
    await user.click(toggle)
    const dialog = last(await screen.findAllByText('触发确认的人可以自己批准这次操作。')).closest('.ant-modal') as HTMLElement
    await user.click(within(dialog).getByRole('button', { name: /取\s*消/ }))
    expect(api.put).not.toHaveBeenCalled()
  })

  it('关闭不需要确认', async () => {
    settings = { agentguard_allow_self_approval: 'true' }
    const user = userEvent.setup()
    renderPage('security_officer')
    const toggle = await screen.findByRole('switch', { name: '允许本人批准' })
    await waitFor(() => expect(toggle).toBeChecked())
    await user.click(toggle)
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('/security/system-settings', { agentguard_allow_self_approval: false }))
  })

  it('租户级安全员只读（平台级设置）', async () => {
    renderPage('security_officer', 'tenant-a')
    const toggle = await screen.findByRole('switch', { name: '允许本人批准' })
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/system/settings'))
    expect(toggle).toBeDisabled()
  })

  it('租户管理员只读', async () => {
    renderPage('tenant_admin')
    const toggle = await screen.findByRole('switch', { name: '允许本人批准' })
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/system/settings'))
    expect(toggle).toBeDisabled()
  })
})

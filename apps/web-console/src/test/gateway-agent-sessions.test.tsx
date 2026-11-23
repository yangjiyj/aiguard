import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import GatewayAgentSessions from '../pages/GatewayAgentSessions'
import { agentApi } from '../services/api'

const { authState } = vi.hoisted(() => ({ authState: {
  user: { id: 'admin-1', role: 'platform_admin', tenant_id: 'tenant-1' },
} }))

vi.mock('../stores/auth', () => ({ useAuthStore: (selector?: (state: typeof authState) => unknown) => selector ? selector(authState) : authState }))
vi.mock('../services/api', () => ({ agentApi: { list: vi.fn() } }))

const session = {
  session_id: 'gateway-session-1', agent_type: 'codex', workspace_id: 'workspace-1',
  risk_score: 12, request_count: 3,
  first_request: '2026-10-10T01:00:00Z', last_request: '2026-10-10T02:00:00Z',
}

describe('Gateway agent session audit', () => {
  let client: QueryClient
  beforeEach(() => {
    vi.clearAllMocks()
    authState.user = { id: 'admin-1', role: 'platform_admin', tenant_id: 'tenant-1' }
    client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.mocked(agentApi.list).mockResolvedValue({ data: { data: [session], total: 1 } } as any)
  })
  const page = () => <QueryClientProvider client={client}><GatewayAgentSessions /></QueryClientProvider>

  it('reads existing gateway audit records with server pagination', async () => {
    render(page())
    expect(await screen.findByText('gateway-session-1')).toBeInTheDocument()
    expect(screen.getByText('workspace-1')).toBeInTheDocument()
    expect(screen.getByText('共 1 条会话')).toBeInTheDocument()
    expect(agentApi.list).toHaveBeenCalledWith({ tenant_scope: 'all', limit: 20, offset: 0 })
  })

  it('tenant accounts never request the all-tenant scope', async () => {
    authState.user = { id: 'tenant-user', role: 'tenant_admin', tenant_id: 'tenant-1' }
    render(page())
    expect(await screen.findByText('gateway-session-1')).toBeInTheDocument()
    expect(agentApi.list).toHaveBeenCalledWith({ tenant_scope: 'tenant', limit: 20, offset: 0 })
    expect(screen.getByText('当前单位')).toBeInTheDocument()
  })

  it('requests the next page instead of slicing only the first returned page', async () => {
    vi.mocked(agentApi.list).mockResolvedValueOnce({ data: { data: [session], total: 21 } } as any)
      .mockResolvedValueOnce({ data: { data: [{ ...session, session_id: 'gateway-session-21' }], total: 21 } } as any)
    const { container } = render(page())
    expect(await screen.findByText('gateway-session-1')).toBeInTheDocument()
    fireEvent.click(container.querySelector('.ant-pagination-next button')!)
    expect(await screen.findByText('gateway-session-21')).toBeInTheDocument()
    expect(agentApi.list).toHaveBeenLastCalledWith({ tenant_scope: 'all', limit: 20, offset: 20 })
    expect(screen.queryByText('gateway-session-1')).not.toBeInTheDocument()
  })

  it('does not present a failed request as an empty audit history', async () => {
    vi.mocked(agentApi.list).mockRejectedValue(new Error('service unavailable'))
    render(page())
    expect(await screen.findByText('会话审计加载失败')).toBeInTheDocument()
    expect(screen.queryByText('暂无网关会话记录')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '重试' })).toBeInTheDocument()
  })

  it('cannot reuse cached audit rows after switching tenant identity', async () => {
    authState.user = { id: 'tenant-user-1', role: 'tenant_admin', tenant_id: 'tenant-1' }
    const view = render(page())
    expect(await screen.findByText('gateway-session-1')).toBeInTheDocument()
    vi.mocked(agentApi.list).mockResolvedValue({ data: { data: [], total: 0 } } as any)
    authState.user = { id: 'tenant-user-2', role: 'tenant_admin', tenant_id: 'tenant-2' }
    view.rerender(page())
    await waitFor(() => expect(agentApi.list).toHaveBeenCalledTimes(2))
    expect(screen.queryByText('gateway-session-1')).not.toBeInTheDocument()
    expect(await screen.findByText('暂无网关会话记录')).toBeInTheDocument()
  })

  it('does not query without a tenant for a tenant-scoped account', () => {
    authState.user = { id: 'tenant-user', role: 'tenant_admin', tenant_id: '' }
    render(page())
    expect(screen.getByText('当前账号未关联单位，无法查询会话')).toBeInTheDocument()
    expect(agentApi.list).not.toHaveBeenCalled()
  })
})

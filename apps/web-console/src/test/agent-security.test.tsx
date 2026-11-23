import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import AgentSecurity from '../pages/AgentSecurity'
import { agentGuardApi } from '../services/api'

vi.mock('../pages/agentguard/AgentRiskOverview', () => ({
  default: () => <div>客户风险态势内容</div>,
}))

const renderPage = (path = '/security/agentguard') => {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <AgentSecurity />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AgentSecurity customer boundary', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.spyOn(agentGuardApi, 'listConfirmations').mockResolvedValue({
      data: {
        data: [{
          id: 'agc_internal_1',
          request_id: 'req_internal_1',
          trace_id: 'trace_internal_1',
          tool_name: 'run_shell',
          source: '',
          raw_decision: 'confirm',
          effective_decision: 'audit',
          status: 'pending',
          timeout_action: 'block',
          reason: 'sensitive_personal_data_egress',
          expires_at: '2030-01-01T00:00:00Z',
          created_at: '2026-01-01T00:00:00Z',
        }, {
          id: 'agc_mcp_hidden',
          request_id: 'req_mcp_hidden',
          trace_id: 'trace_mcp_hidden',
          tool_name: 'mcp_remote_delete',
          source: 'mcp',
          raw_decision: 'confirm',
          effective_decision: 'confirm',
          status: 'pending',
          timeout_action: 'block',
          reason: 'mcp_confirmation',
          expires_at: '2030-01-01T00:00:00Z',
          created_at: '2026-01-01T00:00:01Z',
        }],
      },
    } as any)
    vi.spyOn(agentGuardApi, 'resolveConfirmation').mockResolvedValue({ data: { status: 'approved' } } as any)
    vi.spyOn(agentGuardApi, 'listPolicies').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(agentGuardApi, 'listExceptions').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(agentGuardApi, 'listRollouts').mockResolvedValue({ data: { data: [] } } as any)
  })

  it('renders only customer risk content and does not prefetch governance APIs', async () => {
    renderPage()

    expect(await screen.findByText('客户风险态势内容')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '风险态势', selected: true })).toBeInTheDocument()
    expect(agentGuardApi.listConfirmations).not.toHaveBeenCalled()
    expect(agentGuardApi.listPolicies).not.toHaveBeenCalled()
    expect(agentGuardApi.listExceptions).not.toHaveBeenCalled()
    expect(agentGuardApi.listRollouts).not.toHaveBeenCalled()
    expect(screen.queryByText('策略与管控')).not.toBeInTheDocument()
  })

  it('opens query-linked pending confirmations without exposing internal identifiers', async () => {
    renderPage('/security/agentguard?tab=confirmations')

    expect(await screen.findByRole('tab', { name: '人工确认', selected: true })).toBeInTheDocument()
    expect(await screen.findByText('run_shell')).toBeInTheDocument()
    expect(screen.queryByText('mcp_remote_delete')).not.toBeInTheDocument()
    expect(screen.getByText('需确认')).toBeInTheDocument()
    expect(screen.getByText('审计')).toBeInTheDocument()
    expect(screen.getByText('阻断')).toBeInTheDocument()
    for (const internal of ['agc_internal_1', 'req_internal_1', 'trace_internal_1', 'sensitive_personal_data_egress']) {
      expect(screen.queryByText(internal)).not.toBeInTheDocument()
    }
    expect(agentGuardApi.listPolicies).not.toHaveBeenCalled()
    expect(agentGuardApi.listExceptions).not.toHaveBeenCalled()
    expect(agentGuardApi.listRollouts).not.toHaveBeenCalled()
  })

  it('authorizes an exact client retry without claiming central local-tool execution', async () => {
    const user = userEvent.setup()
    renderPage('/security/agentguard?tab=confirmations')

    expect(await screen.findByText(/中心端不会执行本地工具/)).toBeInTheDocument()
    await user.click(await screen.findByRole('button', { name: '允许客户端重试' }))
    expect(agentGuardApi.resolveConfirmation).not.toHaveBeenCalled()
    const confirmText = await screen.findByText('允许发起人以相同参数重试工具“run_shell”一次？')
    expect(confirmText).toBeInTheDocument()
    expect(confirmText).not.toHaveTextContent(/agc_internal_1|req_internal_1|trace_internal_1/)

    await user.click(screen.getByRole('button', { name: '允许重试' }))
    await waitFor(() => {
      expect(agentGuardApi.resolveConfirmation).toHaveBeenCalledWith('agc_internal_1', {
        status: 'approved',
        note: '控制台批准',
      })
    })
    await waitFor(() => expect(agentGuardApi.listConfirmations).toHaveBeenCalledTimes(2))
  })

  it('rechecks pending confirmations after a 503 without asserting the action failed', async () => {
    const user = userEvent.setup()
    vi.mocked(agentGuardApi.resolveConfirmation).mockRejectedValueOnce(
      Object.assign(new Error('service unavailable'), { response: { status: 503 } }),
    )
    renderPage('/security/agentguard?tab=confirmations')

    await screen.findByText('run_shell')
    expect(agentGuardApi.listConfirmations).toHaveBeenCalledTimes(1)
    await user.click(screen.getByRole('button', { name: '拒绝本次调用' }))
    expect(agentGuardApi.resolveConfirmation).not.toHaveBeenCalled()
    expect(await screen.findByText('确认拒绝工具“run_shell”的本次调用？')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '确认拒绝' }))
    await waitFor(() => {
      expect(agentGuardApi.resolveConfirmation).toHaveBeenCalledWith('agc_internal_1', {
        status: 'rejected',
        note: '控制台拒绝',
      })
    })
    expect(await screen.findByText('处理结果需重新核验，已刷新列表')).toBeInTheDocument()
    expect(screen.queryByText(/处理失败/)).not.toBeInTheDocument()
    await waitFor(() => expect(agentGuardApi.listConfirmations).toHaveBeenCalledTimes(2))
  })
})

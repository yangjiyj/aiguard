import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import AgentGuard from '../pages/AgentGuard'
import { agentGuardApi } from '../services/api'

describe('例外与确认', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(agentGuardApi, 'listExceptions').mockResolvedValue({
      data: { data: [{ id: 'exception-1', scope_type: 'tenant', decision: 'audit', target_pattern: 'partner.example', reason: '已审批业务', enabled: true }] },
    } as never)
    vi.spyOn(agentGuardApi, 'listConfirmations').mockResolvedValue({
      data: { data: [{ id: 'confirmation-1', tool_name: 'network.upload', status: 'pending', source: '', reason: '需要确认' }] },
    } as never)
    vi.spyOn(agentGuardApi, 'listPolicies').mockResolvedValue({ data: { data: [] } } as never)
    vi.spyOn(agentGuardApi, 'listTemplates').mockResolvedValue({ data: { data: [] } } as never)
    vi.spyOn(agentGuardApi, 'getBehaviorBaseline').mockResolvedValue({ data: {} } as never)
    vi.spyOn(agentGuardApi, 'listVersions').mockResolvedValue({ data: { data: [] } } as never)
  })

  it('将旧运行方案链接归一为例外放行，且不读取运行方案相关数据', async () => {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/security/agents/advanced?tab=policies&behavior=network_egress']}>
          <AgentGuard />
        </MemoryRouter>
      </QueryClientProvider>,
    )

    expect(screen.getByRole('heading', { name: '\u5de5\u5177\u786e\u8ba4\u4e0e\u4f8b\u5916' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '例外放行', selected: true })).toBeInTheDocument()
    expect(screen.getAllByRole('tab')).toHaveLength(2)
    expect(screen.queryByText('运行方案')).not.toBeInTheDocument()
    expect(screen.queryByText('推荐运行方案')).not.toBeInTheDocument()
    expect(agentGuardApi.listPolicies).not.toHaveBeenCalled()
    expect(agentGuardApi.listTemplates).not.toHaveBeenCalled()
    expect(agentGuardApi.getBehaviorBaseline).not.toHaveBeenCalled()
  })

  it('缺少展示名时不回显内部范围和规则标识', async () => {
    vi.mocked(agentGuardApi.listExceptions).mockResolvedValue({
      data: {
        data: [{
          id: 'exception-raw-reference',
          scope_type: 'key',
          scope_ref: 'key_internal_123',
          rule_id: 'rule_internal_456',
          target_pattern: 'partner.example',
          decision: 'audit',
          reason: '已审批业务',
          enabled: true,
        }],
      },
    } as never)
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/security/agents/advanced']}>
          <AgentGuard />
        </MemoryRouter>
      </QueryClientProvider>,
    )

    expect(await screen.findByText('partner.example')).toBeInTheDocument()
    expect(screen.getByText('指定密钥', { exact: true })).toBeInTheDocument()
    expect(screen.getByText('按目标匹配', { exact: true })).toBeInTheDocument()
    expect(screen.queryByText('key_internal_123')).not.toBeInTheDocument()
    expect(screen.queryByText('rule_internal_456')).not.toBeInTheDocument()
  })
})

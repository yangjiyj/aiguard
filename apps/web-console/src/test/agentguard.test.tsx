import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import AgentGuard from '../pages/AgentGuard'
import { agentGuardApi } from '../services/api'

vi.mock('antd', async () => {
  const actual = await vi.importActual<typeof import('antd')>('antd')
  return {
    ...actual,
    message: {
      success: vi.fn(),
      error: vi.fn(),
      warning: vi.fn(),
      info: vi.fn(),
      loading: vi.fn(),
      destroy: vi.fn(),
    },
  }
})

describe('例外与确认页', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    vi.restoreAllMocks()
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    vi.spyOn(agentGuardApi, 'listExceptions').mockResolvedValue({
      data: {
        data: [{
          id: 'age_1',
          scope_type: 'project',
          scope_ref: '客服助手',
          rule_id: 'rule_1',
          target_pattern: 'api.partner.example',
          decision: 'audit',
          reason: '已审批的合作方接口',
          expires_at: '2026-06-10T00:00:00Z',
          enabled: true,
        }],
      },
    } as never)
    vi.spyOn(agentGuardApi, 'listConfirmations').mockResolvedValue({
      data: {
        data: [{
          id: 'agc_1',
          tool_name: 'network.upload',
          raw_decision: 'confirm',
          effective_decision: 'confirm',
          status: 'pending',
          timeout_action: 'block',
          reason: 'sensitive_personal_data_egress',
          expires_at: '2026-06-04T00:10:00Z',
          source: '',
        }, {
          id: 'agc_mcp_hidden',
          tool_name: 'mcp_remote_delete',
          raw_decision: 'confirm',
          effective_decision: 'confirm',
          status: 'pending',
          timeout_action: 'block',
          reason: 'mcp_confirmation',
          expires_at: '2026-06-04T00:10:00Z',
          source: 'mcp',
        }],
      },
    } as never)
    vi.spyOn(agentGuardApi, 'createException').mockResolvedValue({ data: { id: 'age_2' } } as never)
    vi.spyOn(agentGuardApi, 'deleteException').mockResolvedValue({ data: { ok: true } } as never)
    vi.spyOn(agentGuardApi, 'resolveConfirmation').mockResolvedValue({ data: { id: 'agc_1', status: 'approved' } } as never)
    vi.spyOn(agentGuardApi, 'listPolicies').mockResolvedValue({ data: { data: [] } } as never)
    vi.spyOn(agentGuardApi, 'listTemplates').mockResolvedValue({ data: { data: [] } } as never)
    vi.spyOn(agentGuardApi, 'getBehaviorBaseline').mockResolvedValue({ data: {} } as never)
    vi.spyOn(agentGuardApi, 'listVersions').mockResolvedValue({ data: { data: [] } } as never)
    vi.spyOn(agentGuardApi, 'simulatePolicy').mockResolvedValue({ data: {} } as never)
  })

  const renderPage = (initialPath = '/security/agents/advanced') => render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialPath]}>
        <AgentGuard />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  it('只展示例外放行和待确认操作，不加载运行方案相关数据', async () => {
    renderPage('/security/agents/advanced?tab=policies&behavior=network_egress')

    expect(await screen.findByRole('heading', { name: '\u5de5\u5177\u786e\u8ba4\u4e0e\u4f8b\u5916' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '例外放行', selected: true })).toBeInTheDocument()
    expect(screen.getAllByRole('tab')).toHaveLength(2)
    for (const removed of ['运行方案', '当前运行方案', '推荐运行方案', '新建运行方案', '方案模板', '查看影响']) {
      expect(screen.queryByText(removed)).not.toBeInTheDocument()
    }
    expect(agentGuardApi.listPolicies).not.toHaveBeenCalled()
    expect(agentGuardApi.listTemplates).not.toHaveBeenCalled()
    expect(agentGuardApi.getBehaviorBaseline).not.toHaveBeenCalled()
    expect(agentGuardApi.listVersions).not.toHaveBeenCalled()
    expect(agentGuardApi.simulatePolicy).not.toHaveBeenCalled()
  })

  it('保留例外创建和删除', async () => {
    const user = userEvent.setup()
    renderPage()

    expect(await screen.findByText('已审批的合作方接口')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '删除' }))
    await waitFor(() => expect(agentGuardApi.deleteException).toHaveBeenCalledWith('age_1'))

    await user.click(screen.getByRole('button', { name: '新增放行' }))
    await user.type(screen.getByLabelText('\u5173\u8054\u89c4\u5219'), 'rule-1')
    await user.type(screen.getByLabelText('审批原因'), '合同约定的合作方地址')
    // 2.9.22 起非全租户范围时“具体对象”必填（新建默认范围是指定应用）。
    await user.type(screen.getByLabelText('具体对象'), 'project-1')
    await user.click(screen.getByRole('button', { name: '创建例外' }))
    await waitFor(() => expect(agentGuardApi.createException).toHaveBeenCalledWith(expect.objectContaining({
      scope_type: 'project',
      scope_ref: 'project-1',
      decision: 'audit',
      rule_id: 'rule-1',
      reason: '合同约定的合作方地址',
      enabled: true,
    })))
  })

  it('保留待确认操作的批准处理，并过滤 MCP 项', async () => {
    const user = userEvent.setup()
    renderPage('/security/agents/advanced?tab=confirmations')

    expect(await screen.findByText('network.upload')).toBeInTheDocument()
    expect(screen.queryByText('mcp_remote_delete')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '允许重试' }))
    expect(await screen.findByText('批准后，同一发起人以相同参数重试时网关放行一次（批准后 30 分钟内有效）；中心端不会执行本地工具。')).toBeInTheDocument()
    const approvalButtons = screen.getAllByRole('button', { name: '允许重试' })
    await user.click(approvalButtons[approvalButtons.length - 1])
    await waitFor(() => expect(agentGuardApi.resolveConfirmation).toHaveBeenCalledWith('agc_1', {
      status: 'approved',
      note: '控制台批准',
    }))
  })
})

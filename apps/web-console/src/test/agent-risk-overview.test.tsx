import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import type { ReactElement } from 'react'
import AgentRiskOverview from '../pages/agentguard/AgentRiskOverview'
import ToolAudit from '../pages/ToolAudit'
import * as api from '../services/api'

const renderWithClient = (ui: ReactElement, initialPath = '/') => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialPath]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  )
}

const LocationProbe = () => {
  const location = useLocation()
  return <div data-testid="location">{location.pathname + location.search}</div>
}

const linkedLocationURL = () => new URL(`http://local${screen.getByTestId('location').textContent || ''}`)

const expectSevenDayWindow = (url: URL) => {
  const from = url.searchParams.get('from')
  const to = url.searchParams.get('to')
  expect(from).toBeTruthy()
  expect(to).toBeTruthy()
  const windowMs = Date.parse(to || '') - Date.parse(from || '')
  expect(windowMs).toBeGreaterThanOrEqual(6.9 * 24 * 60 * 60 * 1000)
  expect(windowMs).toBeLessThanOrEqual(7.1 * 24 * 60 * 60 * 1000)
}

describe('AgentRiskOverview page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.spyOn(api, 'getAgentRiskOverview').mockResolvedValue({
      data: {
        total_tool_calls: 12,
        tool_call_attempts: 9,
        definition_exposed_count: 20,
        invocation_proposed_count: 10,
        execution_forwarded_count: 4,
        result_observed_count: 3,
        confirmation_replay_count: 2,
        unknown_event_count: 1,
        raw_decisions: { allow: 5, audit: 1, confirm: 2, block: 1 },
        effective_decisions: { allow: 3, audit: 4, confirm: 1, block: 1 },
        high_risk_calls: 3,
        blocked_calls: 0,
        audit_calls: 4,
        confirm_calls: 1,
        pending_confirm: 1,
        effective_mode: 'unknown',
        effective_mode_source: 'runtime_status_unavailable',
        audit_ceiling: null,
        runtime_mode_verified: false,
        configured_mode: 'audit_only',
        configured_mode_source: 'system_settings.security_audit_only',
        configured_audit_ceiling: true,
        confirmation_pending: 1,
        confirmation_approved: 3,
        confirmation_rejected: 2,
        confirmation_expired: 1,
        confirmation_executed: 2,
        confirmation_executing: 1,
        confirmation_failed: 4,
        confirmation_unknown: 2,
        confirmation_evidence_failed: 3,
        by_risk_level: [{ risk_level: 'high', count: 3 }],
        top_tools: [{ tool_name: 'bash.exec', count: 4 }],
        by_policy: [{ policy_id: 'pol_block', policy_name: '阻断策略', mode: 'block', count: 2 }],
        top_users: [{ id: 'user_1', name: 'alice', count: 4 }],
        top_apps: [{ id: 'project_1', name: '客服助手', count: 4 }],
        top_keys: [{ id: 'key_1', name: 'sk-live', count: 4 }],
        top_sessions: [{ id: 'sess_1', name: 'sess_1', count: 2 }],
        top_agents: [{ id: 'workbuddy', name: 'WorkBuddy', count: 2 }],
      },
    } as any)
    vi.spyOn(api.agentStatsApi, 'getStats').mockResolvedValue({ data: [] } as any)
  })
  it('shows a loading state before risk data is available', () => {
    vi.mocked(api.getAgentRiskOverview).mockReturnValue(new Promise(() => {}) as any)
    renderWithClient(<AgentRiskOverview />)

    expect(screen.getByTestId('agent-risk-loading')).toBeInTheDocument()
    expect(screen.queryByText('高危调用')).not.toBeInTheDocument()
  })

  it('shows an explicit retryable error instead of zero metrics when the API rejects', async () => {
    vi.mocked(api.getAgentRiskOverview).mockRejectedValue(new Error('network down'))
    renderWithClient(<AgentRiskOverview />)

    expect(await screen.findByText('智能体风险数据加载失败')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '重新加载' })).toBeInTheDocument()
    expect(screen.queryByText('高危调用')).not.toBeInTheDocument()
    expect(screen.queryByText('工具定义暴露（网关观察）')).not.toBeInTheDocument()
  })

  it('isolates an agent-identification API failure without rendering false zero metrics', async () => {
    const user = userEvent.setup()
    vi.mocked(api.agentStatsApi.getStats)
      .mockRejectedValueOnce(new Error('agent stats unavailable'))
      .mockResolvedValueOnce({ data: [] } as any)
    renderWithClient(<AgentRiskOverview />)

    expect(await screen.findByText('智能体识别数据加载失败')).toBeInTheDocument()
    for (const label of ['已识别智能体类型', '累计请求', '特征识别覆盖率']) {
      expect(screen.queryByText(label)).not.toBeInTheDocument()
    }

    await user.click(screen.getByRole('button', { name: '重新加载智能体识别' }))
    await waitFor(() => expect(api.agentStatsApi.getStats).toHaveBeenCalledTimes(2))
    await waitFor(() => {
      expect(screen.queryByText('智能体识别数据加载失败')).not.toBeInTheDocument()
      expect(screen.getByText('已识别智能体类型')).toBeInTheDocument()
    })
  })

  it('marks new metrics unavailable for an old backend response instead of displaying false zeros', async () => {
    vi.mocked(api.getAgentRiskOverview).mockResolvedValue({
      data: {
        total_tool_calls: 12,
        high_risk_calls: 3,
        blocked_calls: 1,
        audit_calls: 4,
        confirm_calls: 1,
        pending_confirm: 1,
        by_risk_level: [],
        top_tools: [],
        by_policy: [],
        top_users: [],
        top_apps: [],
        top_keys: [],
        top_sessions: [],
        top_agents: [],
      },
    } as any)
    renderWithClient(<AgentRiskOverview />)

    const lifecycleTitle = await screen.findByText('工具定义暴露（网关观察）')
    const lifecycleCard = lifecycleTitle.closest('.ant-card')
    expect(lifecycleCard).toHaveTextContent('暂不可用')
    expect(lifecycleCard).not.toHaveTextContent('0')
    expect(screen.getByText('后端版本不支持双决策统计')).toBeInTheDocument()
    expect(screen.getByText('高危调用')).toBeInTheDocument()
  })

  it('never echoes an unknown verified runtime mode', async () => {
    const current = await vi.mocked(api.getAgentRiskOverview)({ start: '', end: '' })
    vi.mocked(api.getAgentRiskOverview).mockResolvedValueOnce({
      ...current,
      data: { ...(current as any).data, runtime_mode_verified: true, effective_mode: 'future_internal_mode' },
    } as any)
    renderWithClient(<AgentRiskOverview />)

    expect(await screen.findByText('运行态：未识别运行模式')).toBeInTheDocument()
    expect(screen.queryByText(/future_internal_mode/)).not.toBeInTheDocument()
  })
  it('supports keyboard drill-down for a core card and a TOP row', async () => {
    const highView = renderWithClient(
      <Routes>
        <Route path="/" element={<><AgentRiskOverview /><LocationProbe /></>} />
        <Route path="/security/agent-tools" element={<LocationProbe />} />
      </Routes>,
    )

    const highRiskCard = (await screen.findByText('高危调用')).closest('.ant-card')
    expect(highRiskCard).toHaveAttribute('role', 'button')
    fireEvent.keyDown(highRiskCard!, { key: 'Enter' })
    let url = linkedLocationURL()
    expect(url.searchParams.get('risk_level')).toBe('high+')

    highView.unmount()
    renderWithClient(
      <Routes>
        <Route path="/" element={<><AgentRiskOverview /><LocationProbe /></>} />
        <Route path="/security/agent-tools" element={<LocationProbe />} />
      </Routes>,
    )
    const topRow = (await screen.findByText('WorkBuddy')).closest('tr')
    expect(topRow).toHaveAttribute('role', 'button')
    fireEvent.keyDown(topRow!, { key: ' ' })
    url = linkedLocationURL()
    expect(url.searchParams.get('agent_type')).toBe('workbuddy')
    expect(url.searchParams.get('risk_level')).toBe('high+')
  })



  it('shows configuration intent, unverified runtime and evidence lifecycle without inferring mode from zero blocks', async () => {
    renderWithClient(<AgentRiskOverview />)

    expect(await screen.findByText('配置意图：全局仅审计')).toBeInTheDocument()
    expect(screen.getByText('运行态未验证')).toBeInTheDocument()
    expect(screen.queryByText(/观测模式/)).not.toBeInTheDocument()
    expect(screen.queryByText(/拦截已生效/)).not.toBeInTheDocument()
    for (const label of [
      '工具定义暴露（网关观察）',
      '调用事实（去重）',
      '模型提出调用',
      '已证实转发',
      '结果已观察',
      '确认重放记录',
      '历史未知事件',
    ]) {
      expect(screen.getByText(label)).toBeInTheDocument()
    }
  })
  it('uses customer-facing labels for configuration and runtime status sources', async () => {
    const user = userEvent.setup()
    renderWithClient(<AgentRiskOverview />)

    const configured = await screen.findByText('配置意图：全局仅审计')
    await user.hover(configured)
    expect(await screen.findByRole('tooltip')).toHaveTextContent('系统安全设置')
    expect(screen.queryByText('system_settings.security_audit_only')).not.toBeInTheDocument()
    await user.unhover(configured)

    const runtime = screen.getByText('运行态未验证')
    await user.hover(runtime)
    expect(await screen.findByText('执行热路径状态未上报')).toBeInTheDocument()
    expect(screen.queryByText('runtime_status_unavailable')).not.toBeInTheDocument()
  })


  it('renders raw decision and effective action from backend maps without deriving allow by subtraction', async () => {
    renderWithClient(<AgentRiskOverview />)

    expect(await screen.findByText('原始判定 → 实际动作')).toBeInTheDocument()
    // total_tool_calls(12) - audit(4) - confirm(2) - block(0) = 6；后端原始 allow=5、实际 allow=3。
    // 页面必须呈现后端双决策事实，不能显示推算出来的 6。
    await waitFor(() => {
      expect(screen.getByTestId('raw-decision-allow')).toHaveTextContent('5')
      expect(screen.getByTestId('effective-decision-allow')).toHaveTextContent('3')
      expect(screen.getByTestId('raw-decision-confirm')).toHaveTextContent('2')
      expect(screen.getByTestId('effective-decision-confirm')).toHaveTextContent('1')
      expect(screen.getByText('需确认判定')).toBeInTheDocument()
      expect(screen.getByText('待处理确认单')).toBeInTheDocument()
      expect(screen.getByText('MCP执行中 1')).toBeInTheDocument()
      expect(screen.getByText('MCP执行失败 4')).toBeInTheDocument()
      expect(screen.getByText('MCP结果不确定 2')).toBeInTheDocument()
      expect(screen.getByText('MCP留证失败 3')).toBeInTheDocument()
    })
  })

  it('uses the raw confirm count and drills confirmation decisions by raw_decision', async () => {
    const user = userEvent.setup()
    renderWithClient(
      <Routes>
        <Route path="/" element={<><AgentRiskOverview /><LocationProbe /></>} />
        <Route path="/security/agent-tools" element={<LocationProbe />} />
      </Routes>,
    )

    const confirmTitle = await screen.findByText('需确认判定')
    const confirmCard = confirmTitle.closest('.ant-card')
    expect(confirmCard).toBeTruthy()
    await waitFor(() => expect(confirmCard).toHaveTextContent('2'))

    await user.click(confirmCard!)
    const url = linkedLocationURL()
    expect(url.pathname).toBe('/security/agent-tools')
    expect(url.searchParams.get('raw_decision')).toBe('confirm')
    expect(url.searchParams.get('risk_level')).toBe('all')
    expectSevenDayWindow(url)
  })

  it('does not expose internal policy or object identifiers on the customer overview', async () => {
    renderWithClient(<AgentRiskOverview />)

    expect(await screen.findByText('阻断策略')).toBeInTheDocument()
    for (const internalID of ['pol_block', 'user_1', 'project_1', 'key_1', 'sess_1']) {
      expect(screen.queryByText(internalID)).not.toBeInTheDocument()
    }
    expect(screen.getByText('会话')).toBeInTheDocument()
  })

  it('drills high-risk TOP rows to high+ while ordinary TOP rows retain all-risk scope', async () => {
    const user = userEvent.setup()
    const view = renderWithClient(
      <Routes>
        <Route path="/" element={<><AgentRiskOverview /><LocationProbe /></>} />
        <Route path="/security/agent-tools" element={<LocationProbe />} />
      </Routes>,
    )

    await user.click(await screen.findByText('WorkBuddy'))
    let url = linkedLocationURL()
    expect(url.searchParams.get('agent_type')).toBe('workbuddy')
    expect(url.searchParams.get('risk_level')).toBe('high+')

    view.unmount()
    renderWithClient(
      <Routes>
        <Route path="/" element={<><AgentRiskOverview /><LocationProbe /></>} />
        <Route path="/security/agent-tools" element={<LocationProbe />} />
      </Routes>,
    )
    await user.click(await screen.findByText('客服助手'))
    url = linkedLocationURL()
    expect(url.searchParams.get('project_id')).toBe('project_1')
    expect(url.searchParams.get('risk_level')).toBe('all')
  })

  it('opens the actual AgentGuard confirmation tab from pending confirmations', async () => {
    const user = userEvent.setup()
    renderWithClient(
      <Routes>
        <Route path="/" element={<><AgentRiskOverview /><LocationProbe /></>} />
        <Route path="/security/agentguard" element={<LocationProbe />} />
      </Routes>,
    )

    const pending = await screen.findByText('待处理确认单')
    await user.click(pending.closest('.ant-card')!)
    const url = linkedLocationURL()
    expect(url.pathname).toBe('/security/agentguard')
    expect(url.searchParams.get('tab')).toBe('confirmations')
  })

  it('links policy rows to tool-audit drill-down with the source time window', async () => {
    const user = userEvent.setup()
    renderWithClient(
      <Routes>
        <Route path="/" element={<><AgentRiskOverview /><LocationProbe /></>} />
        <Route path="/security/agent-tools" element={<LocationProbe />} />
      </Routes>,
    )

    expect(await screen.findByText('调用事实（去重）')).toBeInTheDocument()
    expect(await screen.findByText('阻断策略')).toBeInTheDocument()
    await user.click(screen.getByText('阻断策略'))
    const url = linkedLocationURL()
    expect(url.pathname).toBe('/security/agent-tools')
    expect(url.searchParams.get('policy_id')).toBe('pol_block')
    expect(url.searchParams.get('mode')).toBe('block')
    expect(url.searchParams.get('risk_level')).toBe('all')
    expectSevenDayWindow(url)
  })

  it('links attention-worthy agent signals to high-risk audit rows by agent_type', async () => {
    const user = userEvent.setup()
    renderWithClient(
      <Routes>
        <Route path="/" element={<><AgentRiskOverview /><LocationProbe /></>} />
        <Route path="/security/agent-tools" element={<LocationProbe />} />
      </Routes>,
    )

    expect(await screen.findByText('需关注行为来源 TOP 5')).toBeInTheDocument()
    await user.click(await screen.findByText('WorkBuddy'))
    const url = linkedLocationURL()
    expect(url.pathname).toBe('/security/agent-tools')
    expect(url.searchParams.get('agent_type')).toBe('workbuddy')
    expect(url.searchParams.get('risk_level')).toBe('high+')
    expectSevenDayWindow(url)
  })

  it('links total card to the all-risk tool-audit drill-down', async () => {
    const user = userEvent.setup()
    renderWithClient(
      <Routes>
        <Route path="/" element={<><AgentRiskOverview /><LocationProbe /></>} />
        <Route path="/security/agent-tools" element={<LocationProbe />} />
      </Routes>,
    )

    await user.click(await screen.findByText('调用事实（去重）'))
    const url = linkedLocationURL()
    expect(url.pathname).toBe('/security/agent-tools')
    expect(url.searchParams.get('risk_level')).toBe('all')
    expectSevenDayWindow(url)
  })

  it('links top tools to all-risk tool-audit rows instead of the default high-risk subset', async () => {
    const user = userEvent.setup()
    renderWithClient(
      <Routes>
        <Route path="/" element={<><AgentRiskOverview /><LocationProbe /></>} />
        <Route path="/security/agent-tools" element={<LocationProbe />} />
      </Routes>,
    )

    await user.click(await screen.findByText('bash.exec'))
    const url = linkedLocationURL()
    expect(url.pathname).toBe('/security/agent-tools')
    expect(url.searchParams.get('tool_name')).toBe('bash.exec')
    expect(url.searchParams.get('risk_level')).toBe('all')
    expectSevenDayWindow(url)
  })

  it('does not link identification rows when no equal-count drill-down target exists', async () => {
    const user = userEvent.setup()
    vi.mocked(api.agentStatsApi.getStats).mockResolvedValue({
      data: [
        { agent_type: 'agent-tool-call', session_count: 10, request_count: 2560, content_request_count: 1711, tool_backed_request_count: 477, percent: 100 },
      ],
    } as any)

    renderWithClient(
      <Routes>
        <Route path="/" element={<><AgentRiskOverview /><LocationProbe /></>} />
        <Route path="/audit/access-retention" element={<LocationProbe />} />
        <Route path="/security/agent-tools" element={<LocationProbe />} />
      </Routes>,
    )

    expect(await screen.findByText('待识别智能体请求')).toBeInTheDocument()
    await user.click(screen.getByText('待识别智能体请求'))
    expect(screen.getByTestId('location')).toHaveTextContent('/')
  })

  it('links identification distribution rows to retained access evidence instead of security alerts', async () => {
    const user = userEvent.setup()
    vi.mocked(api.agentStatsApi.getStats).mockResolvedValue({
      data: [
        { agent_type: 'workbuddy', session_count: 1, request_count: 18, content_request_count: 18, percent: 100 },
      ],
    } as any)

    renderWithClient(
      <Routes>
        <Route path="/" element={<><AgentRiskOverview /><LocationProbe /></>} />
        <Route path="/audit/access-retention" element={<LocationProbe />} />
        <Route path="/security/alerts" element={<LocationProbe />} />
      </Routes>,
    )

    expect(await screen.findByText('智能体识别分布')).toBeInTheDocument()
    const workbuddyLabels = await screen.findAllByText('WorkBuddy')
    await user.click(workbuddyLabels[0])
    const url = linkedLocationURL()
    expect(url.pathname).toBe('/audit/access-retention')
    expect(url.searchParams.get('agent_type')).toBe('workbuddy')
    expect(url.searchParams.get('content_only')).toBe('true')
    expectSevenDayWindow(url)
  })
})

describe('ToolAudit linked filters', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.spyOn(api.toolAuditApi, 'listHighRisk').mockResolvedValue({ data: { data: [], total: 0 } } as any)
    vi.spyOn(api.auditDispositionApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.auditApi, 'listEvents').mockResolvedValue({ data: { data: [] } } as any)
  })

  it('passes URL-linked mode/risk/policy filters to the high-risk API', async () => {
    renderWithClient(<ToolAudit />, '/security/agent-tools?mode=block&risk_level=high&policy_id=pol_block')

    await waitFor(() => {
      expect(api.toolAuditApi.listHighRisk).toHaveBeenCalledWith(expect.objectContaining({
        limit: 20,
        offset: 0,
        mode: 'block',
        risk_level: 'high',
        policy_id: 'pol_block',
        skip_total: false,
      }))
    })
    const params = (api.toolAuditApi.listHighRisk as any).mock.calls[0][0]
    expect(new Date(params.to).getTime() - new Date(params.from).getTime()).toBeGreaterThanOrEqual(23 * 60 * 60 * 1000)
    expect(new Date(params.to).getTime() - new Date(params.from).getTime()).toBeLessThanOrEqual(25 * 60 * 60 * 1000)
  })

  it('honors explicit drill-down window and all-risk agent filters from the URL', async () => {
    renderWithClient(
      <ToolAudit />,
      '/security/agent-tools?agent_type=workbuddy&tool_name=read_file&risk_level=all&from=2026-06-16T15:17:42.000Z&to=2026-06-23T15:17:42.000Z',
    )

    await waitFor(() => {
      expect(api.toolAuditApi.listHighRisk).toHaveBeenCalledWith(expect.objectContaining({
        agent_type: 'workbuddy',
        tool_name: 'read_file',
        risk_level: 'all',
        from: '2026-06-16T15:17:42.000Z',
        to: '2026-06-23T15:17:42.000Z',
        limit: 20,
        offset: 0,
        skip_total: false,
      }))
    })
  })

  it('forwards raw/effective decision and MCP server deep links to the API', async () => {
    renderWithClient(
      <ToolAudit />,
      '/security/agent-tools?raw_decision=confirm&effective_decision=audit&server=filesystem&risk_level=all',
    )

    await waitFor(() => {
      expect(api.toolAuditApi.listHighRisk).toHaveBeenCalledWith(expect.objectContaining({
        raw_decision: 'confirm',
        effective_decision: 'audit',
        server: 'filesystem',
        risk_level: 'all',
        limit: 20,
        offset: 0,
        skip_total: false,
      }))
    })
  })

  it('shows linked audit-only system records instead of hiding them from drill-down results', async () => {
    vi.mocked(api.toolAuditApi.listHighRisk).mockResolvedValue({
      data: {
        total: 2,
        data: [
          {
            id: 'tc_audit_only',
            request_id: 'req_audit_only',
            user_id: 'user_admin',
            tool_name: 'run_shell',
            tool_type: 'system',
            risk_level: 'medium',
            status: 'success',
            mode: 'audit',
            matched_action: 'audit',
            matched_policy_name: '仅审计策略',
            match_reason: '审计留痕',
            parameters: { command: 'pwd' },
            created_at: '2026-06-23T15:00:00Z',
          },
        ],
      },
    } as any)

    renderWithClient(<ToolAudit />, '/security/agent-tools?mode=audit&risk_level=all&from=2026-06-16T15:17:42.000Z&to=2026-06-23T15:17:42.000Z')

    expect(await screen.findByText('仅审计策略')).toBeInTheDocument()
    expect(await screen.findByText('显示 1 / 2 条')).toBeInTheDocument()
  })
})

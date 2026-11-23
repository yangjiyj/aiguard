import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AgentStats from '../pages/AgentStats'
import * as api from '../services/api'

describe('AgentStats page', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    vi.clearAllMocks()
  })

  const renderAgentStats = () => {
    return render(
      <QueryClientProvider client={queryClient}>
        <AgentStats />
      </QueryClientProvider>
    )
  }

  it('renders page title', async () => {
    vi.spyOn(api.agentStatsApi, 'getStats').mockResolvedValue({
      data: [],
    } as any)

    vi.spyOn(api.agentStatsApi, 'getDistribution').mockResolvedValue({
      data: [],
    } as any)

    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [] },
    } as any)

    renderAgentStats()

    await waitFor(() => {
      expect(screen.getByText('智能体使用统计')).toBeInTheDocument()
    })
  })

  it('renders agent type distribution card', async () => {
    vi.spyOn(api.agentStatsApi, 'getStats').mockResolvedValue({
      data: [],
    } as any)

    vi.spyOn(api.agentStatsApi, 'getDistribution').mockResolvedValue({
      data: [
        { agent_type: 'claude-code', count: 100 },
        { agent_type: 'cursor', count: 50 },
      ],
    } as any)

    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [] },
    } as any)

    renderAgentStats()

    await waitFor(() => {
      expect(screen.getByText('智能体类型分布')).toBeInTheDocument()
    })

    await waitFor(() => {
      expect(screen.getByText('Claude Code')).toBeInTheDocument()
    })
  })

  it('renders agent stats table', async () => {
    vi.spyOn(api.agentStatsApi, 'getStats').mockResolvedValue({
      data: [
        { agent_type: 'claude-code', request_count: 100, session_count: 10, percent: 40 },
        { agent_type: 'agent-tool-call', request_count: 50, session_count: 5, percent: 20 },
      ],
    } as any)

    vi.spyOn(api.agentStatsApi, 'getDistribution').mockResolvedValue({
      data: [],
    } as any)

    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [] },
    } as any)

    renderAgentStats()

    await waitFor(() => {
      expect(screen.getByText('Claude Code')).toBeInTheDocument()
    })
    expect(screen.getByText('待识别智能体请求')).toBeInTheDocument()

    // Check table columns
    await waitFor(() => {
      expect(screen.getAllByText('智能体类型').length).toBeGreaterThan(0)
      expect(screen.getAllByText('识别方式').length).toBeGreaterThan(0)
      expect(screen.getAllByText('识别规则').length).toBeGreaterThan(0)
      expect(screen.getAllByText('关注风险分类').length).toBeGreaterThan(0)
      expect(screen.getAllByText('采集覆盖').length).toBeGreaterThan(0)
      expect(screen.getAllByText('请求数').length).toBeGreaterThan(0)
      expect(screen.getAllByText('会话数').length).toBeGreaterThan(0)
    })
    expect(screen.getByText('客户端识别与使用明细')).toBeInTheDocument()
    expect(screen.getAllByLabelText('拖拽调整列宽：采集覆盖').length).toBeGreaterThan(0)
    expect(screen.getByText('客户端标识/特征识别')).toBeInTheDocument()
    expect(screen.getByText('工具调用迹象推断')).toBeInTheDocument()
    expect(screen.getByText('客户端请求头/特征指纹')).toBeInTheDocument()
    expect(screen.getByText('工具调用记录反推')).toBeInTheDocument()
    expect(screen.getAllByText(/工具越权/).length).toBeGreaterThan(0)
  })

  it('shows total requests count', async () => {
    vi.spyOn(api.agentStatsApi, 'getStats').mockResolvedValue({
      data: [],
    } as any)

    vi.spyOn(api.agentStatsApi, 'getDistribution').mockResolvedValue({
      data: [
        { agent_type: 'claude-code', count: 150 },
        { agent_type: 'cursor', count: 50 },
      ],
    } as any)

    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [] },
    } as any)

    renderAgentStats()

    await waitFor(() => {
      expect(screen.getByText('已识别请求数')).toBeInTheDocument()
    })
  })

  it('handles empty data gracefully', async () => {
    vi.spyOn(api.agentStatsApi, 'getStats').mockResolvedValue({
      data: [],
    } as any)

    vi.spyOn(api.agentStatsApi, 'getDistribution').mockResolvedValue({
      data: [],
    } as any)

    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [] },
    } as any)

    renderAgentStats()

    await waitFor(() => {
      expect(screen.getByText('暂无已识别的智能体请求。请先让 Claude Code、OpenCode 等客户端通过网关发起请求。')).toBeInTheDocument()
    })
  })

  it('keeps the slow agent stats warm when revisiting the page shortly after', async () => {
    const getStats = vi.spyOn(api.agentStatsApi, 'getStats').mockResolvedValue({
      data: [
        { agent_type: 'claude-code', request_count: 100, session_count: 10, percent: 100 },
      ],
    } as any)

    const getDistribution = vi.spyOn(api.agentStatsApi, 'getDistribution').mockResolvedValue({
      data: [
        { agent_type: 'claude-code', count: 100 },
      ],
    } as any)

    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [] },
    } as any)

    const first = renderAgentStats()
    await waitFor(() => {
      expect(screen.getAllByText('Claude Code').length).toBeGreaterThan(0)
    })
    expect(getStats).toHaveBeenCalledTimes(1)
    expect(getDistribution).toHaveBeenCalledTimes(1)

    first.unmount()
    renderAgentStats()

    await waitFor(() => {
      expect(screen.getAllByText('Claude Code').length).toBeGreaterThan(0)
    })
    await new Promise((resolve) => setTimeout(resolve, 0))

    expect(getStats).toHaveBeenCalledTimes(1)
    expect(getDistribution).toHaveBeenCalledTimes(1)
  })

})

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import dayjs from 'dayjs'
import Dashboard from '../pages/Dashboard'
import * as api from '../services/api'
import { alertOccurrencesApi } from '../services/alertOccurrences'

const { mockAuth } = vi.hoisted(() => ({ mockAuth: { user: { role: 'platform_admin' } as any } }))

vi.mock('../stores/auth', () => ({
  useAuthStore: (selector?: (state: typeof mockAuth) => unknown) => selector ? selector(mockAuth) : mockAuth,
}))

describe('Dashboard customer-facing statistics', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    mockAuth.user = { role: 'platform_admin' }
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    vi.clearAllMocks()
    vi.spyOn(alertOccurrencesApi, 'summary').mockResolvedValue({data:{count_unit:'triage_cases',total:3,categories:[{category:'prompt_injection',count:3}]}} as any)
    vi.spyOn(api.statsApi, 'getOverview').mockResolvedValue({
      data: {
        today_requests: 19,
        today_tokens: 768000,
        yesterday_requests: 146,
        yesterday_tokens: 4200000,
        total_requests: 352,
        total_tokens: 15141071,
        active_projects: 1,
        security_events: 2348,
      },
    } as any)
    vi.spyOn(api.statsApi, 'getUserStats').mockResolvedValue({
      data: [{ user_id: 'user_admin', username: 'admin', total_tokens: 15141071, request_count: 352 }],
    } as any)
    vi.spyOn(api.ws8StatsApi, 'getUserStatsWithTotals').mockResolvedValue({
      data: { data: [{ user_id: 'user_admin', username: 'admin', total_tokens: 15141071, request_count: 352 }], totals: { total_tokens: 15141071, total_requests: 352 } },
    } as any)
    vi.spyOn(api.usageApi, 'byProject').mockResolvedValue({
      data: [{ id: 'proj_001', project_id: 'proj_001', name: '自己开发', project_name: '自己开发', requests: 352, input_tokens: 15000000, output_tokens: 141071, success_rate: 0.895 }],
    } as any)
    vi.spyOn(api.statsApi, 'getModelStats').mockResolvedValue({
      data: [{ model_id: 'model_001', model_name: 'qwen3.6-plus', request_count: 282, input_tokens: 13871805, output_tokens: 62836, total_cost: 0, cost_percent: 0 }],
    } as any)
    vi.spyOn(api.agentStatsApi, 'getStats').mockResolvedValue({
      data: [{ agent_type: 'agent-tool-call', session_count: 21, request_count: 21, percent: 6.46 }],
    } as any)
    vi.spyOn(api.agentStatsApi, 'getDistribution').mockResolvedValue({
      data: [{ agent_type: 'claude-code', count: 21 }],
    } as any)
    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [] },
    } as any)
    vi.spyOn(api.statsApi, 'getOrgStats').mockResolvedValue({
      data: { data: { units: [], total_units: 0, total_depts: 0, total_users: 0 } },
    } as any)
    vi.spyOn(api.usageApi, 'summary').mockResolvedValue({
      data: { requests: 352, input_tokens: 15000000, output_tokens: 141071, total_cost: 0 },
    } as any)
    vi.spyOn(api.usageApi, 'byKey').mockResolvedValue({ data: [] } as any)
    vi.spyOn(api.usageApi, 'trend').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.usageApi, 'byModel').mockResolvedValue({ data: { data: [{ name: 'qwen3.6-plus', requests: 282 }] } } as any)
    vi.spyOn(api.keyApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.projectApi, 'list').mockResolvedValue({ data: { data: [{ id: 'proj_001', name: '自己开发', status: 'active' }] } } as any)
    vi.spyOn(api.accessRetentionApi, 'getSummary').mockResolvedValue({
      data: {
        data: [],
        total: 984,
        summary: {
          total: 984,
          llm_count: 1,
          ai_ide_count: 15,
          normal_public_count: 900,
          device_count: 68,
          retained_content_count: 8,
        },
      },
    } as any)
    vi.spyOn(api.contentAuditApi, 'list').mockResolvedValue({
      data: {
        data: [
          {
            session_id: 'session_a',
            risk_categories: ['prompt_injection', 'agent_openai_codex'],
          },
          {
            session_id: 'session_b',
            risk_categories: ['tool_call'],
          },
          {
            session_id: 'session_c',
            risk_categories: ['network_egress_policy'],
          },
        ],
        total: 3,
      },
    } as any)
    vi.spyOn(api.auditApi, 'listRequests').mockResolvedValue({
      data: {
        data: [
          { request_id: 'req_001', session_id: 'session_a' },
          { request_id: 'req_002', session_id: 'session_a' },
          { request_id: 'req_003', session_id: 'session_b' },
        ],
        total: 3,
      },
    } as any)
  })

  const renderDashboard = () =>
    render(
      <MemoryRouter>
        <QueryClientProvider client={queryClient}>
          <Dashboard />
        </QueryClientProvider>
      </MemoryRouter>
    )

  it('keeps all model calls in the denominator and merges the long tail', async () => {
    vi.mocked(api.usageApi.byModel).mockResolvedValue({ data: { data: [
      { name: 'model-a', requests: 20 }, { name: 'model-a', requests: 20 },
      { name: 'model-b', requests: 20 }, { name: 'model-c', requests: 10 },
      { name: 'model-d', requests: 10 }, { name: 'model-e', requests: 5 },
      { name: 'model-f', requests: 5 }, { name: 'model-g', requests: 5 },
      { name: 'model-h', requests: 5 },
    ] } } as any)
    renderDashboard()
    expect(await screen.findByText('其他模型')).toBeInTheDocument()
    expect(screen.getByText('40.0%')).toBeInTheDocument()
    expect(screen.getByText('15.0%')).toBeInTheDocument()
    expect(screen.getByText('100')).toBeInTheDocument()
    expect(screen.getAllByText('model-a')).toHaveLength(1)
  })

  it('shows customer-facing statistics without security-operation intermediates', async () => {
    renderDashboard()

    expect(await screen.findByText('今日 Token 用量')).toBeInTheDocument()
    expect(screen.queryByText('运营判断')).not.toBeInTheDocument()
    expect(screen.queryByText('待处置告警')).not.toBeInTheDocument()
    expect(screen.getByText('近30天网关访问与 AI 用量')).toBeInTheDocument()
    expect(screen.getByText('近30天请求与 Token 趋势')).toBeInTheDocument()
    expect(screen.getByText('模型调用占比')).toBeInTheDocument()
    await waitFor(() => expect(api.usageApi.byModel).toHaveBeenCalled())
    expect(screen.getAllByText('输出 Token').length).toBeGreaterThan(0)
    expect(screen.queryByText('近30天费用与请求趋势')).not.toBeInTheDocument()
    expect(screen.queryByText('模型成本占比')).not.toBeInTheDocument()
    expect(screen.queryByText('总成本')).not.toBeInTheDocument()
    // 概览卡的大数字已改为万/亿紧凑展示（完整值在 tooltip 里，不进默认 DOM 文本）
    await waitFor(() => expect(screen.getByText('1514万')).toBeInTheDocument())
    const detectionCard = screen.getByRole('button', { name: '查看近24小时安全告警' })
    await waitFor(() => expect(detectionCard).toHaveTextContent('3'))
    expect(screen.getByText('近24小时待处置告警分类 TOP')).toBeInTheDocument()
    expect(screen.getByText('近30天应用调用 TOP')).toBeInTheDocument()
    expect(screen.queryByText('检测命中 TOP（重复已折叠）')).not.toBeInTheDocument()
    await waitFor(() => expect(alertOccurrencesApi.summary).toHaveBeenCalledTimes(1))
    expect(alertOccurrencesApi.summary).toHaveBeenCalledWith(expect.objectContaining({grouping:'cases',disposition:'pending',start_time:expect.any(String),end_time:expect.any(String)}))
    expect(api.contentAuditApi.list).not.toHaveBeenCalled()
    expect(api.auditApi.listRequests).not.toHaveBeenCalled()

    await userEvent.click(screen.getByRole('tab', { name: /应用统计/ }))
    expect((await screen.findAllByText('自己开发')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('352').length).toBeGreaterThan(0)

    await userEvent.click(screen.getByRole('tab', { name: /模型统计/ }))
    expect((await screen.findAllByText('qwen3.6-plus')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('282').length).toBeGreaterThan(0)
    await userEvent.click(screen.getByRole('tab', { name: /智能体统计/ }))
    expect(await screen.findByText('智能体使用统计')).toBeInTheDocument()
    expect(screen.getByText('智能体类型分布')).toBeInTheDocument()
  })


  it('splits gateway traffic, AI calls, and retained content in one 30-day window', async () => {
    renderDashboard()

    expect(await screen.findByText('总网关访问')).toBeInTheDocument()
    expect(screen.getByText('AI 相关调用')).toBeInTheDocument()
    expect(screen.getByText('内容留证')).toBeInTheDocument()
    expect((await screen.findAllByText('984')).length).toBeGreaterThan(0)
    expect(await screen.findByText('16')).toBeInTheDocument()
    expect(await screen.findByText('8')).toBeInTheDocument()
    expect(await screen.findByText('普通公网访问 900 次')).toBeInTheDocument()
    expect(screen.queryByText('普通公网访问 968 次')).not.toBeInTheDocument()
    expect(screen.queryByText('总请求次数')).not.toBeInTheDocument()

    await waitFor(() => expect(api.accessRetentionApi.getSummary).toHaveBeenCalledTimes(1))
    const params = (api.accessRetentionApi.getSummary as any).mock.calls[0][0]
    expect(params).toEqual(expect.objectContaining({ access_type: 'all', summary_detail: 'counts' }))
    const usageParams = vi.mocked(api.usageApi.summary).mock.calls[0][0] as any
    expect(dayjs(usageParams.end_date).diff(dayjs(usageParams.start_date), 'day')).toBe(29)
    expect(new Date(params.to).getTime() - new Date(params.from).getTime()).toBeGreaterThanOrEqual(30 * 24 * 60 * 60 * 1000 - 60 * 1000)
    expect(new Date(params.to).getTime() - new Date(params.from).getTime()).toBeLessThanOrEqual(30 * 24 * 60 * 60 * 1000 + 60 * 1000)
  })

  it('does not present an unavailable gateway summary as zero traffic', async () => {
    vi.spyOn(api.accessRetentionApi, 'getSummary').mockResolvedValue({
      data: {
        data: [],
        total: 0,
        summary: { total: 0 },
        summary_error: 'summary_unavailable',
      },
    } as any)

    renderDashboard()

    expect(await screen.findByRole('alert')).toHaveTextContent('网关访问统计加载失败，未以 0 替代真实数据')
    expect(screen.getAllByText('—')).toHaveLength(3)
    expect(screen.queryByText('普通公网访问 0 次')).not.toBeInTheDocument()
  })

  it('filters deleted keys and applications from current statistics', async () => {
    vi.mocked(api.usageApi.byProject).mockResolvedValue({
      data: [
        { id: 'proj_001', project_id: 'proj_001', name: '自己开发', requests: 352, success_rate: 0.99 },
        { id: 'proj_deleted', project_id: 'proj_deleted', name: '已删除应用', requests: 88, success_rate: 0.99 },
      ],
    } as any)
    vi.mocked(api.projectApi.list).mockResolvedValue({ data: { data: [{ id: 'proj_001', status: 'active' }] } } as any)
    vi.mocked(api.usageApi.byKey).mockResolvedValue({
      data: [
        { id: 'key_live', key_prefix: 'jjd_live', requests: 8 },
        { id: 'key_deleted', key_prefix: 'jjd_deleted', requests: 6 },
      ],
    } as any)
    vi.mocked(api.keyApi.list).mockResolvedValue({ data: { data: [{ id: 'key_live', key_prefix: 'jjd_live' }] } } as any)

    renderDashboard()

    await userEvent.click(await screen.findByRole('tab', { name: /密钥统计/ }))
    expect(await screen.findByText('jjd_live')).toBeInTheDocument()
    expect(screen.queryByText('jjd_deleted')).not.toBeInTheDocument()

    await userEvent.click(screen.getByRole('tab', { name: /应用统计/ }))
    expect((await screen.findAllByText('自己开发')).length).toBeGreaterThan(0)
    expect(screen.queryByText('已删除应用')).not.toBeInTheDocument()
  })

  it('applies one shared time range to all five statistic tabs', async () => {
    // W8 8.5：「所有时间」起点取 overview.data_start（租户时区自然日），不再写死 2026-01-01。
    vi.mocked(api.statsApi.getOverview).mockResolvedValue({ data: { total_tokens: 1, timezone: 'Asia/Shanghai', data_start: '2026-03-05' } } as any)
    renderDashboard()

    await userEvent.click(await screen.findByRole('tab', { name: /密钥统计/ }))
    expect(screen.getByText('统计范围')).toBeInTheDocument()
    await userEvent.click(screen.getByText('近7天'))
    await userEvent.click(screen.getByRole('tab', { name: /用户统计/ }))
    await userEvent.click(screen.getByRole('tab', { name: /应用统计/ }))
    await userEvent.click(screen.getByRole('tab', { name: /模型统计/ }))
    await userEvent.click(screen.getByRole('tab', { name: /智能体统计/ }))

    await waitFor(() => {
      expect(api.usageApi.byKey).toHaveBeenLastCalledWith(expect.objectContaining({ start_date: expect.any(String), end_date: expect.any(String) }))
      expect(api.usageApi.byProject).toHaveBeenLastCalledWith(expect.objectContaining({ start_date: expect.any(String), end_date: expect.any(String) }))
      expect(api.ws8StatsApi.getUserStatsWithTotals).toHaveBeenCalledWith('tokens', 10, expect.objectContaining({ start: expect.any(String), end: expect.any(String) }))
      expect(api.ws8StatsApi.getUserStatsWithTotals).toHaveBeenCalledWith('requests', 10, expect.objectContaining({ start: expect.any(String), end: expect.any(String) }))
      expect(api.statsApi.getModelStats).toHaveBeenLastCalledWith(10, expect.objectContaining({ start: expect.any(String), end: expect.any(String) }))
      expect(api.agentStatsApi.getStats).toHaveBeenLastCalledWith(expect.objectContaining({ start: expect.any(String), end: expect.any(String) }))
      expect(api.agentStatsApi.getDistribution).toHaveBeenLastCalledWith(expect.objectContaining({ start: expect.any(String), end: expect.any(String) }))
    })

    const keyCalls = vi.mocked(api.usageApi.byKey).mock.calls
    const keyRange = keyCalls[keyCalls.length - 1]?.[0] as any
    expect(dayjs(keyRange.end_date).diff(dayjs(keyRange.start_date), 'day')).toBe(6)

    await userEvent.click(screen.getAllByText('所有时间')[0])
    await userEvent.click(screen.getByRole('tab', { name: /密钥统计/ }))
    await waitFor(() => expect(api.usageApi.byKey).toHaveBeenLastCalledWith(expect.objectContaining({ start_date: '2026-03-05' })))
    await userEvent.click(screen.getByRole('tab', { name: /模型统计/ }))
    await userEvent.click(screen.getByRole('tab', { name: /智能体统计/ }))
    await waitFor(() => expect(api.agentStatsApi.getDistribution).toHaveBeenLastCalledWith(expect.objectContaining({ start: '2026-03-04T16:00:00.000Z' })))
    const modelCalls = vi.mocked(api.statsApi.getModelStats).mock.calls
    const distributionCalls = vi.mocked(api.agentStatsApi.getDistribution).mock.calls
    const modelStart = modelCalls[modelCalls.length - 1]?.[1]?.start
    const distributionStart = distributionCalls[distributionCalls.length - 1]?.[0]?.start
    // 2026-03-05 00:00 Asia/Shanghai
    expect(modelStart).toBe('2026-03-04T16:00:00.000Z')
    expect(distributionStart).toBe('2026-03-04T16:00:00.000Z')
  })

  it('W8 8.1: user share denominators come from the same window totals, not all-time tokens', async () => {
    vi.mocked(api.statsApi.getOverview).mockResolvedValue({ data: { total_tokens: 15141071, total_requests: 352, timezone: 'Asia/Shanghai' } } as any)
    // 旧口径：Token 分母 = 全历史 15141071，请求分母 = 近30天 usage summary 352，两个占比都会是 0.0%。
    vi.mocked(api.ws8StatsApi.getUserStatsWithTotals).mockImplementation(async () => ({
      data: {
        data: [{ user_id: 'u1', username: 'alice', total_tokens: 250, request_count: 3 }],
        totals: { total_tokens: 1000, total_requests: 12 },
      },
    }) as any)
    renderDashboard()
    await userEvent.click(await screen.findByRole('tab', { name: /用户统计/ }))
    // Token 250/1000 与请求 3/12 都是 25.0%
    await waitFor(() => expect(screen.getAllByText('25.0%')).toHaveLength(2))
    expect(screen.queryByText('0.0%')).not.toBeInTheDocument()
    expect(api.ws8StatsApi.getUserStatsWithTotals).toHaveBeenCalledWith('tokens', 10, expect.objectContaining({ start: expect.any(String), end: expect.any(String) }))
  })

  it('W8 8.3: header states execution mode, statistics timezone and metric definition', async () => {
    vi.mocked(api.statsApi.getOverview).mockResolvedValue({
      data: { total_tokens: 1, timezone: 'Asia/Tokyo', execution_mode: { configured_mode: 'record', effective_mode: 'record', locked: false, source: 'system_setting' } },
    } as any)
    renderDashboard()
    const ctx = await screen.findByTestId('report-context')
    await waitFor(() => expect(ctx).toHaveTextContent('执行模式：观察留痕'))
    expect(ctx).toHaveTextContent('统计时区：Asia/Tokyo')
    expect(ctx).toHaveTextContent('待处置为未处置且未抑制的告警问题')
  })

  it('W8 8.12: first paint only queries the overview tab', async () => {
    renderDashboard()
    expect(await screen.findByText('今日 Token 用量')).toBeInTheDocument()
    await waitFor(() => expect(api.usageApi.summary).toHaveBeenCalled())
    expect(api.statsApi.getModelStats).not.toHaveBeenCalled()
    expect(api.ws8StatsApi.getUserStatsWithTotals).not.toHaveBeenCalled()
    expect(api.statsApi.getUserStats).not.toHaveBeenCalled()
    expect(api.usageApi.byKey).not.toHaveBeenCalled()
    expect(api.keyApi.list).not.toHaveBeenCalled()
    expect(api.statsApi.getOrgStats).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('tab', { name: /模型统计/ }))
    await waitFor(() => expect(api.statsApi.getModelStats).toHaveBeenCalledTimes(1))
  })

  it('W8 8.9: key usage timestamps render in the tenant timezone', async () => {
    vi.mocked(api.statsApi.getOverview).mockResolvedValue({ data: { timezone: 'Asia/Tokyo' } } as any)
    vi.mocked(api.keyApi.list).mockResolvedValue({ data: { data: [{ id: 'key_live', key_prefix: 'jjd_live' }] } } as any)
    vi.mocked(api.usageApi.byKey).mockResolvedValue({ data: [{ id: 'key_live', key_prefix: 'jjd_live', requests: 1, last_called_at: '2026-09-01T00:30:00Z' }] } as any)
    renderDashboard()
    await userEvent.click(await screen.findByRole('tab', { name: /密钥统计/ }))
    expect(await screen.findByText('2026-09-01 09:30:00')).toBeInTheDocument()
  })

  it('hides organization statistics for ordinary developers', async () => {
    mockAuth.user = { role: 'developer' }

    renderDashboard()

    expect(await screen.findByText('今日 Token 用量')).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: /组织统计/ })).not.toBeInTheDocument()
    await waitFor(() => expect(api.statsApi.getOverview).toHaveBeenCalled())
    expect(api.statsApi.getOrgStats).not.toHaveBeenCalled()
  })
})

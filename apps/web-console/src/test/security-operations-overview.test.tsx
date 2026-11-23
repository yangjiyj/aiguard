import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, useLocation } from 'react-router-dom'
import SecurityOperationsOverview from '../pages/SecurityOperationsOverview'
import * as api from '../services/api'
import { alertOccurrencesApi } from '../services/alertOccurrences'

function LocationProbe() {
  const location = useLocation()
  return <div data-testid="soo-location">{location.pathname + location.search}</div>
}

// 回归护栏：这页原先用 contentAuditApi.list({limit:1, alert_only:true}) 去「数总数」，
// 但 alert_only 在服务端一定走快速路径，那条路径的 total 是渐进式分页值（offset+len+hasMore），
// 于是所有卡片都被钳到 2 或 0。这里锁定三件事：
//   1. 页面显示聚合端点返回的精确总数；
//   2. 页面不再调用会话列表接口；
//   3. 覆盖统计不再带 summary_detail=counts（那会丢掉 timeline，趋势图永远为空）。
describe('SecurityOperationsOverview 取数口径', () => {
  let queryClient: QueryClient

  const overviewPayload = {
    total: 409,
    subjects: 42,
    category_count: 53,
    severity: [
      { key: 'high', count: 270 },
      { key: 'critical', count: 140 },
      { key: 'medium', count: 68 },
    ],
    categories: [
      { key: 'prompt_leak_internal_rules', count: 106 },
      { key: 'email', count: 35 },
      { key: 'agent_detect', count: 99 },
      { key: 'agent_canary_token_leak', count: 21 },
    ],
  }

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    vi.restoreAllMocks()
    vi.spyOn(api.statsApi, 'getOverview').mockResolvedValue({ data: { timezone: 'Asia/Shanghai' } } as any)
    vi.spyOn(alertOccurrencesApi, 'summary').mockResolvedValue({ data: { count_unit: 'triage_cases', total: 0, categories: [] } } as any)
  })

  function renderPage() {
    return render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <SecurityOperationsOverview />
          <LocationProbe />
        </MemoryRouter>
      </QueryClientProvider>,
    )
  }

  it('reports blind CONNECT tunnels as undetected coverage', async () => {
    vi.spyOn(api.contentAuditApi, 'securityOverview').mockResolvedValue({ data: { data: overviewPayload } } as any)
    vi.spyOn(api.accessRetentionApi, 'getSummary').mockResolvedValue({
      data: { summary: { total: 10, undetected_count: 3 } },
    } as any)
    renderPage()
    await waitFor(() => expect(screen.getByTestId('forward-proxy-undetected')).toHaveTextContent('3'))
  })

  it('does not report undetected traffic while coverage data is unavailable', async () => {
    vi.spyOn(api.contentAuditApi, 'securityOverview').mockResolvedValue({ data: { data: overviewPayload } } as any)
    vi.spyOn(api.accessRetentionApi, 'getSummary').mockResolvedValue({ data: { summary: {}, summary_error: 'summary_unavailable' } } as any)
    renderPage()
    await waitFor(() => expect(screen.getByText('409')).toBeTruthy())
    expect(screen.queryByTestId('forward-proxy-undetected')).toBeNull()
  })

  it('显示聚合端点返回的精确总数，而不是渐进式分页值', async () => {
    const overviewSpy = vi.spyOn(api.contentAuditApi, 'securityOverview').mockResolvedValue({
      data: { data: overviewPayload },
    } as any)
    const listSpy = vi.spyOn(api.contentAuditApi, 'list')
    vi.spyOn(api.accessRetentionApi, 'getSummary').mockResolvedValue({
      data: { summary: { total: 1200, risk_count: 12, blocked_count: 3 } },
    } as any)

    renderPage()

    await waitFor(() => expect(screen.getByText('409')).toBeTruthy())
    expect(overviewSpy).toHaveBeenCalledTimes(1)
    // 严重与高危 = 140 + 270
    expect(screen.getByText('410')).toBeTruthy()
    // 会话列表接口必须完全不再被调用
    expect(listSpy).not.toHaveBeenCalled()
  })

  it('分类榜剔除 agent_* 检测项，且保留原始 key 供下钻', async () => {
    vi.spyOn(api.contentAuditApi, 'securityOverview').mockResolvedValue({
      data: { data: overviewPayload },
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getSummary').mockResolvedValue({
      data: { summary: { total: 10 } },
    } as any)

    renderPage()

    await waitFor(() => expect(screen.getByText('409')).toBeTruthy())
    expect(screen.queryByText(/agent_detect/)).toBeNull()
    expect(screen.queryByText(/agent_canary_token_leak/)).toBeNull()
    // 展示的是中文分类名而不是原始英文 key，且数量用该检测项的精确计数。
    // RankedList 把数值和单位渲染在同一个节点里（"106条"），所以按正则匹配。
    expect(screen.queryByText('prompt_leak_internal_rules')).toBeNull()
    expect(screen.getByText(/106\s*条/)).toBeTruthy()
  })

  it('不再展示无法闭环的处置状态指标（待处置等）', async () => {
    vi.spyOn(api.contentAuditApi, 'securityOverview').mockResolvedValue({
      data: { data: overviewPayload },
    } as any)
    vi.spyOn(api.accessRetentionApi, 'getSummary').mockResolvedValue({
      data: { summary: { total: 10 } },
    } as any)

    renderPage()

    await waitFor(() => expect(screen.getByText('409')).toBeTruthy())
    // audit_dispositions / alert_groups.status 只有内容留证页与工具审计页能写，
    // 安全告警页与本总览页都没有处置入口，展示「待处置」只会等于告警总数。
    // W8 8.2：五态枚举不恢复，只保留与首页同口径的「待处置告警」一个真实计数。
    expect(screen.queryByText('待处置')).toBeNull()
    expect(screen.queryByText('已确认风险')).toBeNull()
    expect(screen.queryByText('处置状态分布')).toBeNull()
    // 替代指标来自同一次聚合，且是真实可解释的：涉及主体。
    expect(screen.getByText('涉及主体')).toBeTruthy()
    expect(screen.getByText('42')).toBeTruthy()
    // 风险类型数必须用服务端的精确去重计数（category_count），
    // 不能拿 categories 列表长度代替——那个列表带 LIMIT 24，会被截断。
    expect(screen.getByText('53')).toBeTruthy()
  })

  it('覆盖统计请求不带 summary_detail=counts，趋势图才能拿到 timeline', async () => {
    vi.spyOn(api.contentAuditApi, 'securityOverview').mockResolvedValue({
      data: { data: overviewPayload },
    } as any)
    const summarySpy = vi.spyOn(api.accessRetentionApi, 'getSummary').mockResolvedValue({
      data: {
        summary: {
          total: 1200,
          timeline: [{ bucket: '2026-09-15T00:00:00Z', total_count: 12, risk_count: 1 }],
        },
      },
    } as any)

    renderPage()

    await waitFor(() => expect(summarySpy).toHaveBeenCalled())
    const params = summarySpy.mock.calls[0][0] as Record<string, unknown>
    expect(params).not.toHaveProperty('summary_detail')
    expect(params.access_type).toBe('all')
  })

  it('W8 8.2: 待处置告警与首页同一接口、同一参数、同一时间窗', async () => {
    vi.spyOn(api.contentAuditApi, 'securityOverview').mockResolvedValue({ data: { data: overviewPayload } } as any)
    vi.spyOn(api.accessRetentionApi, 'getSummary').mockResolvedValue({ data: { summary: { total: 10 } } } as any)
    vi.mocked(alertOccurrencesApi.summary).mockResolvedValue({ data: { count_unit: 'triage_cases', total: 7, categories: [] } } as any)

    renderPage()

    const card = await screen.findByRole('button', { name: '查看待处置告警' })
    await waitFor(() => expect(card).toHaveTextContent('7'))
    const call = vi.mocked(alertOccurrencesApi.summary).mock.calls[0][0]
    expect(call).toEqual(expect.objectContaining({ grouping: 'cases', disposition: 'pending' }))
    const overviewCall = vi.mocked(api.contentAuditApi.securityOverview).mock.calls[0][0] as any
    expect(call.start_time).toBe(overviewCall.from)
    expect(call.end_time).toBe(overviewCall.to)
    expect(screen.queryByText(/工具审计/)).toBeNull()
  })

  it('W8 8.3: 页眉写明执行模式、统计时区与口径', async () => {
    vi.mocked(api.statsApi.getOverview).mockResolvedValue({
      data: { timezone: 'Asia/Tokyo', execution_mode: { configured_mode: 'protect', effective_mode: 'protect', locked: false, source: 'system_setting' } },
    } as any)
    vi.spyOn(api.contentAuditApi, 'securityOverview').mockResolvedValue({ data: { data: overviewPayload } } as any)
    vi.spyOn(api.accessRetentionApi, 'getSummary').mockResolvedValue({ data: { summary: { total: 10 } } } as any)

    renderPage()

    const ctx = await screen.findByTestId('report-context')
    await waitFor(() => expect(ctx).toHaveTextContent('执行模式：防护阻断'))
    expect(ctx).toHaveTextContent('统计时区：Asia/Tokyo')
    expect(ctx).toHaveTextContent('口径')
  })

  it('W8 8.6: 支持自然周，下钻携带与本页一致的显式起止', async () => {
    const overviewSpy = vi.spyOn(api.contentAuditApi, 'securityOverview').mockResolvedValue({ data: { data: overviewPayload } } as any)
    vi.spyOn(api.accessRetentionApi, 'getSummary').mockResolvedValue({ data: { summary: { total: 10 } } } as any)
    const user = userEvent.setup()

    renderPage()
    await waitFor(() => expect(screen.getByText('409')).toBeTruthy())
    await user.click(screen.getByText('上周'))
    await waitFor(() => expect(overviewSpy.mock.calls.length).toBeGreaterThan(1))
    const lastWindow = overviewSpy.mock.calls[overviewSpy.mock.calls.length - 1][0] as any
    // 上周 = 7 个自然日，左闭右开
    expect(new Date(lastWindow.to).getTime() - new Date(lastWindow.from).getTime()).toBe(7 * 86400000)

    await user.click(screen.getByRole('button', { name: '查看全部告警' }))
    const params = new URLSearchParams(screen.getByTestId('soo-location').textContent?.split('?')[1] || '')
    expect(params.get('start_time')).toBe(lastWindow.from)
    expect(params.get('end_time')).toBe(lastWindow.to)
    expect(params.get('window_hours')).toBeNull()
  })
})

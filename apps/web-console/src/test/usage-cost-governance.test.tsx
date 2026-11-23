import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import Usage from '../pages/Usage'
import usageSource from '../pages/Usage.tsx?raw'
import { literal, sourceRegex } from './billingSourceLabels'
import * as api from '../services/api'
import dayjs from 'dayjs'
import { buildBillingReportParams } from '../utils/billingReport'


const viewLabels = Object.fromEntries([...usageSource.matchAll(/key: '([^']+)', label: '([^']+)'/g)].map(match => [match[1], match[2]]))
const overviewTitle = literal(usageSource, /<EnterprisePageHeader[^>]*title="([^"]+)"/)
const loadingError = literal(usageSource, /billingAnalyticsError[\s\S]*?message="([^"]+)"/)
const switcherLabel = literal(usageSource, /role="tablist" aria-label="([^"]+)"/)
const tokenPanel = literal(usageSource, /dashboardView === 'tokens'[\s\S]*?<SectionPanel title="([^"]+)"/)

describe('Usage cost governance page', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    vi.clearAllMocks()
    vi.spyOn(api.usageApi, 'summary').mockResolvedValue({
      data: { requests: 120, input_tokens: 1000000, output_tokens: 200000, total_cost: 3.5, data_fresh_until: '2026-06-18T13:00:00Z' },
    } as any)
    vi.spyOn(api.usageApi, 'costCoverage').mockResolvedValue({
      data: {
        total_requests: 120,
        priced_requests: 100,
        unpriced_requests: 20,
        coverage_rate: 0.8333,
        unpriced_model_count: 2,
        cost_trusted_start_date: '2026-05-25',
      },
    } as any)
    vi.spyOn(api.usageApi, 'byProject').mockResolvedValue({
      data: [{
        id: 'proj_001',
        project_id: 'proj_001',
        name: '客服助手',
        requests: 80,
        input_tokens: 800000,
        output_tokens: 100000,
        total_tokens: 900000,
        total_cost: 2.8,
        success_rate: 0.95,
        budget_usage_rate: 0.7,
      }],
    } as any)
    vi.spyOn(api.usageApi, 'byModel').mockResolvedValue({
      data: [{
        id: 'model_001',
        model_id: 'model_001',
        name: 'gpt-4o',
        provider_name: 'OpenAI',
        requests: 60,
        input_tokens: 700000,
        output_tokens: 80000,
        total_tokens: 780000,
        total_cost: 2.4,
        cost_percent: 0.68,
        average_cost: 0.04,
        success_rate: 0.98,
      }],
    } as any)
    vi.spyOn(api.usageApi, 'byUser').mockResolvedValue({
      data: [{
        id: 'user_001',
        user_id: 'user_001',
        username: 'alice',
        name: 'alice',
        requests: 50,
        input_tokens: 500000,
        output_tokens: 50000,
        total_tokens: 550000,
        total_cost: 1.5,
        abnormal_growth: true,
      }],
    } as any)
    vi.spyOn(api.usageApi, 'byKey').mockResolvedValue({
      data: [{
        id: 'key_001',
        key_prefix: 'na_abcd',
        project_name: '客服助手',
        username: 'alice',
        requests: 30,
        input_tokens: 300000,
        output_tokens: 30000,
        total_tokens: 330000,
        total_cost: 1.1,
        last_called_at: '2026-05-25T10:00:00Z',
      }],
    } as any)
    vi.spyOn(api.usageApi, 'byProvider').mockResolvedValue({
      data: [{
        id: 'provider_001',
        name: 'OpenAI',
        provider_type: 'openai',
        model_count: 3,
        requests: 70,
        input_tokens: 700000,
        output_tokens: 70000,
        total_tokens: 770000,
        total_cost: 2.6,
        success_rate: 0.96,
        average_latency_ms: 850,
      }],
    } as any)
    vi.spyOn(api.usageApi, 'recommendations').mockResolvedValue({
      data: [{
        id: 'budget_near_limit',
        severity: 'warning',
        problem: '客服助手费用接近月预算',
        impact: '已使用预算 80%',
        impact_cost: 8,
        project_id: 'proj_001',
        suggestion: '检查高价模型调用占比，必要时调整默认模型。',
      }],
    } as any)
    vi.spyOn(api.billingAnalyticsApi, 'summary').mockResolvedValue({ data: { requests: 100, priced_requests: 80, unpriced_requests: 20, prompt_tokens: 1000000, cached_input_tokens: 300000, cache_write_input_tokens: 100000, output_tokens: 200000, reasoning_tokens: 50000, total_tokens: 1200000, billable_micros: 3500000, upstream_cost_micros: 0, upstream_cost_known_requests: 0, currency: 'CNY' } } as any)
    vi.spyOn(api.billingAnalyticsApi, 'breakdown').mockResolvedValue({ data: [] } as any)
    vi.spyOn(api.billingAnalyticsApi, 'series').mockResolvedValue({ data: [] } as any)
    vi.spyOn(api.billingAnalyticsApi, 'timeProfile').mockResolvedValue({ data: [] } as any)
    vi.spyOn(api.billingAnalyticsApi, 'departmentProviderMatrix').mockResolvedValue({ data: [] } as any)
  })

  const renderPage = () =>
    render(
      <MemoryRouter initialEntries={['/usage']}>
        <QueryClientProvider client={queryClient}>
          <Usage />
        </QueryClientProvider>
      </MemoryRouter>,
    )

  it('提示未计入的历史币种，保持当前事实独立计价', async () => {
    vi.mocked(api.billingAnalyticsApi.summary).mockResolvedValue({ data: { requests: 1, currency: 'USD', other_currencies: ['CNY'], billable_micros: 1000000 } } as any)
    renderPage()
    expect(await screen.findByText('本时间段还有 CNY 计价的历史用量，未计入；可切换币种查看')).toBeInTheDocument()
  })

  it('renders billing amount and token data with four direct analysis views', async () => {
    renderPage()
    expect(await screen.findByText(overviewTitle)).toBeInTheDocument()
    const switcher = screen.getByRole('tablist', { name: switcherLabel })
    expect(within(switcher).getAllByRole('tab')).toHaveLength(4)
    for (const key of ['trend', 'tokens', 'organization', 'time']) expect(within(switcher).getByRole('tab', { name: sourceRegex(viewLabels[key]) })).toBeInTheDocument()
    expect(api.usageApi.costCoverage).not.toHaveBeenCalled()
    expect(api.usageApi.recommendations).not.toHaveBeenCalled()
    await userEvent.click(within(switcher).getByRole('tab', { name: sourceRegex(viewLabels.tokens) }))
    expect(await screen.findByText(tokenPanel)).toBeInTheDocument()
  })

  it('shows model, user, key, and provider dimensions', async () => {
    renderPage()

    await userEvent.click(await screen.findByRole('tab', { name: /部门与渠道/ }))
    expect(await screen.findByText('部门费用占比')).toBeInTheDocument()
    // 「部门与渠道」下已拆为 费用占比 / 部门×渠道 / 多维下钻 三个二级标签页，
    // 六维明细表在「多维下钻」里，需先切进去。
    await userEvent.click(await screen.findByRole('tab', { name: '多维下钻' }))
    await userEvent.click(await screen.findByRole('tab', { name: /按模型/ }))
    expect(await screen.findByText('gpt-4o')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: /按用户/ }))
    expect(await screen.findByText('alice')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: /按 API Key/ }))
    expect(await screen.findByText('na_abcd')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: /按供应商/ }))
    expect((await screen.findAllByText('OpenAI')).length).toBeGreaterThan(0)
  })

  it('passes backend date parameter names', async () => {
    renderPage()

    await waitFor(() => expect(api.usageApi.summary).toHaveBeenCalled())
    const firstCall = vi.mocked(api.usageApi.summary).mock.calls[0][0] as any
    expect(firstCall).toHaveProperty('start_date')
    expect(firstCall).toHaveProperty('end_date')
  })

  it('surfaces billing fact failures and retries without reporting a healthy zero', async () => {
    const facts = vi.mocked(api.billingAnalyticsApi.summary)
    facts.mockRejectedValueOnce(new Error('billing facts unavailable')).mockResolvedValueOnce({ data: { requests: 0, billable_micros: 0, currency: 'CNY' } } as any)
    renderPage()
    expect(await screen.findByText(loadingError)).toBeInTheDocument()
    const retry = literal(usageSource, /retryBillingAnalytics\}>([^<]+)</)
    await userEvent.click(screen.getByRole('button', { name: new RegExp(retry.split('').join('\\s*')) }))
    await waitFor(() => expect(facts).toHaveBeenCalledTimes(2))
  })

  it('reports cache token composition without double counting cached input', async () => {
    // 缓存命中/写入是 prompt_tokens 的子集(表级 CHECK 强制),普通输入必须扣除这两项。
    vi.mocked(api.billingAnalyticsApi.summary).mockResolvedValue({
      data: {
        requests: 100,
        priced_requests: 100,
        unpriced_requests: 0,
        prompt_tokens: 1000,
        cached_input_tokens: 600,
        cache_write_input_tokens: 100,
        output_tokens: 500,
        reasoning_tokens: 200,
        total_tokens: 1500,
        billable_micros: 3500000,
        upstream_cost_micros: 0,
        upstream_cost_known_requests: 0,
        currency: 'CNY',
      },
    } as any)

    renderPage()

    // 缓存命中率 600/1000 = 60.0%，且缓存不与普通输入重复计数
    // （普通输入 = 1000-600-100 = 300，普通输出 = 500-200 = 300）
    // 顶部 KPI 先显示命中率；切到 Token 视图后再核对详细构成。
    expect((await screen.findAllByText(/占输入 60\.0%/)).length).toBeGreaterThan(0)
    expect(screen.queryByText('Token 构成与计费用量')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: /Token 用量/ }))
    expect(await screen.findByText('Token 构成与计费用量')).toBeInTheDocument()
    expect(screen.getByText('普通输入 300')).toBeInTheDocument()
    expect(screen.getByText('普通输出 300')).toBeInTheDocument()
  })

  it('exports the billing report for the selected date range', async () => {
    const report = vi.spyOn(api.billingAnalyticsApi, 'report').mockResolvedValue({
      data: new Blob(['计费报告'], { type: 'text/csv' }),
    } as any)
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:billing-report')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})

    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /生成计费报告/ }))
    const dialog = await screen.findByRole('dialog', { name: /AI 计费分析报告/ })
    expect(dialog).toBeInTheDocument()
    for (const label of ['部门', '个人', '应用', '模型', '智能体']) {
      expect(within(dialog).getAllByText(label).length).toBeGreaterThan(0)
    }
    await userEvent.click(screen.getByRole('button', { name: /下载明细 CSV/ }))

    await waitFor(() => expect(report).toHaveBeenCalledWith(expect.objectContaining({
      start_date: expect.any(String),
      end_date: expect.any(String),
    })))
  })

  it('exports the billing detail as XLSX for the selected range', async () => {
    const report = vi.spyOn(api.billingReportXlsxApi, 'report').mockResolvedValue({
      data: new Blob(['xlsx'], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }),
    } as any)
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:billing-report-xlsx')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})

    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: new RegExp('下载明细 XLSX') }))

    await waitFor(() => expect(report).toHaveBeenCalledWith(expect.objectContaining({
      start_date: expect.any(String),
      end_date: expect.any(String),
    })))
  })

  it('renders a visual billing report and opens the PDF print flow', async () => {
    const print = vi.spyOn(window, 'print').mockImplementation(() => {})

    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /生成计费报告/ }))
    expect(await screen.findByText('经营摘要')).toBeInTheDocument()
    expect(screen.getByText('Token 构成')).toBeInTheDocument()
    expect(screen.getByText('六维费用排行')).toBeInTheDocument()
    await waitFor(() => expect(api.billingAnalyticsApi.breakdown).toHaveBeenCalledWith('agent', expect.any(Object)))
    await userEvent.click(screen.getByRole('button', { name: /导出 PDF/ }))
    expect(print).toHaveBeenCalledTimes(1)
  })

  it('draws the model cost pie from billing facts, not the deprecated total_cost rollup (7.8)', async () => {
    // request_logs.total_cost is no longer written by the gateway, so the rollup reports 0 for every model.
    vi.mocked(api.usageApi.byModel).mockResolvedValue({
      data: [{ id: 'model_001', model_id: 'model_001', name: 'gpt-4o', requests: 60, input_tokens: 700000, output_tokens: 80000, total_tokens: 780000, total_cost: 0 }],
    } as any)
    vi.mocked(api.billingAnalyticsApi.breakdown).mockImplementation(async (dimension: string) => ({
      data: dimension === 'model'
        ? [{ id: 'model_001', name: 'gpt-4o', requests: 60, priced_requests: 60, total_tokens: 780000, billable_micros: 2400000, upstream_cost_micros: 0, cost_share: 1 }]
        : [],
    }) as any)

    renderPage()

    await userEvent.click(await screen.findByRole('tab', { name: new RegExp('趋势与分布') }))
    const panel = (await screen.findByText('模型成本分布')).closest('section') as HTMLElement
    expect(panel).not.toBeNull()
    await waitFor(() => expect(api.billingAnalyticsApi.breakdown).toHaveBeenCalledWith('model', expect.any(Object)))
    await waitFor(() => expect(within(panel).queryByText('暂无数据')).not.toBeInTheDocument())
  })

  it('serializes every report filter into backend query parameters', () => {
    expect(buildBillingReportParams({
      range: [dayjs('2026-07-25'), dayjs('2026-08-24')],
      departmentIds: ['dept-1', 'dept-2'], projectIds: ['app-1'], userIds: ['user-1'],
      modelIds: ['model-1'], providerIds: ['provider-1'], agentTypes: ['codex'],
    })).toEqual({
      start_date: '2026-07-25', end_date: '2026-08-24',
      department_ids: 'dept-1,dept-2', project_ids: 'app-1', user_ids: 'user-1',
      model_ids: 'model-1', provider_ids: 'provider-1', agent_types: 'codex',
    })
  })
})

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import BudgetSnapshot from '../pages/BudgetSnapshot'
import * as api from '../services/api'

describe('BudgetSnapshot page', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    vi.clearAllMocks()
    vi.spyOn(api.budgetApi, 'snapshot').mockResolvedValue({
      data: {
        scope_type: 'tenant',
        scope_id: 'tenant_001',
        day: '2026-06-10',
        month: '2026-06',
        day_requests: 1234,
        day_tokens: 456789,
        day_cost: 89.56,
        month_requests: 32000,
        month_tokens: 9876543,
        month_cost: 1234.5,
        rpm: 42,
        concurrency: 3,
        effective_quota: {
          DailyTokenLimit: 1000000,
          MonthlyTokenLimit: 10000000,
          DailyBudgetLimit: 200,
          MonthlyBudgetLimit: 2000,
          RPMLimit: 100,
          ConcurrencyLimit: 20,
          TriggeredScope: 'tenant',
        },
      },
    } as any)
    vi.spyOn(api.alertApi, 'inbox').mockResolvedValue({
      data: {
        items: [{
          id: 'alert_001',
          severity: 'warning',
          type: 'budget_exceeded',
          message: '本月费用已接近预算阈值',
          created_at: '2026-06-10T08:00:00Z',
        }],
      },
    } as any)
  })

  const renderPage = () => render(
    <QueryClientProvider client={queryClient}>
      <BudgetSnapshot />
    </QueryClientProvider>,
  )

  it('renders a customer-facing usage monitor from backend snapshot fields', async () => {
    renderPage()

    expect(await screen.findByText('用量监控')).toBeInTheDocument()
    expect(await screen.findByText('今日请求')).toBeInTheDocument()
    expect(screen.getAllByText('今日费用').length).toBeGreaterThan(0)
    expect(screen.getAllByText('本月费用').length).toBeGreaterThan(0)
    expect(screen.getAllByText('当前并发').length).toBeGreaterThan(0)
    expect(screen.getByText('用量分析过程')).toBeInTheDocument()
    expect(screen.getByText('采集实时用量')).toBeInTheDocument()
    expect(screen.getByText('配额使用情况')).toBeInTheDocument()
    expect(screen.getByText('近期费用告警')).toBeInTheDocument()
    expect(await screen.findByText('本月费用已接近预算阈值')).toBeInTheDocument()
    expect(screen.queryByText(/scope/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/API Key/)).not.toBeInTheDocument()
    expect(screen.queryByText(/接口待接入/)).not.toBeInTheDocument()
  })

  it('displays budget alerts returned with the backend inbox field names', async () => {
    vi.mocked(api.alertApi.inbox).mockResolvedValueOnce({
      data: {
        items: [{
          ID: 'alert_backend_001',
          Severity: 'warning',
          Type: 'budget_exceeded',
          Title: '本月费用已接近预算阈值',
          CreatedAt: '2026-06-10T08:00:00Z',
        }],
      },
    } as any)

    renderPage()

    expect(await screen.findByText('本月费用已接近预算阈值')).toBeInTheDocument()
    expect(screen.getByText('提醒')).toBeInTheDocument()
    expect(screen.queryByText('-')).not.toBeInTheDocument()
  })

  it('filters security inbox messages out of the cost alert table', async () => {
    vi.mocked(api.alertApi.inbox).mockResolvedValueOnce({
      data: {
        items: [
          {
            id: 'security_001',
            severity: 'critical',
            type: 'security_event',
            title: '安全事件 critical security_check',
            created_at: '2026-06-10T07:37:28Z',
          },
          {
            id: 'budget_001',
            severity: 'warning',
            type: 'quota_near_limit',
            title: '月度预算使用率超过 80%',
            created_at: '2026-06-10T08:00:00Z',
          },
        ],
      },
    } as any)

    renderPage()

    expect(await screen.findByText('月度预算使用率超过 80%')).toBeInTheDocument()
    expect(screen.queryByText('安全事件 critical security_check')).not.toBeInTheDocument()
  })
})

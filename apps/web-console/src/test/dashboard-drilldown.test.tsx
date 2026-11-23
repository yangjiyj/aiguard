import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, useLocation } from 'react-router-dom'
import Dashboard from '../pages/Dashboard'
import * as api from '../services/api'
import { alertOccurrencesApi } from '../services/alertOccurrences'

const { mockAuth } = vi.hoisted(() => ({ mockAuth: { user: { role: 'platform_admin' } as any } }))

vi.mock('../stores/auth', () => ({
  useAuthStore: (selector?: (state: typeof mockAuth) => unknown) => selector ? selector(mockAuth) : mockAuth,
}))

vi.mock('../components/Charts', () => ({
  TrendArea: () => null,
  ModelShareRadial: () => null,
  RankedList: ({ data, onItemClick }: { data: Array<{ name: string; value: number }>; onItemClick?: (item: { name: string; value: number }) => void }) => (
    <div>
      {data.map((item) => (
        onItemClick ? (
          <button key={item.name} type="button" aria-label={'查看安全告警分类 ' + item.name} onClick={() => onItemClick(item)}>{item.name}</button>
        ) : <span key={item.name}>{item.name}</span>
      ))}
    </div>
  ),
}))

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="dashboard-location">{location.pathname}{location.search}</output>
}

describe('Dashboard drilldowns', () => {
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
    vi.spyOn(alertOccurrencesApi, 'summary').mockResolvedValue({data:{count_unit:'triage_cases',total:1,categories:[{category:'prompt_injection',count:1}]}} as any)

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
    vi.spyOn(api.statsApi, 'getUserStats').mockResolvedValue({ data: [] } as any)
    vi.spyOn(api.usageApi, 'byProject').mockResolvedValue({
      data: [{ id: 'proj_001', project_id: 'proj_001', name: '研发助手', requests: 352, input_tokens: 15000000, output_tokens: 141071, success_rate: 0.995 }],
    } as any)
    vi.spyOn(api.statsApi, 'getModelStats').mockResolvedValue({ data: [] } as any)
    vi.spyOn(api.statsApi, 'getOrgStats').mockResolvedValue({ data: { data: { units: [] } } } as any)
    vi.spyOn(api.usageApi, 'summary').mockResolvedValue({
      data: { requests: 352, input_tokens: 15000000, output_tokens: 141071, total_cost: 0 },
    } as any)
    vi.spyOn(api.usageApi, 'byKey').mockResolvedValue({ data: [] } as any)
    vi.spyOn(api.keyApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.projectApi, 'list').mockResolvedValue({ data: { data: [{ id: 'proj_001', name: '研发助手', status: 'active' }] } } as any)
    vi.spyOn(api.usageApi, 'trend').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.usageApi, 'byModel').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.budgetApi, 'snapshot').mockResolvedValue({ data: {} } as any)
    vi.spyOn(api.accessRetentionApi, 'getSummary').mockResolvedValue({
      data: {
        summary: {
          total: 984,
          llm_count: 1,
          ai_ide_count: 15,
          normal_public_count: 900,
          retained_content_count: 8,
        },
      },
    } as any)
    vi.spyOn(api.contentAuditApi, 'list').mockResolvedValue({
      data: {
        data: [{
          session_id: 'session_a',
          risk_categories: ['prompt_injection'],
        }],
        total: 1,
      },
    } as any)
    vi.spyOn(api.auditApi, 'listRequests')
  })

  const renderDashboard = () => render(
    <MemoryRouter initialEntries={['/']}>
      <QueryClientProvider client={queryClient}>
        <Dashboard />
      </QueryClientProvider>
      <LocationProbe />
    </MemoryRouter>,
  )

  it('uses direct drilldowns without security-operation wording or intermediate actions', async () => {
    const user = userEvent.setup()
    renderDashboard()

    const detectionCard = await screen.findByRole('button', { name: '查看近24小时安全告警' })
    expect(detectionCard).toHaveTextContent('近24小时待处置告警')
    await waitFor(() => expect(detectionCard).toHaveTextContent('1'))
    expect(screen.queryByText('待处置告警')).not.toBeInTheDocument()
    expect(screen.queryByText('运营判断')).not.toBeInTheDocument()
    expect(screen.queryByText('需要安全运营介入')).not.toBeInTheDocument()
    expect(screen.queryByText('存在待处置风险')).not.toBeInTheDocument()
    // W8 8.4：标题随统计范围变化，默认近30天。
    expect(screen.getByText('近30天应用调用 TOP')).toBeInTheDocument()
    expect(screen.getByText('研发助手')).toBeInTheDocument()

    detectionCard.focus()
    await user.keyboard('{Enter}')
    await waitFor(() => expect(screen.getByTestId('dashboard-location')).toHaveTextContent('/security/alerts?window_hours=24'))

    await user.click(screen.getByRole('button', { name: /查看安全告警分类/ }))
    await waitFor(() => expect(screen.getByTestId('dashboard-location')).toHaveTextContent('/security/alerts?'))
    expect(screen.getByTestId('dashboard-location')).toHaveTextContent('window_hours=24')

    // 回归防护：下钻必须携带英文分类键。此前跳转带的是中文展示名（如「Prompt 注入」），
    // 而告警页后端是按 LOWER(category) 精确匹配英文枚举的，中文一条都匹配不上，
    // 于是点进去就是一个空白的告警页——这正是客户报的缺陷。
    const categoryParams = new URLSearchParams(screen.getByTestId('dashboard-location').textContent?.split('?')[1] || '')
    expect(categoryParams.get('risk_category')).toBe('prompt_injection')
    const summaryScope=vi.mocked(alertOccurrencesApi.summary).mock.calls[0][0]
    expect(categoryParams.get('start_time')).toBe(summaryScope.start_time)
    expect(categoryParams.get('end_time')).toBe(summaryScope.end_time)
    expect(api.contentAuditApi.list).not.toHaveBeenCalled()

    const evidenceCard = screen.getByRole('button', { name: '查看近30天内容留证' })
    await user.click(evidenceCard)
    await waitFor(() => expect(screen.getByTestId('dashboard-location')).toHaveTextContent('/audit/access-retention?'))
    const params = new URLSearchParams(screen.getByTestId('dashboard-location').textContent?.split('?')[1] || '')
    expect(params.get('from')).not.toBeNull()
    expect(params.get('to')).not.toBeNull()

    expect(api.auditApi.listRequests).not.toHaveBeenCalled()
  })
})

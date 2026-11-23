import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ModelOperations from '../pages/ModelOperations'

const http = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } } }))
vi.mock('axios', () => ({ default: { create: () => http } }))
vi.mock('recharts', async () => {
  const actual: any = await vi.importActual('recharts')
  return { ...actual, ResponsiveContainer: ({ children }: any) => <div data-testid="chart">{children}</div> }
})
const hourly = Array.from({ length: 24 }, (_, i) => ({ at: `2026-10-28T${String(i).padStart(2, '0')}:00:00Z`, attempts: i === 23 ? 9 : 0, success_rate: i === 23 ? 5 / 9 : null, latency_p95_ms: i === 23 ? 64000 : null }))
const monitor = {
  window_hours: 24, generated_at: '2026-10-28T12:00:00Z',
  totals: { attempts: 11, success_rate: 0.6, fallbacks: 1, ttft_p50_ms: 6400 },
  items: [
    { provider_id: 'p1', provider_name: '渠道 A', attempts: 9, successes: 5, success_rate: 5 / 9, latency_p50_ms: 8200, latency_p95_ms: 64000, ttft_p50_ms: 6100, errors: { http_5xx: 2, rate_limited: 1, rejected: 0, network: 1, other: 0 }, fallback_out: 1, fallback_in: 0, model_count: 1, models: [{ model_id: 'm1', model_name: 'claude-test', attempts: 9, success_rate: 5 / 9 }], hourly },
    { provider_id: '', provider_name: 'Ghost', attempts: 1, successes: 1, success_rate: null, latency_p50_ms: null, latency_p95_ms: null, ttft_p50_ms: null, errors: { http_5xx: 0, rate_limited: 0, rejected: 0, network: 0, other: 0 }, fallback_out: 0, fallback_in: 1, model_count: 1, models: [], hourly },
  ],
}
let client: QueryClient
beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  vi.clearAllMocks()
  http.get.mockImplementation((url: string) => Promise.resolve({ data:
    url === '/providers' ? { data: [{ id: 'p1', name: '渠道 A' }] }
      : url === '/models' ? { data: [{ id: 'm1', model_name: 'claude-test', provider_id: 'p1' }] }
        : url.endsWith('/model-operations/providers') ? monitor : {} }))
})
afterEach(() => { cleanup(); client.clear() })
const renderPage = (initial: string) => render(<MemoryRouter initialEntries={[initial]}><QueryClientProvider client={client}><ModelOperations /></QueryClientProvider></MemoryRouter>)

describe('上游渠道标签', () => {
  it('按当前筛选请求渠道监控并渲染汇总与表格', async () => {
    renderPage('/model-operations?tab=providers&window_hours=72&provider_id=p1')
    const table = await screen.findByRole('table')
    await within(table).findByText('渠道 A')
    expect(http.get).toHaveBeenCalledWith('/model-operations/providers', { params: { provider_id: 'p1', model_id: undefined, window_hours: 72 } })
    expect(screen.getByRole('tab', { name: '上游渠道', selected: true })).toBeInTheDocument()
    expect(screen.getByTestId('provider-totals')).toHaveTextContent('11')
    expect(within(table).getByText('55.6%')).toBeInTheDocument()
    expect(within(table).getByText('1 / 0')).toBeInTheDocument()
    expect(within(table).getByLabelText('错误分布：5xx 2，429 限流 1，网络 / 超时 1')).toBeInTheDocument()
    expect(within(table).getAllByText('—').length).toBeGreaterThan(0)
  })

  it('选中渠道后显示趋势与按模型拆分', async () => {
    renderPage('/model-operations?tab=providers')
    await userEvent.click(await screen.findByText('渠道 A'))
    const detail = await screen.findByTestId('provider-detail')
    expect(within(detail).getByTestId('chart')).toBeInTheDocument()
    expect(within(detail).getByText('claude-test')).toBeInTheDocument()
  })

  it('接口失败时只在本标签内报错', async () => {
    http.get.mockImplementation((url: string) => url.endsWith('/model-operations/providers') ? Promise.reject({ response: { status: 503, data: {} } }) : Promise.resolve({ data: { data: [] } }))
    renderPage('/model-operations?tab=providers')
    expect(await screen.findByText('渠道监控数据读取失败')).toBeInTheDocument()
  })
})

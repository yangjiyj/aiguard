import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ModelSLAMonthly from '../components/ModelSLAMonthly'

const http = vi.hoisted(() => ({ get: vi.fn(), interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } } }))
vi.mock('axios', () => ({ default: { create: () => http } }))
const metrics = { requests: 0, eligible_requests: 0, http_successes: 0, platform_failures: 0, client_errors: 0, auth_failures: 0, cancelled: 0, blocked: 0, unknown: 0, availability: null, p50_ms: null, p95_ms: null, first_event_p50_ms: null, first_event_p95_ms: null, first_event_samples: 0, active_minutes: 0, down_minutes: 0, minute_availability: null }
const report = { month: '2026-10', timezone: 'Asia/Shanghai', start_at: '2026-09-30T16:00:00Z', end_at: '2026-10-31T16:00:00Z', generated_at: '2026-10-04T00:00:00Z', observed_until: '2026-10-04T00:00:00Z', in_progress: true, available: false, totals: metrics, models: [{ ...metrics, model_id: 'm1', model_name: 'claude-test', provider_id: 'p1', provider_name: '渠道 A' }], days: [{ ...metrics, day: '2026-10-01' }] }
let client: QueryClient
const renderMonth = () => render(<QueryClientProvider client={client}><ModelSLAMonthly providerId="p1" modelId="m1" /></QueryClientProvider>)
beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  vi.clearAllMocks()
  http.get.mockResolvedValue({ data: { data: report } })
})
afterEach(() => { cleanup(); client.clear(); vi.restoreAllMocks() })
describe('monthly model SLA', () => {
  it('sends a real natural month and timezone with the exact selected identities', async () => {
    renderMonth()
    await screen.findByText('本月进行中')
    expect(http.get).toHaveBeenCalledWith('/model-operations/sla', { params: { month: expect.stringMatching(/^\d{4}-\d{2}$/), timezone: 'Asia/Shanghai', provider_id: 'p1', model_id: 'm1' } })
    await userEvent.click(screen.getByRole('combobox', { name: 'SLA 时区' }))
    await userEvent.click((await screen.findAllByText('UTC')).find((element) => element.classList.contains('ant-select-item-option-content'))!)
    await waitFor(() => expect(http.get).toHaveBeenCalledWith('/model-operations/sla', { params: expect.objectContaining({ timezone: 'UTC', provider_id: 'p1', model_id: 'm1' }) }))
  })

  it('does not invent a perfect SLA from silent minutes or missing first-event samples', async () => {
    renderMonth()
    await screen.findByText('本月暂无可判定证据')
    expect(screen.getAllByText('未知').length).toBeGreaterThan(0)
    expect(screen.queryByText('100.00%')).not.toBeInTheDocument()
    expect(screen.getAllByText('未知 / 未知').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('暂无日可用率样本')).toBeInTheDocument()
  })

  it('exports the selected report as a CSV blob through its authenticated API', async () => {
    const blob = new Blob(['month,model\n2026-10,claude-test\n'], { type: 'text/csv;charset=utf-8' })
    http.get.mockImplementation((url: string) => Promise.resolve({ data: url.endsWith('/export') ? blob : { data: report } }))
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, writable: true, value: vi.fn(() => 'blob:csv-month') })
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, writable: true, value: vi.fn() })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
    renderMonth(); await screen.findByText('本月进行中')
    await userEvent.click(screen.getByRole('button', { name: '导出当前月报 CSV' }))
    await waitFor(() => expect(URL.createObjectURL).toHaveBeenCalledWith(blob))
    expect(http.get).toHaveBeenCalledWith('/model-operations/sla/export', { params: expect.objectContaining({ timezone: 'Asia/Shanghai', provider_id: 'p1', model_id: 'm1' }), responseType: 'blob' })
    expect(click).toHaveBeenCalledTimes(1)
  })

  it('reports denied or malformed exports without downloading a success artifact', async () => {
    http.get.mockImplementation((url: string) => url.endsWith('/export') ? Promise.reject({ response: { status: 403 } }) : Promise.resolve({ data: { data: report } }))
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
    renderMonth(); await screen.findByText('本月进行中')
    await userEvent.click(screen.getByRole('button', { name: '导出当前月报 CSV' }))
    await screen.findByText('当前账号无模型运营权限')
    expect(click).not.toHaveBeenCalled()
  })

  it('shows a server outage as an error rather than an empty month', async () => {
    http.get.mockRejectedValue({ response: { status: 503 } })
    renderMonth()
    await screen.findByText('月度 SLA 读取失败')
    expect(screen.queryByText('本月暂无可判定证据')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '导出当前月报 CSV' })).toBeDisabled()
  })

  it('shows monthly values before a compact note and preserves the full scope in an expandable disclosure', async () => {
    renderMonth()
    await screen.findByText('本月进行中')
    const totals = screen.getByLabelText('月度统计')
    const note = screen.getByText('分母为可判定请求；沉默分钟不算健康。观测结果不代表合同 SLA。')
    expect(totals.compareDocumentPosition(note) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    const detail = screen.getByText(/可用率按业务 HTTP 与传输证据统计/)
    expect(detail).not.toBeVisible()
    await userEvent.click(screen.getByText('统计口径'))
    expect(detail).toBeVisible()
    expect(detail).toHaveTextContent('安全阻断、取消及缺失证据不充作健康样本')
    expect(detail).toHaveTextContent('首事件含文本、推理及工具事件')
    expect(detail).toHaveTextContent('不代表完整生成验证或合同 SLA 承诺')
  })
})

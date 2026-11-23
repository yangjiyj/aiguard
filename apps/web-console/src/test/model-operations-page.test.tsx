import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, useLocation } from 'react-router-dom'
import ModelOperations from '../pages/ModelOperations'
import { canAccessPath } from '../utils/access'
import { modelOperationsApi } from '../services/modelOperations'

const http = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } } }))
vi.mock('axios', () => ({ default: { create: () => http } }))
const ok = (data: unknown) => ({ data })
const config = { version: 1, enabled: false, interval_seconds: 300, concurrency: 2, timeout_seconds: 15, max_targets: 50, max_output_tokens: 128, protocols: ['chat', 'responses', 'messages'], failure_threshold: 3, updated_at: '2026-10-04T00:00:00Z' }
const target = { model_id: 'm1', model_name: 'claude-test', provider_id: 'p1', provider_name: '渠道 A', upstream_model_id: 'claude-real', protocol: 'messages' }
const summary = { ...target, state: 'unknown', samples: 0, successes: 0, availability: null, p50_ms: null, p95_ms: null, last_probe_at: null, hourly: [] }
const record = { ...target, id: 'record-1', source: 'manual', success: false, http_status: 200, body_validated: false, latency_ms: 187, error_kind: 'invalid_body', created_at: '2026-10-04T00:00:00Z' }
const alert = { ...target, id: 'alert-1', state: 'open', failure_count: 3, last_error: 'invalid_body', opened_at: '2026-10-04T00:00:00Z', updated_at: '2026-10-04T01:00:00Z', acknowledged_at: null, resolved_at: null }
let client: QueryClient
let currentConfig = config
let currentAlert: any = alert
const Location = () => { const location = useLocation(); return <output data-testid="location">{location.pathname}{location.search}</output> }
const renderPage = (initial = '/model-operations') => render(<MemoryRouter initialEntries={[initial]}><QueryClientProvider client={client}><ModelOperations /><Location /></QueryClientProvider></MemoryRouter>)
beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })
  vi.clearAllMocks(); currentConfig = config; currentAlert = alert
  http.get.mockImplementation((url: string) => Promise.resolve(ok(
    url === '/providers' ? { data: [{ id: 'p1', name: '渠道 A' }, { id: 'p2', name: '渠道 B' }] }
      : url === '/models' ? { data: [{ id: 'm1', model_name: 'claude-test', provider_id: 'p1' }] }
        : url.endsWith('/overview') ? { targets: [summary], config: currentConfig, generated_at: '2026-10-04T00:00:00Z' }
          : url.endsWith('/targets') ? { items: [target] }
            : url.endsWith('/history') ? { items: [record], next_cursor: 'next-1' }
              : url.endsWith('/alerts') ? { items: [currentAlert] }
                : url.endsWith('/quality') ? { items: [{ ...target, samples: 10, availability: 0.8, http_5xx: 1, http_429: 1, http_4xx: 0, cancelled: 0, p50_ms: 50, p95_ms: 200, avg_first_event_ms: 40, first_event_p50_ms: 30, first_event_p95_ms: 60, output_tokens_per_sec_p50: 42.5, security_p50_ms: 8, pre_upstream_p50_ms: 12, rpm: 1.5, tpm: 150 }] }
                  : url === '/usage/records' ? { records: [{ id: 'request-row', request_id: 'request-1', created_at: '2026-10-04T00:00:00Z', request_status: 'failed', upstream_status_code: 502, latency_ms: 202, upstream_ttft_ms: null, failure_category: 'upstream_5xx', fallback_used: true, attempts: [{ result: 'failed', status_code_category: '5xx', latency_ms: 202, route: { provider_name: '渠道 A' } }] }], total: 21 }
                    : currentConfig)))
  http.put.mockImplementation((_url: string, payload: any) => Promise.resolve(ok({ ...payload, version: payload.version + 1 })))
  http.post.mockResolvedValue(ok({}))
})
afterEach(() => { cleanup(); client.clear(); vi.restoreAllMocks(); sessionStorage.clear() })

describe('model operations console', () => {
  it('preserves raw model operations DTOs and the wrapped SLA response contract', async () => {
    const rawTargets = { items: [target] }
    const wrappedSla = { data: { month: '2026-10', timezone: 'Asia/Shanghai', models: [target] } }
    http.get.mockResolvedValueOnce({ data: rawTargets, status: 200, headers: { 'content-type': 'application/json' } })
    const targets = await modelOperationsApi.targets({ provider_id: 'p1' })
    expect(targets.data.items).toEqual([target])
    expect(targets.data).not.toHaveProperty('data')
    http.get.mockResolvedValueOnce({ data: wrappedSla, status: 200, headers: { 'content-type': 'application/json' } })
    const sla = await modelOperationsApi.sla({ month: '2026-10', timezone: 'Asia/Shanghai', provider_id: 'p1' })
    expect(sla.data.data.month).toBe('2026-10')
    expect(sla.data).not.toHaveProperty('month')
  })

  it('keeps missing evidence unknown and uses an independent model operations view', async () => {
    renderPage()
    await screen.findByText('claude-test')
    expect(screen.queryByText('验证正常')).not.toBeInTheDocument()
    expect(screen.getAllByText('未知').length).toBeGreaterThan(0)
    expect(screen.getByText('未知 / 未知')).toBeInTheDocument()
  })

  it('passes the real window and resets a history cursor when the time filter changes', async () => {
    renderPage('/model-operations?tab=history&provider_id=p1')
    await screen.findByText('invalid_body')
    await userEvent.click(screen.getByRole('button', { name: '下一页' }))
    await waitFor(() => expect(http.get).toHaveBeenCalledWith('/model-operations/history', { params: expect.objectContaining({ provider_id: 'p1', cursor: 'next-1', window_hours: 24, limit: 25 }) }))
    await userEvent.click(screen.getByRole('combobox', { name: '时间窗口' }))
    await userEvent.click(await screen.findByText('近 3 天'))
    await waitFor(() => expect(http.get).toHaveBeenCalledWith('/model-operations/history', { params: expect.objectContaining({ cursor: undefined, window_hours: 72 }) }))
    expect(screen.getByText('第 1 页 · 本页 1 条')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '上一页' })).toBeDisabled()
  })

  it('shows real traffic metrics and opens a server-paginated request diagnosis', async () => {
    renderPage('/model-operations?tab=quality&provider_id=p1&window_hours=72')
    await screen.findByLabelText('claude-test 真实流量质量')
    expect(screen.getByText('80.00%')).toBeInTheDocument()
    expect(screen.getAllByText('可用率 80.0%').length).toBeGreaterThan(0)
    expect(screen.queryByText('较差')).toBeNull()
    expect(screen.getByText('近 3 天 · 1 个模型')).toBeInTheDocument()
    await userEvent.click(screen.getByText('明细表'))
    await screen.findByText('80.0%')
    expect(screen.getByText('1 / 1 / 0')).toBeInTheDocument()
    expect(screen.getByText('0.04 s')).toBeInTheDocument()
    expect(screen.getByText('0.03 s / 0.06 s')).toBeInTheDocument()
    const qualityTable = document.querySelector('.ant-table') as HTMLElement
    expect(within(qualityTable).getByText('42.5 词元/秒')).toBeInTheDocument()
    for (const label of ['输出速度中位数', '网关处理中位数', '安全检测中位数', '每分钟请求数', '每分钟词元数']) expect(screen.getByRole('columnheader', { name: label })).toBeInTheDocument()
    // 8 ms 与 12 ms 统一按秒显示后同为 "0.01 s"（另有列也落在 0.01 s），断言至少出现两处
    expect(screen.getAllByText('0.01 s').length).toBeGreaterThanOrEqual(2)
    // 质量表里「网关处理中位数 8ms」与「安全检测中位数 12ms」按秒显示后同为 0.01 s
    expect(within(qualityTable).getAllByText('0.01 s').length).toBeGreaterThanOrEqual(2)
    await userEvent.click(screen.getByRole('button', { name: '请求诊断' }))
    await screen.findByText('request-1')
    expect(http.get).toHaveBeenCalledWith('/usage/records', { params: expect.objectContaining({ provider_id: 'p1', model_id: 'm1', offset: 0, limit: 20, start: expect.any(String), end: expect.any(String) }) })
    const drawer = document.querySelector('.ant-drawer-body')!
    await userEvent.click(within(drawer as HTMLElement).getByRole('button', { name: '查看' }))
    await screen.findByText('尝试线路')
    expect(screen.getByText('此记录早于分段计时上线')).toBeInTheDocument()
    expect(screen.getByText('已使用')).toBeInTheDocument()
    const next = drawer.querySelector('.ant-pagination-next button') as HTMLElement
    await userEvent.click(next)
    await waitFor(() => expect(http.get).toHaveBeenCalledWith('/usage/records', { params: expect.objectContaining({ offset: 20 }) }))
  })

  it('edits configuration locally, requires costs, and sends only a deliberate save', async () => {
    renderPage('/model-operations?tab=settings')
    const toggle = await screen.findByRole('switch', { name: '定时拨测' })
    await userEvent.click(toggle)
    expect(http.put).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: /保存配置/ })).toBeDisabled()
    await userEvent.click(screen.getByRole('checkbox', { name: '确认周期上游请求费用' }))
    await userEvent.click(screen.getByRole('button', { name: /保存配置/ }))
    await screen.findByText('配置已保存')
    expect(http.put).toHaveBeenCalledWith('/model-operations/config', expect.objectContaining({ version: 1, enabled: true, confirm_cost: true, max_output_tokens: 128 }))
  })

  it('preserves a conflicted settings draft and lets the user rebase deliberately', async () => {
    http.put.mockImplementationOnce(() => { currentConfig = { ...config, version: 2, interval_seconds: 900 }; return Promise.reject({ response: { status: 409 } }) })
    renderPage('/model-operations?tab=settings')
    const interval = await screen.findByRole('spinbutton', { name: '间隔（秒）' })
    await userEvent.clear(interval); await userEvent.type(interval, '600')
    await userEvent.click(screen.getByRole('button', { name: /保存配置/ }))
    await screen.findByText('配置已被其他管理员修改，当前草稿已保留')
    expect(interval).toHaveValue('600')
    await userEvent.click(screen.getByRole('button', { name: '保留草稿并采用最新版本' }))
    expect(interval).toHaveValue('600')
    await userEvent.click(screen.getByRole('button', { name: /保存配置/ }))
    await screen.findByText('配置已保存')
    expect(http.put.mock.calls[1][1]).toEqual(expect.objectContaining({ version: 2, interval_seconds: 600 }))
  })

  it('persists acknowledgement while keeping recovery separate', async () => {
    http.post.mockImplementation(() => { currentAlert = { ...alert, acknowledged_at: '2026-10-04T02:00:00Z', acknowledged_by: 'u1' }; return Promise.resolve(ok(currentAlert)) })
    renderPage('/model-operations?tab=alerts')
    await userEvent.click(await screen.findByRole('button', { name: /确认告警/ }))
    await screen.findByText('已确认')
    expect(http.post).toHaveBeenCalledWith('/model-operations/alerts/alert-1/ack')
    expect(screen.getAllByText('未恢复').length).toBeGreaterThan(0)
    expect(screen.queryByText('已恢复')).not.toBeInTheDocument()
  })

  it('returns to the filtered source and restricts access to system administrators', async () => {
    renderPage('/model-operations?provider_id=p1&return_to=%2Fproviders')
    await userEvent.click(screen.getByRole('button', { name: '返回来源页面' }))
    expect(screen.getByTestId('location')).toHaveTextContent('/providers?provider_id=p1')
    expect(canAccessPath('platform_admin', '/model-operations')).toBe(true)
    expect(canAccessPath('tenant_owner', '/model-operations')).toBe(true)
    expect(canAccessPath('tenant_admin', '/model-operations')).toBe(true)
    expect(canAccessPath('auditor', '/model-operations')).toBe(false)
  })

  it('shows 403 as denied and never manufactures a healthy empty view', async () => {
    http.get.mockImplementation((url: string) => url.endsWith('/targets') ? Promise.reject({ response: { status: 403 } }) : Promise.resolve(ok(url === '/providers' || url === '/models' ? { data: [] } : { targets: [], config })))
    renderPage()
    await screen.findByText('当前账号无模型运营权限')
    expect(screen.queryByText('验证正常')).not.toBeInTheDocument()
  })

  it('retains unsupported native models as unknown inventory and prevents an unsupported request', async () => {
    http.get.mockImplementation((url: string) => Promise.resolve(ok(url.endsWith('/targets') ? { items: [{ ...target, supported: false }] } : url.endsWith('/overview') ? { targets: [summary], config } : { data: [] })))
    renderPage()
    await screen.findByText('当前未适配验证')
    expect(screen.getByText('claude-test')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '验证 claude-test' })).toBeDisabled()
    expect(screen.queryByText('验证失败')).not.toBeInTheDocument()
    expect(screen.queryByText('验证正常')).not.toBeInTheDocument()
  })
})

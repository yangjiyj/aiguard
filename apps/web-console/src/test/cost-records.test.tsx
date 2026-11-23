import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import CostRecords from '../pages/cost/CostRecords'
import * as api from '../services/api'

const renderPage = (queryClient: QueryClient) => render(<MemoryRouter><QueryClientProvider client={queryClient}><CostRecords /></QueryClientProvider></MemoryRouter>)

describe('CostRecords page', () => {
  let queryClient: QueryClient
  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.clearAllMocks()
    vi.spyOn(api, 'getUsageRecordsSummary').mockResolvedValue({ data: { requests: 1, users: 1, apps: 1, keys: 1, input_tokens: 100, output_tokens: 20, total_tokens: 120, billing_amount_micros: 1250000, settled_requests: 1, reserved_requests: 0, released_requests: 0, exception_requests: 0, not_billed_requests: 0, success_requests: 1, failed_requests: 0 } } as any)
    vi.spyOn(api, 'getUsageRecords').mockResolvedValue({ data: { total: 1, records: [{ id: 'rl_1', request_id: 'req_1', session_id: 'sess_1', created_at: '2026-06-12T01:00:00Z', user_name: 'Alice', key_name: '客服助手 Key', key_prefix: 'sk-live', project_name: '客服助手', provider_name: 'OpenAI', model_name: 'gpt-4o', request_status: 'success', upstream_status_code: 200, input_tokens: 100, output_tokens: 20, total_tokens: 120, billing_amount_micros: 1250000, billing_currency: 'CNY', billing_state: 'settled', billing_mode: 'prepaid', latency_ms: 350 }] } } as any)
    vi.spyOn(api.userApi, 'list').mockResolvedValue({ data: [{ id: 'u_1', username: 'Alice' }] } as any)
    vi.spyOn(api.keyApi, 'list').mockResolvedValue({ data: [{ id: 'k_1', name: '客服助手 Key', key_prefix: 'sk-live' }] } as any)
    vi.spyOn(api.projectApi, 'list').mockResolvedValue({ data: [{ id: 'p_1', name: '客服助手' }] } as any)
    vi.spyOn(api.providerApi, 'list').mockResolvedValue({ data: [{ id: 'pr_1', name: 'OpenAI' }] } as any)
    vi.spyOn(api.modelApi, 'list').mockResolvedValue({ data: [{ id: 'm_1', model_name: 'gpt-4o', provider_id: 'pr_1' }] } as any)
  })

  it('shows only settled billing amount and never a legacy cost field', async () => {
    renderPage(queryClient)
    expect((await screen.findAllByText('CNY 1.25')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('已扣费').length).toBeGreaterThan(0)
    expect(screen.queryByText('费用缺口（点击去补定价）')).not.toBeInTheDocument()
    expect(screen.queryByText('输入价格')).not.toBeInTheDocument()
  })

  it('调用明细抽屉显示耗时卡片与旧记录提示', async () => {
    renderPage(queryClient)
    const row = (await screen.findByText('Alice')).closest('tr')!
    fireEvent.click(within(row).getByRole('button', { name: '详情' }))
    expect(await screen.findByText('耗时分解')).toBeInTheDocument()
    expect(screen.getByText('此记录早于分段计时上线')).toBeInTheDocument()
  })

  it('labels a model-not-found failure in Chinese instead of the raw status', async () => {
    vi.mocked(api.getUsageRecords).mockResolvedValueOnce({ data: { total: 1, records: [{ id: 'nf', request_id: 'req-nf', request_status: 'failed', raw_status: 'model_not_found', upstream_status_code: 404, failure_category: 'model_not_found', billing_state: 'not_billed' }] } } as any)
    renderPage(queryClient)
    expect(await screen.findByText(/模型不存在/)).toBeInTheDocument()
    expect(screen.queryByText('其他原因')).not.toBeInTheDocument()
  })

  it('labels metering facts as measured rather than deducted', async () => {
    vi.mocked(api.getUsageRecords).mockResolvedValueOnce({ data: { total: 1, records: [{ id: 'metered', request_id: 'metered', created_at: '2026-06-12T01:00:00Z', billing_amount_micros: 1250000, billing_currency: 'CNY', billing_state: 'settled', billing_mode: 'metering', request_status: 'success', total_tokens: 120 }] } } as any)
    renderPage(queryClient)
    expect(await screen.findByText('已计量')).toBeInTheDocument()
    expect(screen.queryByText('已扣费')).not.toBeInTheDocument()
  })

  it('shows a retryable load error instead of an empty table', async () => {
    const recordsSpy = vi.mocked(api.getUsageRecords)
    recordsSpy.mockRejectedValueOnce(new Error('unavailable'))
    renderPage(queryClient)
    expect(await screen.findByText('调用明细加载失败')).toBeInTheDocument()
    expect(screen.getByText('暂时无法读取计费明细，请检查网络后重试。')).toBeInTheDocument()
    screen.getByRole('button', { name: /重\s*试/ }).click()
    await waitFor(() => expect(recordsSpy).toHaveBeenCalledTimes(2))
  })

  it('makes a nonzero amount smaller than one cent explicit', async () => {
    vi.mocked(api.getUsageRecords).mockResolvedValueOnce({ data: { total: 1, records: [{ id: 'tiny', request_id: 'tiny', created_at: '2026-06-12T01:00:00Z', billing_amount_micros: 1, billing_currency: 'CNY', billing_state: 'settled', request_status: 'success', total_tokens: 1 }] } } as any)
    renderPage(queryClient)
    expect(await screen.findByText('< CNY 0.01')).toBeInTheDocument()
  })

  it('shows only call details and sends the aggregate dashboard elsewhere', async () => {
    renderPage(queryClient)
    await screen.findAllByText('CNY 1.25')
    expect(screen.getByRole('heading', { name: '调用明细' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: '计费概览' })).not.toBeInTheDocument()
    expect(screen.queryByText('上方汇总已结算、待结算与异常调用')).not.toBeInTheDocument()
  })

  it('uses business-object selectors rather than internal-ID text inputs', async () => {
    renderPage(queryClient)
    await screen.findAllByText('CNY 1.25')
    expect(screen.getAllByLabelText('用户筛选').length).toBeGreaterThan(0)
    expect(screen.getAllByLabelText('Key 筛选').length).toBeGreaterThan(0)
    expect(screen.getAllByLabelText('应用筛选').length).toBeGreaterThan(0)
    expect(screen.getAllByLabelText('模型筛选').length).toBeGreaterThan(0)
    expect(screen.getAllByLabelText('供应商筛选').length).toBeGreaterThan(0)
    expect(screen.queryByPlaceholderText('用户 ID')).not.toBeInTheDocument()
    expect(screen.queryByPlaceholderText('Key ID')).not.toBeInTheDocument()
    expect(screen.queryByPlaceholderText('应用 ID')).not.toBeInTheDocument()
    expect(screen.queryByPlaceholderText('模型 ID')).not.toBeInTheDocument()
    expect(screen.queryByPlaceholderText('供应商 ID')).not.toBeInTheDocument()
  })

  it('uses explicit business fallbacks rather than exposing missing IDs', async () => {
    vi.mocked(api.getUsageRecords).mockResolvedValueOnce({ data: { total: 1, records: [{ id: 'rl_missing', request_id: 'req_missing', session_id: '', created_at: '2026-06-12T01:10:00Z', user_name: '', key_name: '', key_prefix: '', project_name: '', provider_name: '', model_name: '', request_status: 'failed', upstream_status_code: 500, input_tokens: 0, output_tokens: 0, total_tokens: 0, billing_amount_micros: null, billing_currency: '', billing_state: 'exception', latency_ms: 0 }] } } as any)
    renderPage(queryClient)
    const row = (await screen.findByText('已删除或不可见用户')).closest('tr')
    expect(row).not.toBeNull()
    expect(within(row!).getByText('已删除或不可见 Key')).toBeInTheDocument()
    expect(within(row!).getByText('已删除或未归属应用')).toBeInTheDocument()
    expect(within(row!).getByText('已删除或不可见供应商')).toBeInTheDocument()
    expect(within(row!).getByText('已删除或不可见模型')).toBeInTheDocument()
    expect(within(row!).getByText('异常待核对')).toBeInTheDocument()
  })
  // 39ebd870e（审计中心表格自适应宽度）有意去掉了错误详情列里的“查看错误详情”按钮：错误列改为纯展示，
  // 打开抽屉的入口是整行点击和“操作”列的“详情”按钮。这里按现在的入口点“详情”。
  it('shows diagnostic evidence and submits literal server filters', async () => {
    vi.mocked(api.getUsageRecords).mockResolvedValue({ data: { total: 1, records: [{ id: 'error', request_id: 'req-error', source_ip: '192.0.2.8', request_status: 'failed', raw_status: 'provider_timeout', upstream_status_code: 504, failure_category: 'timeout', error_message: 'capacity exhausted', billing_state: 'not_billed' }] } } as any)
    renderPage(queryClient)
    expect(await screen.findByText('192.0.2.8')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^详 ?情$/ }))
    expect(await screen.findByText('req-error')).toBeInTheDocument()
    expect(screen.getByText('原始状态：provider_timeout')).toBeInTheDocument()
    expect(screen.getAllByText('capacity exhausted')).toHaveLength(2)
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    const source = screen.getByLabelText('源 IP 筛选')
    fireEvent.change(source, { target: { value: '192.0.2.8' } })
    fireEvent.keyDown(source, { key: 'Enter', code: 'Enter', keyCode: 13 })
    await waitFor(() => expect(api.getUsageRecords).toHaveBeenLastCalledWith(expect.objectContaining({ source_ip: '192.0.2.8', offset: 0 })))
  })

  it('优先显示中文解释，详情保留可复制的上游原文与错误码', async () => {
    const original = 'prompt is too long: 1002476 tokens > 1000000 maximum'
    const hint = '对话上下文超过模型上限（本次 1002476 token，上限 1000000），请压缩上下文或新开对话'
    vi.mocked(api.getUsageRecords).mockResolvedValueOnce({ data: { total: 1, records: [{ id: 'context', request_id: 'context', request_status: 'failed', upstream_status_code: 400, error_message: original, error_hint: hint, upstream_error_code: 'context_length_exceeded', billing_state: 'not_billed' }] } } as any)
    renderPage(queryClient)
    const summary = await screen.findByText(hint)
    expect(summary).toHaveAttribute('title', original)
    expect(screen.queryByText(original)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^详 ?情$/ }))
    expect(await screen.findByText('上游错误原文：')).toBeInTheDocument()
    expect(screen.getByText(original)).toBeInTheDocument()
    expect(screen.getByText('上游错误码：context_length_exceeded')).toBeInTheDocument()
    expect(screen.getByText(original).parentElement?.querySelector('.ant-typography-copy')).not.toBeNull()
    expect(screen.queryByText('错误原文（已脱敏）：')).not.toBeInTheDocument()
  })

  it.each([
    ['prompt is too long: 1002476 tokens > 1000000 maximum', '对话上下文超过模型上限（本次 1002476 token，上限 1000000），请压缩上下文或新开对话'],
    ['rate_limit_error', '上游请求过于频繁，请稍后重试'],
    ['insufficient_quota balance', '上游账号额度不足，请联系管理员'],
  ])('历史记录根据原文补充解释：%s', async (original, hint) => {
    vi.mocked(api.getUsageRecords).mockResolvedValueOnce({ data: { total: 1, records: [{ id: 'legacy', request_id: 'legacy', request_status: 'failed', error_message: original, billing_state: 'not_billed' }] } } as any)
    renderPage(queryClient)
    expect(await screen.findByText(hint)).toHaveAttribute('title', original)
  })


it('诊断证据链接将请求编号传给调用明细查询', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  vi.spyOn(api, 'getUsageRecords').mockResolvedValue({ data: { total: 0, records: [] } } as any)
  render(<MemoryRouter initialEntries={['/cost/records?request_id=req-diagnosis']}><QueryClientProvider client={client}><CostRecords /></QueryClientProvider></MemoryRouter>)
  await waitFor(() => expect(api.getUsageRecords).toHaveBeenCalledWith(expect.objectContaining({ request_id: 'req-diagnosis' })))
})

})

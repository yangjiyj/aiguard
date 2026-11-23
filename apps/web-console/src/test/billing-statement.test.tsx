import { billingSourceLabels } from './billingSourceLabels'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import BillingStatements from '../pages/billing/Statements'
import * as api from '../services/api'

const response = (data: any) => ({ data: { data } } as any)
const line = (model: string, requests: number, tokens: number, billed: number, unpriced = 0, unknown = 0) => ({
  model_name: model, requests, total_tokens: tokens, billed_micros: billed, billed_requests: requests - unpriced - unknown,
  unbilled_requests: unpriced + unknown, unpriced_requests: unpriced, usage_unknown_requests: unknown, failed_requests: 0,
})
const statement = {
  month: '2026-10', timezone: 'Asia/Shanghai', currency: 'CNY',
  total: line('', 6, 2_000, 2_240_001, 1, 1),
  departments: [
    { department_id: 'd1', department_name: '研发部', ...line('', 5, 1_990, 1_240_001, 1, 1), employees: [
      { user_id: 'u1', user_name: 'alice', ...line('', 5, 1_990, 1_240_001, 1, 1), models: [
        line('gpt-6-luna', 3, 1_660, 1_240_001), line('glm-5.2', 1, 330, 0, 1, 0), line('chatgpt', 1, 0, 0, 0, 1),
      ] },
    ] },
    { department_id: '', department_name: '未分配部门', ...line('', 1, 10, 1_000_000), employees: [] },
  ],
}

describe('月度分账单', () => {
  let queryClient: QueryClient
  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue({ data: [{ id: 'tenant-a', name: '测试单位' }] } as any)
    vi.spyOn(api.billingAdminApi, 'runtime').mockResolvedValue(response({ mode: 'metering', prepaid_tools_visible: false }))
    for (const name of ['models', 'customerGroups', 'prices', 'redemptions', 'tariffs'] as const) vi.spyOn(api.billingAdminApi, name).mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'customers').mockResolvedValue({ data: { data: [], meta: { has_more: false, next_cursor: '' } } } as any)
    vi.spyOn(api.billingAdminApi, 'ledger').mockResolvedValue({ data: { data: [], meta: { has_more: false, next_cursor: '' } } } as any)
    vi.spyOn(api.billingAdminApi, 'previewTariff').mockResolvedValue(response(null))
    vi.spyOn(api.billingAdminApi, 'monthlyStatement').mockResolvedValue(response(statement))
  })
  afterEach(() => { vi.restoreAllMocks(); cleanup(); document.body.innerHTML = '' })
  const renderPage = () => render(<MemoryRouter><QueryClientProvider client={queryClient}><BillingStatements /></QueryClientProvider></MemoryRouter>)

  it('首屏是月度分账单：按部门汇总，未计费单列，不混进 0 元', async () => {
    renderPage()
    expect(await screen.findByRole('tab', { name: billingSourceLabels.statement, selected: true })).toBeInTheDocument()
    await waitFor(() => expect(api.billingAdminApi.monthlyStatement).toHaveBeenCalledWith('tenant-a', expect.stringMatching(/^\d{4}-\d{2}$/)))
    const region = within(await screen.findByRole('region', { name: '月度分账单' }))
    const dept = (await region.findByText('研发部')).closest('tr') as HTMLElement
    expect(dept).toHaveTextContent('¥1.240')
    expect(dept).toHaveTextContent('2 次未计费')
    expect(region.getByText('¥2.240')).toBeInTheDocument()
    expect(region.getByText(/未计费调用 2 次/)).toBeInTheDocument()
  })

  it('展开部门可看到员工 × 模型明细，未定价/用量未知的行显示“未计费”', async () => {
    const user = userEvent.setup()
    renderPage()
    const region = within(await screen.findByRole('region', { name: '月度分账单' }))
    const dept = (await region.findByText('研发部')).closest('tr') as HTMLElement
    await user.click(within(dept).getByRole('button', { name: /展开/ }))
    const glm = (await region.findByText('glm-5.2')).closest('tr') as HTMLElement
    expect(glm).toHaveTextContent('未计费')
    expect(glm).toHaveTextContent('未定价')
    expect(glm).not.toHaveTextContent('¥0.000')
    const web = region.getByText('chatgpt').closest('tr') as HTMLElement
    expect(web).toHaveTextContent('用量未知')
    const luna = region.getByText('gpt-6-luna').closest('tr') as HTMLElement
    expect(luna).toHaveTextContent('alice')
    expect(luna).toHaveTextContent('1,660')
  })

  it('导出 Excel 调用服务端 xlsx 接口，文件名带月份', async () => {
    const blob = new Blob(['x'])
    const xlsx = vi.spyOn(api.billingAdminApi, 'monthlyStatementXlsx').mockResolvedValue({ data: blob } as any)
    const createURL = vi.fn(() => 'blob:x')
    Object.assign(URL, { createObjectURL: createURL, revokeObjectURL: vi.fn() })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const user = userEvent.setup()
    renderPage()
    await screen.findByRole('region', { name: '月度分账单' })
    await user.click(screen.getByRole('button', { name: /导出 Excel/ }))
    await waitFor(() => expect(xlsx).toHaveBeenCalledWith('tenant-a', expect.stringMatching(/^\d{4}-\d{2}$/)))
    expect(click).toHaveBeenCalled()
  })

  it('读取失败给出重试，不显示 0 元', async () => {
    vi.mocked(api.billingAdminApi.monthlyStatement).mockRejectedValue(new Error('boom'))
    renderPage()
    expect(await screen.findByText('月度分账单读取失败')).toBeInTheDocument()
    expect(screen.queryByText('¥0.000')).not.toBeInTheDocument()
  })
})

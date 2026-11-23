import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { message } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import BillingPricing from '../pages/billing/Pricing'
import type { BillingPrice } from '../components/billing/modelPricing'
import * as api from '../services/api'
import { useAuthStore } from '../stores/auth'
import { confirmPriceChange, findPriceChangeDialog } from './priceChangeTestUtils'

// 价格历史接口最多返回 500 行（按模型名升序、版本降序截断），版本多时靠后的模型会整体缺失。
// 前端同时读「当前生效价」（scope=effective），合并后 current/configured 不再受历史截断影响。

const response = (data: unknown) => ({ data: { data } } as any)
const price = (name: string, patch: Partial<BillingPrice> & { customer_group?: string } = {}): BillingPrice & { customer_group?: string } => ({
  id: `${name}-v1`, model_name: name, version: 1, pricing_mode: 'direct', currency: 'CNY', status: 'active',
  effective_at: '2026-08-01T00:00:00Z', input_per_million_micros: 4_000_000, output_per_million_micros: 8_000_000,
  has_cached_input_price: false, has_cache_write_price: false, ...patch,
})
const fillers = (prefix: string, count: number) => Array.from({ length: count }, (_, index) => price(`${prefix}-${index}`, { id: `${prefix}-${index}` }))

let history: BillingPrice[]
let effective: BillingPrice[]
let client: QueryClient
let createPrice: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  history = []
  effective = []
  client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  useAuthStore.setState({ isAuthenticated: true, token: 'test-token', user: { id: 'admin', role: 'platform_admin', tenant_id: 'tenant-a' } as any })
  vi.spyOn(api.tenantApi, 'list').mockResolvedValue(response([{ id: 'tenant-a', name: 'Tenant A' }]))
  vi.spyOn(api.billingAdminApi, 'runtime').mockResolvedValue(response({ mode: 'metering' }))
  vi.spyOn(api.billingAdminApi, 'models').mockResolvedValue(response([
    { model_name: 'm1', model_label: '模型1', provider_name: '供应商', status: 'active' },
    { model_name: 'm2', model_label: '模型2', provider_name: '供应商', status: 'active' },
    { model_name: 'm3', model_label: '模型3', provider_name: '供应商', status: 'active' },
  ]))
  vi.spyOn(api.billingAdminApi, 'prices').mockImplementation((async (_tenant: string, params: Record<string, unknown> = {}) => (
    response(params.scope === 'effective' ? effective : history)
  )) as any)
  vi.spyOn(api.billingAdminApi, 'tariffs').mockResolvedValue(response([]))
  vi.spyOn(api.billingAdminApi, 'previewTariff').mockResolvedValue(response(null))
  createPrice = vi.spyOn(api.billingAdminApi, 'createPrice').mockResolvedValue({ data: { data: { unchanged: false } } } as any)
})

afterEach(() => {
  act(() => message.destroy())
  cleanup()
  client.clear()
  vi.restoreAllMocks()
  document.body.innerHTML = ''
})

const show = () => render(<QueryClientProvider client={client}><MemoryRouter><BillingPricing /></MemoryRouter></QueryClientProvider>)
const rowOf = async (label: string) => (await screen.findByText(label)).closest('tr') as HTMLElement

describe('价格列表截断：历史 + 当前生效价合并', () => {
  it('分别用 limit=500 读取历史与当前生效价', async () => {
    show()
    await screen.findByText('模型1')
    await waitFor(() => {
      expect(api.billingAdminApi.prices).toHaveBeenCalledWith('tenant-a', { limit: 500 })
      expect(api.billingAdminApi.prices).toHaveBeenCalledWith('tenant-a', { scope: 'effective', limit: 500 })
    })
  })

  it('历史列表缺了某模型、生效列表里有它：显示为已配置', async () => {
    history = [price('m1')]
    effective = [price('m1'), price('m2')]
    show()
    expect(within(await rowOf('模型2')).getByText('已配置')).toBeInTheDocument()
    expect(within(await rowOf('模型3')).getByText('未配置')).toBeInTheDocument()
  })

  it('同一版本在两个列表里按 id 去重，历史弹窗只列一次', async () => {
    const user = userEvent.setup()
    history = [price('m1')]
    effective = [price('m1')]
    show()
    await rowOf('模型1')
    await user.click(screen.getByRole('button', { name: '查看 m1 历史' }))
    const dialog = await screen.findByRole('dialog', { name: 'm1 定价历史' })
    expect(within(dialog).getAllByText('v1')).toHaveLength(1)
  })

  it('忽略非 default 客户组的行', async () => {
    effective = [price('m3', { customer_group: 'vip' })]
    show()
    expect(within(await rowOf('模型3')).getByText('未配置')).toBeInTheDocument()
  })

  it('批量改价时，只存在于生效列表里的模型能看到旧值 → 新值', async () => {
    const user = userEvent.setup()
    history = [price('m1')]
    effective = [price('m1'), price('m2')]
    show()
    await rowOf('模型2')
    await user.click(screen.getByRole('checkbox', { name: '选择 模型2' }))
    await user.click(screen.getByRole('button', { name: '批量套价' }))
    const batch = await screen.findByRole('dialog', { name: '批量套价' })
    await user.type(within(batch).getByRole('spinbutton', { name: '输入单价（元/百万 Token）' }), '2')
    await user.type(within(batch).getByRole('spinbutton', { name: '输出单价（元/百万 Token）' }), '8')
    await user.click(within(batch).getByRole('button', { name: '应用到 1 个模型' }))
    const confirm = await findPriceChangeDialog()
    const row = within(confirm).getByText('模型2').closest('tr') as HTMLElement
    expect(within(row).getByText('¥4.000')).toBeInTheDocument()
    expect(within(row).getByText('¥2.000')).toBeInTheDocument()
    expect(within(row).getByText('调整')).toBeInTheDocument()
    await confirmPriceChange(user)
    await waitFor(() => expect(createPrice).toHaveBeenCalledTimes(1))
    expect(createPrice.mock.calls[0][0]).not.toHaveProperty('confirm_zero_price')
  })

  it('批量改成 0 时，只存在于生效列表里的模型也要求勾选确认并带 confirm_zero_price', async () => {
    const user = userEvent.setup()
    history = [price('m1')]
    effective = [price('m1'), price('m2')]
    show()
    await rowOf('模型2')
    await user.click(screen.getByRole('checkbox', { name: '选择 模型2' }))
    await user.click(screen.getByRole('button', { name: '批量套价' }))
    const batch = await screen.findByRole('dialog', { name: '批量套价' })
    await user.type(within(batch).getByRole('spinbutton', { name: '输入单价（元/百万 Token）' }), '0')
    await user.type(within(batch).getByRole('spinbutton', { name: '输出单价（元/百万 Token）' }), '0')
    await user.click(within(batch).getByRole('button', { name: '应用到 1 个模型' }))
    const confirm = await findPriceChangeDialog()
    expect(within(confirm).getByRole('alert')).toHaveTextContent('模型2')
    expect(within(confirm).getByRole('button', { name: '确认写入 1 个模型' })).toBeDisabled()
    await confirmPriceChange(user)
    await waitFor(() => expect(createPrice).toHaveBeenCalledTimes(1))
    expect(createPrice.mock.calls[0][0]).toMatchObject({ model_name: 'm2', confirm_zero_price: true })
  })
})

describe('价格列表截断提示', () => {
  const historyWarning = '价格历史记录较多，仅加载了前 500 条，部分模型的历史版本可能未列出；当前生效价格已单独完整加载。'
  const effectiveWarning = '当前生效价格超过 500 条，列表可能不完整，请联系管理员处理。'

  it('历史返回 500 行：提示历史被截断，不提示生效价', async () => {
    history = fillers('h', 500)
    show()
    expect(await screen.findByText(historyWarning)).toBeInTheDocument()
    expect(screen.queryByText(effectiveWarning)).not.toBeInTheDocument()
  })

  it('当前生效价返回 500 行：提示生效价可能不完整', async () => {
    effective = fillers('e', 500)
    show()
    expect(await screen.findByText(effectiveWarning)).toBeInTheDocument()
    expect(screen.queryByText(historyWarning)).not.toBeInTheDocument()
  })

  it('不足 500 行：没有任何截断提示', async () => {
    history = fillers('h', 499)
    effective = fillers('e', 10)
    show()
    await screen.findByText('模型1')
    expect(screen.queryByText(historyWarning)).not.toBeInTheDocument()
    expect(screen.queryByText(effectiveWarning)).not.toBeInTheDocument()
  })
})

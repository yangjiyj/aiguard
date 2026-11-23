import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest'
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { message } from 'antd'
import ModelPricingTable from '../components/billing/ModelPricingTable'
import type { BillingModel, BillingPrice } from '../components/billing/modelPricing'
import { apiClient, billingAdminApi } from '../services/api'
import { cancelPriceChange, confirmPriceChange, findPriceChangeDialog } from './priceChangeTestUtils'

// 后端 409 price_zero_confirmation_required：前端手里的「当前价」是旧的或不全，所以没带确认标志。
// 此时必须重读当前生效价、让用户确认后才带 confirm_zero_price 重发，而不是只把报错丢给用户。

const makeModels = (count: number): BillingModel[] => Array.from({ length: count }, (_, index) => ({
  model_name: `m${index + 1}`, model_label: `模型${index + 1}`, provider_name: '供应商', status: 'active',
}))
const directPrice = (name: string, patch: Partial<BillingPrice> = {}): BillingPrice => ({
  id: `${name}-v1`, model_name: name, version: 1, pricing_mode: 'direct', currency: 'CNY', status: 'active',
  effective_at: '2026-08-01T00:00:00Z', input_per_million_micros: 4_000_000, output_per_million_micros: 8_000_000,
  has_cached_input_price: false, has_cache_write_price: false, ...patch,
})
const zero = { input_per_million_micros: 0, output_per_million_micros: 0 }
const conflict = () => Object.assign(new Error('conflict'), {
  response: { status: 409, data: { error: { code: 'price_zero_confirmation_required', message: 'x' } } },
})
const saved = { data: { data: { unchanged: false } } } as any

let createPrice: MockInstance<typeof billingAdminApi.createPrice>
let pricesSpy: MockInstance<typeof billingAdminApi.prices>
let effective: Record<string, (BillingPrice & { customer_group?: string })[]>
let reread: 'ok' | 'fail'

beforeEach(() => {
  effective = {}
  reread = 'ok'
  createPrice = vi.spyOn(billingAdminApi, 'createPrice').mockResolvedValue(saved)
  pricesSpy = vi.spyOn(billingAdminApi, 'prices').mockImplementation((async (_tenant: string, params: Record<string, unknown> = {}) => {
    if (reread === 'fail') throw new Error('network')
    return { data: { data: effective[String(params.model_name)] ?? [] } }
  }) as any)
  vi.spyOn(apiClient, 'get').mockResolvedValue({ data: { data: { image_models: [], tools: [], recognized_model: false, suggested_template_id: '' } } } as any)
})

afterEach(() => {
  act(() => message.destroy())
  cleanup()
  vi.restoreAllMocks()
  document.body.innerHTML = ''
})

function renderTable(models: BillingModel[], prices: BillingPrice[], onRefresh = vi.fn()) {
  render(<ModelPricingTable tenantID="tenant-a" models={models} prices={prices} loading={false} onRefresh={onRefresh} />)
  return onRefresh
}

describe('单行保存遇到 409', () => {
  it('重读当前生效价后弹确认（取 default 组），确认后带 confirm_zero_price 重发', async () => {
    const user = userEvent.setup()
    // vip 组的价格本来就是 0/0，若被误取会判成「无需确认」
    effective.m1 = [
      { ...directPrice('m1', { id: 'vip', ...zero }), customer_group: 'vip' },
      { ...directPrice('m1'), customer_group: 'default' },
    ]
    createPrice.mockRejectedValueOnce(conflict()).mockResolvedValue(saved)
    const onRefresh = renderTable(makeModels(1), [directPrice('m1', zero)])
    await user.click(screen.getByRole('button', { name: '保存 m1 定价' }))

    const dialog = await findPriceChangeDialog()
    expect(within(dialog).getByRole('alert')).toHaveTextContent('以下 1 个模型的输入、输出价格将被改成 0，相当于免费')
    expect(within(dialog).getByText('¥4.000')).toBeInTheDocument()
    expect(createPrice).toHaveBeenCalledTimes(1)
    expect(createPrice.mock.calls[0][0]).not.toHaveProperty('confirm_zero_price')
    expect(pricesSpy).toHaveBeenCalledWith('tenant-a', { scope: 'effective', model_name: 'm1', limit: 20 })
    expect(onRefresh).toHaveBeenCalled()

    await confirmPriceChange(user)
    await waitFor(() => expect(createPrice).toHaveBeenCalledTimes(2))
    expect(createPrice.mock.calls[1][0]).toMatchObject({ model_name: 'm1', input_per_million_micros: 0, output_per_million_micros: 0, confirm_zero_price: true })
    expect(await screen.findByText('模型1 定价已保存')).toBeInTheDocument()
  })

  it('取消确认：不重发', async () => {
    const user = userEvent.setup()
    effective.m1 = [{ ...directPrice('m1'), customer_group: 'default' }]
    createPrice.mockRejectedValueOnce(conflict())
    renderTable(makeModels(1), [directPrice('m1', zero)])
    await user.click(screen.getByRole('button', { name: '保存 m1 定价' }))
    await findPriceChangeDialog()
    await cancelPriceChange(user)
    await new Promise(resolve => setTimeout(resolve, 200))
    expect(createPrice).toHaveBeenCalledTimes(1)
    expect(screen.queryByText('模型1 定价已保存')).not.toBeInTheDocument()
  })

  it('高级编辑器里取消清零确认：不重发，编辑器保持打开', async () => {
    const user = userEvent.setup()
    effective.m1 = [{ ...directPrice('m1'), customer_group: 'default' }]
    createPrice.mockRejectedValueOnce(conflict())
    renderTable(makeModels(1), [directPrice('m1', { ...zero, pricing_extras: { image_pricing: { mode: 'token' } } })])
    await user.click(screen.getByRole('button', { name: 'm1 图片与工具计费' }))
    const editor = await screen.findByRole('dialog', { name: '模型1 · 定价配置' })
    await user.click(within(editor).getByRole('button', { name: '保存收费配置' }))
    await findPriceChangeDialog()
    await cancelPriceChange(user)
    await waitFor(() => expect(screen.queryByText('确认价格变更')).not.toBeInTheDocument())
    expect(createPrice).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('dialog', { name: '模型1 · 定价配置' })).toBeInTheDocument()
  })

  it('重读当前价失败：提示刷新页面，不重发', async () => {
    const user = userEvent.setup()
    reread = 'fail'
    const error = vi.spyOn(message, 'error')
    createPrice.mockRejectedValueOnce(conflict())
    renderTable(makeModels(1), [directPrice('m1', zero)])
    await user.click(screen.getByRole('button', { name: '保存 m1 定价' }))
    await waitFor(() => expect(error).toHaveBeenCalledWith('无法读取当前价格，请刷新页面后重试'))
    expect(createPrice).toHaveBeenCalledTimes(1)
    expect(screen.queryByText('确认价格变更')).not.toBeInTheDocument()
  })

  it('重读后发现并不是清零（状态已变）：提示原因并刷新，不重发', async () => {
    const user = userEvent.setup()
    effective.m1 = [{ ...directPrice('m1', zero), customer_group: 'default' }]
    const error = vi.spyOn(message, 'error')
    createPrice.mockRejectedValueOnce(conflict())
    const onRefresh = renderTable(makeModels(1), [directPrice('m1', zero)])
    await user.click(screen.getByRole('button', { name: '保存 m1 定价' }))
    await waitFor(() => expect(error).toHaveBeenCalledWith('这次提交会把非零价格改成 0（免费），请在确认框中明确勾选确认后再提交'))
    expect(createPrice).toHaveBeenCalledTimes(1)
    expect(onRefresh).toHaveBeenCalled()
    expect(screen.queryByText('确认价格变更')).not.toBeInTheDocument()
  })
})

describe('批量套价遇到 409', () => {
  const INPUT = '输入单价（元/百万 Token）'
  const OUTPUT = '输出单价（元/百万 Token）'
  async function applyZeroBatch(user: ReturnType<typeof userEvent.setup>, count: number) {
    await user.click(screen.getByRole('checkbox', { name: '选择当前结果' }))
    await user.click(screen.getByRole('button', { name: '批量套价' }))
    const dialog = await screen.findByRole('dialog', { name: '批量套价' })
    await user.type(within(dialog).getByRole('spinbutton', { name: INPUT }), '0')
    await user.type(within(dialog).getByRole('spinbutton', { name: OUTPUT }), '0')
    await user.click(within(dialog).getByRole('button', { name: `应用到 ${count} 个模型` }))
    // 三个模型在前端看来都是「新增价格」，先过一遍普通确认
    await confirmPriceChange(user)
  }
  // m1 的价格被历史截断挤出了前端列表（前端认为未配置），后端其实有非零价格
  const serverRejectsM1 = () => createPrice.mockImplementation((async (payload: Record<string, unknown>) => {
    if (payload.model_name === 'm1' && payload.confirm_zero_price !== true) throw conflict()
    return saved
  }) as any)

  it('3 行里只有 1 行被拦：合并成一个确认框只列这一行，确认后只重发它，汇总全部成功', async () => {
    const user = userEvent.setup()
    effective.m1 = [{ ...directPrice('m1'), customer_group: 'default' }]
    serverRejectsM1()
    const onRefresh = renderTable(makeModels(3), [])
    await applyZeroBatch(user, 3)

    const alert = await screen.findByText(/以下 1 个模型的输入、输出价格将被改成 0/)
    const dialog = alert.closest('[role="dialog"]') as HTMLElement
    expect(alert).toHaveTextContent('模型1')
    expect(within(dialog).queryByText('模型2')).not.toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '确认写入 1 个模型' })).toBeDisabled()
    expect(pricesSpy).toHaveBeenCalledWith('tenant-a', { scope: 'effective', model_name: 'm1', limit: 20 })
    expect(pricesSpy).not.toHaveBeenCalledWith('tenant-a', expect.objectContaining({ model_name: 'm2' }))

    await confirmPriceChange(user)
    expect(await screen.findByText('成功 3 个，失败 0 个')).toBeInTheDocument()
    const calls = createPrice.mock.calls.map(([payload]) => payload)
    expect(calls).toHaveLength(4)
    expect(calls.filter(payload => payload.model_name === 'm1').map(payload => payload.confirm_zero_price)).toEqual([undefined, true])
    calls.filter(payload => payload.model_name !== 'm1').forEach(payload => expect(payload).not.toHaveProperty('confirm_zero_price'))
    expect(onRefresh).toHaveBeenCalled()
  })

  it('取消清零确认：该行记为失败（已取消清零确认）并保持选中，其余行成功', async () => {
    const user = userEvent.setup()
    effective.m1 = [{ ...directPrice('m1'), customer_group: 'default' }]
    serverRejectsM1()
    renderTable(makeModels(3), [])
    await applyZeroBatch(user, 3)
    await screen.findByText(/以下 1 个模型的输入、输出价格将被改成 0/)
    await cancelPriceChange(user)

    expect(await screen.findByText('成功 2 个，失败 1 个')).toBeInTheDocument()
    expect(screen.getByText(/已取消清零确认/)).toBeInTheDocument()
    expect(createPrice).toHaveBeenCalledTimes(3)
    await waitFor(() => {
      expect(screen.getByRole('checkbox', { name: '选择 模型1' })).toBeChecked()
      expect(screen.getByRole('checkbox', { name: '选择 模型2' })).not.toBeChecked()
    })
  })

  it('重读当前价失败：该行记为失败，原因是无法读取当前价格，不重发', async () => {
    const user = userEvent.setup()
    reread = 'fail'
    serverRejectsM1()
    renderTable(makeModels(3), [])
    await applyZeroBatch(user, 3)

    expect(await screen.findByText('成功 2 个，失败 1 个')).toBeInTheDocument()
    expect(screen.getByText(/无法读取当前价格，请刷新页面后重试/)).toBeInTheDocument()
    expect(createPrice).toHaveBeenCalledTimes(3)
    expect(screen.queryByText('确认价格变更')).not.toBeInTheDocument()
  })
})

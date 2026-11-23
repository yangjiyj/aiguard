import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest'
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { message } from 'antd'
import ModelPricingTable from '../components/billing/ModelPricingTable'
import { directPricePayload, type BillingModel, type BillingPrice } from '../components/billing/modelPricing'
import { billingAdminApi, apiClient } from '../services/api'
import { extractApiError } from '../utils/apiError'
import { cancelPriceChange, confirmPriceChange, findPriceChangeDialog, queryPriceChangeDialog } from './priceChangeTestUtils'

// directPricePayload 默认透传真实实现，个别用例让它对某个模型抛异常。
vi.mock('../components/billing/modelPricing', async importOriginal => {
  const actual = await importOriginal<typeof import('../components/billing/modelPricing')>()
  return { ...actual, directPricePayload: vi.fn(actual.directPricePayload) }
})

const realDirectPricePayload = (await vi.importActual<typeof import('../components/billing/modelPricing')>('../components/billing/modelPricing')).directPricePayload

const makeModels = (count: number): BillingModel[] => Array.from({ length: count }, (_, index) => ({
  model_name: `m${index + 1}`, model_label: `模型${index + 1}`, provider_name: '供应商', status: 'active',
}))
const directPrice = (name: string, patch: Partial<BillingPrice> = {}): BillingPrice => ({
  id: `${name}-v1`, model_name: name, version: 1, pricing_mode: 'direct', currency: 'CNY', status: 'active',
  effective_at: '2026-08-01T00:00:00Z', input_per_million_micros: 4_000_000, output_per_million_micros: 8_000_000,
  has_cached_input_price: false, has_cache_write_price: false, ...patch,
})
const ratioPrice = (name: string, patch: Partial<BillingPrice> = {}): BillingPrice => ({
  id: `${name}-r1`, model_name: name, version: 1, pricing_mode: 'newapi_ratio', currency: 'CNY', status: 'active',
  effective_at: '2026-08-01T00:00:00Z', input_per_million_micros: 0, output_per_million_micros: 0,
  base_input_per_million_micros: 2_000_000, model_ratio_ppm: 1_000_000, completion_ratio_ppm: 4_000_000, ...patch,
})

const INPUT = '输入单价（元/百万 Token）'
const OUTPUT = '输出单价（元/百万 Token）'

let createPrice: MockInstance<typeof billingAdminApi.createPrice>
let createRatioPrice: MockInstance<typeof billingAdminApi.createRatioPrice>

beforeEach(() => {
  vi.mocked(directPricePayload).mockImplementation(realDirectPricePayload)
  createPrice = vi.spyOn(billingAdminApi, 'createPrice').mockResolvedValue({ data: { data: { unchanged: false } } } as any)
  createRatioPrice = vi.spyOn(billingAdminApi, 'createRatioPrice').mockResolvedValue({ data: { data: { unchanged: false } } } as any)
  vi.spyOn(apiClient, 'get').mockResolvedValue({ data: { data: { image_models: [], tools: [], recognized_model: false, suggested_template_id: '' } } } as any)
})

afterEach(() => {
  act(() => message.destroy())
  cleanup()
  vi.restoreAllMocks()
  document.body.innerHTML = ''
})

function renderTable(models: BillingModel[], prices: BillingPrice[]) {
  return render(<ModelPricingTable tenantID="tenant-a" models={models} prices={prices} loading={false} onRefresh={vi.fn()} />)
}

async function openBatch(user: ReturnType<typeof userEvent.setup>, count: number) {
  await user.click(screen.getByRole('checkbox', { name: '选择当前结果' }))
  await user.click(screen.getByRole('button', { name: '批量套价' }))
  const dialog = await screen.findByRole('dialog', { name: '批量套价' })
  return { dialog, apply: within(dialog).getByRole('button', { name: `应用到 ${count} 个模型` }) }
}
const spin = (dialog: HTMLElement, name: string) => within(dialog).getByRole('spinbutton', { name })
const confirmDialog = findPriceChangeDialog
const noConfirmDialog = () => expect(queryPriceChangeDialog()).not.toBeInTheDocument()

describe('批量套价：清零根因固化（输入框把空白/空值变成 0）', () => {
  const models = makeModels(7)
  const prices = models.map(model => directPrice(model.model_name))

  it('(a) 只敲一个空格：被必填规则拦住，不弹确认、不发请求', async () => {
    const user = userEvent.setup()
    renderTable(models, prices)
    const { dialog, apply } = await openBatch(user, 7)
    await user.type(spin(dialog, INPUT), ' ')
    await user.type(spin(dialog, OUTPUT), '8')
    await user.click(apply)
    expect(await within(dialog).findByText('请输入输入单价')).toBeInTheDocument()
    noConfirmDialog()
    expect(createPrice).not.toHaveBeenCalled()
  })

  it('(b) 在已有数字上全选后粘贴空白文本：值不会变成 0', async () => {
    const user = userEvent.setup()
    renderTable(models, prices)
    const { dialog, apply } = await openBatch(user, 7)
    const input = spin(dialog, INPUT)
    await user.type(input, '3')
    await user.keyboard('{Control>}a{/Control}')
    await user.paste('   ')
    await user.type(spin(dialog, OUTPUT), '8')
    await user.click(apply)
    expect(await within(dialog).findByText('请输入输入单价')).toBeInTheDocument()
    expect(input).toHaveValue('')
    noConfirmDialog()
    expect(createPrice).not.toHaveBeenCalled()
  })

  it('(c) 空框按方向键下再应用：弹出确认，7 行「改成 0」，红色提示点名模型，勾选前确认按钮禁用，取消后 0 个请求', async () => {
    const user = userEvent.setup()
    renderTable(models, prices)
    const { dialog, apply } = await openBatch(user, 7)
    for (const name of [INPUT, OUTPUT]) {
      await user.click(spin(dialog, name))
      await user.keyboard('{ArrowDown}')
      expect(spin(dialog, name)).toHaveValue('0.00')
    }
    await user.click(apply)

    const confirm = await confirmDialog()
    expect(within(confirm).getAllByText('改成 0')).toHaveLength(7)
    const alert = within(confirm).getByRole('alert')
    expect(alert).toHaveTextContent('以下 7 个模型的输入、输出价格将被改成 0，相当于免费')
    models.forEach(model => expect(alert).toHaveTextContent(`模型${model.model_name.slice(1)}`))
    const ok = within(confirm).getByRole('button', { name: '确认写入 7 个模型' })
    expect(ok).toBeDisabled()

    await cancelPriceChange(user)
    await waitFor(noConfirmDialog)
    expect(createPrice).not.toHaveBeenCalled()
    // 批量弹窗保持打开，表单值保留
    expect(screen.getByRole('dialog', { name: '批量套价' })).toBeInTheDocument()
    expect(spin(dialog, INPUT)).toHaveValue('0.00')

    await user.click(apply)
    await confirmPriceChange(user)
    await waitFor(() => expect(createPrice).toHaveBeenCalledTimes(7))
    createPrice.mock.calls.forEach(([payload]) => expect(payload).toMatchObject({ input_per_million_micros: 0, output_per_million_micros: 0, confirm_zero_price: true }))
    expect(await screen.findByText('成功 7 个，失败 0 个')).toBeInTheDocument()
  })

  it('(d) 手工输入 0/0：同样先确认，勾选前不能提交', async () => {
    const user = userEvent.setup()
    renderTable(models, prices)
    const { dialog, apply } = await openBatch(user, 7)
    await user.type(spin(dialog, INPUT), '0')
    await user.type(spin(dialog, OUTPUT), '0')
    await user.click(apply)
    const confirm = await confirmDialog()
    expect(within(confirm).getByRole('button', { name: '确认写入 7 个模型' })).toBeDisabled()
    await user.click(within(confirm).getByRole('checkbox', { name: '我已核对，确认把以上模型的价格改成 0' }))
    expect(within(confirm).getByRole('button', { name: '确认写入 7 个模型' })).toBeEnabled()
    await user.click(within(confirm).getByRole('button', { name: '确认写入 7 个模型' }))
    await waitFor(() => expect(createPrice).toHaveBeenCalledTimes(7))
    createPrice.mock.calls.forEach(([payload]) => expect(payload.confirm_zero_price).toBe(true))
  })
})

describe('批量套价：确认弹窗内容与请求范围', () => {
  it('展示「旧值 → 新值」，无变化的行不写入', async () => {
    const user = userEvent.setup()
    const models = makeModels(2)
    renderTable(models, [directPrice('m1'), directPrice('m2', { input_per_million_micros: 2_000_000 })])
    const { dialog, apply } = await openBatch(user, 2)
    await user.type(spin(dialog, INPUT), '2')
    await user.type(spin(dialog, OUTPUT), '8')
    await user.click(apply)

    const confirm = await confirmDialog()
    expect(within(confirm).queryByRole('alert')).not.toBeInTheDocument()
    expect(within(confirm).queryByRole('checkbox')).not.toBeInTheDocument()
    const changedRow = within(confirm).getByText('模型1').closest('tr') as HTMLElement
    expect(within(changedRow).getByText('¥4.000')).toBeInTheDocument()
    expect(within(changedRow).getByText('¥2.000')).toBeInTheDocument()
    expect(within(changedRow).getByText('调整')).toBeInTheDocument()
    const sameRow = within(confirm).getByText('模型2').closest('tr') as HTMLElement
    expect(within(sameRow).getByText('无变化')).toBeInTheDocument()
    expect(within(confirm).getByRole('button', { name: '确认写入 1 个模型' })).toBeEnabled()

    await confirmPriceChange(user)
    await waitFor(() => expect(createPrice).toHaveBeenCalledTimes(1))
    expect(createPrice.mock.calls[0][0]).toMatchObject({ model_name: 'm1', input_per_million_micros: 2_000_000 })
    expect(createPrice.mock.calls[0][0]).not.toHaveProperty('confirm_zero_price')
  })

  it('全部无变化时不弹确认也不发请求', async () => {
    const user = userEvent.setup()
    renderTable(makeModels(2), [directPrice('m1'), directPrice('m2')])
    const { dialog, apply } = await openBatch(user, 2)
    await user.type(spin(dialog, INPUT), '4')
    await user.type(spin(dialog, OUTPUT), '8')
    await user.click(apply)
    await waitFor(() => expect(screen.getByText('所选模型的价格都没有变化，未新增版本')).toBeInTheDocument())
    noConfirmDialog()
    expect(createPrice).not.toHaveBeenCalled()
  })

  it('混合场景：1 个改成 0、1 个调整、1 个无变化，只发 2 个请求，只有改成 0 的带标志', async () => {
    const user = userEvent.setup()
    renderTable(makeModels(3), [
      directPrice('m1'),
      directPrice('m2', { input_per_million_micros: 0, output_per_million_micros: 0, has_cached_input_price: true, cached_input_per_million_micros: 0 }),
      directPrice('m3', { input_per_million_micros: 0, output_per_million_micros: 0 }),
    ])
    const { dialog, apply } = await openBatch(user, 3)
    await user.type(spin(dialog, INPUT), '0')
    await user.type(spin(dialog, OUTPUT), '0')
    await user.click(apply)
    const confirm = await confirmDialog()
    expect(within(within(confirm).getByText('模型1').closest('tr') as HTMLElement).getByText('改成 0')).toBeInTheDocument()
    expect(within(within(confirm).getByText('模型2').closest('tr') as HTMLElement).getByText('调整')).toBeInTheDocument()
    expect(within(within(confirm).getByText('模型3').closest('tr') as HTMLElement).getByText('无变化')).toBeInTheDocument()
    expect(within(confirm).getByRole('alert')).toHaveTextContent('以下 1 个模型')
    expect(within(confirm).getByRole('alert')).not.toHaveTextContent('模型2')
    await confirmPriceChange(user)
    await waitFor(() => expect(createPrice).toHaveBeenCalledTimes(2))
    const byModel = Object.fromEntries(createPrice.mock.calls.map(([payload]) => [payload.model_name, payload]))
    expect(byModel.m1.confirm_zero_price).toBe(true)
    expect(byModel.m2).not.toHaveProperty('confirm_zero_price')
    expect(byModel.m3).toBeUndefined()
  })

  it('倍率行的直接价字段为 0，不会被误判为「改成 0」', async () => {
    const user = userEvent.setup()
    renderTable(makeModels(1), [ratioPrice('m1')])
    const { dialog, apply } = await openBatch(user, 1)
    await user.type(spin(dialog, INPUT), '3')
    await user.type(spin(dialog, OUTPUT), '6')
    await user.click(apply)
    const confirm = await confirmDialog()
    expect(within(confirm).queryByRole('alert')).not.toBeInTheDocument()
    expect(within(confirm).queryByRole('checkbox')).not.toBeInTheDocument()
    expect(within(confirm).getByText('调整')).toBeInTheDocument()
    expect(within(confirm).getAllByText('基础 ¥2.000 × 模型 1.000 × 输出 4.000').length).toBeGreaterThan(0)
    await confirmPriceChange(user)
    await waitFor(() => expect(createPrice).toHaveBeenCalledTimes(1))
    expect(createPrice.mock.calls[0][0]).not.toHaveProperty('confirm_zero_price')
  })

  it('倍率模式基础价为 0：走倍率接口并带 confirm_zero_price', async () => {
    const user = userEvent.setup()
    renderTable(makeModels(1), [ratioPrice('m1')])
    await user.click(screen.getByRole('checkbox', { name: '选择当前结果' }))
    await user.click(screen.getByRole('button', { name: '批量套价' }))
    const dialog = await screen.findByRole('dialog', { name: '批量套价' })
    await user.click(within(dialog).getByText('倍率'))
    await user.type(spin(dialog, '基础输入单价（元/百万 Token）'), '0')
    await user.click(within(dialog).getByRole('button', { name: '应用到 1 个模型' }))
    const confirm = await confirmDialog()
    expect(within(confirm).getByText('改成 0')).toBeInTheDocument()
    await confirmPriceChange(user)
    await waitFor(() => expect(createRatioPrice).toHaveBeenCalledTimes(1))
    expect(createRatioPrice.mock.calls[0][0]).toMatchObject({ model_name: 'm1', base_input_per_million_micros: 0, confirm_zero_price: true })
    expect(createPrice).not.toHaveBeenCalled()
  })
})

describe('批量套价：当前版本带失效时间', () => {
  it('提交不带失效时间会取消它：判为调整并在提示列写明「取消失效时间」，仍会写入', async () => {
    const user = userEvent.setup()
    renderTable(makeModels(2), [
      directPrice('m1', { expires_at: '2099-11-01T00:00:00Z' }),
      directPrice('m2'),
    ])
    const { dialog, apply } = await openBatch(user, 2)
    await user.type(spin(dialog, INPUT), '4')
    await user.type(spin(dialog, OUTPUT), '8')
    await user.click(apply)

    const confirm = await confirmDialog()
    const changedRow = within(confirm).getByText('模型1').closest('tr') as HTMLElement
    expect(within(changedRow).getByText('调整')).toBeInTheDocument()
    expect(within(changedRow).getByText('取消失效时间')).toBeInTheDocument()
    expect(within(changedRow).getByText(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}/)).toBeInTheDocument()
    const sameRow = within(confirm).getByText('模型2').closest('tr') as HTMLElement
    expect(within(sameRow).getByText('无变化')).toBeInTheDocument()
    expect(within(sameRow).queryByText('取消失效时间')).not.toBeInTheDocument()
    expect(within(confirm).getByRole('button', { name: '确认写入 1 个模型' })).toBeEnabled()

    await confirmPriceChange(user)
    await waitFor(() => expect(createPrice).toHaveBeenCalledTimes(1))
    expect(createPrice.mock.calls[0][0]).toMatchObject({ model_name: 'm1', input_per_million_micros: 4_000_000 })
  })
})

describe('批量套价：payload 构造异常与失败汇总', () => {
  it('某行构造 payload 抛异常：该行记为失败，其余照常写入，弹窗不卡死', async () => {
    const user = userEvent.setup()
    vi.mocked(directPricePayload).mockImplementation((tenant, name, draft) => {
      if (name === 'm2') throw new Error('输入单价必须是非负数')
      return realDirectPricePayload(tenant, name, draft)
    })
    renderTable(makeModels(3), makeModels(3).map(model => directPrice(model.model_name)))
    const { dialog, apply } = await openBatch(user, 3)
    await user.type(spin(dialog, INPUT), '2')
    await user.type(spin(dialog, OUTPUT), '8')
    await user.click(apply)
    await confirmPriceChange(user)

    expect(await screen.findByText('成功 2 个，失败 1 个')).toBeInTheDocument()
    expect(screen.getByText(/输入单价必须是非负数/)).toBeInTheDocument()
    expect(createPrice.mock.calls.map(([payload]) => payload.model_name).sort()).toEqual(['m1', 'm3'])
    await waitFor(() => {
      expect(screen.getByRole('checkbox', { name: '选择 模型2' })).toBeChecked()
      expect(screen.getByRole('checkbox', { name: '选择 模型1' })).not.toBeChecked()
    })
    // batchSaving 已复位：重新打开后确认按钮可点击、没有加载态
    await user.click(screen.getByRole('button', { name: '批量套价' }))
    const again = (await screen.findByText('应用到 1 个模型')).closest('button') as HTMLButtonElement
    expect(again).toBeEnabled()
    expect(again.className).not.toMatch(/loading/)
  })

  it('全部行都构造失败：不弹确认、不发请求，直接汇总失败', async () => {
    const user = userEvent.setup()
    vi.mocked(directPricePayload).mockImplementation(() => { throw new Error('输入单价必须是非负数') })
    renderTable(makeModels(2), makeModels(2).map(model => directPrice(model.model_name)))
    const { dialog, apply } = await openBatch(user, 2)
    await user.type(spin(dialog, INPUT), '2')
    await user.type(spin(dialog, OUTPUT), '8')
    await user.click(apply)
    expect(await screen.findByText('成功 0 个，失败 2 个')).toBeInTheDocument()
    noConfirmDialog()
    expect(createPrice).not.toHaveBeenCalled()
  })
})

describe('高级编辑器保存', () => {
  const extras = { image_pricing: { mode: 'token' as const } }
  const editorPrice = (patch: Partial<BillingPrice> = {}) => directPrice('m1', { pricing_extras: extras, ...patch })
  const editorInput = (dialog: HTMLElement, name: string) => within(dialog).getByRole('spinbutton', { name })
  async function openEditor(user: ReturnType<typeof userEvent.setup>) {
    await user.click(screen.getByRole('button', { name: 'm1 图片与工具计费' }))
    return screen.findByRole('dialog', { name: '模型1 · 定价配置' })
  }

  it('有变化：先弹确认，确认后才发请求', async () => {
    const user = userEvent.setup()
    renderTable(makeModels(1), [editorPrice()])
    const editor = await openEditor(user)
    const input = editorInput(editor, '文本输入（元/百万 Token）')
    await user.clear(input)
    await user.type(input, '2')
    await user.click(within(editor).getByRole('button', { name: '保存收费配置' }))
    const confirm = await confirmDialog()
    expect(within(confirm).getByText('¥4.000')).toBeInTheDocument()
    expect(within(confirm).getByText('¥2.000')).toBeInTheDocument()
    expect(createPrice).not.toHaveBeenCalled()
    await confirmPriceChange(user)
    await waitFor(() => expect(createPrice).toHaveBeenCalledTimes(1))
    expect(createPrice.mock.calls[0][0]).toMatchObject({ model_name: 'm1', input_per_million_micros: 2_000_000 })
    expect(createPrice.mock.calls[0][0]).not.toHaveProperty('confirm_zero_price')
  })

  it('取消：不发请求，编辑器保持打开', async () => {
    const user = userEvent.setup()
    renderTable(makeModels(1), [editorPrice()])
    const editor = await openEditor(user)
    const input = editorInput(editor, '文本输入（元/百万 Token）')
    await user.clear(input)
    await user.type(input, '2')
    await user.click(within(editor).getByRole('button', { name: '保存收费配置' }))
    await confirmDialog()
    await cancelPriceChange(user)
    await waitFor(noConfirmDialog)
    expect(createPrice).not.toHaveBeenCalled()
    expect(screen.getByRole('dialog', { name: '模型1 · 定价配置' })).toBeInTheDocument()
  })

  it('改成 0/0：确认弹窗要求勾选，确认后请求带 confirm_zero_price', async () => {
    const user = userEvent.setup()
    renderTable(makeModels(1), [editorPrice()])
    const editor = await openEditor(user)
    for (const name of ['文本输入（元/百万 Token）', '普通输出（元/百万 Token）']) {
      const input = editorInput(editor, name)
      await user.clear(input)
      await user.type(input, '0')
    }
    await user.click(within(editor).getByRole('button', { name: '保存收费配置' }))
    const confirm = await confirmDialog()
    expect(within(confirm).getByText('改成 0')).toBeInTheDocument()
    expect(within(confirm).getByRole('button', { name: '确认写入 1 个模型' })).toBeDisabled()
    await confirmPriceChange(user)
    await waitFor(() => expect(createPrice).toHaveBeenCalledTimes(1))
    expect(createPrice.mock.calls[0][0]).toMatchObject({ input_per_million_micros: 0, output_per_million_micros: 0, confirm_zero_price: true })
  })

  it('无变化：直接发请求；后端返回 unchanged 时提示未新增版本', async () => {
    const user = userEvent.setup()
    createPrice.mockResolvedValue({ data: { data: { id: 'm1-v1', version: 1, unchanged: true } } } as any)
    renderTable(makeModels(1), [editorPrice()])
    const editor = await openEditor(user)
    await user.click(within(editor).getByRole('button', { name: '保存收费配置' }))
    await waitFor(() => expect(createPrice).toHaveBeenCalledTimes(1))
    noConfirmDialog()
    expect(createPrice.mock.calls[0][0]).not.toHaveProperty('confirm_zero_price')
    expect(await screen.findByText('模型1 价格没有变化，未新增版本')).toBeInTheDocument()
  })
})

describe('行内保存与响应处理', () => {
  it('行内保存重新保存当前价格：不弹确认，直接发请求；真正新增版本时提示已保存', async () => {
    const user = userEvent.setup()
    renderTable(makeModels(1), [directPrice('m1')])
    await user.click(screen.getByRole('button', { name: '保存 m1 定价' }))
    await waitFor(() => expect(createPrice).toHaveBeenCalledTimes(1))
    noConfirmDialog()
    expect(createPrice.mock.calls[0][0]).not.toHaveProperty('confirm_zero_price')
    expect(await screen.findByText('模型1 定价已保存')).toBeInTheDocument()
  })

  it('响应 unchanged: true：提示价格没有变化，未新增版本', async () => {
    const user = userEvent.setup()
    createPrice.mockResolvedValue({ data: { data: { id: 'm1-v1', version: 1, unchanged: true } } } as any)
    renderTable(makeModels(1), [directPrice('m1')])
    await user.click(screen.getByRole('button', { name: '保存 m1 定价' }))
    expect(await screen.findByText('模型1 价格没有变化，未新增版本')).toBeInTheDocument()
    expect(screen.queryByText('模型1 定价已保存')).not.toBeInTheDocument()
  })

  it('后端 409 price_zero_confirmation_required 映射为中文提示', () => {
    const error = { response: { data: { error: { code: 'price_zero_confirmation_required', message: 'x' } } } }
    expect(extractApiError(error)).toBe('这次提交会把非零价格改成 0（免费），请在确认框中明确勾选确认后再提交')
  })
})

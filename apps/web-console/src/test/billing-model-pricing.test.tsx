import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import ModelPricingTable from '../components/billing/ModelPricingTable'
import {
  buildPricingRows,
  directPricePayload,
  ratioPricePayload,
  type BillingModel,
  type BillingPrice,
} from '../components/billing/modelPricing'
import * as api from '../services/api'
import { confirmPriceChange } from './priceChangeTestUtils'

const past = '2026-08-01T00:00:00Z'
const models: BillingModel[] = [
  { model_name: 'free-model', model_label: '免费模型', provider_name: '供应商甲', status: 'active' },
  { model_name: 'paid-model', model_label: '付费模型', provider_name: '供应商甲', status: 'active' },
  { model_name: 'unset-model', model_label: '待定价模型', provider_name: '供应商乙', status: 'active' },
]
const prices: BillingPrice[] = [
  {
    id: 'free-v1', model_name: 'free-model', version: 1, pricing_mode: 'direct',
    currency: 'CNY', status: 'active', effective_at: past,
    input_per_million_micros: 0, output_per_million_micros: 0,
    has_cached_input_price: false, has_cache_write_price: false,
  },
  {
    id: 'paid-v1', model_name: 'paid-model', version: 1, pricing_mode: 'direct',
    currency: 'CNY', status: 'active', effective_at: past,
    input_per_million_micros: 1_000_000, output_per_million_micros: 2_000_000,
    has_cached_input_price: false, has_cache_write_price: false,
  },
]

describe('model pricing matrix', () => {
  beforeEach(() => {
    vi.spyOn(api.billingAdminApi, 'createPrice').mockResolvedValue({ data: { data: {} } } as any)
    vi.spyOn(api.billingAdminApi, 'createRatioPrice').mockResolvedValue({ data: { data: {} } } as any)
  })

  afterEach(() => {
    vi.restoreAllMocks()
    cleanup()
    document.body.innerHTML = ''
  })

  it('builds one row for every model and treats an explicit zero price as configured', () => {
    const rows = buildPricingRows(models, prices, new Date('2026-08-17T00:00:00Z'))
    expect(rows.map((row) => [row.modelName, row.configured])).toEqual([
      ['free-model', true],
      ['paid-model', true],
      ['unset-model', false],
    ])
    expect(rows[0].current?.id).toBe('free-v1')
    expect(rows[2].current).toBeNull()
  })

  it('ignores draft, retired, future, and expired versions and picks the valid version by effective time then version', () => {
    const history: BillingPrice[] = [
      { id: 'draft', model_name: 'paid-model', version: 9, pricing_mode: 'direct', currency: 'CNY', status: 'draft', effective_at: '2026-08-10T00:00:00Z' },
      { id: 'retired', model_name: 'paid-model', version: 8, pricing_mode: 'direct', currency: 'CNY', status: 'retired', effective_at: '2026-08-11T00:00:00Z' },
      { id: 'future', model_name: 'paid-model', version: 7, pricing_mode: 'direct', currency: 'CNY', status: 'active', effective_at: '2026-08-18T00:00:00Z' },
      { id: 'expired', model_name: 'paid-model', version: 6, pricing_mode: 'direct', currency: 'CNY', status: 'active', effective_at: '2026-08-12T00:00:00Z', expires_at: '2026-08-16T00:00:00Z' },
      { id: 'valid-older', model_name: 'paid-model', version: 10, pricing_mode: 'direct', currency: 'CNY', status: 'active', effective_at: '2026-08-14T00:00:00Z' },
      { id: 'valid-same-time-v1', model_name: 'paid-model', version: 1, pricing_mode: 'direct', currency: 'CNY', status: 'active', effective_at: '2026-08-15T00:00:00Z' },
      { id: 'valid-same-time-v2', model_name: 'paid-model', version: 2, pricing_mode: 'direct', currency: 'CNY', status: 'active', effective_at: '2026-08-15T00:00:00Z' },
    ]

    const [row] = buildPricingRows([models[1]], history, new Date('2026-08-17T00:00:00Z'))
    expect(row.current?.id).toBe('valid-same-time-v2')
    expect(row.configured).toBe(true)
  })

  it('distinguishes models never configured from models with no currently effective version', () => {
    const futurePrice: BillingPrice = {
      id: 'future-only', model_name: 'paid-model', version: 1, pricing_mode: 'direct',
      currency: 'CNY', status: 'active', effective_at: '2026-08-18T00:00:00Z',
    }
    const rows = buildPricingRows([models[1], models[2]], [futurePrice], new Date('2026-08-17T00:00:00Z'))

    expect(rows[0]).toMatchObject({ configured: true, current: null })
    expect(rows[0].history).toHaveLength(1)
    expect(rows[1]).toMatchObject({ configured: false, current: null, history: [] })
  })

  it('shows 未配置 only without history and 当前未生效 when history exists without a current version', () => {
    const futurePrice: BillingPrice = {
      id: 'future-only', model_name: 'paid-model', version: 1, pricing_mode: 'direct',
      currency: 'CNY', status: 'active', effective_at: '2099-08-18T00:00:00Z',
    }
    render(<ModelPricingTable tenantID="tenant-a" models={[models[1], models[2]]} prices={[futurePrice]} loading={false} onRefresh={vi.fn()} />)

    expect(screen.getByText('当前未生效')).toBeInTheDocument()
    expect(screen.getByText('未配置')).toBeInTheDocument()
  })

  it('builds immutable tenant/model payloads for direct and ratio pricing', () => {
    expect(directPricePayload('tenant-a', 'free-model', {
      inputPerMillionYuan: 0,
      outputPerMillionYuan: 0,
      cachedInputPerMillionYuan: null,
      cacheWritePerMillionYuan: null,
    })).toMatchObject({
      tenant_id: 'tenant-a', model_name: 'free-model',
      input_per_million_micros: 0, output_per_million_micros: 0,
    })
    expect(ratioPricePayload('tenant-a', 'paid-model', {
      baseInputPerMillionYuan: 1,
      modelRatio: 0.5,
      completionRatio: 2,
      cachedInputRatio: null,
      cacheWriteRatio: null,
    })).toMatchObject({
      tenant_id: 'tenant-a', model_name: 'paid-model',
      base_input_per_million_micros: 1_000_000,
      model_ratio_ppm: 500_000,
      completion_ratio_ppm: 2_000_000,
    })
  })

  it('shows all models, supports search and filters only unconfigured models', async () => {
    const user = userEvent.setup()
    render(<ModelPricingTable tenantID="tenant-a" models={models} prices={prices} loading={false} onRefresh={vi.fn()} />)

    expect(screen.getByText('免费模型')).toBeInTheDocument()
    expect(screen.getByText('付费模型')).toBeInTheDocument()
    expect(screen.getByText('待定价模型')).toBeInTheDocument()
    expect(screen.getAllByText('已配置')).toHaveLength(2)
    expect(screen.getByText('未配置')).toBeInTheDocument()

    await user.type(screen.getByPlaceholderText('搜索模型或供应商'), '待定价')
    expect(screen.queryByText('免费模型')).not.toBeInTheDocument()
    expect(screen.getByText('待定价模型')).toBeInTheDocument()
    await user.clear(screen.getByPlaceholderText('搜索模型或供应商'))
    await user.click(screen.getByRole('checkbox', { name: '只看未配置' }))
    expect(screen.queryByText('付费模型')).not.toBeInTheDocument()
    expect(screen.getByText('待定价模型')).toBeInTheDocument()
  })

  it('saves one row with its catalog model name and exposes only that model history', async () => {
    const user = userEvent.setup()
    const onRefresh = vi.fn()
    render(<ModelPricingTable tenantID="tenant-a" models={models} prices={prices} loading={false} onRefresh={onRefresh} />)

    await user.click(screen.getByRole('button', { name: '保存 free-model 定价' }))
    await waitFor(() => expect(api.billingAdminApi.createPrice).toHaveBeenCalledWith(expect.objectContaining({
      tenant_id: 'tenant-a', model_name: 'free-model',
      input_per_million_micros: 0, output_per_million_micros: 0,
    })))
    expect(screen.queryByRole('textbox', { name: '模型名' })).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '查看 free-model 历史' }))
    const drawer = await screen.findByRole('dialog', { name: 'free-model 定价历史' })
    expect(within(drawer).getByText('v1')).toBeInTheDocument()
    expect(within(drawer).queryByText('paid-model')).not.toBeInTheDocument()
  })

  it('opens one model history without showing another model versions', async () => {
    const user = userEvent.setup()
    render(<ModelPricingTable tenantID="tenant-a" models={models} prices={prices} loading={false} onRefresh={vi.fn()} />)

    await user.click(screen.getByRole('button', { name: '查看 free-model 历史' }))
    const dialog = await screen.findByRole('dialog', { name: 'free-model 定价历史' })
    expect(within(dialog).getByText('v1')).toBeInTheDocument()
    expect(within(dialog).queryByText('paid-model')).not.toBeInTheDocument()
  })

  it('keeps failed rows selected when a batch save partially fails', async () => {
    const user = userEvent.setup()
    vi.mocked(api.billingAdminApi.createPrice).mockImplementation(async (payload: Record<string, unknown>) => {
      if (payload.model_name === 'unset-model') throw new Error('fixture failure')
      return { data: { data: {} } } as any
    })
    render(<ModelPricingTable tenantID="tenant-a" models={models} prices={prices} loading={false} onRefresh={vi.fn()} />)

    await user.click(screen.getByRole('checkbox', { name: '选择 '+ models[1].model_label }))
    await user.click(screen.getByRole('checkbox', { name: '选择 '+ models[2].model_label }))
    await user.click(screen.getByRole('button', { name: '批量套价' }))

    const dialog = await screen.findByRole('dialog', { name: '批量套价' })
    await user.type(within(dialog).getByRole('spinbutton', { name: '输入单价（元/百万 Token）' }), '3')
    await user.type(within(dialog).getByRole('spinbutton', { name: '输出单价（元/百万 Token）' }), '6')
    await user.click(within(dialog).getByRole('button', { name: '应用到 2 个模型' }))
    // 批量套价现在先展示价格变更确认，确认后才真正写入
    await confirmPriceChange(user)

    expect(await screen.findByText('成功 1 个，失败 1 个')).toBeInTheDocument()
    expect(screen.getAllByText(models[2].model_label!)).not.toHaveLength(0)
    await waitFor(() => {
      expect(screen.getByRole('checkbox', { name: '选择 '+ models[2].model_label })).toBeChecked()
      expect(screen.getByRole('checkbox', { name: '选择 '+ models[1].model_label })).not.toBeChecked()
    })
  })
})

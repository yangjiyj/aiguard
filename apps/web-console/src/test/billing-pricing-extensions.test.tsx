import pricingEditorSource from '../components/billing/ModelPricingEditor.tsx?raw'
import { literal } from './billingSourceLabels'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { message } from 'antd'
import ModelPricingTable from '../components/billing/ModelPricingTable'
import { billingAdminApi, apiClient } from '../services/api'
import type { BillingPrice } from '../components/billing/modelPricing'
import { toolPricingOptionsWithExisting } from '../components/billing/toolPricingCatalog'
import { confirmPriceChange } from './priceChangeTestUtils'

const migrationWarning = literal(pricingEditorSource, /initial\.kind === 'legacy'[^\n]*message="([^"]+)"/)

const model = { model_name: 'image-model', model_label: '图片模型', provider_name: '供应商', status: 'active' }
const price: BillingPrice = {
  id: 'usd-v1', model_name: model.model_name, version: 1, pricing_mode: 'direct', currency: 'USD', status: 'active',
  effective_at: '2026-08-01T00:00:00Z', input_per_million_micros: 2000000, output_per_million_micros: 8000000,
  pricing_extras: { image_per_image_micros: 40000, tool_prices_per_thousand_micros: { web_search: 10000000 } },
}

const capabilities = {
  image_models: [{ id: 'dall-e-3', model_patterns: ['dall-e-3'], label: 'DALL·E 3：尺寸与质量', mode: 'per_image',
    sizes: ['1024x1024', '1024x1792', '1792x1024'], qualities: ['standard', 'hd'], default_size: '1024x1024', default_quality: 'standard',
    basis: '按图片张数计价', reference: 'https://platform.openai.com/docs/guides/images' }],
  tools: [{ name: 'web_search', label: '联网搜索（OpenAI / Anthropic）', unit: 'per_thousand_calls', support: 'native', evidence: ['响应中的搜索调用'], reference_currency: 'USD', reference_price_per_thousand_micros: 25000000, reference_basis: 'New API 明确匹配的模型参考', reference_url: 'https://github.com/QuantumNous/new-api/blob/reference/common/price.go' }], recognized_model: false, suggested_template_id: '',
}

beforeEach(() => { vi.spyOn(apiClient, 'get').mockResolvedValue({ data: { data: capabilities } } as any) })

afterEach(() => { act(() => message.destroy()); cleanup(); vi.restoreAllMocks(); document.body.innerHTML = '' })

describe('extended model pricing', () => {
  it('preserves USD and all advanced prices when editing token prices', async () => {
    const save = vi.spyOn(billingAdminApi, 'createPrice').mockResolvedValue({ data: {} } as any)
    render(<ModelPricingTable tenantID="tenant-a" models={[model]} prices={[price]} loading={false} onRefresh={vi.fn()} />)
    expect(screen.queryByRole('button', { name: '同步 New API 定价' })).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '保存 image-model 定价' }))
    await waitFor(() => expect(save).toHaveBeenCalledWith(expect.objectContaining({
      currency: 'USD', input_per_million_micros: 2000000, output_per_million_micros: 8000000,
      pricing_extras: price.pricing_extras,
    })))
  })

  it('saves image and actual tool unit prices from the visible configuration form', async () => {
    const save = vi.spyOn(billingAdminApi, 'createPrice').mockResolvedValue({ data: {} } as any)
    render(<ModelPricingTable tenantID="tenant-a" models={[model]} prices={[price]} loading={false} onRefresh={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: 'image-model 图片与工具计费' }))
    const dialog = screen.getByRole('dialog')
    await userEvent.click(within(dialog).getByText('按张生图'))
    await userEvent.click(within(dialog).getByRole('tab', { name: '图片规格 / 价格' }))
    const imageInput = await within(dialog).findByLabelText('图片规格价格')
    await userEvent.clear(imageInput)
    await userEvent.type(imageInput, '0.05')
    await userEvent.click(within(dialog).getByRole('button', { name: '保存收费配置' }))
    await confirmPriceChange(userEvent.setup())
    await waitFor(() => expect(save).toHaveBeenCalledWith(expect.objectContaining({
      currency: 'USD', input_per_million_micros: 2000000,
      pricing_extras: expect.objectContaining({ image_pricing: { mode: 'per_image', variants: [{ size: '*', quality: '*', price_per_image_micros: 50000 }] }, tool_prices_per_thousand_micros: { web_search: 10000000 } }),
    })))
    expect(save.mock.calls[0][0].pricing_extras).not.toHaveProperty('image_per_image_micros')
  })

  it('preserves exact tiny image and request prices when a form is opened and saved without edits', async () => {
    const precise: BillingPrice = { ...price, pricing_extras: {
      image_pricing: { mode: 'per_image', default_size: '1024x1024', default_quality: 'standard', variants: [{ size: '1024x1024', quality: 'standard', price_per_image_micros: 1234 }] },
      request_per_call_micros: 123, tool_prices_per_thousand_micros: { web_search: 12345 },
    } }
    const save = vi.spyOn(billingAdminApi, 'createPrice').mockResolvedValue({ data: {} } as any)
    render(<ModelPricingTable tenantID="tenant-a" models={[model]} prices={[precise]} loading={false} onRefresh={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: 'image-model 图片与工具计费' }))
    const dialog = screen.getByRole('dialog')
    await userEvent.click(within(dialog).getByRole('tab', { name: '图片规格 / 价格' }))
    const imageInput = await within(dialog).findByLabelText('图片规格价格')
    expect(imageInput).toHaveValue('1.23')
    await userEvent.click(within(dialog).getByRole('combobox', { name: '图片价格单位' }))
    await userEvent.click(await screen.findByText('美元/张'))
    expect(imageInput).toHaveValue('0.00')
    await userEvent.click(within(dialog).getByRole('combobox', { name: '图片价格单位' }))
    await userEvent.click(await screen.findByText('美元/1000 张'))
    expect(imageInput).toHaveValue('1.23')
    await userEvent.click(imageInput)
    await userEvent.tab()
    await userEvent.click(within(dialog).getByRole('button', { name: '保存收费配置' }))
    await waitFor(() => expect(save).toHaveBeenCalledWith(expect.objectContaining({ pricing_extras: expect.objectContaining({
      image_pricing: precise.pricing_extras?.image_pricing, request_per_call_micros: 123, tool_prices_per_thousand_micros: { web_search: 12345 },
    }) })))
  })

  it.each([
    { newapi_fixed_quantity: true, request_per_call_micros: 123456, source: 'legacy-fixed' },
    { image_per_image_micros: 1234, request_per_call_micros: 456, source: 'legacy-token-and-image' },
  ])('retains existing fixed and image addon billing unless a new mode is explicitly chosen', async (legacy) => {
    const save = vi.spyOn(billingAdminApi, 'createPrice').mockResolvedValue({ data: {} } as any)
    render(<ModelPricingTable tenantID="tenant-a" models={[model]} prices={[{ ...price, pricing_extras: legacy }]} loading={false} onRefresh={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: 'image-model 图片与工具计费' }))
    const dialog = screen.getByRole('dialog')
    await userEvent.click(within(dialog).getByRole('button', { name: '保存收费配置' }))
    await waitFor(() => expect(save).toHaveBeenCalledWith(expect.objectContaining({
      input_per_million_micros: 2000000, output_per_million_micros: 8000000,
      pricing_extras: expect.objectContaining(legacy),
    })))
    expect(save.mock.calls[0][0].pricing_extras).not.toHaveProperty('image_pricing')
  })

  it('keeps legacy fixed prices for chat when an image mode is explicitly adopted', async () => {
    const save = vi.spyOn(billingAdminApi, 'createPrice').mockResolvedValue({ data: {} } as any)
    render(<ModelPricingTable tenantID="tenant-a" models={[model]} prices={[{ ...price, pricing_extras: { newapi_fixed_quantity: true, request_per_call_micros: 123456, image_per_image_micros: 40000 } }]} loading={false} onRefresh={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: 'image-model 图片与工具计费' }))
    const dialog = screen.getByRole('dialog')
    await userEvent.click(within(dialog).getByText('按张生图'))
    expect(within(dialog).getByText(migrationWarning)).toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('button', { name: '保存收费配置' }))
    await confirmPriceChange(userEvent.setup())
    await waitFor(() => expect(save).toHaveBeenCalledWith(expect.objectContaining({ pricing_extras: expect.objectContaining({
      newapi_fixed_quantity: true, request_per_call_micros: 123456,
      image_pricing: { mode: 'per_image', variants: [{ size: '*', quality: '*', price_per_image_micros: 163456 }] },
    }) })))
  })

  it('offers a sourced tool fee for explicit adoption without changing existing prices automatically', async () => {
    const save = vi.spyOn(billingAdminApi, 'createPrice').mockResolvedValue({ data: {} } as any)
    render(<ModelPricingTable tenantID="tenant-a" models={[model]} prices={[price]} loading={false} onRefresh={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: 'image-model 图片与工具计费' }))
    const dialog = screen.getByRole('dialog')
    await userEvent.click(within(dialog).getByRole('tab', { name: '工具附加费（1）' }))
    expect(await within(dialog).findByText('New API 参考：$25.000')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('工具每千次单价')).toHaveValue('10.00')
    expect(within(dialog).getByRole('link', { name: '查看来源' })).toHaveAttribute('href', capabilities.tools[0].reference_url)
    await userEvent.click(within(dialog).getByRole('button', { name: '采用参考费率' }))
    await userEvent.click(within(dialog).getByRole('button', { name: '保存收费配置' }))
    await confirmPriceChange(userEvent.setup())
    await waitFor(() => expect(save).toHaveBeenCalledWith(expect.objectContaining({ pricing_extras: expect.objectContaining({ tool_prices_per_thousand_micros: { web_search: 25000000 } }) })))
  })

  it('blocks adopting a USD tool reference into a CNY price without exchange conversion', async () => {
    render(<ModelPricingTable tenantID="tenant-a" models={[model]} prices={[{ ...price, currency: 'CNY' }]} loading={false} onRefresh={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: 'image-model 图片与工具计费' }))
    const dialog = screen.getByRole('dialog')
    await userEvent.click(within(dialog).getByRole('tab', { name: '工具附加费（1）' }))
    expect(await within(dialog).findByRole('button', { name: '采用参考费率' })).toBeDisabled()
    expect(within(dialog).getByText('参考币种为 USD；请按当前币种的渠道合同录入，不换汇。')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('工具每千次单价')).toHaveValue('10.00')
  })

  it('offers provider specification templates without invented prices and blocks incomplete image rules', async () => {
    const save = vi.spyOn(billingAdminApi, 'createPrice').mockResolvedValue({ data: {} } as any)
    const validation = vi.spyOn(message, 'error')
    render(<ModelPricingTable tenantID="tenant-a" models={[model]} prices={[]} loading={false} onRefresh={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: 'image-model 图片与工具计费' }))
    const dialog = screen.getByRole('dialog')
    await waitFor(() => expect(apiClient.get).toHaveBeenCalledWith('/billing/pricing-capabilities', { params: { tenant_id: 'tenant-a', model_name: 'image-model' } }))
    await userEvent.click(within(dialog).getByRole('combobox', { name: '模型规格模板' }))
    await userEvent.click(await screen.findByText('DALL·E 3：尺寸与质量'))
    expect(within(dialog).getByLabelText('图片规格价格')).toHaveValue('')
    expect(within(dialog).getByRole('tab', { name: '图片规格 / 价格' })).toHaveAttribute('aria-selected', 'true')
    await userEvent.click(within(dialog).getByRole('button', { name: '保存收费配置' }))
    await waitFor(() => expect(validation).toHaveBeenCalledWith('请补全图片尺寸、质量及价格'))
    expect(save).not.toHaveBeenCalled()
  })

  it('explicitly applies the already selected recommended model template without filling a price', async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: { data: { ...capabilities, recognized_model: true, suggested_template_id: 'dall-e-3' } } } as any)
    const save = vi.spyOn(billingAdminApi, 'createPrice').mockResolvedValue({ data: {} } as any)
    render(<ModelPricingTable tenantID="tenant-a" models={[model]} prices={[]} loading={false} onRefresh={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: 'image-model 图片与工具计费' }))
    const dialog = screen.getByRole('dialog')
    const apply = within(dialog).getByRole('button', { name: '套用规格模板' })
    await waitFor(() => expect(apply).toBeEnabled())
    expect(within(dialog).getByText('仅填写规格，不自动填价')).toBeInTheDocument()
    await userEvent.click(apply)
    const imageInput = await within(dialog).findByLabelText('图片规格价格')
    expect(imageInput).toHaveValue('')
    await userEvent.type(imageInput, '0.04')
    await userEvent.click(within(dialog).getByRole('button', { name: '保存收费配置' }))
    await confirmPriceChange(userEvent.setup())
    await waitFor(() => expect(save).toHaveBeenCalledWith(expect.objectContaining({ pricing_extras: expect.objectContaining({
      image_pricing: { mode: 'per_image', default_size: '1024x1024', default_quality: 'standard', variants: [{ size: '1024x1024', quality: 'standard', price_per_image_micros: 40000 }] },
    }) })))
  })

  it('keeps ordinary text models focused on Token prices and starts new tool charges empty', async () => {
    const save = vi.spyOn(billingAdminApi, 'createPrice').mockResolvedValue({ data: {} } as any)
    const validation = vi.spyOn(message, 'error')
    render(<ModelPricingTable tenantID="tenant-a" models={[model]} prices={[{ ...price, pricing_extras: {} }]} loading={false} onRefresh={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: 'image-model 图片与工具计费' }))
    const dialog = screen.getByRole('dialog')
    expect(within(dialog).queryByLabelText('图片默认尺寸')).not.toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('tab', { name: '工具附加费（0）' }))
    await waitFor(() => expect(within(dialog).getByRole('tab', { name: '工具附加费（0）' })).toHaveAttribute('aria-selected', 'true'))
    await userEvent.click(await within(dialog).findByRole('button', { name: '新增工具收费' }))
    expect(within(dialog).getByRole('combobox', { name: '工具类型' })).toHaveValue('')
    expect(within(dialog).getByLabelText('工具每千次单价')).toHaveValue('')
    await userEvent.click(within(dialog).getByRole('combobox', { name: '工具类型' }))
    expect(await screen.findByText('联网搜索（OpenAI / Anthropic）')).toBeInTheDocument()
    await userEvent.click(within(dialog).getByLabelText('工具每千次单价'))
    await userEvent.click(within(dialog).getByRole('button', { name: '保存收费配置' }))
    await waitFor(() => expect(validation).toHaveBeenCalledWith('请填写有效的自定义工具类型'))
    expect(save).not.toHaveBeenCalled()
  })

  it('saves multimodal text and image Token components separately without a per-image charge', async () => {
    const save = vi.spyOn(billingAdminApi, 'createPrice').mockResolvedValue({ data: {} } as any)
    const multimodal: BillingPrice = { ...price, pricing_extras: { image_pricing: { mode: 'token' }, image_input_per_million_micros: 1000000, cached_image_input_per_million_micros: 200000, image_output_per_million_micros: 4000000 } }
    render(<ModelPricingTable tenantID="tenant-a" models={[model]} prices={[multimodal]} loading={false} onRefresh={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: 'image-model 图片与工具计费' }))
    const dialog = screen.getByRole('dialog')
    await userEvent.click(within(dialog).getByRole('tab', { name: '图片规格 / 价格' }))
    const imageOutput = await within(dialog).findByRole('spinbutton', { name: '图像输出（美元/百万 Token）' })
    await userEvent.clear(imageOutput)
    await userEvent.type(imageOutput, '5.25')
    await userEvent.click(within(dialog).getByRole('button', { name: '保存收费配置' }))
    await confirmPriceChange(userEvent.setup())
    await waitFor(() => expect(save).toHaveBeenCalledWith(expect.objectContaining({ input_per_million_micros: 2000000,
      pricing_extras: expect.objectContaining({ image_pricing: { mode: 'token' }, image_input_per_million_micros: 1000000, cached_image_input_per_million_micros: 200000, image_output_per_million_micros: 5250000 }),
    })))
    expect(save.mock.calls[0][0].pricing_extras).not.toHaveProperty('image_per_image_micros')
  })

  it('uses normal Token rates for image Tokens after an explicit switch from multimodal pricing', async () => {
    const save = vi.spyOn(billingAdminApi, 'createPrice').mockResolvedValue({ data: {} } as any)
    const multimodal: BillingPrice = { ...price, pricing_extras: { image_pricing: { mode: 'token' }, image_input_per_million_micros: 1000000, cached_image_input_per_million_micros: 200000, image_output_per_million_micros: 4000000 } }
    render(<ModelPricingTable tenantID="tenant-a" models={[model]} prices={[multimodal]} loading={false} onRefresh={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: 'image-model 图片与工具计费' }))
    const dialog = screen.getByRole('dialog')
    await userEvent.click(within(dialog).getByText('Token'))
    await userEvent.click(within(dialog).getByRole('button', { name: '保存收费配置' }))
    await confirmPriceChange(userEvent.setup())
    await waitFor(() => expect(save).toHaveBeenCalled())
    const payload = save.mock.calls[0][0] as any
    expect(payload.input_per_million_micros).toBe(2000000)
    expect(payload.output_per_million_micros).toBe(8000000)
    expect(payload.pricing_extras.image_pricing).toMatchObject({ mode: 'token' })
    expect(payload.pricing_extras).not.toHaveProperty('image_input_per_million_micros')
    expect(payload.pricing_extras).not.toHaveProperty('cached_image_input_per_million_micros')
    expect(payload.pricing_extras).not.toHaveProperty('image_output_per_million_micros')
  })

  it('allows an explicitly counted custom tool without duplicate options or invented prices', async () => {
    const options = toolPricingOptionsWithExisting(['search_tq', 'search_tq', '__custom__'])
    expect(options.filter((option) => option.value === 'search_tq')).toHaveLength(1)
    expect(options.some((option) => option.value === '__custom__')).toBe(false)
    const save = vi.spyOn(billingAdminApi, 'createPrice').mockResolvedValue({ data: {} } as any)
    render(<ModelPricingTable tenantID="tenant-a" models={[model]} prices={[{ ...price, pricing_extras: {} }]} loading={false} onRefresh={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: 'image-model 图片与工具计费' }))
    const dialog = screen.getByRole('dialog')
    await userEvent.click(within(dialog).getByRole('tab', { name: '工具附加费（0）' }))
    await userEvent.click(await within(dialog).findByRole('button', { name: '新增工具收费' }))
    await userEvent.click(within(dialog).getByRole('combobox', { name: '工具类型' }))
    await userEvent.click(await screen.findByText('自定义（上游明确返回计数）'))
    await userEvent.type(within(dialog).getByLabelText('自定义工具计数类型'), 'search_tq')
    await userEvent.type(within(dialog).getByLabelText('工具每千次单价'), '2.50')
    await userEvent.click(within(dialog).getByRole('button', { name: '保存收费配置' }))
    await confirmPriceChange(userEvent.setup())
    await waitFor(() => expect(save).toHaveBeenCalledWith(expect.objectContaining({ pricing_extras: expect.objectContaining({ tool_prices_per_thousand_micros: { search_tq: 2500000 } }) })))
  })
})

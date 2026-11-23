import { formatMicrosDecimal, UNKNOWN_MONEY } from '../../utils/money'
import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, Col, Form, Input, Modal, Row, Segmented, Select, Space, Tabs, Typography, message } from 'antd'
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons'
import { apiClient } from '../../services/api'
import { currencyUnitLabel } from '../../utils/currencyUnit'
import TwoDecimalInput from './TwoDecimalInput'
import { MICROS_PER_YUAN, imageQualityLabel, type EditablePriceDraft, type ImagePricingTemplate, type PricingCapabilities, type PricingRow, type PriceExtensions } from './modelPricing'
import { toolPricingOptionsWithExisting, toolPricingUnit } from './toolPricingCatalog'

const { Text } = Typography
const amount = (value?: number | null, quantity = 1) => value == null ? null : value * quantity / MICROS_PER_YUAN
const micros = (value: number | null | undefined, quantity = 1) => value == null ? undefined : Math.round(value * MICROS_PER_YUAN / quantity)
const normalize = (value?: string) => value?.trim().toLowerCase() ?? ''
const currencyOptions = [{ value: 'CNY', label: '人民币 CNY' }, { value: 'USD', label: '美元 USD' }]
type BillingKind = 'token' | 'multimodal' | 'per_image' | 'legacy'

function ImageSpecSelect({ value, onChange, options, ariaLabel }: {
  value?: string
  onChange?: (value: string) => void
  options: { value: string; label: string }[]
  ariaLabel: string
}) {
  return <Select mode="tags" value={value ? [value] : []} options={options} allowClear showSearch
    aria-label={ariaLabel} placeholder="选择或输入提供商规格" maxTagCount={1} style={{ width: '100%' }}
    onChange={(values: string[]) => onChange?.(values[values.length - 1] ?? '')} />
}

function initialValues(draft: EditablePriceDraft) {
  const extras = draft.pricingExtras
  const legacyImagePrice = (extras.image_per_image_micros ?? 0) + (extras.newapi_fixed_quantity ? extras.request_per_call_micros ?? 0 : 0)
  const imagePricing = extras.image_pricing
  const legacy = !imagePricing && (extras.image_per_image_micros !== undefined || extras.newapi_fixed_quantity !== undefined)
  const imageKind: BillingKind = imagePricing?.mode === 'per_image'
    ? 'per_image'
    : legacy ? 'legacy'
    : extras.image_input_per_million_micros != null || extras.cached_image_input_per_million_micros != null || extras.image_output_per_million_micros != null ? 'multimodal' : 'token'
  const variants = imagePricing?.variants ?? (legacyImagePrice > 0 ? [{ size: '*', quality: '*', price_per_image_micros: legacyImagePrice }] : [])
  const imageQuantity = variants.some((variant) => variant.price_per_image_micros > 0 && variant.price_per_image_micros < 10000) ? 1000 : 1
  return {
    kind: imageKind, currency: draft.currency, mode: draft.mode,
    input: draft.inputPerMillionYuan, output: draft.outputPerMillionYuan,
    cached_input: draft.cachedInputPerMillionYuan, cache_write: draft.cacheWritePerMillionYuan,
    base_input: draft.baseInputPerMillionYuan, model_ratio: draft.modelRatio, completion_ratio: draft.completionRatio,
    cached_ratio: draft.cachedInputRatio, cache_write_ratio: draft.cacheWriteRatio,
    image_input: amount(extras.image_input_per_million_micros),
    cached_image_input: amount(extras.cached_image_input_per_million_micros),
    image_output: amount(extras.image_output_per_million_micros),
    reasoning: amount(extras.reasoning_per_million_micros),
    request_price: amount(extras.request_per_call_micros, 1000),
    legacy_image_price: amount(extras.image_per_image_micros, 1000),
    default_size: imagePricing?.default_size ?? '', default_quality: imagePricing?.default_quality ?? '',
    image_quantity: imageQuantity,
    variants: variants.map((variant) => ({ size: variant.size, quality: variant.quality, price: amount(variant.price_per_image_micros, imageQuantity) })),
    tools: Object.entries(extras.tool_prices_per_thousand_micros ?? {}).map(([name, value]) => ({ name, custom_name: name, price: amount(value) })),
  }
}

interface Props {
  tenantID: string
  row: PricingRow
  draft: EditablePriceDraft
  saving: boolean
  onCancel: () => void
  onSave: (draft: Partial<EditablePriceDraft>) => Promise<boolean>
}

export default function ModelPricingEditor({ tenantID, row, draft, saving, onCancel, onSave }: Props) {
  const [form] = Form.useForm()
  const [capabilities, setCapabilities] = useState<PricingCapabilities | null>(null)
  const [capabilityError, setCapabilityError] = useState(false)
  const [templateID, setTemplateID] = useState<string>()
  const [tab, setTab] = useState('base')
  const initial = useMemo(() => initialValues(draft), [draft])
  const kind: BillingKind = Form.useWatch('kind', form) ?? initial.kind
  const mode = Form.useWatch('mode', form) ?? draft.mode
  const currency = Form.useWatch('currency', form) ?? draft.currency
  const imageQuantity = Form.useWatch('image_quantity', { form, preserve: true }) ?? initial.image_quantity
  const configuredTools = Form.useWatch('tools', form) ?? initial.tools
  const template = capabilities?.image_models?.find((item) => item.id === templateID)
  const moneyUnit = currencyUnitLabel(currency)

  useEffect(() => {
    let active = true
    apiClient.get('/billing/pricing-capabilities', { params: { tenant_id: tenantID, model_name: row.modelName } })
      .then((response) => {
        if (!active) return
        const data: PricingCapabilities = response.data.data
        setCapabilities(data)
        setTemplateID(data.suggested_template_id || undefined)
      }).catch(() => { if (active) setCapabilityError(true) })
    return () => { active = false }
  }, [row.modelName, tenantID])

  const options = (values: string[] | undefined, current: string[] = [], quality = false, wildcard = true) => [...new Set([...(values ?? []), ...current.filter(Boolean), ...(wildcard ? ['*'] : [])])]
    .filter((value) => wildcard || value !== '*')
    .map((value) => ({ value, label: value === '*' ? '任意（兜底）' : quality ? imageQualityLabel(value) : value }))
  const sizes = options(template?.sizes, (form.getFieldValue('variants') ?? []).map((value: { size?: string }) => value.size ?? ''))
  const qualities = options(template?.qualities, (form.getFieldValue('variants') ?? []).map((value: { quality?: string }) => value.quality ?? ''), true)
  const nativeTools = capabilities?.tools?.filter((tool) => tool.support === 'native').map((tool) => ({ value: tool.name, label: tool.label }))
  const toolOptions = nativeTools?.length
    ? [...nativeTools, ...toolPricingOptionsWithExisting(configuredTools.map((tool: { name: string }) => tool.name)).filter((option) => !nativeTools.some((tool) => tool.value === option.value))]
    : toolPricingOptionsWithExisting(configuredTools.map((tool: { name: string }) => tool.name))

  const toolReference = (index: number) => {
    const selectedName = form.getFieldValue(['tools', index, 'name'])
    const name = selectedName === '__custom__' ? normalize(form.getFieldValue(['tools', index, 'custom_name'])) : selectedName
    const reference = capabilities?.tools?.find((tool) => tool.name === name)
    const hasReference = reference?.reference_price_per_thousand_micros != null && reference.reference_currency
    return <Space direction="vertical" size={2}>
      <Text type="secondary" style={{ fontSize: 12 }}>每{toolPricingUnit(name)}</Text>
      {hasReference ? <>
        <Text style={{ fontSize: 12 }}>New API 参考：{reference.reference_currency === 'USD' ? '$' : '¥'}{formatMicrosDecimal(reference.reference_price_per_thousand_micros) ?? UNKNOWN_MONEY}</Text>
        <Text type="secondary" style={{ fontSize: 12 }}>{reference.reference_basis}</Text>
        <Space size={8} wrap>
          <Button size="small" disabled={currency !== reference.reference_currency}
            onClick={() => form.setFieldValue(['tools', index, 'price'], amount(reference.reference_price_per_thousand_micros))}>采用参考费率</Button>
          {reference.reference_url && <a href={reference.reference_url} target="_blank" rel="noreferrer">查看来源</a>}
        </Space>
        {currency !== reference.reference_currency && <Text type="secondary" style={{ fontSize: 12 }}>参考币种为 {reference.reference_currency}；请按当前币种的渠道合同录入，不换汇。</Text>}
      </> : <Text type="secondary" style={{ fontSize: 12 }}>无可核实参考费率，请按渠道合同填写。</Text>}
    </Space>
  }

  const applyTemplate = (selected: ImagePricingTemplate) => {
    setTemplateID(selected.id)
    const values: Record<string, unknown> = {
      kind: selected.mode === 'per_image' ? 'per_image' : 'multimodal',
      default_size: selected.default_size, default_quality: selected.default_quality,
    }
    if (selected.mode === 'per_image' && !(form.getFieldValue('variants') ?? []).length) {
      values.variants = [{ size: selected.default_size, quality: selected.default_quality, price: null }]
    }
    form.setFieldsValue(values)
    setTab('image')
  }

  const save = async (values: ReturnType<typeof initialValues>) => {
    if (values.kind !== 'legacy' && (normalize(values.default_size) === '*' || normalize(values.default_quality) === '*')) {
      message.error('默认尺寸和质量须填写实际规格，兜底仅用于价格表'); setTab('image'); return
    }
    const toolPrices: Record<string, number> = {}
    for (const tool of values.tools ?? []) {
      const name = tool.name === '__custom__' ? normalize(tool.custom_name) : tool.name
      if (!name || !/^[a-z][a-z0-9_.:-]{0,95}$/.test(name)) { message.error('请填写有效的自定义工具类型'); setTab('tools'); return }
      if (name in toolPrices) { message.error('工具类型不可重复'); setTab('tools'); return }
      if (tool.price == null || !Number.isFinite(tool.price) || tool.price < 0) { message.error('请填写工具收费金额'); setTab('tools'); return }
      toolPrices[name] = micros(tool.price)!
    }
    const variants: NonNullable<NonNullable<PriceExtensions['image_pricing']>['variants']> = []
    if (values.kind === 'per_image') {
      const keys = new Set<string>()
      for (const variant of values.variants ?? []) {
        const size = normalize(variant.size), quality = normalize(variant.quality)
        if (!size || !quality || variant.price == null || !Number.isFinite(variant.price) || variant.price < 0) {
          message.error('请补全图片尺寸、质量及价格'); setTab('image'); return
        }
        const key = `${size}/${quality}`
        if (keys.has(key)) { message.error('图片尺寸与质量组合不可重复'); setTab('image'); return }
        keys.add(key)
        variants.push({ size, quality, price_per_image_micros: micros(variant.price, values.image_quantity)! })
      }
      if (!variants.length) { message.error('按张生图至少需要一个尺寸与质量价格'); setTab('image'); return }
    }
    const extras: PriceExtensions = {
      ...draft.pricingExtras,
      image_input_per_million_micros: micros(values.image_input),
      cached_image_input_per_million_micros: micros(values.cached_image_input),
      image_output_per_million_micros: micros(values.image_output),
      reasoning_per_million_micros: micros(values.reasoning),
      request_per_call_micros: micros(values.request_price, 1000),
      tool_prices_per_thousand_micros: toolPrices,
    }
    if (!values.tools?.length && draft.pricingExtras.tool_prices_per_thousand_micros === undefined) delete extras.tool_prices_per_thousand_micros
    if (values.kind === 'legacy') {
      extras.image_per_image_micros = micros(values.legacy_image_price, 1000)
    } else {
      extras.image_pricing = { mode: values.kind === 'per_image' ? 'per_image' : 'token',
        default_size: normalize(values.default_size) || undefined,
        default_quality: normalize(values.default_quality) || undefined,
        ...(values.kind === 'per_image' ? { variants } : {}),
      }
      delete extras.image_per_image_micros
    }
    if (values.kind === 'token') {
      delete extras.image_input_per_million_micros
      delete extras.cached_image_input_per_million_micros
      delete extras.image_output_per_million_micros
    }
    const result = await onSave({
      currency: values.currency, mode: values.mode, pricingExtras: extras,
      inputPerMillionYuan: values.input ?? 0, outputPerMillionYuan: values.output ?? 0,
      cachedInputPerMillionYuan: values.cached_input ?? null, cacheWritePerMillionYuan: values.cache_write ?? null,
      baseInputPerMillionYuan: values.base_input ?? 0, modelRatio: values.model_ratio ?? 1, completionRatio: values.completion_ratio ?? 1,
      cachedInputRatio: values.cached_ratio ?? null, cacheWriteRatio: values.cache_write_ratio ?? null,
    })
    if (result) onCancel()
  }

  const field = (name: string, label: string, required = false, hint?: string) => <Col span={12} key={name}>
    <Form.Item name={name} label={label} extra={hint} rules={required ? [{ required: true, message: '请填写价格' }] : []}>
      <TwoDecimalInput min={0} style={{ width: '100%' }} />
    </Form.Item>
  </Col>

  return <Modal open title={`${row.modelLabel} · 定价配置`} width={880} style={{ top: 28 }}
    styles={{ body: { maxHeight: 'calc(100vh - 180px)', overflowY: 'auto', paddingRight: 8 } }}
    okText="保存收费配置" cancelText="取消" confirmLoading={saving} onCancel={onCancel} onOk={() => form.submit()}>
    <Form form={form} layout="vertical" initialValues={initial} onFinish={() => save(form.getFieldsValue(true))}
      onFinishFailed={() => { message.error('请补全必填价格'); setTab('base') }}>
      <Row gutter={16}>
        <Col span={16}><Form.Item name="kind" label="模型计费方式">
          <Segmented block options={[...(initial.kind === 'legacy' ? [{ value: 'legacy', label: '沿用旧配置' }] : []), { value: 'token', label: 'Token' }, { value: 'multimodal', label: '多模态 Token' }, { value: 'per_image', label: '按张生图' }]} />
        </Form.Item></Col>
        <Col span={8}><Form.Item name="currency" label="货币单位"><Select options={currencyOptions} /></Form.Item></Col>
      </Row>
      <Form.Item label="规格模板"><Space wrap align="end">
        <Select aria-label="模型规格模板" value={templateID} placeholder="选择提供商模板（不含价格）" style={{ width: 330 }}
          options={(capabilities?.image_models ?? []).map((item) => ({ value: item.id, label: item.label }))}
          onChange={(id) => { const item = capabilities?.image_models.find((entry) => entry.id === id); if (item) applyTemplate(item) }} />
        <Button disabled={!template} onClick={() => { if (template) applyTemplate(template) }}>套用规格模板</Button>
        {capabilities?.recognized_model && <Text type="secondary">已识别当前模型</Text>}
        <Text type="secondary">仅填写规格，不自动填价</Text>
      </Space></Form.Item>
      {capabilityError && <Alert type="warning" showIcon message="规格模板暂时无法读取，可手动填写提供商支持的尺寸与质量。" style={{ marginBottom: 12 }} />}
      {initial.kind === 'legacy' && kind !== 'legacy' && <Alert type="warning" showIcon style={{ marginBottom: 12 }} message="保存将替换旧的图片计价规则。" />}
      <Tabs activeKey={tab} onChange={setTab} items={[
        { key: 'base', label: kind === 'per_image' ? '聊天 Token / 调用费' : 'Token / 调用费', children: <>
          <Form.Item name="mode" label="Token 定价方法"><Segmented options={[{ value: 'direct', label: '直接单价' }, { value: 'newapi_ratio', label: '基础价 × 倍率' }]} /></Form.Item>
          <Row gutter={16}>
            {mode === 'direct' ? <>
              {field('input', `文本输入（${moneyUnit}/百万 Token）`, kind !== 'per_image')}
              {field('output', `普通输出（${moneyUnit}/百万 Token）`, kind !== 'per_image')}
              {field('cached_input', `缓存命中（${moneyUnit}/百万 Token）`, false, '留空按输入价计费')}
              {field('cache_write', `缓存写入（${moneyUnit}/百万 Token）`, false, '留空按输入价计费')}
            </> : <>
              {field('base_input', `基础输入（${moneyUnit}/百万 Token）`, kind !== 'per_image')}
              {field('model_ratio', '模型倍率', true)}
              {field('completion_ratio', '输出倍率', true)}
              {field('cached_ratio', '缓存命中倍率（可选）')}
              {field('cache_write_ratio', '缓存写入倍率（可选）')}
            </>}
            {field('reasoning', `推理输出（${moneyUnit}/百万 Token）`, false, '留空按输出价计费；设置后从普通输出中扣除')}
            {field('request_price', `${draft.pricingExtras.newapi_fixed_quantity ? '原固定价格' : '额外调用费'}（${moneyUnit}/千次请求）`, false, draft.pricingExtras.newapi_fixed_quantity ? kind === 'legacy' ? '沿用原规则：图片按张，其他接口按次' : '保留聊天等非图片接口固定费用' : '留空或 0.00 不加价')}
          </Row>
        </> },
        { key: 'image', label: '图片规格 / 价格', children: <>
          {kind === 'token' && <Form.Item style={{ marginBottom: 12 }}><Button onClick={() => form.setFieldValue('kind', 'multimodal')}>配置图像 Token 价格</Button></Form.Item>}
          {kind === 'legacy' && <Row gutter={16}>{field('legacy_image_price', `原每张附加费（${moneyUnit}/1000 张）`, false, '沿用旧规则；选择新方式后才配置尺寸与质量')}</Row>}
          {(kind === 'multimodal' || kind === 'per_image') && <>
          <Row gutter={16}>
            <Col span={12}><Form.Item name="default_size" label="省略尺寸时使用"><ImageSpecSelect ariaLabel="图片默认尺寸" options={options(template?.sizes, [form.getFieldValue('default_size')], false, false)} /></Form.Item></Col>
            <Col span={12}><Form.Item name="default_quality" label="省略质量时使用"><ImageSpecSelect ariaLabel="图片默认质量" options={options(template?.qualities, [form.getFieldValue('default_quality')], true, false)} /></Form.Item></Col>
          </Row>
          {kind !== 'per_image' ? <Row gutter={16}>
            {field('image_input', `图像输入（${moneyUnit}/百万 Token）`, false, '留空使用文本输入价')}
            {field('cached_image_input', `图像缓存命中（${moneyUnit}/百万 Token）`, false, '留空使用缓存命中价')}
            {field('image_output', `图像输出（${moneyUnit}/百万 Token）`, false, '留空使用普通输出价')}
          </Row> : <>
            <Space wrap style={{ marginBottom: 10 }}><Text>图片价格单位</Text>
              <Form.Item name="image_quantity" noStyle><Select aria-label="图片价格单位" style={{ width: 180 }} options={[{ value: 1, label: `${moneyUnit}/张` }, { value: 1000, label: `${moneyUnit}/1000 张` }]}
                onChange={(quantity) => form.setFieldValue('variants', (form.getFieldValue('variants') ?? []).map((value: { price: number | null }) => ({ ...value, price: value.price == null ? null : value.price * quantity / imageQuantity })))} /></Form.Item>
            </Space>
            <div style={{ border: '1px solid #f0f0f0', borderRadius: 8, padding: '12px 12px 4px' }}>
              <Row gutter={12} style={{ marginBottom: 8 }}><Col span={7}><Text strong>尺寸</Text></Col><Col span={7}><Text strong>质量</Text></Col><Col span={8}><Text strong>价格（{moneyUnit}/{imageQuantity === 1000 ? '1000 张' : '张'}）</Text></Col></Row>
              <Form.List name="variants">{(fields, { add, remove }) => <>
                {fields.map((field) => <Row gutter={12} key={field.key} align="top">
                  <Col span={7}><Form.Item name={[field.name, 'size']}><ImageSpecSelect ariaLabel="图片规格尺寸" options={sizes} /></Form.Item></Col>
                  <Col span={7}><Form.Item name={[field.name, 'quality']}><ImageSpecSelect ariaLabel="图片规格质量" options={qualities} /></Form.Item></Col>
                  <Col span={8}><Form.Item name={[field.name, 'price']}><TwoDecimalInput aria-label="图片规格价格" min={0} style={{ width: '100%' }} /></Form.Item></Col>
                  <Col span={2}><Form.Item><Button aria-label="删除图片规格" icon={<DeleteOutlined />} onClick={() => remove(field.name)} /></Form.Item></Col>
                </Row>)}
                <Form.Item style={{ marginBottom: 8 }}><Space wrap>
                  <Button aria-label="新增尺寸质量" type="dashed" icon={<PlusOutlined />} onClick={() => add({ size: template?.default_size || '*', quality: template?.default_quality || '*', price: null })}>新增尺寸质量</Button>
                  {template?.mode === 'per_image' && <Button onClick={() => {
                    const existing = form.getFieldValue('variants') ?? []
                    form.setFieldValue('variants', template.sizes.flatMap((size) => template.qualities.map((quality) => existing.find((entry: { size: string; quality: string }) => entry.size === size && entry.quality === quality) ?? { size, quality, price: null })))
                  }}>展开模板全部规格</Button>}
                </Space></Form.Item>
              </>}</Form.List>
            </div>
          </>}
          </>}
        </> },
        { key: 'tools', label: `工具附加费（${configuredTools.length}）`, children: <>
          <Row gutter={12} style={{ marginBottom: 8 }}><Col span={14}><Text strong>工具类型</Text></Col><Col span={8}><Text strong>价格（{moneyUnit}）</Text></Col></Row>
          <Form.List name="tools">{(fields, { add, remove }) => <>
            {fields.map((field) => <Row key={field.key} gutter={12} align="top">
              <Col span={14}>
                <Form.Item name={[field.name, 'name']}><Select aria-label="工具类型" showSearch optionFilterProp="label" placeholder="选择工具类型" options={[...toolOptions, { value: '__custom__', label: '自定义（上游明确返回计数）' }]} /></Form.Item>
                <Form.Item noStyle shouldUpdate>{() => form.getFieldValue(['tools', field.name, 'name']) === '__custom__' && <Form.Item name={[field.name, 'custom_name']}>
                  <Input aria-label="自定义工具计数类型" placeholder="与 usage.tool_calls 中的类型一致" />
                </Form.Item>}</Form.Item>
              </Col>
              <Col span={8}><Form.Item name={[field.name, 'price']}><TwoDecimalInput aria-label="工具每千次单价" min={0} placeholder="填写实际价格" style={{ width: '100%' }} /></Form.Item>
                <Form.Item noStyle shouldUpdate>{() => toolReference(field.name)}</Form.Item>
              </Col>
              <Col span={2}><Form.Item><Button aria-label="删除工具收费" icon={<DeleteOutlined />} onClick={() => remove(field.name)} /></Form.Item></Col>
            </Row>)}
            <Form.Item><Button aria-label="新增工具收费" type="dashed" icon={<PlusOutlined />} onClick={() => add({})}>新增工具收费</Button></Form.Item>
          </>}</Form.List>
        </> },
      ]} />
    </Form>
  </Modal>
}

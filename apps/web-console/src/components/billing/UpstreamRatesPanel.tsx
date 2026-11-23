import { useCurrencyStore } from '../../stores/currency'
import { formatMicrosDecimal, UNKNOWN_MONEY } from '../../utils/money'
import { useEffect, useRef, useState } from 'react'
import { Alert, Button, Card, Divider, Form, Modal, Popconfirm, Select, Space, Switch, Table, Typography, message } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { billingEmployeeApi } from '../../services/api'
import { extractApiError } from '../../utils/apiError'
import TwoDecimalInput from './TwoDecimalInput'
import { toolPricingOptionsWithExisting, toolPricingUnit } from './toolPricingCatalog'
import { formatMoneyMicros } from './billingFormat'
import ModelIdentity from './ModelIdentity'
import { BILLING_SECTION_LABELS as labels } from './sectionLabels'
import { modelDisplayLabel } from './modelDisplay'

const tokenFields = [['input', '输入'], ['cached_input', '缓存命中'], ['cache_write', '缓存写入'], ['output', '输出']]
const optionalFields = [['reasoning_per_million_micros', '推理 / 百万 Token'], ['image_input_per_million_micros', '图片输入 / 百万 Token'], ['cached_image_input_per_million_micros', '缓存图片输入 / 百万 Token']]
const initialPriceUnit = (micros: unknown) => Number(micros) > 0 && Number(micros) < 10_000 ? 1000 : 1
const amountMicros = (value: unknown) => Math.round(Number(value ?? 0) * 1_000_000)

export default function UpstreamRatesPanel({ tenantID, models: billingModels = [], prices = [] }: { tenantID: string; models?: any[]; prices?: any[] }) {
  const cache = useQueryClient()
  const [open, setOpen] = useState(false)
  const [imageUnit, setImageUnit] = useState(1)
  const [requestUnit, setRequestUnit] = useState(1)
  const [preservedExtensions, setPreservedExtensions] = useState<Record<string, unknown>>({})
  const [form] = Form.useForm()
  const formTools: Array<{ name?: string }> = Form.useWatch('tools', form) || []
  const toolOptions = toolPricingOptionsWithExisting(formTools.flatMap(tool => tool.name ? [tool.name] : []))
  const activeTenant = useRef(tenantID)
  activeTenant.current = tenantID
  const modelCatalog = useQuery({ queryKey: ['upstream-models', tenantID], queryFn: () => billingEmployeeApi.upstreamModels(tenantID), enabled: !!tenantID })
  const models: any[] = modelCatalog.data?.data?.data || []
  const rates = useQuery({ queryKey: ['upstream-rates', tenantID], queryFn: () => billingEmployeeApi.upstreamRates(tenantID), enabled: !!tenantID })
  useEffect(() => { setOpen(false); form.resetFields(); setPreservedExtensions({}) }, [tenantID, form])
  const save = useMutation({
    mutationFn: (input: { tenant: string; payload: Record<string, unknown> }) => billingEmployeeApi.saveUpstreamRate(input.tenant, input.payload),
    onSuccess: (_, input) => { void cache.invalidateQueries({ queryKey: ['upstream-rates', input.tenant] }); if (activeTenant.current === input.tenant) setOpen(false); message.success('按量成本已保存') },
    onError: error => message.error(extractApiError(error) || '保存失败'),
  })
  const remove = useMutation({
    mutationFn: (input: { tenant: string; provider: string; model: string }) => billingEmployeeApi.deleteUpstreamRate(input.tenant, input.provider, input.model),
    onSuccess: (_, input) => { void cache.invalidateQueries({ queryKey: ['upstream-rates', input.tenant] }); message.success('按量成本已删除') },
    onError: error => message.error(extractApiError(error) || '删除采购成本失败'),
  })
  const salePrice = (rate: any) => {
    const now = Date.now()
    const price = prices.filter(price => price.model_name === rate.model_name && price.status === 'active' && (!price.effective_at || Date.parse(price.effective_at) <= now) && (!price.expires_at || Date.parse(price.expires_at) > now))
      .sort((a, b) => Number(b.version || 0) - Number(a.version || 0))[0]
    if (!price) return <Typography.Text type="secondary">未录入内部结算价</Typography.Text>
    const input = price.pricing_mode === 'newapi_ratio' ? Number(price.base_input_per_million_micros || 0) * Number(price.model_ratio_ppm || 1000000) / 1000000 * Number(price.group_ratio_ppm || 1000000) / 1000000 : Number(price.input_per_million_micros || 0)
    const output = price.pricing_mode === 'newapi_ratio' ? input * Number(price.completion_ratio_ppm || 1000000) / 1000000 : Number(price.output_per_million_micros || 0)
    return <Space direction="vertical" size={0}><Typography.Text>输入：{formatMoneyMicros(Math.round(input), price.currency)}</Typography.Text><Typography.Text>输出：{formatMoneyMicros(Math.round(output), price.currency)}</Typography.Text></Space>
  }
  const edit = (rate?: any) => {
    form.resetFields()
    const extensions = rate?.extensions || {}
    setPreservedExtensions({ ...extensions })
    const loadedImageUnit = initialPriceUnit(extensions.image_per_image_micros)
    const loadedRequestUnit = initialPriceUnit(extensions.request_per_call_micros)
    setImageUnit(loadedImageUnit)
    setRequestUnit(loadedRequestUnit)
    form.setFieldsValue({ model_key: rate ? `${rate.provider_id}:${rate.model_name}` : undefined, currency: rate?.currency || useCurrencyStore.getState().tenantCurrency,
      ...Object.fromEntries(tokenFields.map(([key]) => [key, Number(rate?.[`${key}_per_million_micros`] || 0) / 1_000_000])),
      image_per_image_micros: Number(extensions.image_per_image_micros || 0) / 1_000_000 * loadedImageUnit,
      request_per_call_micros: Number(extensions.request_per_call_micros || 0) / 1_000_000 * loadedRequestUnit,
      newapi_fixed_quantity: !!extensions.newapi_fixed_quantity,
      ...Object.fromEntries(optionalFields.map(([key]) => [key, extensions[key] == null ? undefined : Number(extensions[key]) / 1_000_000])),
      tools: Object.entries(extensions.tool_prices_per_thousand_micros || {}).map(([name, micros]) => ({ name, price: Number(micros) / 1_000_000 })),
    })
    setOpen(true)
  }
  const submit = (values: any) => {
    const model = models.find(item => `${item.provider_id}:${item.model_name}` === values.model_key)
    if (!model) { message.error('请选择已加载的渠道和模型'); return }
    const tools: Record<string, number> = {}
    for (const tool of values.tools || []) {
      if (Object.prototype.hasOwnProperty.call(tools, tool.name)) { message.error('工具类型不可重复'); return }
      tools[tool.name] = amountMicros(tool.price)
    }
    const extensions: Record<string, unknown> = { ...preservedExtensions,
      image_per_image_micros: Math.round(Number(values.image_per_image_micros || 0) * 1_000_000 / imageUnit), request_per_call_micros: Math.round(Number(values.request_per_call_micros || 0) * 1_000_000 / requestUnit),
      newapi_fixed_quantity: !!values.newapi_fixed_quantity, tool_prices_per_thousand_micros: tools,
    }
    for (const [key] of optionalFields) {
      if (values[key] == null || values[key] === '') delete extensions[key]
      else extensions[key] = amountMicros(values[key])
    }
    save.mutate({ tenant: tenantID, payload: { provider_id: model.provider_id, model_name: model.model_name, currency: values.currency,
      ...Object.fromEntries(tokenFields.map(([key]) => [`${key}_per_million_micros`, amountMicros(values[key])])), extensions,
    } })
  }
  return <Card title={labels.upstream} extra={<Button type="primary" disabled={!tenantID || modelCatalog.isLoading || modelCatalog.isError} onClick={() => edit()}>录入采购成本</Button>}>
    {modelCatalog.isError && <Alert type="error" style={{ marginBottom: 12 }} message="渠道模型加载失败" action={<Button onClick={() => void modelCatalog.refetch()}>重试模型加载</Button>} />}
    {rates.isError && <Alert type="error" message="采购成本加载失败" action={<Button onClick={() => void rates.refetch()}>重试</Button>} />}
    <Table rowKey={rate => `${rate.provider_id}:${rate.model_name}`} dataSource={rates.data?.data?.data || []} loading={rates.isLoading} scroll={{ x: 1000 }} locale={{ emptyText: <span>暂无模型按量成本。<Button type="link" size="small" disabled={!tenantID || modelCatalog.isLoading || modelCatalog.isError} onClick={() => edit()}>录入第一条采购成本</Button></span> }} columns={[
      { title: '渠道', dataIndex: 'provider_name' }, { title: '模型', dataIndex: 'model_name', render: (name: string) => <ModelIdentity modelName={name} label={modelDisplayLabel(name, [...billingModels, ...models])} /> }, { title: '币种', dataIndex: 'currency' },
      { title: '模型售价 / 百万 Token', render: (_: unknown, rate: any) => salePrice(rate) },
      ...tokenFields.map(([key, label]) => ({ title: `${label} / 百万 Token`, render: (_: unknown, rate: any) => formatMicrosDecimal(rate[`${key}_per_million_micros`]) ?? UNKNOWN_MONEY })),
      { title: '附加成本', render: (_: unknown, rate: any) => <Space direction="vertical" size={0}><Typography.Text>图片：{formatMicrosDecimal(rate.extensions?.image_per_image_micros ?? 0, { quantity: initialPriceUnit(rate.extensions?.image_per_image_micros) }) ?? UNKNOWN_MONEY} / {initialPriceUnit(rate.extensions?.image_per_image_micros) === 1000 ? '千张' : '张'}</Typography.Text><Typography.Text>工具：{Object.keys(rate.extensions?.tool_prices_per_thousand_micros || {}).length} 类</Typography.Text></Space> },
      { title: '操作', render: (_: unknown, rate: any) => <Space><Button type="link" disabled={modelCatalog.isLoading || modelCatalog.isError} onClick={() => edit(rate)}>编辑</Button><Popconfirm title="确认删除按量采购成本？" description="之后的调用不再按此价格计算成本，历史记录保留。" okText="确认删除" cancelText="取消" onConfirm={() => remove.mutate({ tenant: tenantID, provider: rate.provider_id, model: rate.model_name })}><Button danger type="link" loading={remove.isPending}>删除</Button></Popconfirm></Space> },
    ]} />
    {open && <Modal width={760} title="录入采购成本" open onCancel={() => setOpen(false)} onOk={() => form.submit()} confirmLoading={save.isPending} okButtonProps={{ disabled: !tenantID || modelCatalog.isLoading || modelCatalog.isError }}>
      <Form form={form} layout="vertical" onFinish={submit}>
        <Space wrap>
          <Form.Item name="model_key" label="渠道 / 模型" rules={[{ required: true, message: '请选择渠道和模型' }]}><Select aria-label="成本渠道模型" showSearch optionFilterProp="label" style={{ width: 400 }} options={Array.from(new Map(models.filter(model => model.provider_id).map(model => [`${model.provider_id}:${model.model_name}`, { value: `${model.provider_id}:${model.model_name}`, label: `${model.provider_name} · ${modelDisplayLabel(model.model_name, [...billingModels, ...models])}` }])).values())} /></Form.Item>
          <Form.Item name="currency" label="采购成本币种" rules={[{ required: true }]}><Select aria-label="成本币种" style={{ width: 180 }} options={[{ value: 'CNY', label: '人民币 CNY' }, { value: 'USD', label: '美元 USD' }]} /></Form.Item>
        </Space>
        <Space wrap>{tokenFields.map(([key, label]) => <Form.Item key={key} name={key} label={`${label} / 百万 Token`} rules={[{ required: true, message: '请输入成本' }]}><TwoDecimalInput aria-label={`成本${label}`} min={0} max={1000000000} style={{ width: 160 }} /></Form.Item>)}</Space>
        <Divider>图片、按次费用和推理成本</Divider>
        <Space wrap>
          <Form.Item label="图片计价单位"><Select aria-label="成本图片计价单位" value={imageUnit} style={{ width: 120 }} options={[{ value: 1, label: '每张' }, { value: 1000, label: '每千张' }]} onChange={unit => { form.setFieldValue('image_per_image_micros', Number(form.getFieldValue('image_per_image_micros') || 0) * unit / imageUnit); setImageUnit(unit) }} /></Form.Item>
          <Form.Item name="image_per_image_micros" label={`图片 / ${imageUnit === 1000 ? '千张' : '张'}`} rules={[{ required: true }]}><TwoDecimalInput aria-label="成本图片价格" min={0} max={1000000000} style={{ width: 160 }} /></Form.Item>
          <Form.Item label="按次成本计价单位"><Select aria-label="成本按次成本计价单位" value={requestUnit} style={{ width: 120 }} options={[{ value: 1, label: '每次' }, { value: 1000, label: '每千次' }]} onChange={unit => { form.setFieldValue('request_per_call_micros', Number(form.getFieldValue('request_per_call_micros') || 0) * unit / requestUnit); setRequestUnit(unit) }} /></Form.Item>
          <Form.Item name="request_per_call_micros" label={`按次成本 / ${requestUnit === 1000 ? '千次' : '次'}`} rules={[{ required: true }]}><TwoDecimalInput aria-label="成本固定费用" min={0} max={1000000000} style={{ width: 160 }} /></Form.Item>
          <Form.Item name="newapi_fixed_quantity" label="固定费用按图片张数计算" valuePropName="checked"><Switch aria-label="成本按图片数量" /></Form.Item>
          {optionalFields.map(([key, label]) => <Form.Item key={key} name={key} label={label}><TwoDecimalInput aria-label={`成本${label}`} placeholder="留空沿用对应 Token 价格" min={0} max={1000000000} style={{ width: 220 }} /></Form.Item>)}
        </Space>
        <Typography.Paragraph type="secondary">推理 Token 包含在输出中，单独设置价格时会从普通输出中扣除；所有金额使用所选采购币种。</Typography.Paragraph>
        <Divider>工具成本</Divider>
        <Form.List name="tools" rules={[{ validator: async (_, tools) => { if (tools?.length > 64) throw new Error('最多配置 64 种工具成本') } }]}>
          {(fields, { add, remove }, { errors }) => <>
            {fields.map(field => <Space key={field.key} align="start">
              <Form.Item name={[field.name, 'name']} label="工具类型" rules={[{ required: true, message: '请选择工具类型' }]}><Select aria-label="成本工具类型" style={{ width: 280 }} showSearch optionFilterProp="label" placeholder="请选择工具类型" options={toolOptions.map(option => ({ ...option, disabled: formTools.some((tool, index) => index !== field.name && tool.name === option.value) }))} /></Form.Item>
              <Form.Item name={[field.name, 'price']} label={`采购成本 / ${toolPricingUnit(formTools[field.name]?.name || '')}`} rules={[{ required: true, message: '请输入工具成本' }]}><TwoDecimalInput aria-label="成本工具每千次" min={0} max={1000000000} style={{ width: 180 }} /></Form.Item>
              <Form.Item label=" "><Button danger onClick={() => remove(field.name)}>删除工具</Button></Form.Item>
            </Space>)}
            <Form.Item><Space direction="vertical"><Button type="dashed" onClick={() => add({})}>新增工具成本</Button><Form.ErrorList errors={errors} /></Space></Form.Item>
          </>}
        </Form.List>
      </Form>
    </Modal>}
  </Card>
}

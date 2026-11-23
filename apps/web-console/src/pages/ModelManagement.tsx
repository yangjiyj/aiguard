import GatewayAccess from '../components/GatewayAccess'
import {useGatewayAccess} from '../hooks/useGatewayAccess'
import { useState } from 'react'
import { Table, Button, Space, message, Typography, Popconfirm, Switch, Tooltip, Tabs, Modal, Form, Input, Select, Checkbox, Drawer, Tag, Alert, Descriptions } from 'antd'
import { DeleteOutlined, SwapOutlined, CheckCircleOutlined, PlusOutlined, ApiOutlined, PlayCircleOutlined, BarChartOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { providerApi, modelApi, apiClient as api } from '../services/api'
import ProviderIdentity from '../components/providers/ProviderIdentity'
import ModelProbeDialog, { type ProbeModel } from '../components/ModelProbeDialog'
import { extractApiError } from '../utils/apiError'
import { getModelBatchDeleteErrorMessage, validateModelBatchDeleteSelection } from '../utils/modelBatchDelete'

const { Title, Text } = Typography
interface Provider { id: string; name: string; provider_type?: string; status?: string }

// 根据调用入口选择生成各协议地址，保留客户域名、端口及反代前缀。
const buildGatewayEndpoint = (pathAfterV1: string, configuredBase?: string): string => {
  const rawBase = String(configuredBase || '').trim()
  if (!rawBase) return ''
  try {
    const parsed = new URL(rawBase)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return ''
    parsed.search = ''
    parsed.hash = ''
    parsed.pathname = parsed.pathname.replace(/\/+$/, '').replace(/\/v1$/, '')
    const root = parsed.toString().replace(/\/+$/, '')
    return `${root}/v1/${pathAfterV1.replace(/^\/+/, '')}`
  } catch {
    return ''
  }
}

// Examples use saved protocol configuration, not live availability claims.
// Runtime routing separately checks effective endpoint capability evidence.
const PROTOCOL_EXAMPLES: Record<string, { label: string; path: string; body: (modelName: string) => string }> = {
  chat_completions: {
    label: 'Chat Completions',
    path: 'chat/completions',
    body: (modelName) => JSON.stringify({ model: modelName, messages: [{ role: 'user', content: '你好' }] }, null, 2),
  },
  responses: {
    label: 'Responses',
    path: 'responses',
    body: (modelName) => JSON.stringify({ model: modelName, input: '你好' }, null, 2),
  },
  anthropic_messages: {
    label: 'Anthropic Messages',
    path: 'messages',
    body: (modelName) => JSON.stringify({ model: modelName, max_tokens: 1024, messages: [{ role: 'user', content: '你好' }] }, null, 2),
  },
  embeddings: {
    label: '向量嵌入',
    path: 'embeddings',
    body: (modelName) => JSON.stringify({ model: modelName, input: '需要向量化的文本' }, null, 2),
  },
}
const PROTOCOL_LABELS: Record<string, string> = {
  ...Object.fromEntries(Object.entries(PROTOCOL_EXAMPLES).map(([key, value]) => [key, value.label])),
  images: '图像生成',
  gemini: 'Gemini',
}
// curl 示例统一引用密钥环境变量，绝不把任何密钥明文写进页面或复制到剪贴板
const API_KEY_ENV_NAME = 'AIGUARD_API_KEY'

const buildCurlExample = (endpoint: string, body: string): string =>
  [`curl -sS '${endpoint}'`, `  -H "Authorization: Bearer $${API_KEY_ENV_NAME}"`, `  -H 'Content-Type: application/json'`, `  -d '${body.replace(/'/g, `'\\''`)}'`].join(' \\\n')

const listRows = (response: any): any[] => {
  const payload = response?.data
  return Array.isArray(payload?.items) ? payload.items : Array.isArray(payload?.data) ? payload.data : Array.isArray(payload) ? payload : []
}

const MODEL_ADVICE: Record<string, string> = { expired: '验证已过期，建议重新验证', unverified: '未验证，建议验证', unsupported: '探测未通过，建议检查', unhealthy: '健康检查异常，建议检查' }

function ModelManagement() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [probeModels, setProbeModels] = useState<ProbeModel[] | null>(null)
  const [modelScope, setModelScope] = useState<'active' | 'retained' | 'all'>(searchParams.get('model_id') ? 'all' : 'active')
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([])
  const [createOpen, setCreateOpen] = useState(false)
  const [createForm] = Form.useForm()
  const createProviderId = Form.useWatch('provider_id', createForm) as string | undefined
  const [detailModel, setDetailModel] = useState<any>(null)
  const provQ = useQuery({ queryKey: ['providers'], queryFn: providerApi.list })
  const modelQ = useQuery({ queryKey: ['models'], queryFn: () => modelApi.list() })
  // 网关公开 Base URL 与密钥管理页同源同键（gateway_public_base_url）
  const settingsQ = useQuery({ queryKey: ['system-settings'], queryFn: () => api.get('/system/settings').then((r) => r.data) })
  const gatewayAccess = useGatewayAccess(settingsQ.data)
  const createModelM = useMutation({
    mutationFn: (data: { provider_id: string; model_name: string; model_label?: string; upstream_model_id?: string; protocols?: string[] }) => modelApi.create(data),
    onSuccess: () => { message.success('模型已添加并启用'); setCreateOpen(false); createForm.resetFields(); qc.invalidateQueries({ queryKey: ['models'] }) },
    onError: (err: any) => message.error(extractApiError(err) || '添加模型失败'),
  })

  const toggleModelM = useMutation({
    mutationFn: (d: { id: string; status: string }) => modelApi.updateStatus(d.id, d.status),
    onSuccess: () => { message.success('模型状态已更新'); qc.invalidateQueries({ queryKey: ['models'] }) },
    onError: (error) => message.error(extractApiError(error) || '更新失败'),
  })
  const batchEnableM = useMutation({
    mutationFn: async (ids: string[]) => Promise.all(ids.map((id) => modelApi.updateStatus(id, 'active'))),
    onSuccess: () => { message.success('批量启用完成'); qc.invalidateQueries({ queryKey: ['models'] }) },
    onError: (error) => message.error(extractApiError(error) || '批量启用失败'),
  })
  const batchDeleteM = useMutation({
    mutationFn: async (ids: string[]) => (await modelApi.batchDelete(ids)).data,
    onSuccess: (result) => { setSelectedRowKeys([]); message.success(`已处理 ${result.requested} 个：删除 ${result.deleted} 个，停用保留 ${result.disabled} 个，失败 ${result.failed} 个`); qc.invalidateQueries({ queryKey: ['models'] }) },
    onError: (err: any) => message.error(getModelBatchDeleteErrorMessage(err)),
  })
  const deleteModelM = useMutation({
    mutationFn: async (id: string) => {
      try { return await modelApi.delete(id) } catch (err: any) {
        const detail = err?.response?.data?.message || err?.response?.data?.error?.message || ''
        if (err?.response?.status === 400 || detail.includes('引用') || detail.includes('reference')) { await modelApi.updateStatus(id, 'disabled'); return { _fallback: true } }
        throw err
      }
    },
    // 迁移 812 已把 request_logs / proxy_usage_daily 的外键改为 SET NULL / CASCADE，
    // 有历史调用的模型也能真正删除；这里的 fallback 只作为极端情况的兜底。
    onSuccess: (result: any) => { message.success(result?._fallback ? '该模型仍被其他数据引用，已停用但未彻底移除' : '模型已删除'); qc.invalidateQueries({ queryKey: ['models'] }) },
    onError: (err: any) => message.error(extractApiError(err) || '删除失败'),
  })

  const providers: Provider[] = listRows(provQ.data)
  const models = listRows(modelQ.data)
  const providerMap: Record<string, Provider> = Object.fromEntries(providers.map((item) => [item.id, item]))
  const nativeCreateProvider = ['gemini', 'vertex', 'bedrock'].includes(providerMap[createProviderId || '']?.provider_type || '')
  const activeModels = models.filter((item) => item.callable === true)
  const callableModelCount = new Set(activeModels.map((item) => item.model_name)).size
  const retainedModels = models.filter((item) => item.callable !== true)
  const scopedModels = modelScope === 'active' || retainedModels.length === 0 ? activeModels : modelScope === 'retained' ? retainedModels : models
  const providerFilter = searchParams.get('provider_id')
  const modelFilter = searchParams.get('model_id')
  const visibleModels = scopedModels.filter((model) => (!providerFilter || model.provider_id === providerFilter) && (!modelFilter || model.id === modelFilter))
  const selectedActiveCount = models.filter((item) => selectedRowKeys.includes(item.id) && item.status === 'active').length
  const pending = batchDeleteM.isPending || batchEnableM.isPending || toggleModelM.isPending || deleteModelM.isPending || createModelM.isPending

  const handleBatchDelete = () => {
    const validation = validateModelBatchDeleteSelection(selectedRowKeys)
    if (validation) { message.warning(validation); return }
    batchDeleteM.mutate(selectedRowKeys.map(String))
  }
  const columns = [
    { title: '模型', dataIndex: 'model_label', key: 'model', width: 210, ellipsis: true, render: (label: string, record: any) => <Text strong>{label || record.model_name || '已删除或不可见模型'}</Text> },
    { title: '供应商', key: 'provider', width: 160, ellipsis: true, render: (_: unknown, record: any) => <ProviderIdentity providerType={providerMap[record.provider_id]?.provider_type} name={providerMap[record.provider_id]?.name || '已删除或不可见供应商'} /> },
    // 可调用只由管理员开关、渠道、凭据、上游下架决定；探测结果只作为下方的建议。
    { title: '可调用状态', dataIndex: 'availability_state', key: 'availability_state', width: 190, render: (state: string, record: any) => <Space direction="vertical" size={2}>
      <Tag color={state === 'callable' ? 'green' : state === 'upstream_removed' ? 'red' : 'default'}>{({callable:'可调用',upstream_removed:'上游已移除',pending_admission:'待纳入',disabled:'人工禁用',provider_disabled:'上游已禁用',credential_unavailable:'凭据不可用'} as Record<string,string>)[state] || '未知'}</Tag>
      {MODEL_ADVICE[record.advice] && <Text type="secondary" style={{ fontSize: 12 }}>{MODEL_ADVICE[record.advice]}</Text>}
    </Space> },
    { title: '协议依据', dataIndex: 'proof_state', key: 'proof_state', width: 120, render: (proof: string) => <Tag>{proof === 'verified' ? '已验证' : proof === 'manual' ? '人工确认' : '未验证'}</Tag> },
    { title: '纳入管理', dataIndex: 'status', key: 'status', width: 120, render: (status: string, record: any) => <Switch checked={status === 'active'} checkedChildren="启用" unCheckedChildren="禁用" disabled={pending || record.inventory_state === 'upstream_removed'} loading={toggleModelM.isPending} onChange={(checked) => toggleModelM.mutate({ id: record.id, status: checked ? 'active' : 'disabled' })} /> },
    { title: '操作', key: 'action', width: 340, fixed: 'right' as const, render: (_: unknown, record: any) => <Space size={4}>
      <Button type="link" size="small" icon={<ApiOutlined />} onClick={() => setDetailModel(record)}>接入</Button>
      <Tooltip title="真实验证上游模型"><Button type="text" size="small" aria-label={`验证 ${record.model_name}`} icon={<PlayCircleOutlined />} disabled={pending} onClick={() => setProbeModels([{ ...record, provider_type: providerMap[record.provider_id]?.provider_type }])} /></Tooltip>
      <Tooltip title="模型验证与运营历史"><Button type="text" size="small" aria-label={`运营 ${record.model_name}`} icon={<BarChartOutlined />} onClick={() => navigate(`/model-operations?model_id=${encodeURIComponent(record.id)}&provider_id=${encodeURIComponent(record.provider_id)}&return_to=${encodeURIComponent('/models')}`)} /></Tooltip>
      <Tooltip title="选路策略在“模型路由”统一配置"><Button type="link" size="small" icon={<SwapOutlined />} onClick={() => navigate(`/model-routing?model=${encodeURIComponent(record.model_name)}`)}>路由</Button></Tooltip>
      <Popconfirm title="删除此模型？" onConfirm={() => deleteModelM.mutate(record.id)} okText="删除" cancelText="取消" okButtonProps={{ danger: true }} disabled={pending}><Button type="link" size="small" danger icon={<DeleteOutlined />} disabled={pending}>删除</Button></Popconfirm>
    </Space> },
  ]

  return <div>
    <div className="page-header"><Title level={4} style={{ margin: 0, fontSize: 20, fontWeight: 600 }}>模型管理</Title><Text type="secondary">管理已纳入的模型及其启用状态；目录候选只在模型上游同步时展示。价格只在“价格与成本”配置。</Text></div>
    <div className="content-card" style={{ padding: '16px 20px' }}>
      <div style={{ marginBottom: 14, display: 'flex', justifyContent: 'flex-end' }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => { createForm.resetFields(); setCreateOpen(true) }}>手动添加模型</Button>
      </div>
      <div style={{ marginBottom: 14, display: 'flex', gap: 16 }}><span><Text strong>当前可调用模型</Text>：{callableModelCount}（{activeModels.length} 个上游来源）</span>{retainedModels.length > 0 && <span><Text strong>其他状态与保留</Text>：{retainedModels.length}</span>}<Text type="secondary">模型价格在“价格与成本”统一管理，不在此处展示或编辑。</Text></div>
      {retainedModels.length > 0 && <Tabs activeKey={modelScope} onChange={(key) => { setModelScope(key as 'active' | 'retained' | 'all'); setSelectedRowKeys([]) }} items={[{ key: 'active', label: `可调用来源 ${activeModels.length}` }, { key: 'retained', label: `其他状态与保留 ${retainedModels.length}` }, { key: 'all', label: `全部记录 ${models.length}` }]} />}
      {(providerFilter || modelFilter) && <Space wrap style={{ marginBottom: 12 }}><Tag>已按{modelFilter ? '模型' : '上游'}筛选</Tag><Button size="small" onClick={() => { setSearchParams({}); setSelectedRowKeys([]) }}>清除筛选</Button><Button size="small" icon={<BarChartOutlined />} onClick={() => navigate(`/model-operations?${searchParams.toString()}&return_to=${encodeURIComponent('/models')}`)}>模型运营</Button></Space>}
      {visibleModels.length > 0 && <div style={{ marginBottom: 12, padding: '8px 12px', background: 'var(--bg-secondary)', borderRadius: 6, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
        <Text type="secondary">已选 {selectedRowKeys.length} / 当前视图 {visibleModels.length}</Text>
        <Space>
          <Button size="small" icon={<PlayCircleOutlined />} disabled={!selectedRowKeys.length || selectedRowKeys.length > 50 || pending} onClick={() => setProbeModels(models.filter((model) => selectedRowKeys.includes(model.id)).map((model) => ({ ...model, provider_type: providerMap[model.provider_id]?.provider_type })))}>批量验证</Button>
          {modelScope === 'retained' && <Popconfirm title={`确认将选中的 ${selectedRowKeys.length} 个模型重新启用？`} onConfirm={() => { batchEnableM.mutate(selectedRowKeys.map(String)); setSelectedRowKeys([]) }} disabled={!selectedRowKeys.length || pending}><Button size="small" icon={<CheckCircleOutlined />} disabled={!selectedRowKeys.length || pending} loading={batchEnableM.isPending}>批量重新启用</Button></Popconfirm>}
          <Popconfirm title={`确认处理选中的 ${selectedRowKeys.length} 个模型？`} description={`其中当前启用 ${selectedActiveCount} 个；有历史引用的模型将自动停用保留，不会删除历史记录。`} onConfirm={handleBatchDelete} okText="确认删除" okButtonProps={{ danger: true }} cancelText="取消" disabled={!selectedRowKeys.length || pending}><Button size="small" danger icon={<DeleteOutlined />} disabled={!selectedRowKeys.length || pending} loading={batchDeleteM.isPending}>批量删除</Button></Popconfirm>
        </Space>
      </div>}
      <Table columns={columns} dataSource={visibleModels} rowKey="id" loading={modelQ.isLoading} scroll={{ x: 920 }} rowSelection={{ selectedRowKeys, onChange: (keys) => { if (!pending) setSelectedRowKeys(keys) }, getCheckboxProps: () => ({ disabled: pending }) }} pagination={{ defaultPageSize: 10, showSizeChanger: true, showTotal: (count) => `当前视图 ${count} 条` }} />
    </div>
    <ModelProbeDialog open={probeModels !== null} models={probeModels || []} onClose={() => setProbeModels(null)} />
    <Modal title="手动添加模型" open={createOpen} onCancel={() => setCreateOpen(false)} footer={null} width={520}>
      <Form form={createForm} layout="vertical" initialValues={{ protocols: ['auto'] }} onFinish={(values) => {
        const protocols = Array.isArray(values.protocols) ? values.protocols.filter((value: string) => value !== 'auto') : []
        createModelM.mutate({ ...values, protocols: protocols.length ? protocols : undefined })
      }} style={{ marginTop: 16 }}>
        <Form.Item name="provider_id" label="模型上游" rules={[{ required: true, message: '请选择模型上游' }]}>
          <Select placeholder="请选择模型上游" onChange={(id) => { if (['gemini', 'vertex', 'bedrock'].includes(providerMap[id]?.provider_type || '')) createForm.setFieldValue('protocols', ['auto']) }} options={providers.filter((p) => p.status !== 'disabled').map((p) => ({ value: p.id, label: `${p.name}${p.provider_type === 'gemini' || p.provider_type === 'vertex' ? '（Vertex AI / Gemini）' : ''}` }))} />
        </Form.Item>
        <Form.Item name="model_name" label="对外模型名称" rules={[{ required: true, message: '请输入对外模型名称' }]}>
          <Input placeholder="例如：gemini-2.5-flash" />
        </Form.Item>
        <Form.Item name="upstream_model_id" label="上游模型 ID" extra="留空时沿用对外模型名称；Vertex Gemini 可填写 gemini-2.5-flash。">
          <Input placeholder="例如：gemini-2.5-flash" />
        </Form.Item>
        <Form.Item name="model_label" label="显示名称">
          <Input placeholder="例如：Gemini 2.5 Flash" />
        </Form.Item>
        <Form.Item name="protocols" label="上游协议" extra={nativeCreateProvider ? '将使用已保存的上游凭据发送最小原生生成请求；验证成功后才登记网关聊天能力。' : '自动检测会真实验证上游支持的协议，仅保存验证成功的能力。'}>
          <Checkbox.Group options={[
            { label: nativeCreateProvider ? '验证原生生成能力' : '自动检测', value: 'auto' },
            { label: 'Chat Completions', value: 'chat_completions' },
            { label: 'Responses', value: 'responses' },
            { label: 'Anthropic Messages', value: 'anthropic_messages' },
            { label: 'Gemini', value: 'gemini' },
            { label: '图像生成', value: 'images' },
            { label: '向量嵌入', value: 'embeddings' },
          ].filter(option => !nativeCreateProvider || option.value === 'auto')} />
        </Form.Item>
        <Space style={{ width: '100%', justifyContent: 'flex-end' }}><Button onClick={() => setCreateOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={createModelM.isPending}>添加并启用</Button></Space>
      </Form>
    </Modal>
    <Drawer title={detailModel ? `接入说明 · ${detailModel.model_label || detailModel.model_name || ''}` : '接入说明'} width={560} open={!!detailModel} onClose={() => setDetailModel(null)} destroyOnClose>
      {detailModel && <>
        <Alert type="info" showIcon style={{ marginBottom: 16 }} message="调用方连接的是网关公开地址" description="上游供应商地址与上游凭据由平台统一保管，不会出现在调用配置里；请配合「密钥管理」创建的网关密钥使用。" />
        <Descriptions size="small" column={1} bordered style={{ marginBottom: 16 }}>
          <Descriptions.Item label="对外模型名称"><Text code>{detailModel.model_name}</Text></Descriptions.Item>
          {detailModel.model_label ? <Descriptions.Item label="显示名称">{detailModel.model_label}</Descriptions.Item> : null}
          {detailModel.upstream_model_id ? <Descriptions.Item label="上游模型 ID"><Text code>{detailModel.upstream_model_id}</Text></Descriptions.Item> : null}
          <Descriptions.Item label="上游渠道">{providerMap[detailModel.provider_id]?.name || '已删除或不可见供应商'}</Descriptions.Item>
          <Descriptions.Item label="状态">{<Tag>{detailModel.availability_state || detailModel.status}</Tag>}</Descriptions.Item>
        </Descriptions>
        <Text strong>调用地址</Text>
        {settingsQ.isPending ? <div style={{ marginTop: 8 }}><Text type="secondary">正在读取网关公开地址…</Text></div>
          : (() => {
              const configuredBase = gatewayAccess.url
              if (settingsQ.isError || !configuredBase) {
                return <Alert type="warning" showIcon style={{ marginTop: 8 }} message="调用地址读取失败" description="请刷新重试或联系管理员。" />
              }
              const protocolFlags = detailModel.capabilities?.protocols
              const configuredProtocols = protocolFlags && typeof protocolFlags === 'object' && !Array.isArray(protocolFlags)
                ? Object.keys(PROTOCOL_LABELS).filter((value) => protocolFlags[value === 'responses' ? 'responses_native' : value] === true)
                : []
              const exampleEntries = configuredProtocols.filter((value: string) => PROTOCOL_EXAMPLES[value])
              const otherProtocols = configuredProtocols.filter((value: string) => !PROTOCOL_EXAMPLES[value])
              return <Space direction="vertical" size={12} style={{ width: '100%', marginTop: 8 }}>
                <GatewayAccess access={gatewayAccess}/>
                <Text type="secondary" style={{ fontSize: 12 }}>鉴权：请求头携带 <Text code>Authorization: Bearer ${API_KEY_ENV_NAME}</Text>；密钥在「密钥管理」创建，请保存到环境变量 {API_KEY_ENV_NAME}，不要写进代码或仓库。</Text>
                {exampleEntries.length === 0 && otherProtocols.length === 0
                  ? <Space wrap>
                    <Text type="secondary">调用协议待验证</Text>
                    <Button type="link" icon={<BarChartOutlined aria-hidden="true" />} onClick={() => navigate(`/model-operations?model_id=${encodeURIComponent(detailModel.id)}&provider_id=${encodeURIComponent(detailModel.provider_id)}&return_to=${encodeURIComponent('/models')}`)}>模型运营</Button>
                  </Space>
                  : null}
                {exampleEntries.map((value: string) => {
                  const example = PROTOCOL_EXAMPLES[value]
                  const endpoint = buildGatewayEndpoint(example.path, configuredBase)
                  if (!endpoint) return null
                  return <div key={value}>
                    <Space size={8} wrap style={{ marginBottom: 4 }}>
                      <Tag color="blue">{example.label}</Tag>
                      <Text code copyable style={{ fontSize: 12 }}>{endpoint}</Text>
                    </Space>
                    <Input.TextArea readOnly autoSize={{ minRows: 4, maxRows: 12 }} value={buildCurlExample(endpoint, example.body(detailModel.model_name))} style={{ fontFamily: 'monospace', fontSize: 12 }} />
                  </div>
                })}
                {otherProtocols.length > 0 && <Alert type="info" showIcon message={`协议配置：${otherProtocols.map((value: string) => PROTOCOL_LABELS[value]).join('、')}`} description="这些协议暂无内置调用示例，请按网关协议文档接入。" />}
              </Space>
            })()}
      </>}
    </Drawer>
  </div>
}
export default ModelManagement

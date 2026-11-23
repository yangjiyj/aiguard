import { useState } from 'react'
import { Alert, Table, Button, Space, Modal, Form, Input, Select, Segmented, message, Typography, Tag, Popconfirm, Tooltip, Divider, Grid } from 'antd'
import { PlusOutlined, EditOutlined, SyncOutlined, DeleteOutlined, RollbackOutlined, PlayCircleOutlined, BarChartOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import dayjs from 'dayjs'
import { providerApi, modelApi } from '../services/api'
import type { ModelCatalogSyncResult } from '../services/api'
import { extractApiError } from '../utils/apiError'
import { formatLatencySeconds } from '../utils/modelProbe'
import ProviderIdentity from '../components/providers/ProviderIdentity'
import AzureModelSyncModal from '../components/providers/AzureModelSyncModal'
import ModelCatalogSyncModal from '../components/providers/ModelCatalogSyncModal'
import ModelProbeDialog, { type ProbeModel } from '../components/ModelProbeDialog'

const { Title, Text } = Typography
interface Provider { id: string; name: string; provider_type: string; base_url: string; auth_mode?: string; has_credential: boolean; credential_updated_at?: string; status: string }
interface DeletedProvider { id: string; name: string; provider_type: string; has_credential: boolean; status: 'deleted' }
interface ProviderMetrics { provider_id: string; route_count: number; avg_ttft_ms: number | null; samples: number; failing_route_count: number; auth_failures: number }
const ptColor: Record<string, string> = { openai: 'green', anthropic: 'purple', azure: 'blue', bedrock: 'orange', gemini: 'cyan', vertex: 'cyan', deepseek: 'geekblue', moonshot: 'magenta', kimi: 'magenta', zhipu: 'volcano', minimax: 'lime', qwen: 'cyan', hunyuan: 'blue', doubao: 'purple', newapi: 'gold', openrouter: 'blue', xinference: 'cyan' }
const ptLabel: Record<string, string> = { openai: 'OpenAI', anthropic: 'Anthropic', azure: 'Azure OpenAI', bedrock: 'AWS Bedrock', gemini: 'Google Vertex AI / Gemini', deepseek: 'DeepSeek', moonshot: 'Moonshot', kimi: 'Kimi', zhipu: '智谱GLM', minimax: 'MiniMax', qwen: '阿里千问', hunyuan: '腾讯混元', doubao: '字节豆包', newapi: 'NewAPI 上游', openrouter: 'OpenRouter', xinference: 'Xinference' }
ptLabel.vertex = 'Google Vertex AI'
const defaultUrls: Record<string, string> = {
  openai: 'https://api.openai.com',
  anthropic: 'https://api.anthropic.com',
  azure: '',
  bedrock: 'https://bedrock-runtime.us-east-1.amazonaws.com',
  gemini: 'https://generativelanguage.googleapis.com',
  vertex: 'https://us-central1-aiplatform.googleapis.com',
  deepseek: 'https://api.deepseek.com',
  moonshot: 'https://api.moonshot.cn/v1',
  kimi: 'https://api.kimi.com/coding/v1',
  zhipu: 'https://open.bigmodel.cn/api/paas/v4',
  minimax: 'https://api.minimax.chat/v1',
  qwen: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
  hunyuan: 'https://api.hunyuan.cloud.tencent.com/v1',
  doubao: 'https://ark.cn-beijing.volces.com/api/v3',
  newapi: '',
  openrouter: 'https://openrouter.ai/api/v1',
  xinference: '',
  custom: '',
}

function Providers() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const providerFilter = searchParams.get('provider_id')
  const screens = Grid.useBreakpoint()
  const isNarrow = screens.md === false
  const [modalOpen, setModalOpen] = useState(false)
  const [editProv, setEditProv] = useState<Provider | null>(null)
  const [azureSyncProvider, setAzureSyncProvider] = useState<Provider | null>(null)
  const [catalogSyncProvider, setCatalogSyncProvider] = useState<Provider | null>(null)
  const [historyOpen, setHistoryOpen] = useState(false)
  const [trashOpen, setTrashOpen] = useState(false)
  const [historyProvider, setHistoryProvider] = useState<Provider | null>(null)
  const [recoveryNotice, setRecoveryNotice] = useState('')
  const [testProvider, setTestProvider] = useState<Provider | null>(null)
  const [form] = Form.useForm()
  const selectedProviderType = Form.useWatch('provider_type', form) as string | undefined
  const accessMode = (Form.useWatch('access_mode', form) as string | undefined) || 'standard'
  const isCompleteChat = accessMode === 'complete_chat'
  const isGeminiProvider = selectedProviderType === 'gemini' || selectedProviderType === 'vertex'
  const isVertexProvider = selectedProviderType === 'vertex'
  const isBedrockProvider = selectedProviderType === 'bedrock'

  const provQ = useQuery({ queryKey: ['providers'], queryFn: () => providerApi.list() })
  const testModelsQ = useQuery({ queryKey: ['models'], queryFn: () => modelApi.list(), enabled: testProvider !== null })
  const metricsQ = useQuery({ queryKey: ['provider-metrics'], queryFn: () => providerApi.metrics(), refetchInterval: 60_000 })
  const deletedQ = useQuery({ queryKey: ['deleted-providers'], queryFn: () => providerApi.deleted(), enabled: trashOpen })
  const historyQ = useQuery({
    queryKey: ['provider-credential-history', historyProvider?.id],
    enabled: historyOpen && !!historyProvider?.id,
    queryFn: () => providerApi.history(historyProvider!.id),
  })

  const createM = useMutation({
  mutationFn: (d: { name: string; provider_type: string; base_url: string; api_key?: string; auth_mode?: string; model_id?: string }) => providerApi.create(d),
    onSuccess: () => { message.success('渠道创建成功'); qc.invalidateQueries({ queryKey: ['providers'] }); setModalOpen(false); form.resetFields() },
    onError: (error: any) => {
      if (error.response?.data?.error?.code === 'provider_unsupported') { message.warning('当前版本暂未适配该原生渠道') } else { message.error(extractApiError(error) || '创建失败') }
    },
  })
  const updateM = useMutation({
    mutationFn: (d: { id: string; name?: string; base_url?: string; api_key?: string; status?: string }) => providerApi.update(d.id, d),
    onSuccess: () => { message.success('更新成功'); qc.invalidateQueries({ queryKey: ['providers'] }); setModalOpen(false); setEditProv(null); form.resetFields() },
    onError: (error: any) => message.error(extractApiError(error) || '更新失败'),
  })
  const deleteProviderM = useMutation({
    mutationFn: (id: string) => providerApi.delete(id),
    onSuccess: () => { message.success('渠道已删除'); qc.invalidateQueries({ queryKey: ['providers'] }); qc.invalidateQueries({ queryKey: ['deleted-providers'] }); qc.invalidateQueries({ queryKey: ['models'] }) },
    onError: (error: any) => message.error(extractApiError(error) || '删除失败，请稍后重试'),
  })
  const restoreProviderM = useMutation({
    mutationFn: (id: string) => providerApi.restore(id),
    onSuccess: async () => {
      setRecoveryNotice('模型上游恢复成功，请同步模型并重新保存默认路由。')
      await Promise.all([
        qc.invalidateQueries({ queryKey: ['providers'] }),
        qc.invalidateQueries({ queryKey: ['deleted-providers'] }),
        qc.invalidateQueries({ queryKey: ['models'] }),
        qc.invalidateQueries({ queryKey: ['model-routing'] }),
      ])
    },
    onError: (error: any) => message.error(extractApiError(error) || '恢复失败，请新增模型上游。'),
  })
  // 同步结果由弹窗回传：这里只负责刷新受影响的缓存并给出回执，
  // 保证「模型管理」页看到的是同步后的真实清单。
  const handleCatalogSynced = (result: ModelCatalogSyncResult) => {
    const notify = result.verification_failed ? message.warning : message.success
    notify(
      `${result.verification_failed ? '目录已同步，部分模型验证失败' : '同步完成'}: 新增 ${result.created}, 更新 ${result.updated}, 协议验证 ${result.verified || 0}, 沿用验证 ${result.reused || 0}, 移除 ${result.deactivated || 0}`
      + `, 验证失败 ${result.verification_failed || 0}, 跳过 ${result.skipped}`
      + (result.not_found_model_ids && result.not_found_model_ids.length > 0
        ? `, 上游已不存在 ${result.not_found_model_ids.length}`
        : '')
    )
    qc.invalidateQueries({ queryKey: ['models'] })
  }

  const metricsList: ProviderMetrics[] = Array.isArray(metricsQ.data?.data?.data) ? metricsQ.data.data.data : []
  const metricsByProvider = new Map(metricsList.map((m) => [m.provider_id, m]))

  const provCols = [
    { title: '渠道名称', dataIndex: 'name', key: 'name', width: 150, render: (v: string, r: Provider) => <ProviderIdentity providerType={r.provider_type} name={v} strong /> },
    { title: '类型', dataIndex: 'provider_type', key: 'provider_type', width: 120, render: (t: string) => <Tag color={ptColor[t] || 'default'}>{ptLabel[t] || t}</Tag> },
    { title: 'API 地址', dataIndex: 'base_url', key: 'base_url', ellipsis: true, render: (v: string) => <Tooltip title={v}><Text style={{ fontSize: 12 }}>{v}</Text></Tooltip> },
    { title: '凭据', dataIndex: 'has_credential', key: 'has_credential', width: 150, render: (v: boolean, r: Provider) => {
      const m = metricsByProvider.get(r.id)
      return (
        <Space size={4} direction="vertical" style={{ lineHeight: 1.2 }}>
          <Tag color={v ? 'green' : 'default'}>{v ? '已配置' : '未配置'}</Tag>
          {v && m && m.auth_failures > 0 && (
            <Tooltip title={`近 30 分钟有 ${m.auth_failures} 次 401/403 鉴权失败，API Key 可能已失效，请检查或轮换凭据`}>
              <Tag color="error">近期鉴权失败 {m.auth_failures} 次</Tag>
            </Tooltip>
          )}
        </Space>
      )
    } },
    { title: '凭据更新时间', dataIndex: 'credential_updated_at', key: 'credential_updated_at', width: 170, render: (v: string | undefined, r: Provider) => {
      if (!r.has_credential) return <Text style={{ color: 'var(--text-tertiary)' }}>未配置</Text>
      return v ? <Text style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{dayjs(v).format('YYYY-MM-DD HH:mm:ss')}</Text> : <Text style={{ color: 'var(--text-tertiary)' }}>未知</Text>
    } },
    { title: '线路数', key: 'route_count', width: 80, align: 'right' as const, render: (_: any, r: Provider) => {
      const m = metricsByProvider.get(r.id)
      return m ? m.route_count : '-'
    } },
    { title: '近30分钟失败线路', key: 'failing_route_count', width: 130, align: 'right' as const, render: (_: any, r: Provider) => {
      const m = metricsByProvider.get(r.id)
      if (!m || m.samples === 0) return <Text style={{ color: 'var(--text-tertiary)' }}>-</Text>
      return m.failing_route_count > 0
        ? <Text type="danger">{m.failing_route_count} 条</Text>
        : <Text style={{ color: 'var(--text-secondary)' }}>0 条</Text>
    } },
    { title: '平均首Token延迟', key: 'avg_ttft_ms', width: 130, align: 'right' as const, render: (_: any, r: Provider) => {
      const m = metricsByProvider.get(r.id)
      if (!m || m.avg_ttft_ms == null) return <Text style={{ color: 'var(--text-tertiary)' }}>-</Text>
      return formatLatencySeconds(m.avg_ttft_ms)
    } },
    { title: '状态', dataIndex: 'status', key: 'status', width: 80, render: (s: string) => <Tag color={s === 'active' ? 'success' : 'default'}>{s === 'active' ? '启用' : '禁用'}</Tag> },
    { title: '操作', key: 'action', width: isNarrow ? 350 : 520, fixed: isNarrow ? undefined : 'right' as const, render: (_: any, r: Provider) => (
      <Space size={4} wrap={isNarrow}>
        <Tooltip title={r.has_credential ? '验证指定模型' : '先配置凭据才能验证'}><Button type="text" size="small" aria-label={`验证上游 ${r.name}`} icon={<PlayCircleOutlined />} disabled={!r.has_credential} onClick={() => setTestProvider(r)} /></Tooltip>
        <Tooltip title="模型验证与运营历史"><Button type="text" size="small" aria-label={`运营上游 ${r.name}`} icon={<BarChartOutlined />} onClick={() => navigate(`/model-operations?provider_id=${encodeURIComponent(r.id)}&return_to=${encodeURIComponent('/providers')}`)} /></Tooltip>
        <Button type="link" size="small" onClick={() => navigate(`/model-routing?provider=${r.id}`)}>查看线路</Button>
    <Button type="link" size="small" icon={<EditOutlined />} onClick={() => {
      setEditProv(r)
      form.setFieldsValue({ ...r, access_mode: r.auth_mode === 'authorization_raw' ? 'complete_chat' : 'standard' })
      setModalOpen(true)
    }}>编辑</Button>
        <Button type="link" size="small" onClick={() => { setHistoryProvider(r); setHistoryOpen(true) }}>凭据历史</Button>
    {r.auth_mode === 'authorization_raw' ? (
      <Tooltip title="完整 Chat 接口已在接入时验证模型">
      <Tag color="blue">无需同步</Tag>
      </Tooltip>
    ) : <Tooltip title={r.status !== 'active' ? '请先启用该渠道再同步模型' : r.has_credential && ['gemini', 'vertex', 'bedrock'].includes(r.provider_type) ? '该类型的模型请在“模型管理”里手动添加' : r.has_credential ? '从上游拉取模型目录，再选择要同步哪些模型' : r.provider_type === 'gemini' ? '请先配置服务账号 JSON' : r.provider_type === 'bedrock' ? '请先配置 AWS 凭据 JSON' : '请先配置 API Key 再同步模型'}>
          <Button
            type="link"
            size="small"
            icon={<SyncOutlined />}
            disabled={r.provider_type === 'gemini' || r.provider_type === 'vertex' || r.provider_type === 'bedrock' || !r.has_credential || r.status !== 'active'}
            onClick={() => {
              // Azure 需要逐个 deployment 验证后才能纳入，走专用弹窗；
              // 其他渠道统一走"拉目录 → 勾选 → 同步"。
              if (r.provider_type === 'azure') {
                setAzureSyncProvider(r)
                return
              }
              setCatalogSyncProvider(r)
            }}
          >
            同步模型
          </Button>
    </Tooltip>}
        <Popconfirm title="删除此渠道?" description="删除后该渠道及关联模型将停止使用；历史审计和费用记录仍会保留。确定要删除吗?" onConfirm={() => deleteProviderM.mutate(r.id)} okText="删除" cancelText="取消" okType="danger">
          <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
        </Popconfirm>
      </Space>
    )},
  ]

  const _provRaw = provQ.data?.data
  const provData: Provider[] = Array.isArray(_provRaw?.items) ? _provRaw.items
                 : Array.isArray(_provRaw?.data) ? _provRaw.data
                 : Array.isArray(_provRaw) ? _provRaw
                 : []
  const deletedRaw = deletedQ.data?.data
  const deletedProviders: DeletedProvider[] = Array.isArray(deletedRaw?.items) ? deletedRaw.items : []
  const deletedColumns = [
    { title: '渠道名称', dataIndex: 'name', key: 'name', render: (value: string, provider: DeletedProvider) => <ProviderIdentity providerType={provider.provider_type} name={value} strong /> },
    { title: '类型', dataIndex: 'provider_type', key: 'provider_type', render: (value: string) => <Tag>{ptLabel[value] || value}</Tag> },
    { title: '历史凭据', dataIndex: 'has_credential', key: 'has_credential', render: (value: boolean) => value ? <Tag color="green">可恢复</Tag> : <Tag>不可恢复</Tag> },
    { title: '操作', key: 'action', width: 140, render: (_: unknown, provider: DeletedProvider) => <Button type="link" icon={<RollbackOutlined />} disabled={!provider.has_credential} loading={restoreProviderM.isPending && restoreProviderM.variables === provider.id} onClick={() => restoreProviderM.mutate(provider.id)}>恢复上游</Button> },
  ]
  const _historyDataRaw = historyQ.data?.data
  const historyData = Array.isArray(_historyDataRaw?.items) ? _historyDataRaw.items
                    : Array.isArray(_historyDataRaw?.data) ? _historyDataRaw.data
                    : Array.isArray(_historyDataRaw) ? _historyDataRaw
                    : []
  const historyCols = [
    { title: '凭据ID', dataIndex: 'id', key: 'id', width: 120, ellipsis: true },
    { title: '名称', dataIndex: 'name', key: 'name', width: 120 },
    { title: '状态', dataIndex: 'status', key: 'status', width: 100, render: (s: string) => <Tag color={s === 'active' ? 'green' : s === 'rotated' ? 'gold' : 'default'}>{s}</Tag> },
    { title: '轮换时间', dataIndex: 'rotated_at', key: 'rotated_at', width: 170, render: (v: string | undefined) => v || <Text style={{ color: 'var(--text-tertiary)' }}>-</Text> },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 170 },
  ]

  const testRaw = testModelsQ.data?.data
  const testModels: ProbeModel[] = (Array.isArray(testRaw?.items) ? testRaw.items : Array.isArray(testRaw?.data) ? testRaw.data : Array.isArray(testRaw) ? testRaw : []).filter((model: ProbeModel) => model.provider_id === testProvider?.id).map((model: ProbeModel) => ({ ...model, provider_type: testProvider?.provider_type }))

  return (
    <div>
      <div className="page-header">
        <Title level={4} style={{ margin: 0, fontSize: 20, fontWeight: 600, color: 'var(--text-primary)' }}>模型上游</Title>
        <Text style={{ fontSize: 13, color: 'var(--text-secondary)' }}>配置 AI 服务提供商的 API 接入并同步模型目录；模型的定价与纳入开关在「模型管控 · 模型管理」，选路策略与容灾在「模型管控 · 模型路由」</Text>
      </div>
      {recoveryNotice && <Alert style={{ marginBottom: 16 }} type="success" showIcon closable onClose={() => setRecoveryNotice('')} message={recoveryNotice} />}
      <div className="content-card" style={{ padding: '16px 20px' }}>
        <div style={{ marginBottom: 14, display: 'flex', justifyContent: 'space-between' }}>
          <Text style={{ color: 'var(--text-secondary)' }}>配置 AI 服务提供商的 API 接入；根据渠道类型填写 API Key、服务账号 JSON 或 AWS 凭据 JSON</Text>
          <Space><Button aria-label="回收站" icon={<DeleteOutlined />} onClick={() => setTrashOpen(true)}>回收站</Button><Button type="primary" icon={<PlusOutlined />} onClick={() => { setEditProv(null); form.resetFields(); form.setFieldsValue({ access_mode: 'standard' }); setModalOpen(true) }}>添加渠道</Button></Space>
        </div>
        {providerFilter && <Space style={{ marginBottom: 12 }}><Tag>已按上游筛选</Tag><Button size="small" onClick={() => setSearchParams({})}>清除筛选</Button></Space>}
        <Table columns={provCols} dataSource={provData.filter((provider) => !providerFilter || provider.id === providerFilter)} rowKey="id" loading={provQ.isLoading} scroll={{ x: 'max-content' }} pagination={{ defaultPageSize: 10, showSizeChanger: true, showTotal: (t) => `共 ${t} 条` }} />
      </div>
      <Modal title="上游回收站" open={trashOpen} onCancel={() => setTrashOpen(false)} footer={null} width={760}>
        <Table columns={deletedColumns} dataSource={deletedProviders} rowKey="id" loading={deletedQ.isLoading} pagination={{ pageSize: 10 }} locale={{ emptyText: '回收站为空' }} />
      </Modal>

      <Modal title={editProv ? '编辑渠道' : '添加上游渠道'} open={modalOpen} onCancel={() => setModalOpen(false)} footer={null} width={520}>
    <Form form={form} onFinish={(values) => {
      const fields = { ...values }
      delete fields.access_mode
      if (editProv) {
      updateM.mutate({ ...fields, id: editProv.id })
      return
      }
      createM.mutate(isCompleteChat
      ? { ...fields, provider_type: 'custom', auth_mode: 'authorization_raw' }
      : fields)
    }} layout="vertical" style={{ marginTop: 16 }}>
      <Form.Item name="access_mode" label="接入方式" initialValue="standard">
      <Segmented block disabled={!!editProv} options={[
        { value: 'standard', label: '标准 API 根地址' },
        { value: 'complete_chat', label: '完整 Chat 接口' },
      ]} onChange={(value) => {
        if (value === 'complete_chat') form.setFieldsValue({ provider_type: 'custom', base_url: '', api_key: '', model_id: '' })
      }} />
      </Form.Item>
          <Form.Item name="name" label="渠道名称" rules={[{ required: true, message: '请输入渠道名称' }]}>
            <Input placeholder="例如: OpenAI 官方、DeepSeek 官方" />
          </Form.Item>
      {!isCompleteChat && <>
          <Form.Item name="provider_type" label="渠道类型" rules={[{ required: true, message: '请选择渠道类型' }]}>
            <Select placeholder="选择提供商类型" options={[
              { value: 'openai', label: 'OpenAI' },
              { value: 'anthropic', label: 'Anthropic' },
              { value: 'deepseek', label: 'DeepSeek' },
              { value: 'moonshot', label: 'Moonshot (月之暗面)' },
              { value: 'kimi', label: 'Kimi Coding' },
              { value: 'newapi', label: 'NewAPI 上游（自动探测模型协议）' },
              { value: 'openrouter', label: 'OpenRouter' },
              { value: 'xinference', label: 'Xinference' },
              { value: 'azure', label: 'Azure OpenAI' },
              { value: 'bedrock', label: 'AWS Bedrock（AWS 凭据 JSON）' },
              { value: 'zhipu', label: '智谱 GLM' },
              { value: 'minimax', label: 'MiniMax' },
              { value: 'qwen', label: '阿里千问 Qwen' },
              { value: 'hunyuan', label: '腾讯混元' },
              { value: 'doubao', label: '字节豆包 Doubao' },
              { value: 'custom', label: '自定义 (自建中转)' },
              { value: 'gemini', label: 'Google Gemini（API Key / 服务账号 JSON）' },
              { value: 'vertex', label: 'Google Vertex AI' },
            ]}
            onChange={(val) => {
              form.setFieldsValue({ base_url: defaultUrls[val] || '' })
            }} />
          </Form.Item>
      </>}
      <Form.Item name="base_url" label={isCompleteChat ? '完整 Chat URL' : 'API 地址'} rules={[
      { required: true, message: isCompleteChat ? '请输入完整 Chat URL' : '请输入 API 地址' },
      ...(isCompleteChat ? [{ type: 'url' as const, message: '请输入有效的 HTTP(S) URL' }] : []),
      ]}>
            <Input placeholder="https://api.openai.com/v1" />
          </Form.Item>
      {isCompleteChat ? <>
      <Form.Item name="api_key" label="Authorization 值" rules={[{ required: !editProv, message: '请输入 Authorization 值' }]} extra={editProv?.has_credential ? '留空则保留当前值' : undefined}>
        <Input.Password autoComplete="new-password" placeholder="按厂商要求填写完整值，系统不会自动添加 Bearer" />
      </Form.Item>
      {!editProv && <Form.Item name="model_id" label="模型 ID" rules={[{ required: true, message: '请输入模型 ID' }]}>
        <Input placeholder="例如 vendor-model-72b" />
      </Form.Item>}
      </> : <>
          <Text style={{ display: 'block', margin: '-4px 0 8px', fontSize: 12, color: 'var(--text-tertiary)' }}>
            {isGeminiProvider ? (isVertexProvider ? 'Vertex AI 使用完整 GCP 服务账号 JSON；凭据将加密存储。' : 'Gemini 支持普通 API Key；接入 Vertex AI 地址时使用完整 GCP 服务账号 JSON。凭据将加密存储。') : isBedrockProvider ? '此渠道需要粘贴 AWS 凭据 JSON，不是普通 API Key；网关会使用其中的 Access Key、Secret Key 和 Region 签名请求。' : '此渠道使用 API Key，凭据将加密存储。'}
          </Text>
          <Form.Item name="api_key" label={isGeminiProvider ? (isVertexProvider ? '服务账号 JSON' : 'API Key / 服务账号 JSON') : isBedrockProvider ? 'AWS 凭据 JSON（Access Key + Secret Key）' : 'API Key'} extra={<Text style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>{isGeminiProvider ? (editProv?.has_credential ? '留空则保留当前凭据；填写新值将轮换凭据' : isVertexProvider ? '粘贴下载的完整服务账号 JSON' : '填写 Gemini API Key；Vertex 地址请粘贴完整服务账号 JSON') : isBedrockProvider ? (editProv?.has_credential ? '留空则保留当前 AWS 凭据 JSON；填写完整 JSON 将轮换凭据' : '粘贴完整 JSON，至少包含 access_key_id、secret_access_key、region，可选 session_token') : (editProv?.has_credential ? '留空则保留当前 API Key；填写新值将进行轮换，加密存储' : 'API Key 用于同步模型目录，加密存储')}</Text>}>
            {isGeminiProvider || isBedrockProvider ? (
              <Input.TextArea autoSize={{ minRows: 4, maxRows: 8 }} placeholder={isBedrockProvider ? '粘贴 AWS 凭据 JSON，例如 {"access_key_id":"...","secret_access_key":"...","region":"us-east-1"}' : isVertexProvider ? '粘贴完整的 GCP 服务账号 JSON（以 { 开头）' : 'Gemini API Key，或以 { 开头的完整服务账号 JSON'} />
            ) : (
              <Input.Password placeholder={editProv?.has_credential ? '留空保留当前凭据，填写则轮换' : 'sk-...'} />
            )}
          </Form.Item>
      </>}
          <Divider style={{ margin: '16px 0' }} />
          <div style={{ background: 'rgba(24,144,255,0.04)', padding: 12, borderRadius: 6, marginBottom: 16 }}>
            <Text style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
        {isCompleteChat ? '提交后会向该地址发送一次最小请求验证 URL、Authorization 和模型；验证成功才会接入。此类接口无需同步模型。' : isGeminiProvider ? '提示：Gemini 通道不支持同步模型目录。添加渠道后，请在「模型管控 · 模型管理」中手动添加模型，并填写上游模型 ID（例如 gemini-2.5-flash）。' : isBedrockProvider ? '提示：Bedrock 通道不支持同步模型目录。添加渠道后，请在「模型管控 · 模型管理」中手动添加模型，并填写上游模型 ID（例如 anthropic.claude-3-5-sonnet-20241022-v2:0）。' : '提示：添加渠道后，点击"同步模型"按钮从上游获取可用模型列表，然后在「模型管控 · 模型管理」中选择哪些模型纳入管理并设价，选路策略在「模型管控 · 模型路由」配置。'}
            </Text>
          </div>
          <Form.Item style={{ marginBottom: 0 }}>
            <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
              <Button onClick={() => setModalOpen(false)}>取消</Button>
              <Button type="primary" htmlType="submit" loading={createM.isPending || updateM.isPending}>
        {editProv ? '保存' : isCompleteChat ? '验证并接入' : isGeminiProvider || isBedrockProvider ? '添加渠道' : '添加并同步'}
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={`凭据历史 - ${historyProvider?.name || ''}`}
        open={historyOpen}
        onCancel={() => { setHistoryOpen(false); setHistoryProvider(null) }}
        footer={null}
        width={760}
      >
        <Table
          style={{ marginTop: 16 }}
          columns={historyCols}
          dataSource={historyData}
          rowKey="id"
          loading={historyQ.isLoading}
          pagination={{ defaultPageSize: 5, showSizeChanger: false }}
        />
      </Modal>

      {testProvider && <>
        {testModelsQ.isError ? <Modal title="验证指定模型" open onCancel={() => setTestProvider(null)} footer={<Button onClick={() => testModelsQ.refetch()}>重试</Button>}><Alert type="error" message="模型清单读取失败" showIcon /></Modal>
          : testModelsQ.isLoading ? <Modal title="验证指定模型" open onCancel={() => setTestProvider(null)} footer={null}><div role="status">正在读取模型</div></Modal>
          : <ModelProbeDialog open models={testModels} allowSelection onClose={() => setTestProvider(null)} />}
      </>}

      <AzureModelSyncModal
        provider={azureSyncProvider}
        open={azureSyncProvider !== null}
        onClose={() => setAzureSyncProvider(null)}
        onCommitted={() => {
          qc.invalidateQueries({ queryKey: ['models'] })
          qc.invalidateQueries({ queryKey: ['providers'] })
        }}
      />

      <ModelCatalogSyncModal
        provider={catalogSyncProvider}
        open={catalogSyncProvider !== null}
        onClose={() => setCatalogSyncProvider(null)}
        onSynced={handleCatalogSynced}
      />
    </div>
  )
}

export default Providers

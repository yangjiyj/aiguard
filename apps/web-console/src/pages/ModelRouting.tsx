import { useMemo, useRef, useState } from 'react'
import { Alert, Button, Card, Col, Empty, Input, Popconfirm, Result, Row, Skeleton, Space, Statistic, Table, Tag, Tooltip, Typography, message } from 'antd'
import { EditOutlined, SearchOutlined } from '@ant-design/icons'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import axios from 'axios'
import type { ColumnsType } from 'antd/es/table'
import RuleEditorDrawer from '../components/model-routing/RuleEditorDrawer'
import ProviderIdentity from '../components/providers/ProviderIdentity'
import { strategyLabel } from '../components/model-routing/routingLabels'
import {
  modelRoutingApi,
  type ModelRouteLineStatus,
  type ModelRoutingConfig,
  type ModelRoutingException,
  type ModelRoutingProviderOption,
  type ModelRoutingRule,
  type ModelRoutingStatusItem,
  type ModelRoutingValidationResult,
} from '../services/api'
import { useAuthStore } from '../stores/auth'
import { formatLatencySeconds } from '../utils/modelProbe'
import { configFingerprint, editorIdentity } from './modelRoutingState'

type EditorTarget =
  | { kind: 'default'; rule: ModelRoutingRule | null }
  | { kind: 'model'; modelName: string; rule?: ModelRoutingException }

function errorMessage(error: unknown, fallback: string): string {
  if (axios.isAxiosError(error) && error.response?.status === 409) return '配置已被其他管理员更新，请刷新页面后重新编辑。'
  if (axios.isAxiosError(error)) {
    const payload = error.response?.data as { error?: { message?: string }; message?: string } | undefined
    return payload?.error?.message || payload?.message || fallback
  }
  return fallback
}

const priceText = (line: ModelRouteLineStatus) => {
  if (line.input_per_million == null && line.output_per_million == null) return <Typography.Text type="secondary">未设置</Typography.Text>
  const parts = []
  if (line.input_per_million != null) parts.push(`输入 $${line.input_per_million}`)
  if (line.output_per_million != null) parts.push(`输出 $${line.output_per_million}`)
  return <Typography.Text>{parts.join(' / ')} / 百万 Token</Typography.Text>
}

function configForModel(base: ModelRoutingConfig | undefined, item: ModelRoutingStatusItem): ModelRoutingConfig {
  const byRef = new Map((base?.providers || []).map((provider) => [provider.route_ref, provider]))
  const providers = item.routes.map((route, index) => ({
    route_ref: route.route_ref,
    display_name: route.provider_name,
    enabled: byRef.get(route.route_ref)?.enabled ?? true,
    priority: byRef.get(route.route_ref)?.priority || index + 1,
    weight: byRef.get(route.route_ref)?.weight || Math.max(1, Math.floor(100 / item.routes.length)),
    relative_cost: byRef.get(route.route_ref)?.relative_cost,
    actual_cost: byRef.get(route.route_ref)?.actual_cost,
  }))
  const strategy = base?.strategy === 'weighted' || base?.strategy === 'smart' ? base.strategy : 'priority'
  return {
    strategy,
    objective: strategy === 'smart' ? (base?.objective || 'stability') : undefined,
    cost_basis: strategy === 'smart' && base?.objective === 'cost' ? (base.cost_basis || 'relative') : 'none',
    providers,
  }
}

export default function ModelRouting() {
  const client = useQueryClient()
  const navigate = useNavigate()
  const role = useAuthStore((state) => state.user?.role)
  const canWrite = role === 'platform_admin' || role === 'tenant_owner'
  const [searchParams, setSearchParams] = useSearchParams()
  const focusModel = searchParams.get('model') || ''
  const providerFilter = searchParams.get('provider') || ''

  const [editor, setEditor] = useState<EditorTarget | null>(null)
  const [query, setQuery] = useState(focusModel)
  const [validation, setValidation] = useState<ModelRoutingValidationResult>()
  const [validating, setValidating] = useState(false)
  const validationSequence = useRef(0)
  const validationAbort = useRef<AbortController>()
  const editorIdentityRef = useRef('')
  const currentFingerprint = useRef('')
  const validatedSnapshot = useRef<{ identity: string; fingerprint: string }>()

  const overviewQ = useQuery({ queryKey: ['model-routing'], queryFn: modelRoutingApi.overview })
  const statusQ = useQuery({
    queryKey: ['model-routing-status', query, providerFilter],
    queryFn: () => modelRoutingApi.status({ q: query || undefined, provider: providerFilter || undefined, min_route_count: 2, limit: 100 }),
  })
  const providersQ = useQuery({
    queryKey: ['model-routing-providers'],
    queryFn: modelRoutingApi.providers,
    enabled: editor?.kind === 'default',
  })

  const overview = overviewQ.data
  const rows = statusQ.data?.models || []
  const exceptionsByModel = useMemo(() => {
    const map = new Map<string, ModelRoutingException>()
    for (const item of overview?.model_exceptions || []) map.set(item.model_name, item)
    return map
  }, [overview?.model_exceptions])

  const currentItem = editor?.kind === 'model' ? rows.find((item) => item.model_name === editor.modelName) : undefined
  const editorProviderOptions = useMemo<ModelRoutingProviderOption[]>(() => {
    if (editor?.kind === 'default') return providersQ.data?.providers || []
    return (currentItem?.routes || []).map((route) => ({ route_ref: route.route_ref, display_name: route.provider_name }))
  }, [currentItem, editor?.kind, providersQ.data?.providers])
  const initialConfig = useMemo(() => {
    if (!editor) return { strategy: 'smart', objective: 'stability', cost_basis: 'none', providers: [] } as ModelRoutingConfig
    if (editor.kind === 'default') {
      const existing = editor.rule?.config
      const byRef = new Map((existing?.providers || []).map((provider) => [provider.route_ref, provider]))
      const providers = editorProviderOptions.map((provider, index) => ({
        route_ref: provider.route_ref,
        display_name: provider.display_name,
        enabled: byRef.get(provider.route_ref)?.enabled ?? true,
        priority: byRef.get(provider.route_ref)?.priority || index + 1,
        weight: byRef.get(provider.route_ref)?.weight || 100,
        relative_cost: byRef.get(provider.route_ref)?.relative_cost,
        actual_cost: byRef.get(provider.route_ref)?.actual_cost,
      }))
      return { strategy: existing?.strategy || 'smart', objective: existing?.strategy === 'smart' ? (existing.objective || 'stability') : undefined, cost_basis: existing?.cost_basis || 'none', providers }
    }
    if (!currentItem) return { strategy: 'priority', cost_basis: 'none', providers: [] } as ModelRoutingConfig
    return configForModel(editor.rule?.config || overview?.default_rule?.config, currentItem)
  }, [currentItem, editor, editorProviderOptions, overview?.default_rule?.config])

  const invalidateValidation = (config?: ModelRoutingConfig) => {
    validationSequence.current += 1
    validationAbort.current?.abort()
    validationAbort.current = undefined
    setValidating(false)
    setValidation(undefined)
    validatedSnapshot.current = undefined
    if (config) currentFingerprint.current = configFingerprint(config)
  }

  const openDefaultEditor = async () => {
    const result = await providersQ.refetch()
    if (result.isError || !result.data) {
      message.error('加载上游失败，请稍后重试。')
      return
    }
    invalidateValidation()
    editorIdentityRef.current = editorIdentity('default', '', overview?.default_rule?.config_version || 0)
    setEditor({ kind: 'default', rule: overview?.default_rule || null })
  }

  const openEditor = (item: ModelRoutingStatusItem) => {
    const rule = exceptionsByModel.get(item.model_name)
    const config = configForModel(rule?.config || overview?.default_rule?.config, item)
    invalidateValidation()
    currentFingerprint.current = configFingerprint(config)
    editorIdentityRef.current = editorIdentity('override', item.model_name, rule?.config_version || 0)
    setEditor({ kind: 'model', modelName: item.model_name, rule })
  }

  const closeEditor = () => {
    invalidateValidation()
    editorIdentityRef.current = ''
    setEditor(null)
  }

  const validateCurrent = async (config: ModelRoutingConfig) => {
    if (!editor) return
    invalidateValidation(config)
    const sequence = validationSequence.current
    const identity = editorIdentityRef.current
    const fingerprint = configFingerprint(config)
    const controller = new AbortController()
    validationAbort.current = controller
    setValidating(true)
    try {
      const result = await modelRoutingApi.validate(editor.kind === 'model' ? editor.modelName : undefined, config, controller.signal)
      if (controller.signal.aborted || sequence !== validationSequence.current || identity !== editorIdentityRef.current || fingerprint !== currentFingerprint.current) return
      setValidation(result)
      validatedSnapshot.current = { identity, fingerprint }
    } catch (error) {
      if (!controller.signal.aborted) message.error(errorMessage(error, '检查失败，请核对上游状态后重试。'))
    } finally {
      if (sequence === validationSequence.current) setValidating(false)
    }
  }

  const saveMut = useMutation({
    mutationFn: (config: ModelRoutingConfig) => {
      if (!editor) throw new Error('editor closed')
      if (editor.kind === 'default') return modelRoutingApi.saveDefault(editor.rule?.config_version || 0, config)
      return modelRoutingApi.saveOverride(editor.modelName, editor.rule?.config_version || 0, config)
    },
    onSuccess: async () => {
      message.success(editor?.kind === 'default' ? '系统默认负载方式已保存' : '负载方式已保存')
      closeEditor()
      await Promise.all([client.invalidateQueries({ queryKey: ['model-routing'] }), client.invalidateQueries({ queryKey: ['model-routing-status'] })])
    },
    onError: (error) => message.error(errorMessage(error, '保存失败，请稍后重试。')),
  })

  const clearConfigMut = useMutation({
    mutationFn: modelRoutingApi.deleteOverride,
    onSuccess: async () => {
      message.success('已恢复系统默认负载方式')
      await Promise.all([client.invalidateQueries({ queryKey: ['model-routing'] }), client.invalidateQueries({ queryKey: ['model-routing-status'] })])
    },
    onError: (error) => message.error(errorMessage(error, '恢复失败，请稍后重试。')),
  })

  const clearDefaultMut = useMutation({
    mutationFn: modelRoutingApi.deleteDefault,
    onSuccess: async () => {
      message.success('已清除系统默认路由')
      await Promise.all([client.invalidateQueries({ queryKey: ['model-routing'] }), client.invalidateQueries({ queryKey: ['model-routing-status'] })])
    },
    onError: (error) => message.error(errorMessage(error, '清除失败，请稍后重试。')),
  })

  const saveCurrent = (config: ModelRoutingConfig) => {
    const snapshot = validatedSnapshot.current
    if (!canWrite || !validation?.valid || !snapshot || snapshot.identity !== editorIdentityRef.current || snapshot.fingerprint !== configFingerprint(config) || snapshot.fingerprint !== currentFingerprint.current) {
      message.warning('配置已变化，请重新执行保存前检查。')
      invalidateValidation(config)
      return
    }
    saveMut.mutate(config)
  }

  const clearFocus = () => {
    searchParams.delete('model')
    searchParams.delete('provider')
    setSearchParams(searchParams, { replace: true })
    setQuery('')
  }

  if (overviewQ.isLoading) return <Skeleton active paragraph={{ rows: 8 }} />
  if (overviewQ.isError || !overview) return <Result status="error" title="模型路由加载失败" subTitle="未修改任何配置，请检查网络后重试。" extra={<Button onClick={() => overviewQ.refetch()}>重新加载</Button>} />

  const configuredCount = rows.filter((item) => exceptionsByModel.has(item.model_name)).length
  const defaultRouteInvalid = overview.default_rule?.invalid && overview.default_rule.invalid_reason === 'configured_route_removed'
  // 失效或已失去冗余意义的模型级规则：主表只展示多上游模型，这些残留必须在这里给出出口。
  const pendingExceptions = (overview.model_exceptions || []).filter((item) => item.invalid || !rows.some((row) => row.model_name === item.model_name))
  const defaultLabel = strategyLabel(overview.default_rule)
  const routeColumns: ColumnsType<ModelRouteLineStatus> = [
    { title: '上游', dataIndex: 'provider_name', key: 'provider_name', render: (value: string) => <ProviderIdentity name={value} strong /> },
    { title: '运行状态', key: 'health', width: 140, render: (_, line) => line.health_state === 'unhealthy' || line.failures_30m > 0 ? <Tag color="warning">近期波动</Tag> : line.health_state === 'healthy' ? <Tag color="success">正常</Tag> : <Tag>待产生调用数据</Tag> },
    { title: '最近延迟', key: 'ttft', width: 180, render: (_, line) => line.avg_ttft_ms != null ? formatLatencySeconds(line.avg_ttft_ms) : <Typography.Text type="secondary">暂无调用样本</Typography.Text> },
    { title: '参考成本', key: 'price', width: 250, render: (_, line) => <Tooltip title="成本数据仅在成本类策略中使用">{priceText(line)}</Tooltip> },
  ]
  const modelColumns: ColumnsType<ModelRoutingStatusItem> = [
    { title: '模型', dataIndex: 'model_name', key: 'model_name', render: (name: string) => <Typography.Text strong>{name}</Typography.Text> },
    { title: '可用上游', key: 'route_count', width: 150, render: (_, item) => <Tag color="blue">{item.route_count} 条路径</Tag> },
    {
      title: '负载方式', key: 'strategy', width: 250,
      render: (_, item) => {
        const rule = exceptionsByModel.get(item.model_name)
        if (rule?.invalid) return <Space direction="vertical" size={0}><Tag color="red">原配置已失效</Tag><Typography.Text type="secondary">可重新配置或恢复默认</Typography.Text></Space>
        return <Space direction="vertical" size={0}><Typography.Text>{rule ? strategyLabel(rule) : defaultLabel}</Typography.Text><Typography.Text type="secondary">{rule ? '该模型单独配置' : '使用系统默认'}</Typography.Text></Space>
      },
    },
    {
      title: '操作', key: 'action', width: 210,
      render: (_, item) => {
        const rule = exceptionsByModel.get(item.model_name)
        return <Space><Button type="link" disabled={!canWrite} onClick={() => openEditor(item)}>配置负载</Button>{rule && <Button type="link" disabled={!canWrite || clearConfigMut.isPending} onClick={() => clearConfigMut.mutate(item.model_name)}>恢复默认</Button>}</Space>
      },
    },
  ]

  const pendingColumns: ColumnsType<ModelRoutingException> = [
    { title: '模型', dataIndex: 'model_name', key: 'model_name', render: (name: string) => <Typography.Text strong>{name}</Typography.Text> },
    { title: '状态', key: 'state', width: 200, render: (_, item) => (item.invalid ? <Tag color="red">原配置已失效</Tag> : <Tag>已无多上游</Tag>) },
    {
      title: '操作', key: 'action', width: 160,
      render: (_, item) => (
        <Popconfirm title={`清除 ${item.model_name} 的模型级规则？`} okText="清除" okButtonProps={{ danger: true }} cancelText="取消" onConfirm={() => clearConfigMut.mutate(item.model_name)}>
          <Button type="link" danger disabled={!canWrite || clearConfigMut.isPending}>清除规则</Button>
        </Popconfirm>
      ),
    },
  ]

  return (
    <div className="model-routing-page">
      <header className="model-routing-header">
        <div><Typography.Title level={4}>模型路由</Typography.Title><Typography.Paragraph>当同一个模型接入多个上游时，在这里设置请求如何分配以及故障时如何切换。</Typography.Paragraph></div>
      </header>
      {!canWrite && <Alert type="info" showIcon message="只读查看" description="你可以查看多上游模型和负载方式，修改需要模型路由管理权限。" />}
      {defaultRouteInvalid && (
        <Alert
          style={{ marginTop: 16 }}
          type="error"
          showIcon
          message="默认路由已失效"
          description="默认路由引用的线路已删除或不可用。可以直接清除默认路由，单上游模型会继续直接调用，不受影响。"
          action={
            <Space>
              <Popconfirm
                title="清除默认路由？"
                description="清除后，未单独配置的多上游模型将回退到直接路由。"
                okText="清除"
                okButtonProps={{ danger: true }}
                cancelText="取消"
                onConfirm={() => clearDefaultMut.mutate()}
              >
                <Button danger type="primary" size="small" loading={clearDefaultMut.isPending}>清除默认路由</Button>
              </Popconfirm>
              <Button size="small" onClick={() => navigate('/providers')}>前往模型上游</Button>
            </Space>
          }
        />
      )}
      {!defaultRouteInvalid && !overview.outbound_route_available && (
        <Alert
          style={{ marginTop: 16 }}
          type="warning"
          showIcon
          message="当前没有可出站的模型线路"
          description="请先恢复或新增模型上游并同步至少一个可调用模型，然后配置并保存默认路由。"
          action={<Button onClick={() => navigate('/providers')}>前往模型上游</Button>}
        />
      )}
      <Row gutter={[16, 16]} style={{ margin: '16px 0' }}>
        <Col xs={24} md={8}><Card size="small"><Statistic title="多上游模型" value={rows.length} suffix="个" /></Card></Col>
        <Col xs={24} md={8}><Card size="small"><Statistic title="单独配置" value={configuredCount} suffix="个" /></Card></Col>
        <Col xs={24} md={8}>
          <Card size="small">
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'flex-start' }}>
              <div><Statistic title="系统默认方式" value={defaultLabel} /><Typography.Text type="secondary">未单独配置的多上游模型统一继承</Typography.Text></div>
              {canWrite && <Button type="link" icon={<EditOutlined />} aria-label="配置系统默认" onClick={openDefaultEditor}>配置</Button>}
            </div>
          </Card>
        </Col>
      </Row>
      {(focusModel || providerFilter) && <Alert style={{ marginBottom: 12 }} type="info" showIcon closable onClose={clearFocus} message={focusModel ? `正在查找多上游模型：${focusModel}` : '正在按上游筛选'} action={<Button size="small" onClick={clearFocus}>查看全部</Button>} />}
      <Card title="多上游模型" extra={<Input allowClear prefix={<SearchOutlined />} placeholder="搜索模型" value={query} onChange={(event) => setQuery(event.target.value)} style={{ width: 240 }} />}>
        <Table rowKey="model_name" columns={modelColumns} dataSource={rows} loading={statusQ.isLoading} pagination={{ defaultPageSize: 20, showTotal: (total) => `共 ${total} 个多上游模型` }} rowClassName={(item) => (focusModel && item.model_name === focusModel ? 'model-routing-focus-row' : '')} expandable={{ rowExpandable: (item) => item.routes.length > 0, expandedRowRender: (item) => <Table rowKey="route_ref" size="small" columns={routeColumns} dataSource={item.routes} pagination={false} /> }} locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={query ? '没有匹配的多上游模型' : '当前没有可配置的多上游模型；同名模型接入第 2 个上游后会自动显示'} /> }} />
      </Card>
      {pendingExceptions.length > 0 && (
        <Card title="待处理的模型级规则" style={{ marginTop: 16 }}>
          <Alert style={{ marginBottom: 12 }} type="warning" showIcon message="这些规则引用的模型当前不是多上游状态" description="删除上游后相关规则会自动清理；这里列出的是历史遗留配置，可以直接清除。" />
          <Table
            rowKey="model_name"
            size="small"
            pagination={false}
            dataSource={pendingExceptions}
            columns={pendingColumns}
          />
        </Card>
      )}
      <RuleEditorDrawer open={Boolean(editor)} scope={editor?.kind === 'default' ? 'default' : 'model'} modelName={editor?.kind === 'model' ? editor.modelName : undefined} initialConfig={initialConfig} providerOptions={editorProviderOptions} validating={validating} saving={saveMut.isPending} validation={validation} canSave={Boolean(validation?.valid && validatedSnapshot.current?.identity === editorIdentityRef.current && validatedSnapshot.current?.fingerprint === currentFingerprint.current)} onClose={closeEditor} onDirty={invalidateValidation} onValidate={validateCurrent} onSave={saveCurrent} />
    </div>
  )
}

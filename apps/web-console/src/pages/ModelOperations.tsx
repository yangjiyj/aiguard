import { useEffect, useState } from 'react'
import { Alert, Button, Checkbox, Descriptions, Drawer, Empty, Form, InputNumber, Popconfirm, Select, Space, Switch, Table, Tabs, Tag, Tooltip, Typography } from 'antd'
import { ArrowLeftOutlined, CheckOutlined, PlayCircleOutlined, ReloadOutlined, SaveOutlined } from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts'
import { modelApi, providerApi } from '../services/api'
import { modelOperationsApi, type ModelOperationAlert, type ModelOperationFilters, type ModelOperationTarget, type ModelOperationsConfig, type ModelProbeRecord, type ModelQualityItem, type ModelTargetSummary, type ProbeProtocol } from '../services/modelOperations'
import ModelProbeDialog, { type ProbeModel } from '../components/ModelProbeDialog'
import { modelOperationError, probeLatency, probeProtocolLabels, probeRecordPassed } from '../utils/modelProbe'
import ModelRequestDiagnostics from '../components/ModelRequestDiagnostics'
import ModelSLAMonthly from '../components/ModelSLAMonthly'
import ModelQualityView from '../components/ModelQualityView'
import ProviderMonitor from '../components/ProviderMonitor'
import { useAuthStore } from '../stores/auth'
import './ModelOperations.css'

const { Title, Text } = Typography
const readRows = (response: any): any[] => Array.isArray(response?.data?.items) ? response.data.items : Array.isArray(response?.data?.data) ? response.data.data : Array.isArray(response?.data) ? response.data : []
const targetKey = (target: ModelOperationTarget) => `${target.model_id}:${target.protocol}`
const time = (value?: string | null) => value && !Number.isNaN(new Date(value).getTime()) ? new Date(value).toLocaleString('zh-CN') : '未知'
const percentage = (value?: number | null) => value === null || value === undefined ? '未知' : `${(value * 100).toFixed(1)}%`
const number = (value?: number | null) => value === undefined || value === null ? '未知' : value.toLocaleString('zh-CN')
const stateMeta: Record<string, { text: string; color: string }> = {
  healthy: { text: '验证正常', color: 'green' }, degraded: { text: '验证异常', color: 'red' }, stale: { text: '证据过期', color: 'orange' }, unknown: { text: '未知', color: 'default' },
}
const stateTag = (state?: string) => { const meta = stateMeta[state || 'unknown'] || stateMeta.unknown; return <Tag color={meta.color}>{meta.text}</Tag> }

function CursorControls({ index, count, nextCursor, loading, onPrevious, onNext }: { index: number; count: number; nextCursor?: string | null; loading: boolean; onPrevious: () => void; onNext: () => void }) {
  return <div className="modelops-pagination"><Text type="secondary">第 {index + 1} 页 · 本页 {count} 条</Text><Space><Button disabled={index === 0 || loading} onClick={onPrevious}>上一页</Button><Button disabled={!nextCursor || loading} onClick={onNext}>下一页</Button></Space></div>
}

export function ModelOperationsSettings() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const principal = `${user?.tenant_id || 'unknown'}:${user?.id || 'unknown'}`
  const configQ = useQuery({ queryKey: ['model-operations', 'config', `jjdguard:model-probe:${principal}`], queryFn: () => modelOperationsApi.config().then((response) => response.data) })
  const [draft, setDraft] = useState<ModelOperationsConfig | null>(null)
  const [confirmed, setConfirmed] = useState(false)
  const [conflict, setConflict] = useState(false)
  const [saveError, setSaveError] = useState('')
  const [saved, setSaved] = useState(false)
  useEffect(() => { if (configQ.data && draft === null) setDraft({ ...configQ.data, protocols: [...configQ.data.protocols] }) }, [configQ.data, draft])
  const update = (patch: Partial<ModelOperationsConfig>) => { setDraft((current) => current ? { ...current, ...patch } : current); setConfirmed(false); setSaved(false) }
  const saveM = useMutation({
    mutationFn: (value: ModelOperationsConfig) => modelOperationsApi.updateConfig(value, confirmed),
    onSuccess: (response) => {
      setDraft({ ...response.data, protocols: [...response.data.protocols] })
      setConflict(false); setConfirmed(false); setSaveError(''); setSaved(true)
      qc.setQueryData(['model-operations', 'config', `jjdguard:model-probe:${principal}`], response.data)
      qc.invalidateQueries({ queryKey: ['model-operations'] })
    },
    onError: (error: any) => {
      setSaved(false)
      if (error?.response?.status === 409) { setConflict(true); setSaveError('配置已被其他管理员修改，当前草稿已保留'); configQ.refetch() }
      else setSaveError(modelOperationError(error, '配置保存失败，草稿已保留'))
    },
  })
  if (configQ.isError && !draft) return <Alert type="error" showIcon message={modelOperationError(configQ.error, '无法读取拨测配置')} />
  if (!draft) return <div role="status">正在读取配置</div>
  const perRound = draft.max_targets
  const daily = Math.ceil(86400 / draft.interval_seconds) * perRound
  const valid = draft.protocols.length > 0 && draft.interval_seconds >= 60 && draft.interval_seconds <= 86400 && draft.concurrency >= 1 && draft.concurrency <= 5 && draft.timeout_seconds >= 1 && draft.timeout_seconds <= 60 && draft.max_targets >= 1 && draft.max_targets <= 100 && draft.max_output_tokens >= 1 && draft.max_output_tokens <= 1024 && draft.failure_threshold >= 1 && draft.failure_threshold <= 10
  return <section className="modelops-settings" aria-label="周期拨测配置">
    <div className="modelops-section-heading"><Title level={5}>周期拨测</Title><Tag>{draft.enabled ? '草稿：启用' : '草稿：关闭'}</Tag><Text type="secondary">版本 {draft.version}</Text></div>
    {conflict && <Alert type="warning" showIcon message={saveError} description={<Space wrap><Text>服务器版本 {configQ.data?.version ?? '读取中'}，草稿版本 {draft.version}</Text><Button size="small" disabled={!configQ.data || configQ.isFetching} onClick={() => { if (configQ.data) { setDraft({ ...draft, version: configQ.data.version }); setConflict(false); setSaveError(''); setConfirmed(false) } }}>保留草稿并采用最新版本</Button><Popconfirm title="丢弃草稿并载入最新配置？" onConfirm={() => { if (configQ.data) { setDraft({ ...configQ.data, protocols: [...configQ.data.protocols] }); setConflict(false); setSaveError(''); setConfirmed(false) } }}><Button size="small" disabled={!configQ.data}>重新载入</Button></Popconfirm></Space>} />}
    {!conflict && saveError && <Alert type="error" showIcon message={saveError} />}
    {saved && <Alert type="success" showIcon message="配置已保存" />}
    <Form layout="vertical" className="modelops-config-grid">
      <Form.Item label="定时拨测"><Switch aria-label="定时拨测" checked={draft.enabled} disabled={saveM.isPending} onChange={(enabled) => update({ enabled })} /></Form.Item>
      <Form.Item label="间隔（秒）"><InputNumber aria-label="间隔（秒）" min={60} max={86400} precision={0} value={draft.interval_seconds} disabled={saveM.isPending} onChange={(value) => { if (value !== null) update({ interval_seconds: value }) }} /></Form.Item>
      <Form.Item label="并发"><InputNumber aria-label="并发" min={1} max={5} precision={0} value={draft.concurrency} disabled={saveM.isPending} onChange={(value) => { if (value !== null) update({ concurrency: value }) }} /></Form.Item>
      <Form.Item label="单次超时（秒）"><InputNumber aria-label="单次超时（秒）" min={1} max={60} precision={0} value={draft.timeout_seconds} disabled={saveM.isPending} onChange={(value) => { if (value !== null) update({ timeout_seconds: value }) }} /></Form.Item>
      <Form.Item label="每轮协议请求上限"><InputNumber aria-label="每轮协议请求上限" min={1} max={100} precision={0} value={draft.max_targets} disabled={saveM.isPending} onChange={(value) => { if (value !== null) update({ max_targets: value }) }} /></Form.Item>
      <Form.Item label="每请求输出 Token 上限"><InputNumber aria-label="每请求输出 Token 上限" min={1} max={1024} precision={0} value={draft.max_output_tokens} disabled={saveM.isPending} onChange={(value) => { if (value !== null) update({ max_output_tokens: value }) }} /></Form.Item>
      <Form.Item label="连续失败告警阈值"><InputNumber aria-label="连续失败告警阈值" min={1} max={10} precision={0} value={draft.failure_threshold} disabled={saveM.isPending} onChange={(value) => { if (value !== null) update({ failure_threshold: value }) }} /></Form.Item>
      <Form.Item label="验证协议" className="modelops-protocol-setting"><Select aria-label="定时验证协议" mode="multiple" value={draft.protocols} disabled={saveM.isPending} onChange={(protocols: ProbeProtocol[]) => update({ protocols })} options={Object.entries(probeProtocolLabels).map(([value, label]) => ({ value, label }))} /></Form.Item>
    </Form>
    <Alert type="warning" showIcon message={`预算上界：每轮 ${number(perRound)} 请求，每日 ${number(daily)} 请求`} description={`每请求输出不超过 ${number(draft.max_output_tokens)} Token；每日输出预算上界 ${number(daily * draft.max_output_tokens)} Token，另有输入 Token 及上游最小计费。实际费用按上游价格和实际用量计算。`} />
    <div className="modelops-save"><Checkbox checked={confirmed} disabled={saveM.isPending} onChange={(event) => setConfirmed(event.target.checked)}>确认周期上游请求费用</Checkbox><Button type="primary" icon={<SaveOutlined />} loading={saveM.isPending} disabled={!valid || conflict || (draft.enabled && !confirmed)} onClick={() => saveM.mutate(draft)}>保存配置</Button></div>
    <Text type="secondary" className="modelops-evidence">最后保存：{time(configQ.data?.updated_at)}</Text>
  </section>
}

export default function ModelOperations() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const principal = `${user?.tenant_id || 'unknown'}:${user?.id || 'unknown'}`
  const [search, setSearch] = useSearchParams()
  const providerId = search.get('provider_id') || undefined
  const modelId = search.get('model_id') || undefined
  const rawWindow = Number(search.get('window_hours') || 24)
  const windowHours = [6, 24, 72, 168].includes(rawWindow) ? rawWindow : 24
  const tab = ['targets', 'history', 'quality', 'providers', 'sla', 'alerts', 'settings'].includes(search.get('tab') || '') ? search.get('tab')! : 'targets'
  const [source, setSource] = useState<'manual' | 'scheduled' | undefined>()
  const [alertState, setAlertState] = useState<string | undefined>('open')
  const [cursors, setCursors] = useState<Record<string, string[]>>({ targets: [''], history: [''], quality: [''], alerts: [''] })
  const [selected, setSelected] = useState<React.Key[]>([])
  const [probeModels, setProbeModels] = useState<ProbeModel[] | null>(null)
  const [detail, setDetail] = useState<ModelTargetSummary | null>(null)
  const [targetPage, setTargetPage] = useState(1)
  const [diagnosticTarget, setDiagnosticTarget] = useState<ModelQualityItem | null>(null)
  const [ackError, setAckError] = useState('')
  const filters: ModelOperationFilters = { provider_id: providerId, model_id: modelId, window_hours: windowHours }
  const cursorList = cursors[tab] || ['']
  const pageFilters = { ...filters, cursor: cursorList[cursorList.length - 1] || undefined, limit: 25 }
  const providerQ = useQuery({ queryKey: ['providers'], queryFn: providerApi.list })
  const modelsQ = useQuery({ queryKey: ['models'], queryFn: () => modelApi.list() })
  const overviewQ = useQuery({ queryKey: ['model-operations', 'overview', principal, filters], queryFn: () => modelOperationsApi.overview(filters).then((response) => response.data), refetchInterval: 30_000, enabled: tab === 'targets' })
  const targetFilters = { provider_id: providerId, model_id: modelId }
  const targetQ = useQuery({ queryKey: ['model-operations', 'targets', principal, targetFilters], queryFn: () => modelOperationsApi.targets(targetFilters).then((response) => response.data), enabled: tab === 'targets', refetchInterval: 30_000 })
  const historyQ = useQuery({ queryKey: ['model-operations', 'history', principal, { ...pageFilters, source }], queryFn: () => modelOperationsApi.history({ ...pageFilters, source }).then((response) => response.data), enabled: tab === 'history' })
  const qualityQ = useQuery({ queryKey: ['model-operations', 'quality', principal, filters], queryFn: () => modelOperationsApi.quality(filters).then((response) => response.data), enabled: tab === 'quality', refetchInterval: 30_000 })
  const alertFilters = { ...targetFilters, cursor: pageFilters.cursor, limit: 25, state: alertState }
  const alertsQ = useQuery({ queryKey: ['model-operations', 'alerts', principal, alertFilters], queryFn: () => modelOperationsApi.alerts(alertFilters).then((response) => response.data), enabled: tab === 'alerts', refetchInterval: 30_000 })
  const ackM = useMutation({ mutationFn: modelOperationsApi.ackAlert, onSuccess: () => { setAckError(''); qc.invalidateQueries({ queryKey: ['model-operations', 'alerts'] }) }, onError: (error) => setAckError(modelOperationError(error, '告警确认失败')) })
  const providers = readRows(providerQ.data)
  const models: ProbeModel[] = readRows(modelsQ.data).map((model) => ({ ...model, provider_type: providers.find((provider) => provider.id === model.provider_id)?.provider_type }))
  const targets = Array.isArray(targetQ.data?.items) ? targetQ.data.items : []
  const summaries = new Map((overviewQ.data?.targets || []).map((target) => [targetKey(target), target]))
  const selectedModels = models.filter((model) => targets.some((target) => selected.includes(targetKey(target)) && target.model_id === model.id))
  const history = Array.isArray(historyQ.data?.items) ? historyQ.data.items : []
  const quality = Array.isArray(qualityQ.data?.items) ? qualityQ.data.items : []
  const alerts = Array.isArray(alertsQ.data?.items) ? alertsQ.data.items : []
  const resetPages = () => { setCursors({ targets: [''], history: [''], quality: [''], alerts: [''] }); setSelected([]); setDetail(null); setTargetPage(1) }
  const changeFilter = (key: string, value?: string) => { const next = new URLSearchParams(search); if (value) next.set(key, value); else next.delete(key); if (key === 'provider_id') next.delete('model_id'); resetPages(); setSearch(next) }
  useEffect(() => { resetPages() }, [providerId, modelId, windowHours])
  const previous = () => { setCursors((current) => ({ ...current, [tab]: cursorList.slice(0, -1) })); setSelected([]) }
  const next = (cursor?: string | null) => { if (cursor) { setCursors((current) => ({ ...current, [tab]: [...cursorList, cursor] })); setSelected([]) } }
  const currentQuery = tab === 'targets' ? targetQ : tab === 'history' ? historyQ : tab === 'quality' ? qualityQ : alertsQ
  const pageData = currentQuery.data as { items?: unknown[]; next_cursor?: string | null } | undefined
  const returnTo = search.get('return_to')
  const returnPath = returnTo === '/providers' || returnTo === '/models' ? returnTo : undefined
  const modelIdentity = (_: unknown, target: ModelOperationTarget) => <Space direction="vertical" size={0}><Button type="link" className="modelops-model-link" onClick={() => navigate(`/models?model_id=${encodeURIComponent(target.model_id)}`)}>{target.model_name || target.model_id}</Button><Text type="secondary" className="modelops-small">{target.provider_name || target.provider_id}</Text></Space>
  const targetColumns = [
    { title: '模型 / 上游', key: 'model', width: 240, render: modelIdentity },
    { title: '协议', dataIndex: 'protocol', width: 150, render: (value: ProbeProtocol) => probeProtocolLabels[value] || value },
    { title: '状态', key: 'state', width: 160, render: (_: unknown, target: ModelOperationTarget) => target.supported === false ? <Tag>当前未适配验证</Tag> : stateTag(summaries.get(targetKey(target))?.state) },
    { title: '可用率', key: 'availability', width: 100, render: (_: unknown, target: ModelOperationTarget) => percentage(summaries.get(targetKey(target))?.availability) },
    { title: '样本', key: 'samples', width: 85, render: (_: unknown, target: ModelOperationTarget) => number(summaries.get(targetKey(target))?.samples) },
    { title: <Tooltip title="完整协议请求和正文验证的总耗时">总耗时 P50 / P95</Tooltip>, key: 'latency', width: 190, render: (_: unknown, target: ModelOperationTarget) => { const summary = summaries.get(targetKey(target)); return `${probeLatency(summary?.p50_ms)} / ${probeLatency(summary?.p95_ms)}` } },
    { title: '最近验证 / 失败', key: 'last', width: 230, render: (_: unknown, target: ModelOperationTarget) => { const summary = summaries.get(targetKey(target)); return <Space direction="vertical" size={0}><Text className="modelops-small">{time(summary?.last_probe_at)}</Text><Text type="danger" className="modelops-small">{summary?.last_error || '—'}</Text></Space> } },
    { title: '操作', key: 'actions', width: 150, render: (_: unknown, target: ModelOperationTarget) => <Space size={0}><Tooltip title={target.supported === false ? '当前未适配验证' : '验证模型'}><Button type="text" aria-label={`验证 ${target.model_name}`} icon={<PlayCircleOutlined />} disabled={target.supported === false || modelsQ.isError || modelsQ.isLoading} onClick={() => { const model = models.find((item) => item.id === target.model_id); if (model) setProbeModels([model]) }} /></Tooltip><Button type="link" size="small" disabled={!summaries.has(targetKey(target))} onClick={() => setDetail(summaries.get(targetKey(target))!)}>历史曲线</Button></Space> },
  ]
  const historyColumns = [
    { title: '模型 / 上游', key: 'model', width: 220, render: modelIdentity },
    { title: '时间', dataIndex: 'created_at', width: 180, render: time },
    { title: '来源', dataIndex: 'source', width: 90, render: (value: string) => value === 'manual' ? '手动' : value === 'scheduled' ? '定时' : '未知' },
    { title: '协议', dataIndex: 'protocol', width: 140, render: (value: ProbeProtocol) => probeProtocolLabels[value] || value },
    { title: '结果', key: 'result', width: 110, render: (_: unknown, record: ModelProbeRecord) => <Tag color={probeRecordPassed(record) ? 'green' : 'red'}>{probeRecordPassed(record) ? '验证通过' : '验证失败'}</Tag> },
    { title: 'HTTP / 正文', key: 'http', width: 140, render: (_: unknown, record: ModelProbeRecord) => `${record.http_status ?? '未收到'} / ${record.body_validated === true ? '已验证' : '未通过'}` },
    { title: '总耗时', dataIndex: 'latency_ms', width: 110, render: probeLatency },
    { title: '错误', key: 'error', width: 200, render: (_: unknown, record: ModelProbeRecord) => record.error_message || record.error_kind || '—' },
  ]
  const qualityColumns = [
    { title: '模型 / 上游', key: 'model', width: 230, render: (_: unknown, record: ModelQualityItem) => <Space direction="vertical" size={0}><Text>{record.model_name || record.model_id || '未知模型'}</Text><Text type="secondary" className="modelops-small">{record.provider_name || record.provider_id || '未知上游'}</Text></Space> },
    { title: '真实请求样本', key: 'samples', width: 130, render: (_: unknown, record: ModelQualityItem) => number(record.samples ?? record.total) },
    { title: '上游观测样本', dataIndex: 'upstream_samples', width: 130, render: number },
    { title: '上游可用率', key: 'success_rate', width: 110, render: (_: unknown, record: ModelQualityItem) => percentage(record.success_rate ?? record.availability) },
    { title: '5xx / 429 / 其他4xx', key: 'errors', width: 180, render: (_: unknown, record: ModelQualityItem) => `${number(record.http_5xx)} / ${number(record.http_429)} / ${number(record.http_4xx)}` },
    { title: '取消', dataIndex: 'cancelled', width: 80, render: number },
    { title: '安全阻断', dataIndex: 'blocked', width: 100, render: number },
    { title: '总耗时 P50 / P95', key: 'latency', width: 185, render: (_: unknown, record: ModelQualityItem) => `${probeLatency(record.p50_ms)} / ${probeLatency(record.p95_ms)}` },
    { title: '首字中位数 / 九五分位', key: 'firstPercentiles', width: 190, render: (_: unknown, record: ModelQualityItem) => `${probeLatency(record.first_event_p50_ms)} / ${probeLatency(record.first_event_p95_ms)}` },
    { title: '输出速度中位数', dataIndex: 'output_tokens_per_sec_p50', width: 150, render: (value?: number | null) => value == null ? '未知' : `${value.toFixed(1)} 词元/秒` },
    { title: '网关处理中位数', dataIndex: 'pre_upstream_p50_ms', width: 150, render: probeLatency },
    { title: '安全检测中位数', dataIndex: 'security_p50_ms', width: 150, render: probeLatency },
    { title: '每分钟请求数', dataIndex: 'rpm', width: 140, render: number },
    { title: '每分钟词元数', dataIndex: 'tpm', width: 140, render: number },
    { title: '首事件均值', dataIndex: 'avg_first_event_ms', width: 120, render: probeLatency },
    { title: '诊断', key: 'diagnosis', width: 110, render: (_: unknown, record: ModelQualityItem) => <Button type="link" size="small" disabled={!record.samples} onClick={() => setDiagnosticTarget(record)}>请求诊断</Button> },
  ]
  const alertColumns = [
    { title: '模型 / 上游', key: 'model', width: 220, render: modelIdentity },
    { title: '协议', dataIndex: 'protocol', width: 140, render: (value: ProbeProtocol) => probeProtocolLabels[value] || value },
    { title: '告警状态', dataIndex: 'state', width: 100, render: (value: string) => <Tag color={value === 'open' ? 'red' : value === 'resolved' ? 'green' : 'default'}>{value === 'open' ? '未恢复' : value === 'resolved' ? '已恢复' : '未知'}</Tag> },
    { title: '失败 / 最近发生', key: 'failure', width: 220, render: (_: unknown, record: ModelOperationAlert) => <Space direction="vertical" size={0}><Text>{record.last_error || record.message || record.error_kind || '模型验证失败'}</Text><Text type="secondary" className="modelops-small">{time(record.updated_at || record.last_seen_at || record.opened_at)}</Text></Space> },
    { title: '恢复时间', dataIndex: 'resolved_at', width: 180, render: (value: string | null) => value ? time(value) : '—' },
    { title: '确认', key: 'ack', width: 180, render: (_: unknown, record: ModelOperationAlert) => record.acknowledged_at ? <Space direction="vertical" size={0}><Tag>已确认</Tag><Text className="modelops-small">{time(record.acknowledged_at)}</Text></Space> : <Button size="small" icon={<CheckOutlined />} loading={ackM.isPending && ackM.variables === record.id} disabled={ackM.isPending} onClick={() => ackM.mutate(record.id)}>确认告警</Button> },
  ]
  return <div className="modelops-page">
    <div className="page-header modelops-heading"><Space wrap>{returnPath && <Button aria-label="返回来源页面" icon={<ArrowLeftOutlined />} onClick={() => navigate(`${returnPath}${providerId ? `?provider_id=${encodeURIComponent(providerId)}` : ''}`)} />}<Title level={4} style={{ margin: 0, fontSize: 20 }}>模型运营</Title></Space><Tooltip title="刷新当前视图"><Button aria-label="刷新当前视图" icon={<ReloadOutlined />} onClick={() => qc.invalidateQueries({ queryKey: ['model-operations'] })} /></Tooltip></div>
    {tab !== 'settings' && <div className="modelops-filters">
      <Select aria-label="筛选上游" allowClear showSearch optionFilterProp="label" placeholder="全部上游" value={providerId} onChange={(value) => changeFilter('provider_id', value)} options={providers.map((provider) => ({ value: provider.id, label: provider.name }))} loading={providerQ.isLoading} />
      <Select aria-label="筛选模型" allowClear showSearch optionFilterProp="label" placeholder="全部模型" value={modelId} onChange={(value) => changeFilter('model_id', value)} options={models.filter((model) => !providerId || model.provider_id === providerId).map((model) => ({ value: model.id, label: model.model_label || model.model_name }))} loading={modelsQ.isLoading} />
      {tab !== 'alerts' && tab !== 'sla' && <Select aria-label="时间窗口" value={windowHours} onChange={(value) => changeFilter('window_hours', String(value))} options={[{ value: 6, label: '近 6 小时' }, { value: 24, label: '近 24 小时' }, { value: 72, label: '近 3 天' }, { value: 168, label: '近 7 天' }]} />}
    </div>}
    <Tabs activeKey={tab} onChange={(value) => { setSelected([]); changeFilter('tab', value) }} items={[{ key: 'targets', label: '主动验证' }, { key: 'history', label: '探测历史' }, { key: 'quality', label: '真实流量质量' }, { key: 'providers', label: '上游渠道' }, { key: 'sla', label: '月度 SLA' }, { key: 'alerts', label: '运营告警' }, { key: 'settings', label: '拨测配置' }]} />
    {tab === 'settings' ? <ModelOperationsSettings /> : tab === 'sla' ? <ModelSLAMonthly providerId={providerId} modelId={modelId} /> : tab === 'providers' ? <ProviderMonitor filters={filters} principal={principal} /> : <>
      {(providerQ.isError || modelsQ.isError) && <Alert type="warning" showIcon message="上游或模型清单读取失败" description="筛选选项暂不可用，保留当前查询条件。" />}
      {currentQuery.isError ? <Alert type="error" showIcon message={modelOperationError(currentQuery.error, '模型运营数据读取失败')} /> : <>
        {tab === 'targets' && <>
          {overviewQ.isError && <Alert type="warning" showIcon message={modelOperationError(overviewQ.error, '验证统计不可用，当前目标状态未知')} />}
          <div className="modelops-table-heading"><Space wrap><Tag color={overviewQ.data?.config?.enabled === true ? 'blue' : 'default'}>{overviewQ.data?.config?.enabled === true ? '定时拨测已启用' : overviewQ.data?.config ? '定时拨测已关闭' : '拨测配置未知'}</Tag><Text type="secondary">统计时间 {time(overviewQ.data?.generated_at)}</Text></Space><Button icon={<PlayCircleOutlined />} disabled={!selectedModels.length || selectedModels.length > 50} onClick={() => setProbeModels(selectedModels)}>验证所选 {selectedModels.length || ''}</Button></div>
          <Table size="small" rowKey={targetKey} dataSource={targets} columns={targetColumns} pagination={{ current: targetPage, pageSize: 25, showSizeChanger: false, onChange: (page) => { setTargetPage(page); setSelected([]) }, showTotal: (total) => `共 ${total} 个协议目标` }} loading={targetQ.isLoading || overviewQ.isLoading} scroll={{ x: 1500 }} rowSelection={{ selectedRowKeys: selected, onChange: setSelected, getCheckboxProps: (target) => ({ disabled: target.supported === false }) }} locale={{ emptyText: '暂无模型目标' }} />
        </>}
        {tab === 'history' && <><div className="modelops-table-heading"><Select aria-label="探测来源" allowClear placeholder="全部来源" style={{ width: 150 }} value={source} onChange={(value) => { setSource(value); resetPages() }} options={[{ value: 'manual', label: '手动' }, { value: 'scheduled', label: '定时' }]} /></div><Table size="small" rowKey="id" dataSource={history} columns={historyColumns} pagination={false} loading={historyQ.isLoading} scroll={{ x: 1350 }} locale={{ emptyText: '暂无探测证据' }} /></>}
        {tab === 'quality' && <ModelQualityView items={quality} loading={qualityQ.isLoading} columns={qualityColumns} onDiagnose={setDiagnosticTarget} windowHours={windowHours} />}
        {tab === 'alerts' && <>{ackError && <Alert type="error" showIcon message={ackError} />}<div className="modelops-table-heading"><Select aria-label="告警状态筛选" allowClear placeholder="全部状态" style={{ width: 150 }} value={alertState} onChange={(value) => { setAlertState(value); resetPages() }} options={[{ value: 'open', label: '未恢复' }, { value: 'resolved', label: '已恢复' }]} /></div><Table size="small" rowKey="id" dataSource={alerts} columns={alertColumns} pagination={false} loading={alertsQ.isLoading} scroll={{ x: 1250 }} locale={{ emptyText: '所选条件暂无告警记录' }} /></>}
        {(tab === 'history' || tab === 'alerts') && <CursorControls index={cursorList.length - 1} count={pageData?.items?.length || 0} nextCursor={pageData?.next_cursor} loading={currentQuery.isFetching} onPrevious={previous} onNext={() => next(pageData?.next_cursor)} />}
      </>}
    </>}
    <ModelProbeDialog open={probeModels !== null} models={probeModels || []} onClose={() => setProbeModels(null)} />
    {diagnosticTarget && <ModelRequestDiagnostics key={`${diagnosticTarget.provider_id}:${diagnosticTarget.model_id}:${windowHours}`} target={diagnosticTarget} windowHours={windowHours} onClose={() => setDiagnosticTarget(null)} />}
    <Drawer title={detail ? `${detail.model_name} · ${probeProtocolLabels[detail.protocol] || detail.protocol}` : '验证历史'} width={760} open={detail !== null} onClose={() => setDetail(null)} destroyOnClose>
      {detail && <>
        <Descriptions size="small" column={2} items={[{ key: 'provider', label: '上游', children: detail.provider_name }, { key: 'state', label: '状态', children: stateTag(detail.state) }, { key: 'availability', label: '可用率', children: percentage(detail.availability) }, { key: 'samples', label: '样本', children: number(detail.samples) }, { key: 'p50', label: '总耗时 P50', children: probeLatency(detail.p50_ms) }, { key: 'p95', label: '总耗时 P95', children: probeLatency(detail.p95_ms) }]} />
        <Title level={5}>验证可用率趋势</Title>
        {detail.hourly?.some((hour) => hour.samples > 0) ? <div className="modelops-chart"><ResponsiveContainer width="100%" height={260}><LineChart data={detail.hourly.map((hour) => ({ ...hour, available_percent: hour.availability === null ? null : hour.availability * 100, label: new Date(hour.hour).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) }))}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="label" minTickGap={40} /><YAxis domain={[0, 100]} unit="%" /><ChartTooltip /><Line name="可用率" type="monotone" dataKey="available_percent" stroke="var(--chart-1)" strokeWidth={2} dot={false} connectNulls={false} /></LineChart></ResponsiveContainer></div> : <Empty description="暂无趋势样本" />}
        <Space wrap><Button onClick={() => { setDetail(null); const next = new URLSearchParams(search); next.set('model_id', detail.model_id); next.set('provider_id', detail.provider_id); next.set('tab', 'history'); resetPages(); setSearch(next) }}>探测明细</Button><Button onClick={() => { setDetail(null); const next = new URLSearchParams(search); next.set('model_id', detail.model_id); next.set('provider_id', detail.provider_id); next.set('tab', 'quality'); resetPages(); setSearch(next) }}>真实流量</Button></Space>
      </>}
    </Drawer>
  </div>
}

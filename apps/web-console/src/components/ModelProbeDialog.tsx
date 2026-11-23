import { useEffect, useRef, useState } from 'react'
import { Alert, Button, Checkbox, Modal, Select, Space, Table, Tag, Typography } from 'antd'
import { PlayCircleOutlined, ReloadOutlined, StopOutlined } from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { modelOperationsApi, type ModelProbeJob, type ModelProbeRecord, type ProbeProtocol } from '../services/modelOperations'
import { useAuthStore } from '../stores/auth'
import { modelOperationError, probeLatency, probeProtocolLabels, probeRecordPassed } from '../utils/modelProbe'

const { Text } = Typography
export interface ProbeModel { id: string; model_name: string; model_label?: string; provider_id?: string; provider_type?: string; protocols?: string[] }
const terminal = (job?: ModelProbeJob | null) => !!job && ['completed', 'failed', 'cancelled', 'interrupted'].includes(job.state)
const jobLabels: Record<string, string> = { queued: '排队中', running: '验证中', completed: '已完成', failed: '任务失败', cancelled: '已取消', interrupted: '任务中断' }
interface Invocation { key: string; modelIds: string[]; protocols?: ProbeProtocol[]; expectedVersion: number; maxOutputTokens: number; jobId?: string }
const newKey = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (value) => value.toString(16).padStart(2, '0')).join('')

export default function ModelProbeDialog({ open, models, allowSelection = false, onClose }: {
  open: boolean
  models: ProbeModel[]
  allowSelection?: boolean
  onClose: () => void
}) {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const storageKey = `jjdguard:model-probe:${user?.tenant_id || 'unknown'}:${user?.id || 'unknown'}`
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [protocols, setProtocols] = useState<ProbeProtocol[]>([])
  const [confirmed, setConfirmed] = useState(false)
  const [confirmedVersion, setConfirmedVersion] = useState<number | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  const [invocation, setInvocation] = useState<Invocation | null>(null)
  const [error, setError] = useState('')
  const [activeJob, setActiveJob] = useState<string | null>(null)
  const mountedRef = useRef(true)
  const principalRef = useRef(storageKey)
  principalRef.current = storageKey
  const ids = JSON.stringify(models.map((model) => model.id))
  const configQ = useQuery({ queryKey: ['model-operations', 'config', storageKey], queryFn: () => modelOperationsApi.config().then((response) => response.data), enabled: open })
  const jobQ = useQuery({
    queryKey: ['model-operations', 'job', storageKey, invocation?.jobId],
    queryFn: () => modelOperationsApi.job(invocation!.jobId!).then((response) => response.data),
    enabled: open && !!invocation?.jobId,
    retry: false,
    refetchInterval: (query) => terminal(query.state.data) || query.state.status === 'error' ? false : 1000,
  })
  const job = jobQ.data
  const inProgress = submitting || (!!invocation && !terminal(job))
  const selectedModels = selectedIds.map((id) => models.find((model) => model.id === id))
  const nativeProtocol = (type?: string) => type === 'anthropic' ? 'messages' : ['gemini', 'vertex', 'bedrock'].includes(type || '') ? 'chat' : undefined
  const nativeMismatch = protocols.length > 0 && selectedModels.some((model) => { const required = nativeProtocol(model?.provider_type); return required && !protocols.includes(required) })
  const nativeChatSelected = selectedModels.some((model) => nativeProtocol(model?.provider_type) === 'chat')
  const requestCount = selectedModels.reduce((total, model) => total + (protocols.length === 0 || nativeProtocol(model?.provider_type) ? 1 : protocols.length), 0)
  const maxOutputTokens = invocation?.maxOutputTokens ?? configQ.data?.max_output_tokens
  const results = Array.isArray(job?.items) ? job.items : []
  const skipped = Array.isArray(job?.skipped) ? job.skipped : []
  const knownUnexecuted = skipped.filter((record) => ['provider_auth_failed', 'unsupported', 'configuration_changed', 'cancelled'].includes(record.reason)).length
  const unknownOutcomes = skipped.length - knownUnexecuted
  const outcomeKeys = [...results, ...skipped].map((record) => `${record.model_id}:${record.provider_id}:${record.protocol}`)
  const evidenceBound = !!job && results.every((record) => record.invocation_id === job.job_id) && new Set(results.map((record) => record.id)).size === results.length && new Set(outcomeKeys).size === outcomeKeys.length
  const complete = job?.state === 'completed' && job.total > 0 && job.completed === results.length && results.length + skipped.length === job.total && evidenceBound
  const costsConfirmed = confirmed && confirmedVersion === configQ.data?.version
  const passed = results.filter(probeRecordPassed).length
  useEffect(() => { mountedRef.current = true; return () => { mountedRef.current = false } }, [])
  useEffect(() => {
    if (!open) return
    let saved: Invocation | null = null
    let readError = ''
    try {
      const raw = sessionStorage.getItem(storageKey)
      if (raw) {
        const value = JSON.parse(raw)
        if (typeof value?.key === 'string' && Number.isInteger(value.expectedVersion) && value.expectedVersion > 0 && Number.isInteger(value.maxOutputTokens) && Array.isArray(value.modelIds) && value.modelIds.every((id: unknown) => typeof id === 'string') && (!value.protocols || (Array.isArray(value.protocols) && value.protocols.every((protocol: string) => ['chat', 'responses', 'messages'].includes(protocol)))) && (!value.jobId || typeof value.jobId === 'string')) saved = value
        else readError = '任务恢复信息无效，请先检查探测历史'
      }
    } catch { readError = '任务恢复信息不可读，请先检查探测历史' }
    setInvocation(saved)
    setSelectedIds(saved?.modelIds || (allowSelection ? [] : JSON.parse(ids) as string[]))
    setProtocols(saved?.protocols || [])
    setConfirmed(false)
    setActiveJob(null)
    setSubmitting(false)
    setCancelling(false)
    setError(readError)
  }, [open, ids, allowSelection, storageKey])
  const jobState = job?.state
  useEffect(() => {
    if (jobState && ['completed', 'failed', 'cancelled', 'interrupted'].includes(jobState)) {
      qc.invalidateQueries({ queryKey: ['model-operations', 'history'] })
      qc.invalidateQueries({ queryKey: ['model-operations', 'overview'] })
      qc.invalidateQueries({ queryKey: ['model-operations', 'alerts'] })
    }
  }, [jobState, qc])
  const persist = (value: Invocation) => { sessionStorage.setItem(storageKey, JSON.stringify(value)); if (mountedRef.current && principalRef.current === storageKey) setInvocation(value) }
  const test = async () => {
    if (submitting || (invocation?.jobId && !terminal(job))) return
    if (!invocation && (!costsConfirmed || requestCount === 0 || requestCount > 50 || nativeMismatch || !configQ.data || configQ.isFetching)) return
    const value: Invocation = invocation && !invocation.jobId ? invocation : { key: newKey(), modelIds: [...selectedIds], ...(protocols.length ? { protocols: [...protocols] } : {}), expectedVersion: configQ.data!.version, maxOutputTokens: configQ.data!.max_output_tokens }
    try { persist(value) } catch { setError('无法保存任务恢复标识，验证尚未发起'); return }
    setSubmitting(true)
    setError('')
    try {
      const response = await modelOperationsApi.test(value.modelIds, value.protocols, value.key, value.expectedVersion)
      if (!response.data.job_id) throw new Error('missing job id')
      const started = { ...value, jobId: response.data.job_id }
      persist(started)
      qc.setQueryData(['model-operations', 'job', storageKey, started.jobId], response.data)
    } catch (failure: any) {
      if (mountedRef.current && principalRef.current === storageKey) {
        const code = failure?.response?.data?.error?.code
        if ([400, 403, 404, 415, 422].includes(failure?.response?.status) && ['not_found', 'invalid_request', 'permission_denied', 'cost_confirmation_required', 'unsupported_media_type'].includes(code)) {
          sessionStorage.removeItem(storageKey)
          setInvocation(null); setConfirmed(false); setActiveJob(null)
          setError(`验证未发起：${modelOperationError(failure, '请求已被拒绝，请刷新模型列表后重试')}`)
          qc.invalidateQueries({ queryKey: ['model-operations', 'targets'] })
        } else if (failure?.response?.status === 409 && code === 'config_conflict') {
          sessionStorage.removeItem(storageKey)
          setInvocation(null); setConfirmed(false)
          setError('费用预算配置已变更，验证尚未发起；请核对新预算后再次确认费用')
          configQ.refetch()
        } else {
          const existing = failure?.response?.status === 409 ? failure?.response?.data?.error?.details?.job_id : undefined
          setActiveJob(typeof existing === 'string' ? existing : null)
          setError(modelOperationError(failure, '提交结果尚未确认；重试将使用同一请求标识，请勿重复创建任务'))
        }
      }
    } finally { if (mountedRef.current && principalRef.current === storageKey) setSubmitting(false) }
  }
  const follow = () => {
    if (!activeJob || !invocation) return
    try { persist({ ...invocation, jobId: activeJob }); setActiveJob(null); setError('') } catch { setError('无法保存任务恢复标识') }
  }
  const cancel = async () => {
    if (!invocation?.jobId || cancelling || terminal(job)) return
    setCancelling(true)
    setError('')
    try {
      const response = await modelOperationsApi.cancelJob(invocation.jobId)
      qc.setQueryData(['model-operations', 'job', storageKey, invocation.jobId], response.data)
      await jobQ.refetch()
    } catch (failure) { setError(modelOperationError(failure, '取消尚未确认，请继续跟进原任务')) }
    finally { setCancelling(false) }
  }
  const newTest = () => { sessionStorage.removeItem(storageKey); setInvocation(null); setError(''); setActiveJob(null); setConfirmed(false) }
  const close = () => { if (terminal(job)) sessionStorage.removeItem(storageKey); onClose() }
  const columns = [
    { title: '模型', key: 'model', width: 170, render: (_: unknown, record: ModelProbeRecord) => record.model_name || models.find((model) => model.id === record.model_id)?.model_name || record.model_id },
    { title: '协议', dataIndex: 'protocol', width: 150, render: (value: ProbeProtocol) => probeProtocolLabels[value] || value },
    { title: '结果', key: 'result', width: 100, render: (_: unknown, record: ModelProbeRecord) => record.invocation_id !== job?.job_id ? <Tag color="orange">证据不符</Tag> : <Tag color={probeRecordPassed(record) ? 'green' : 'red'}>{probeRecordPassed(record) ? '验证通过' : '验证失败'}</Tag> },
    { title: 'HTTP', dataIndex: 'http_status', width: 75, render: (value: number | null) => value && value > 0 ? value : '未收到' },
    { title: '正文', dataIndex: 'body_validated', width: 85, render: (value: boolean) => value === true ? '已验证' : '未通过' },
    { title: '总耗时', dataIndex: 'latency_ms', width: 120, render: probeLatency },
    { title: '错误', key: 'error', width: 170, render: (_: unknown, record: ModelProbeRecord) => record.error_kind || '—' },
  ]
  return <Modal title="验证上游模型" open={open} width={960} onCancel={close} destroyOnClose footer={
    <Space wrap>
      <Button onClick={close}>关闭</Button>
      {invocation?.jobId && !terminal(job) && <Button icon={<StopOutlined />} loading={cancelling} onClick={cancel}>取消验证</Button>}
      {terminal(job) ? <Button icon={<PlayCircleOutlined />} onClick={newTest}>新验证</Button>
        : !invocation?.jobId && <Button type="primary" icon={invocation ? <ReloadOutlined /> : <PlayCircleOutlined />} onClick={test} loading={submitting} disabled={submitting || (!invocation && (!costsConfirmed || requestCount === 0 || requestCount > 50 || nativeMismatch || models.length === 0 || !configQ.data || configQ.isFetching))}>{invocation ? '重试提交' : '开始验证'}</Button>}
    </Space>
  }>
    <Space direction="vertical" style={{ width: '100%' }} size={14}>
      {allowSelection ? <Select aria-label="待验证模型" mode="multiple" placeholder="选择模型" style={{ width: '100%' }} value={selectedIds} onChange={(value) => { setSelectedIds(value); setConfirmed(false) }} disabled={!!invocation} options={models.map((model) => ({ value: model.id, label: model.model_label || model.model_name }))} />
        : <Text>已选模型：{selectedIds.map((id) => { const model = models.find((item) => item.id === id); return model?.model_label || model?.model_name || id }).join('、') || '暂无可验证模型'}</Text>}
      {requestCount > 50 && <Alert type="warning" showIcon message="每次最多 50 个协议请求，请减少模型或协议" />}
      {nativeMismatch && <Alert type="warning" showIcon message="所选原生上游需要对应验证协议：Claude 使用 Messages，Gemini / Vertex / Bedrock 使用 Chat" />}
      <Select aria-label="验证协议" mode="multiple" placeholder="每个模型自动选择一个已登记协议" style={{ width: '100%' }} value={protocols} disabled={!!invocation} onChange={(value) => { setProtocols(value); setConfirmed(false) }} options={Object.entries(probeProtocolLabels).map(([value, label]) => ({ value, label }))} />
      {nativeChatSelected && <Text type="secondary">Gemini / Vertex 使用 generateContent，Bedrock 使用 Converse。Chat 验证成功后登记网关的统一聊天能力。</Text>}
      {!invocation && <>
        <Alert type="warning" showIcon message={`真实请求可能产生上游费用 · ${requestCount} 次请求`} description={`每请求输出上限 ${maxOutputTokens ?? '未知'} Token，本次输出预算上界 ${maxOutputTokens === undefined ? '未知' : (requestCount * maxOutputTokens).toLocaleString('zh-CN')} Token，另有输入用量。验证不调整模型状态或路由。`} />
        <Checkbox checked={costsConfirmed} onChange={(event) => { setConfirmed(event.target.checked); setConfirmedVersion(configQ.data?.version ?? null) }}>确认本次上游请求费用</Checkbox>
      </>}
      {configQ.isError && !invocation && <Alert type="error" showIcon message={modelOperationError(configQ.error, '无法读取费用预算，验证尚未发起')} action={<Button size="small" onClick={() => configQ.refetch()}>重试</Button>} />}
      {inProgress && <Alert type="info" showIcon message={job ? `${jobLabels[job.state] || '状态未知'} · 已完成 ${job.completed ?? results.length} / ${job.total ?? '未知'}` : submitting ? '正在提交验证任务' : '提交结果尚未确认'} description="关闭窗口不会取消后台任务；已发出的请求仍可能产生费用。" />}
      {job && terminal(job) && <Alert type={complete && passed === job.total && skipped.length === 0 ? 'success' : complete ? 'warning' : 'error'} showIcon message={complete ? `验证完成：${passed} 项通过，${results.length - passed} 项失败${knownUnexecuted ? `，${knownUnexecuted} 项未执行` : ''}${unknownOutcomes ? `，${unknownOutcomes} 项结果未知` : ''}` : `${jobLabels[job.state] || '状态未知'} · 已完成 ${job.completed ?? results.length} / ${job.total}`} description={!complete && job.state === 'completed' ? '结果不完整，请检查探测历史' : job.error_code || undefined} />}
      {jobQ.isError && <Alert type="error" showIcon message={modelOperationError(jobQ.error, '无法读取任务状态，尚未确认终态')} action={<Button size="small" icon={<ReloadOutlined />} onClick={() => jobQ.refetch()}>重试读取</Button>} />}
      {error && <Alert type="error" showIcon message={error} action={activeJob ? <Button size="small" onClick={follow}>跟进已有验证</Button> : undefined} />}
      {!!results.length && <Table size="small" rowKey={(record) => record.id || `${record.model_id}:${record.protocol}`} columns={columns} dataSource={results} pagination={false} scroll={{ x: 880 }} />}
      {!!skipped.length && <Table size="small" rowKey={(record) => `${record.model_id}:${record.provider_id}:${record.protocol}`} dataSource={skipped} pagination={false} columns={[{ title: '模型', dataIndex: 'model_name' }, { title: '协议', dataIndex: 'protocol', render: (value: ProbeProtocol) => probeProtocolLabels[value] || value }, { title: '状态', render: (_: unknown, record: NonNullable<ModelProbeJob['skipped']>[number]) => <Tag>{['provider_auth_failed', 'unsupported', 'configuration_changed', 'cancelled'].includes(record.reason) ? '未执行' : '结果未知'}</Tag> }, { title: '原因', dataIndex: 'reason', render: (value: string) => ({ provider_auth_failed: '同上游鉴权失败，后续请求已停止', unsupported: '当前未适配验证', configuration_changed: '配置已变更', cancelled: '已取消', worker_interrupted: '执行进程中断，缺少完成证据', unknown_after_interruption: '请求已发出，未取得完整结果' } as Record<string, string>)[value] || '执行结果未知' }]} />}
    </Space>
  </Modal>
}

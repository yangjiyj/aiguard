import { Alert, Button, Spin, Tag, Tooltip, Typography } from 'antd'
import { ArrowRightOutlined, ReloadOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { serviceHealthApi } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { canAccessPath } from '../utils/access'
import { EnterprisePageHeader } from '../components/EnterpriseUI'

const { Text, Title } = Typography
type Component = Record<string, unknown>
type ComponentMeta = { name: string; purpose: string; path: string; action: string }
type Metric = { field: string; label: string; unit?: string; kind?: 'time' | 'connection' | 'boolean' | 'status' | 'percent'; absentWhenZero?: string }

const COMPONENTS: Record<string, ComponentMeta> = {
  'control-plane': { name: '管理后端', purpose: '用户、配置与管理接口', path: '/system/settings', action: '系统设置' },
  'gateway-core': { name: '请求网关', purpose: '接入请求与执行安全策略', path: '/connect/channels', action: '接入通道' },
  'security-engine': { name: '安全检测引擎', purpose: '内容与工具风险检测', path: '/security/policies?tab=detection', action: '检测配置' },
  judge: { name: '语义安全判官', purpose: '判断语义攻击与间接注入', path: '/security/policies?tab=detection', action: '语义检测配置' },
  'audit-pipeline': { name: '审计处理', purpose: '保存请求的安全审计结果', path: '/audit/access-retention?view=requests', action: '请求记录' },
  'billing-compensation': { name: '计费补偿任务', purpose: '补结算异常请求或释放费用预占', path: '/cost/statements', action: '账单' },
}

const STATUS: Record<string, { label: string; color: string }> = {
  healthy: { label: '正常', color: 'green' }, degraded: { label: '异常', color: 'orange' },
  unreachable: { label: '不可达', color: 'red' }, processing: { label: '处理中', color: 'gold' },
  stale: { label: '已过期', color: 'orange' }, unknown: { label: '待监测', color: 'default' },
  disabled: { label: '未启用', color: 'default' },
}

const REASONS: Record<string, string> = {
  evidence_query_failed: '数据库证据查询失败，当前无法确认状态。',
  timeout: '健康探针超时，请检查服务响应和网络连接。',
  connection_failed: '健康探针连接失败，请检查服务和网络连接。',
  request_failed: '健康探针请求失败，请检查服务连接。',
  redirect_rejected: '健康探针返回重定向，尚未得到有效健康结果。',
  invalid_url: '健康探针地址不可用，请检查服务配置。',
  runtime_source_not_configured: '判官运行监测尚未接入，暂不能确认当前状态。',
  semantic_config_unavailable: '语义检测配置暂不可用，请检查管理服务。',
  runtime_report_missing: '尚未收到有效判官运行报告，或报告已过期。',
  runtime_config_pending: '语义配置尚未在全部运行节点生效。',
  judge_not_required: '当前语义检测配置不需要判官。',
  runtime_report_error: '判官运行报告显示异常，请检查语义检测配置。',
  judge_unavailable: '判官报告不可用，请检查语义检测配置与运行情况。',
  judge_timeouts: '判官判断请求出现超时，请检查模型响应和处理能力。',
  judge_failures: '判官判断请求出现失败，请检查模型连接与检测配置。',
  not_required: '当前计费模式不需要费用补偿任务。',
  awaiting_first_run: '补偿任务尚未开始，暂不能确认任务状态。',
  running: '补偿任务正在检查异常请求。',
  execution_failed: '最近一次补偿检查失败，请检查计费任务运行情况。',
  items_failed: '部分异常请求补偿失败，请检查计费处理结果。',
  heartbeat_stale: '补偿任务运行记录已过期，需要新的任务结果。',
  worker_stopped: '补偿任务已停止，请检查管理服务运行情况。',
}

const probeMetrics: Metric[] = [
  { field: 'http_status', label: '探针 HTTP 状态' }, { field: 'latency_ms', label: '探针耗时', unit: '毫秒' },
  { field: 'cached', label: '使用缓存结果', kind: 'boolean' }, { field: 'cache_age_seconds', label: '缓存结果年龄', unit: '秒' },
]
const METRICS: Record<string, Metric[]> = {
  'control-plane': [
    { field: 'database', label: '数据库连接', kind: 'connection' }, { field: 'redis', label: '缓存连接', kind: 'connection' },
  ],
  'gateway-core': probeMetrics,
  'security-engine': [
    ...probeMetrics,
    { field: 'engine_resource_profile', label: '生效资源档位' },
    { field: 'engine_detected_cpus', label: '检测到 CPU', unit: '核' },
    { field: 'engine_web_concurrency', label: 'Web 并发', unit: '路' },
    { field: 'engine_input_workers', label: '输入工作线程', unit: '个' },
    { field: 'engine_tier1_workers', label: 'Tier-1 进程', unit: '个' },
    { field: 'engine_tier1_threads', label: 'Tier-1 线程', unit: '个' },
    { field: 'engine_tier1_inference_workers', label: 'Tier-1 推理进程', unit: '个' },
    { field: 'engine_tier1_inference_capacity', label: 'Tier-1 单进程容量', unit: '路' },
    { field: 'engine_tier1_concurrency_status', label: 'Tier-1 并发匹配' },
    { field: 'engine_tier1_replicas', label: 'Tier-1 副本数（配置）', unit: '个' },
    { field: 'engine_tier1_scale_mode', label: 'Tier-1 扩容模式' },
    { field: 'engine_tier1_live_provider', label: 'Tier-1 实测后端' },
    { field: 'engine_tier1_live_threads', label: 'Tier-1 实测线程', unit: '个' },
    { field: 'engine_tier1_live_batch_windows', label: 'Tier-1 单次窗口批量', unit: '个' },
    { field: 'engine_tier1_live_inference_workers', label: 'Tier-1 实测推理进程', unit: '个' },
    { field: 'engine_tier1_live_inference_capacity', label: 'Tier-1 实测单进程容量', unit: '路' },
    { field: 'engine_tier1_live_uvicorn_workers', label: 'Tier-1 实测进程数', unit: '个' },
    { field: 'engine_tier1_capacity_matches_profile', label: 'Tier-1 容量与档位一致', kind: 'boolean' },
    { field: 'engine_tier1_live_reachable', label: 'Tier-1 探针可达', kind: 'boolean' },
    { field: 'engine_judge_capacity', label: '每进程判官容量', unit: '路' },
    { field: 'engine_judge_global_concurrency', label: '全局判官预算', unit: '路' },
    { field: 'engine_judge_budget_status', label: '判官预算状态' },
    { field: 'engine_node_id', label: '上报节点' },
    { field: 'engine_shared_state_healthy', label: '共享状态正常', kind: 'boolean' },
    { field: 'engine_metrics_scope', label: '指标范围' },
    { field: 'judge_calls_per_request_avg', label: '每请求判官调用', unit: '次' },
    { field: 'fingerprint_hit_rate', label: '指纹命中率', kind: 'percent' },
    { field: 'engine_metrics_requests', label: '指标样本请求数', unit: '个' },
  ],
  judge: [
    { field: 'runtime_fresh', label: '运行报告有效', kind: 'boolean' },
    { field: 'runtime_reported_at', label: '最近运行报告', kind: 'time' },
    { field: 'runtime_active_nodes', label: '报告节点', unit: '个' },
    { field: 'runtime_applied_nodes', label: '配置生效节点', unit: '个' },
    { field: 'judge_required', label: '需要语义判官', kind: 'boolean' },
    { field: 'judge_operational', label: '判官可用', kind: 'boolean' },
    { field: 'judge_window_attempts', label: '窗口内判断请求', unit: '次' },
    { field: 'judge_window_successes', label: '窗口内成功', unit: '次' },
    { field: 'judge_window_timeouts', label: '窗口内超时', unit: '次' },
    { field: 'judge_p50_latency_ms', label: '判断耗时中位数', unit: '毫秒' },
    { field: 'judge_breaker_open', label: '熔断已开启', kind: 'boolean' },
    { field: 'judge_consecutive_failures', label: '连续失败', unit: '次' },
    { field: 'judge_last_attempt_at', label: '最近判断请求', kind: 'time' },
    { field: 'judge_last_success_at', label: '最近判断成功', kind: 'time' },
    { field: 'fault_events_24h', label: '近 24 小时故障事件', unit: '条' },
  ],
  'audit-pipeline': [
    { field: 'requests_24h', label: '近 24 小时请求', unit: '条' },
    { field: 'pending_24h', label: '待处理审计', unit: '条' },
    { field: 'oldest_pending_age_seconds', label: '最久等待时间', unit: '秒', absentWhenZero: 'pending_24h' },
    { field: 'processing_threshold_seconds', label: '积压判断阈值', unit: '秒' },
  ],
  'billing-compensation': [
    { field: 'backlog_status', label: '待处理积压', kind: 'status' },
    { field: 'worker_status', label: '补偿任务运行', kind: 'status' },
    { field: 'stale_reserved_count', label: '超时费用预占', unit: '条' },
    { field: 'oldest_stale_age_seconds', label: '最久预占时间', unit: '秒', absentWhenZero: 'stale_reserved_count' },
    { field: 'active_lease_count', label: '当前执行占用', unit: '条' },
    { field: 'expired_unreleased_lease_count', label: '过期未释放占用', unit: '条' },
    { field: 'oldest_expired_unreleased_seconds', label: '最久过期时间', unit: '秒', absentWhenZero: 'expired_unreleased_lease_count' },
    { field: 'worker_running', label: '任务正在执行', kind: 'boolean' },
    { field: 'worker_last_started_at', label: '最近任务开始', kind: 'time' },
    { field: 'worker_last_completed_at', label: '最近任务结束', kind: 'time' },
  ],
}

const timestamp = (value: unknown): string => {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T/.test(value)) return '未获取'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '未获取' : date.toLocaleString('zh-CN', { hour12: false })
}

const metricValue = (metric: Metric, record: Component): string => {
  const value = record[metric.field]
  if (value === null || value === undefined) return metric.absentWhenZero && record[metric.absentWhenZero] === 0 ? '无' : '未获取'
  if (metric.kind === 'time') return timestamp(value)
  if (metric.kind === 'connection') return value === 'ok' ? '连接正常' : value === 'error' ? '连接失败' : '未获取'
  if (metric.kind === 'boolean') return typeof value === 'boolean' ? (value ? '是' : '否') : '未获取'
  if (metric.kind === 'status') return value === 'clean' ? '无积压' : value === 'backlog' ? '有积压' : STATUS[String(value)]?.label || '未获取'
  if (metric.kind === 'percent') return typeof value === 'number' && Number.isFinite(value) ? `${(value * 100).toFixed(1)}%` : '未获取'
  // Deployment strings (profile name, node id, budget status) are shown as-is:
  // treating them as missing evidence would hide the effective profile.
  if (typeof value === 'string') return value === '' ? '未获取' : value
  return typeof value === 'number' && Number.isFinite(value) ? `${value.toLocaleString('zh-CN')}${metric.unit ? ` ${metric.unit}` : ''}` : '未获取'
}

const conclusion = (record: Component): { status: string; title: string; reason: string } => {
  const status = typeof record.status === 'string' && STATUS[record.status] ? record.status : 'unknown'
  const reason = typeof record.reason_code === 'string' ? REASONS[record.reason_code] : undefined
  if (record.reason_code === 'evidence_query_failed') return { status: 'degraded', title: '证据查询失败', reason: REASONS.evidence_query_failed }
  if (record.component === 'billing-compensation') {
    if (status === 'disabled') return { status, title: '未启用', reason: REASONS.not_required }
    const worker = record.worker_status
    const workerReason = typeof record.worker_reason_code === 'string' ? REASONS[record.worker_reason_code] : undefined
    if (worker === 'stale') return { status: 'stale', title: '任务状态已过期', reason: workerReason || REASONS.heartbeat_stale }
    if (worker === 'degraded') return { status: 'degraded', title: '补偿任务异常', reason: workerReason || REASONS.execution_failed }
    if (record.backlog_status === 'backlog') return { status: status === 'unknown' ? 'unknown' : 'degraded', title: '存在待处理积压', reason: '有超时费用预占或过期执行占用，需检查补偿处理结果。' }
    if (worker === 'processing') return { status: 'processing', title: '任务运行中', reason: workerReason || REASONS.running }
    if (worker === 'disabled') return { status: 'disabled', title: '任务未启用', reason: workerReason || REASONS.not_required }
    if (status === 'healthy' && worker === 'healthy') return { status, title: '正常', reason: '无待处理积压，最近一次补偿检查已完成。' }
    if (record.backlog_status === 'clean') return { status: status === 'degraded' ? status : 'unknown', title: '无积压，任务状态待监测', reason: workerReason || '数据库中没有待处理积压，尚不能确认补偿任务当前是否正常运行。' }
    return { status, title: STATUS[status].label, reason: reason || workerReason || '尚未取得完整积压与任务运行证据。' }
  }
  if (record.component === 'judge') {
    if (status === 'disabled') return { status, title: '未启用', reason: reason || REASONS.judge_not_required }
    return { status, title: STATUS[status].label, reason: reason || (status === 'healthy' ? '判官运行报告确认配置已生效且当前可用。' : status === 'processing' ? '语义配置正在生效，需要等待运行报告。' : status === 'degraded' ? '判官运行报告显示异常，请检查语义检测配置。' : '尚未取得有效判官运行证据；没有故障记录不能证明运行正常。') }
  }
  if (status === 'degraded' && record.component === 'control-plane') {
    const dependencyReason = record.database === 'error' && record.redis === 'error' ? '数据库和缓存连接失败，请检查依赖服务。' : record.database === 'error' ? '数据库连接失败，请检查数据库服务。' : record.redis === 'error' ? '缓存连接失败，请检查缓存服务。' : '管理服务报告异常，请检查数据库与缓存连接。'
    return { status, title: STATUS[status].label, reason: reason || dependencyReason }
  }
  if (status === 'degraded' && record.component === 'audit-pipeline' && typeof record.pending_24h === 'number' && record.pending_24h > 0) {
    return { status, title: STATUS[status].label, reason: reason || '审计记录等待处理已超过阈值，请检查审计写入。' }
  }
  if (status === 'unknown') return { status, title: record.observed_at == null && ['gateway-core', 'security-engine'].includes(String(record.component)) ? '未获取观测结果' : '待监测', reason: reason || (record.component === 'audit-pipeline' && record.requests_24h === 0 ? '近 24 小时没有请求样本，暂不能确认审计处理状态。' : '当前证据不足，暂不能确认组件状态。') }
  const descriptions: Record<string, string> = {
    'control-plane': '管理服务数据库与缓存检查正常。', 'gateway-core': '请求网关健康探针响应正常。',
    'security-engine': '安全检测引擎健康探针响应正常。', 'audit-pipeline': '窗口内请求已有审计结果，没有待处理审计。',
  }
  return { status, title: STATUS[status].label, reason: reason || (status === 'healthy' ? descriptions[String(record.component)] : status === 'processing' ? '审计结果仍在处理中，尚未超过积压判断阈值。' : status === 'unreachable' ? '无法连接健康探针，请检查服务和网络连接。' : '组件报告异常，请查看诊断指标并检查服务运行情况。') }
}

// Raw evidence, addresses and arbitrary API fields never reach the view.
const technicalEntries = (record: Component): [string, string][] => {
  const entries: [string, string][] = [['component', String(record.component)]]
  for (const field of ['status', 'worker_status', 'backlog_status', 'runtime_status']) {
    const value = record[field]
    if (typeof value === 'string' && ['healthy', 'degraded', 'unreachable', 'processing', 'stale', 'unknown', 'disabled', 'clean', 'backlog', 'applied', 'pending', 'unavailable', 'partially_applied'].includes(value)) entries.push([field, value])
  }
  for (const field of ['reason_code', 'worker_reason_code', 'fault_evidence_reason_code']) {
    const value = record[field]
    if (typeof value === 'string' && REASONS[value]) entries.push([field, value])
  }
  return entries
}

function ComponentRow({ record, role }: { record: Component; role?: string }) {
  const id = String(record.component)
  const meta = COMPONENTS[id]
  const view = conclusion(record)
  return (
    <section aria-label={meta.name} style={{ borderTop: '1px solid var(--border-color)', padding: '18px 0', minWidth: 0 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 220px), 1fr))', gap: '10px 24px', alignItems: 'start' }}>
        <div style={{ minWidth: 0 }}>
          <Title level={5} style={{ margin: '0 0 4px', fontSize: 15 }}>{meta.name}</Title>
          <Text type="secondary" style={{ fontSize: 12 }}>{meta.purpose}</Text>
        </div>
        <div style={{ minWidth: 0 }}>
          <Tag role="status" aria-label="当前状态" color={STATUS[view.status].color} style={{ marginBottom: 6 }}>{STATUS[view.status].label}</Tag>
          {view.title !== STATUS[view.status].label && <div><Text strong>{view.title}</Text></div>}
          <div style={{ marginTop: 4, overflowWrap: 'anywhere' }}><Text type="secondary">{view.reason}</Text></div>
        </div>
        <div style={{ minWidth: 0 }}>
          <Text type="secondary" style={{ fontSize: 12, display: 'block', marginBottom: 6 }}>观测时间：{timestamp(record.observed_at)}</Text>
          {canAccessPath(role, meta.path.split('?')[0]) && <Link to={meta.path}>{meta.action} <ArrowRightOutlined aria-hidden="true" /></Link>}
        </div>
      </div>
      <details style={{ marginTop: 12, minWidth: 0 }}>
        <summary style={{ cursor: 'pointer', color: 'var(--text-secondary)', fontSize: 12 }}>诊断指标</summary>
        {record.reason_code === 'evidence_query_failed' ? <Text type="secondary">本次指标未获取。</Text> : (
          <dl style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 200px), 1fr))', gap: '12px 24px', margin: '14px 0' }}>
            {METRICS[id].map((metric) => <div key={metric.field} style={{ minWidth: 0 }}><dt><Text type="secondary" style={{ fontSize: 12 }}>{metric.label}</Text></dt><dd style={{ margin: '4px 0 0', overflowWrap: 'anywhere' }}>{metricValue(metric, record)}</dd></div>)}
          </dl>
        )}
        {id === 'judge' && <Text type="secondary" style={{ display: 'block', fontSize: 12 }}>判官窗口指标取自最近上报节点。</Text>}
        {id === 'security-engine' && typeof record.engine_metrics_note === 'string' && <Text type="warning" style={{ display: 'block', fontSize: 12 }}>{record.engine_metrics_note}</Text>}
        {record.fault_evidence_reason_code === 'evidence_query_failed' && <Text type="warning" style={{ display: 'block', fontSize: 12 }}>故障事件统计暂不可用，判官状态以运行报告为准。</Text>}
        <details style={{ marginTop: 12, minWidth: 0 }}>
          <summary style={{ cursor: 'pointer', color: 'var(--text-secondary)', fontSize: 12 }}>技术详情</summary>
          <dl style={{ margin: '10px 0', fontSize: 12 }}>
            {technicalEntries(record).map(([field, value]) => <div key={field} style={{ display: 'flex', flexWrap: 'wrap', gap: '4px 16px', marginBottom: 4 }}><dt style={{ overflowWrap: 'anywhere' }}>{field}</dt><dd style={{ margin: 0, overflowWrap: 'anywhere' }}>{value}</dd></div>)}
          </dl>
        </details>
      </details>
    </section>
  )
}

export default function ServiceHealth() {
  const role = useAuthStore((state) => state.user?.role)
  const readQ = useQuery({ queryKey: ['service-health-readmodel'], queryFn: () => serviceHealthApi.readModel(), refetchInterval: 30_000 })
  const payload = readQ.data?.data?.data
  const raw: unknown[] = Array.isArray(payload?.components) ? payload.components : []
  const components = Object.keys(COMPONENTS).flatMap((id) => {
    const record = raw.find((entry): entry is Component => !!entry && typeof entry === 'object' && (entry as Component).component === id)
    return record ? [record] : []
  })
  const forbidden = (readQ.error as any)?.response?.status === 403
  const engine = components.find((record) => record.component === 'security-engine')
  const cascadeWarnings = Array.isArray(engine?.engine_cascade_warnings) ? engine.engine_cascade_warnings as string[] : []
  const degradationReasons = Array.isArray(engine?.engine_degradation_reasons) ? engine.engine_degradation_reasons as string[] : []

  return (
    <div className="enterprise-page" style={{ minWidth: 0 }}>
      <EnterprisePageHeader eyebrow="系统管理" title="服务健康" actions={<div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'center' }}>
        {canAccessPath(role, '/model-operations') && <Link to="/model-operations?tab=quality">模型运营 <ArrowRightOutlined aria-hidden="true" /></Link>}
        <Tooltip title="刷新状态"><Button aria-label="刷新状态" icon={<ReloadOutlined />} loading={readQ.isFetching} onClick={() => readQ.refetch()} /></Tooltip>
      </div>} />
      {readQ.isError ? <Alert type="error" showIcon message="服务状态暂时无法获取" description={forbidden ? '服务健康为平台管理员专用视图，当前账号无权限查看。' : '请检查管理服务连接后重试。'} /> : readQ.isLoading ? <Spin /> : components.length === 0 ? (
        <Alert type="warning" showIcon message="暂无组件证据" description="当前没有可用的组件状态，不能确认服务健康。" />
      ) : <>
        {components.length < Object.keys(COMPONENTS).length && <Alert type="warning" showIcon message="组件数据不完整" description="部分组件尚未返回状态，请刷新或检查管理服务。" />}
        {cascadeWarnings.length > 0 && <Alert type="warning" showIcon message="Tier-1 级联已关闭或处于降级状态" description={<ul style={{ margin: 0, paddingLeft: 18 }}>{cascadeWarnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>} />}
        {degradationReasons.length > 0 && <Alert type="error" showIcon message="检测降级（审计可见）" description={<ul style={{ margin: 0, paddingLeft: 18 }}>{degradationReasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>} />}
        <div style={{ minWidth: 0 }}>{components.map((record) => <ComponentRow key={String(record.component)} record={record} role={role} />)}</div>
        <Text type="secondary" style={{ fontSize: 12, overflowWrap: 'anywhere' }}>数据生成时间：{timestamp(payload?.generated_at)}</Text>
      </>}
    </div>
  )
}

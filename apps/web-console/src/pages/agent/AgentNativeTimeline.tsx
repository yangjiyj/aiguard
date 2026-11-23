import { useState } from 'react'
import { Alert, Button, Descriptions, Drawer, Empty, Input, Space, Table, Tag, Typography } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { EnterprisePageHeader } from '../../components/EnterpriseUI'
import { useAuditQueryIdentity } from '../../hooks/useAuditQueryIdentity'
import { useAuthStore } from '../../stores/auth'
import { unifiedAssetsApi, unifiedAssetKeys } from '../../services/unifiedAssets'
import { nativeEventsApi, nativeEventKeys, type NativeEventFilter, type NativeEventReference, type NativeEventResolution, type NativeObservation } from '../../services/nativeEvents'
import { canWriteAgent, time } from './dict'

const eventLabels: Record<string, string> = {
  'carrier.observed': '发现载体', 'definition.observed': '发现定义', 'asset.observed': '发现资产',
  'app.observed': '发现应用', 'workflow.observed': '发现工作流', 'run.started': '运行开始',
  'run.ended': '运行结束', 'instance.started': '实例开始', 'instance.ended': '实例结束', 'action.observed': '动作观察',
}
const resultLabels: Record<string, string> = {
  completed: '完成', failed: '失败', cancelled: '取消', unknown: '未知', attempted: '尝试',
  succeeded: '成功', denied: '拒绝',
}
const resolutionLabels: Record<NativeEventResolution['status'], string> = {
  matched: '精确匹配', missing: '未找到', ambiguous: '匹配不唯一',
  unavailable: '未核验', not_applicable: '不适用',
}
const resolutionReasons: Record<string, string> = {
  not_action_observed: '仅对动作观察事件核验旧事件引用',
  no_legacy_event_id: '来源未声明 legacy_event_id',
  no_same_tenant_endpoint_match: '未找到同租户且同端点的精确事件编号',
  multiple_same_tenant_endpoint_matches: '同租户且同端点存在多个事件编号匹配',
  exact_legacy_id_mismatch: '返回的事件编号与来源声明不完全相同',
  legacy_event_unresolved: '旧事件引用未匹配，因此未继续核验',
  no_session_id: '匹配事件未声明会话编号',
  no_same_tenant_endpoint_session: '未找到同租户且同端点的会话',
  multiple_same_tenant_endpoint_sessions: '同租户且同端点存在多个会话匹配',
  exact_session_id_mismatch: '返回的会话编号与匹配事件不完全相同',
  no_security_event_id: '匹配事件未声明告警编号',
  no_exact_agent_endpoint_alert: '未找到来源、端点和事件编号均匹配的告警',
  multiple_exact_agent_endpoint_alerts: '同一告警编号返回多个匹配',
  exact_security_event_id_mismatch: '返回的告警编号与匹配事件不完全相同',
}
const alertDeepLinkRoles = ['dept_manager', 'tenant_owner', 'tenant_admin', 'auditor']
function resolutionDisplay(value: NativeEventResolution, sessionLink = false, alertLink = false) {
  const color = value.status === 'matched' ? 'green' : value.status === 'ambiguous' ? 'orange' : 'default'
  return <Space wrap>
    <Tag color={color}>{resolutionLabels[value.status]}</Tag>
    {value.status === 'matched' && value.id && (sessionLink
      ? <Link to={'/agent/sessions/' + encodeURIComponent(value.id)}>{value.id}</Link>
      : alertLink
        ? <Link to={'/security/alerts?event_id=' + encodeURIComponent(value.id)}>{value.id}</Link>
        : <Typography.Text copyable>{value.id}</Typography.Text>)}
    {value.reason && <Typography.Text type="secondary">{resolutionReasons[value.reason] ?? '关联尚未核验'}</Typography.Text>}
  </Space>
}
function NativeReferenceAssetLink({ scope, sourceID, refHash }: { scope: string; sourceID: string; refHash: string }) {
  const role = useAuthStore(state => state.user?.role)
  const validHash = /^[a-f0-9]{64}$/.test(refHash)
  const mapping = useQuery({
    queryKey: unifiedAssetKeys.nativeReferenceLink(scope, sourceID, refHash),
    queryFn: () => unifiedAssetsApi.nativeReferenceLink(sourceID, refHash),
    enabled: validHash,
    retry: false,
  })
  if (!validHash) return <Typography.Text type="secondary">完整引用哈希无效，未查询</Typography.Text>
  if (mapping.isPending) return <Typography.Text type="secondary">检查当前手工映射…</Typography.Text>
  if (mapping.isError) return <Typography.Text type="danger">资产映射查询失败</Typography.Text>
  if (mapping.data?.linked && mapping.data.asset_id) return <Space wrap>
    <Tag color="green">操作员关联</Tag>
    <Link to={'/agent/assets?asset_id=' + encodeURIComponent(mapping.data.asset_id)}>资产 {mapping.data.asset_id}</Link>
  </Space>
  const params = new URLSearchParams({ source_id: sourceID, ref_hash: refHash })
  return <Space wrap>
    <Tag>未做手工关联</Tag>
    {canWriteAgent(role) && <Link to={'/agent/assets?' + params.toString()}>在资产目录中手工关联</Link>}
  </Space>
}
function nativeEventError(error: unknown): string {
  const status = (error as { response?: { status?: number } })?.response?.status
  if (status === 402) return '当前许可证不允许查看原生运行记录（402）'
  if (status === 403) return '无权查看当前原生运行记录（403）'
  if (status === 400) return '筛选条件无效，请清除筛选后重试（400）'
  if (status === 404) return '原生运行接口尚未启用或不可用（404）'
  return '原生运行记录加载失败，请重试'
}
export default function AgentNativeTimeline() {
  const scope = useAuditQueryIdentity()
  const [search] = useSearchParams()
  return <NativeTimeline key={scope + '|' + search.toString()} scope={scope} />
}
function NativeTimeline({ scope }: { scope: string }) {
  const userRole = useAuthStore(state => state.user?.role || '')
  const [search, setSearch] = useSearchParams()
  const [cursors, setCursors] = useState<number[]>([])
  const [selectedKey, setSelectedKey] = useState<string>()
  const filters: NativeEventFilter = {
    endpoint_id: search.get('endpoint') || undefined,
    source_id: search.get('source') || undefined,
    ref_hash: search.get('ref') || undefined,
    before_sequence: cursors[cursors.length - 1],
    limit: 20,
  }
  const list = useQuery({ queryKey: nativeEventKeys.list(scope, filters), queryFn: () => nativeEventsApi.list(filters), retry: false })
  const rows = list.isError ? [] : list.data?.items ?? []
  const selected = rows.find(row => row.endpoint_id + ':' + row.event_id === selectedKey)
  const narrow = (row: NativeObservation, ref?: NativeEventReference) => {
    const params = new URLSearchParams({ endpoint: row.endpoint_id, source: row.source_id })
    if (ref) params.set('ref', ref.ref_hash)
    setSelectedKey(undefined)
    setSearch(params)
  }
  const clear = () => { setSelectedKey(undefined); setSearch(new URLSearchParams()) }
  return <div className="enterprise-page">
    <EnterprisePageHeader eyebrow="智能体安全" title="原生运行调查" description="按采集来源与原生对象检查工作流、运行、实例和动作记录。" />
    <Alert type="info" showIcon message="原生关系与动作结果由采集端上报"
      description="已登记凭据证明上报来源；不证明业务主体身份、执行前阻断或因果关系。来源时间与接收时间分别展示，记录顺序不代表执行顺序。" />
    <Space wrap style={{ margin: '16px 0' }}>
      <Input.Search aria-label="筛选来源端点" placeholder="来源端点编号" defaultValue={filters.endpoint_id} allowClear style={{ width: 280 }}
        onSearch={value => setSearch(value ? new URLSearchParams({ endpoint: value }) : new URLSearchParams())} />
      {filters.source_id && <Tag>已限定上报来源</Tag>}
      {filters.ref_hash && <Tag>已限定同一原生对象</Tag>}
      <Button onClick={clear}>清除筛选</Button>
      <Button onClick={() => { setSelectedKey(undefined); if (cursors.length) setCursors([]); else void list.refetch() }}>刷新最新记录</Button>
      <Link to="/agent/sessions">终端会话与告警调查</Link>
      <Link to="/agent/assets">查看资产目录</Link>
    </Space>
    {list.isError ? <Alert type="error" showIcon message={nativeEventError(list.error)} action={<Button aria-label="重试" onClick={() => void list.refetch()}>重试</Button>} /> :
      <Table<NativeObservation> rowKey={row => row.endpoint_id + ':' + row.event_id} loading={list.isPending} dataSource={rows} pagination={false} scroll={{ x: 1400 }}
        locale={{ emptyText: <Empty description="暂无匹配的原生记录；未采集到记录不代表没有运行活动" /> }}
        columns={[
          { title: '事件', render: (_, row) => <Button type="link" onClick={() => setSelectedKey(row.endpoint_id + ':' + row.event_id)}>{eventLabels[row.event_type] ?? row.event_type} · {row.event_id}</Button> },
          { title: '上报来源', render: (_, row) => <Space direction="vertical" size={0}><Typography.Text>{row.producer.native_id}</Typography.Text><Button type="link" onClick={() => narrow(row)}>仅看此来源</Button></Space> },
          { title: '来源端点', render: (_, row) => <Link to={'/agent/endpoints?endpoint=' + encodeURIComponent(row.endpoint_id)}>{row.endpoint_id}</Link> },
          { title: '上报结果', render: (_, row) => row.outcome || row.status ? resultLabels[row.outcome || row.status || ''] ?? '未知' : '未报告' },
          { title: '来源时间', render: (_, row) => time(row.occurred_at) },
          { title: '接收时间', render: (_, row) => time(row.received_at) },
        ]} />}
    <Space style={{ marginTop: 16 }}>
      <Button disabled={!cursors.length || list.isFetching} onClick={() => { setSelectedKey(undefined); setCursors(values => values.slice(0, -1)) }}>上一页</Button>
      <Typography.Text>第 {cursors.length + 1} 页 · 每页 20 条</Typography.Text>
      <Button disabled={!list.data?.next_before_sequence || list.isFetching || list.isError}
        onClick={() => { const next = list.data?.next_before_sequence; if (next) { setSelectedKey(undefined); setCursors(values => [...values, next]) } }}>下一页</Button>
    </Space>
    <Drawer title="原生事件与关联依据" open={!!selected} onClose={() => setSelectedKey(undefined)} width={1000} destroyOnHidden>
      {selected && <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Descriptions bordered size="small" column={2} items={[
          { key: 'id', label: '事件编号', children: selected.event_id, span: 2 },
          { key: 'type', label: '事件类型', children: eventLabels[selected.event_type] ?? selected.event_type },
          { key: 'producer', label: '自报来源', children: selected.producer.native_id },
          { key: 'endpoint', label: '凭据对应端点', children: <Link to={'/agent/endpoints?endpoint=' + encodeURIComponent(selected.endpoint_id)}>{selected.endpoint_id}</Link>, span: 2 },
          { key: 'source-time', label: '来源时间', children: time(selected.occurred_at) },
          { key: 'receive-time', label: '接收时间', children: time(selected.received_at) },
        ]} />
        <Alert type="warning" showIcon message="以下原生对象关联由来源声明"
          description="只按同一来源下完整的对象标识查找记录；不会根据相似名称、时间接近或到达顺序补出父子关系。来源声明与现有记录匹配不证明因果或执行。" />
        {selected.investigation && selected.investigation.legacy_event.status !== 'not_applicable' && <Space direction="vertical" size={8} style={{ width: '100%' }}>
          <Typography.Title level={5}>旧事件关联核验</Typography.Title>
          <Alert type="info" showIcon message="只展示租户与端点边界内的精确记录匹配"
            description="legacy_event_id 来自动作上报内容。会话和告警只从精确匹配的现有事件解析，并继续校验租户、端点及告警来源摘要；匹配不证明因果或执行。" />
          <Descriptions bordered size="small" column={1} items={[
            { key: 'legacy-event', label: '来源声明的旧事件编号', children: resolutionDisplay(selected.investigation.legacy_event) },
            { key: 'session', label: '同端点会话', children: resolutionDisplay(selected.investigation.session, true) },
            { key: 'alert', label: '已核验的安全告警编号', children: resolutionDisplay(selected.investigation.alert, false, alertDeepLinkRoles.includes(userRole)) },
          ]} />
        </Space>}
        <Table<NativeEventReference> size="small" rowKey="role" dataSource={selected.references} pagination={false} scroll={{ x: 850 }}
          columns={[
            { title: '关系字段', dataIndex: 'role' },
            { title: '对象类型', render: (_, row) => row.ref.kind },
            { title: '原生编号', render: (_, row) => row.ref.native_id },
            { title: '命名空间 / 版本', render: (_, row) => row.ref.namespace + (row.ref.revision ? ' / ' + row.ref.revision : '') },
            { title: '资产映射', render: (_, row) => <NativeReferenceAssetLink scope={scope} sourceID={selected.source_id} refHash={row.ref_hash} /> },
            { title: '调查', render: (_, row) => <Button onClick={() => narrow(selected, row)}>查看该对象记录</Button> },
          ]} />
        <Typography.Title level={5}>原始上报内容</Typography.Title>
        {selected.payload ? <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(selected.payload, null, 2)}</pre> :
          <Typography.Text type="secondary">当前权限仅可查看记录摘要，原始内容未返回。</Typography.Text>}
      </Space>}
    </Drawer>
  </div>
}

import { useEffect, useState } from 'react'
import { Alert, Button, Card, Descriptions, Drawer, Empty, Popconfirm, Select, Space, Table, Tag, Typography } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { EnterprisePageHeader, MetricCard, SectionPanel } from '../../components/EnterpriseUI'
import { useAuditQueryIdentity } from '../../hooks/useAuditQueryIdentity'
import { useAuthStore } from '../../stores/auth'
import { agentEndpointApi } from '../../services/agentEndpoint'
import { isFullNativeReferenceHash, unifiedAssetsApi, unifiedAssetKeys, type AssetFilters, type AssetObservation, type UnifiedAsset } from '../../services/unifiedAssets'
import { assetTypes, canWriteAgent, label, time } from './dict'
import { assetError, catalogLabels, coverageGaps, endpointHealth } from './assetCoverage'

const unifiedTypes = [...assetTypes, { value: 'application', label: '应用' }, { value: 'workflow', label: '工作流' }]

function SourceHealth({ id, scope }: { id: string; scope: string }) {
  const endpoint = useQuery({ queryKey: ['agent', scope, 'asset-source-health', id], queryFn: () => agentEndpointApi.endpoint(id), retry: false })
  const [page, setPage] = useState(1)
  const params = { endpoint_id: id, page, page_size: 5 }
  const sessions = useQuery({ queryKey: ['agent', scope, 'asset-source-sessions', params], queryFn: () => agentEndpointApi.sessions(params), retry: false })
  const health = endpoint.data && endpointHealth(endpoint.data)
  return <Card title="来源端点健康与调查" size="small">
    <Link to={`/agent/endpoints?endpoint=${encodeURIComponent(id)}`}>端点详情：{id}</Link>
    {endpoint.isError ? <Alert type="error" showIcon message={assetError(endpoint.error)} /> : endpoint.isPending ? <Typography.Paragraph>端点健康加载中…</Typography.Paragraph> : endpoint.data && health && <Descriptions column={2} size="small" items={[
      { key: 'online', label: '在线状态', children: `${health.label} · ${health.reason}`, span: 2 },
      { key: 'heartbeat', label: '最后心跳', children: time(endpoint.data.last_heartbeat_at) },
      { key: 'event', label: '最近事件', children: time(endpoint.data.last_event_at) },
      { key: 'queue', label: '积压事件', children: endpoint.data.health?.queue_events ?? '未上报' },
      { key: 'drop', label: '丢弃事件', children: endpoint.data.health?.dropped_events ?? '未上报' },
      { key: 'upload', label: '上传诊断', children: endpoint.data.health?.last_upload_error ? '端点报告上传异常，请查看端点诊断' : '未报告上传异常；不代表已经验证上传成功', span: 2 },
    ]} />}
    <Typography.Paragraph type="secondary">以下会话与该来源端点关联，不能据此认定会话使用了这项资产。进入会话可查看时间线和关联告警。</Typography.Paragraph>
    {sessions.isError ? <Alert type="error" message={assetError(sessions.error)} showIcon /> : <Table size="small" rowKey="id" loading={sessions.isPending} dataSource={sessions.data?.items ?? []}
      locale={{ emptyText: '暂无该端点的会话记录' }}
      pagination={{ current: page, pageSize: 5, total: sessions.data?.total ?? 0, showSizeChanger: false, onChange: setPage }}
      columns={[
        { title: '来源端点的会话', render: (_, row) => <Link to={`/agent/sessions/${encodeURIComponent(row.session_id)}`}>{row.session_id}</Link> },
        { title: '最近活动', render: (_, row) => time(row.last_request_at) },
        { title: '阻断 / 收敛', render: (_, row) => `${row.blocked_count} / ${row.would_block_count}` },
      ]} />}
  </Card>
}
function AssetDetail({ asset, scope }: { asset: UnifiedAsset; scope: string }) {
  const [page, setPage] = useState(1)
  const [sourceEndpoint, setSourceEndpoint] = useState<string>()
  const history = useQuery({ queryKey: unifiedAssetKeys.history(scope, asset.id, page), queryFn: () => unifiedAssetsApi.history(asset.id, page), retry: false })
  return <Space direction="vertical" size={16} style={{ width: '100%' }}>
    <Descriptions bordered size="small" column={2} items={[
      { key: 'id', label: '资产编号', children: asset.id, span: 2 },
      { key: 'name', label: '名称', children: asset.name },
      { key: 'type', label: '类型', children: label(unifiedTypes, asset.asset_type) },
      { key: 'owner', label: '责任人编号', children: asset.owner_user_id || '未登记' },
      { key: 'unit', label: '业务单位', children: asset.business_unit || '未登记' },
      { key: 'service', label: '业务服务', children: asset.business_service || '未登记' },
      { key: 'catalog', label: '目录状态', children: catalogLabels[asset.catalog_status] ?? '未知状态' },
      { key: 'exception', label: '例外原因 / 到期', children: asset.catalog_reason ? `${asset.catalog_reason} · ${time(asset.catalog_expires_at)}` : '无例外记录', span: 2 },
      { key: 'first', label: '首次发现', children: time(asset.first_seen) },
      { key: 'last', label: '最近发现', children: time(asset.last_seen) },
    ]} />
    <Alert type="warning" showIcon message="覆盖缺口与待核验项" description={<ul>{coverageGaps(asset).map(gap => <li key={gap}>{gap}</li>)}</ul>} />
    <Typography.Title level={5}>静态扫描与来源历史</Typography.Title>
    <Typography.Text type="secondary">逐条展示历史扫描判定，不将静态放行解释为运行时控制。当前页仅包含部分历史，时间为来源声明和服务端接收时间。</Typography.Text>
    {history.isError ? <Alert type="error" message={assetError(history.error)} showIcon action={<Button onClick={() => void history.refetch()}>重试</Button>} /> : <Table<AssetObservation> size="small" rowKey="id" scroll={{ x: 1500 }} loading={history.isPending} dataSource={history.data?.items ?? []}
      pagination={{ current: page, pageSize: 20, total: history.data?.total ?? 0, showSizeChanger: false, onChange: setPage, showTotal: total => `共 ${total} 条历史` }}
      locale={{ emptyText: <Empty description="暂无资产观察记录；覆盖情况待核验" /> }}
      columns={[
        { title: '来源', render: (_, row) => row.source_type === 'agent_endpoint' ? <Button type="link" onClick={() => setSourceEndpoint(row.source_namespace)}>检查端点 {row.source_namespace}</Button> : `${row.source_type} · ${row.source_namespace}` },
        { title: '来源事件编号', dataIndex: 'source_event_id' },
        { title: '版本 / 哈希', render: (_, row) => <span>{row.version || '未记录'} / {row.hash || '未记录'}</span> },
        { title: '该次快照', render: (_, row) => row.present ? '存在' : '未报告存在' },
        { title: '扫描状态', render: (_, row) => row.scan_status || '未记录' },
        { title: '扫描判定', render: (_, row) => row.scan_decision || '未记录' },
        { title: '来源时间', render: (_, row) => time(row.source_occurred_at) },
        { title: '接收时间', render: (_, row) => time(row.received_at) },
      ]} />}
    {sourceEndpoint && <SourceHealth key={sourceEndpoint} id={sourceEndpoint} scope={scope} />}
  </Space>
}
export default function AgentAssetCoverage() {
  const scope = useAuditQueryIdentity()
  return <AssetCoveragePage key={scope} scope={scope} />
}
function AssetCoveragePage({ scope }: { scope: string }) {
  const [searchParams, setSearchParams] = useSearchParams()
  const sourceID = searchParams.get('source_id') || ''
  const refHash = searchParams.get('ref_hash') || ''
  const assetID = searchParams.get('asset_id') || ''
  const validSource = sourceID !== '' && sourceID === sourceID.trim() && Array.from(sourceID).every(character => character.charCodeAt(0) >= 0x20 && character.charCodeAt(0) !== 0x7f) && isFullNativeReferenceHash(refHash)
  const sourceRef = validSource ? { source_type: 'identity_event' as const, source_namespace: 'native:' + sourceID, native_id: refHash } : undefined
  const role = useAuthStore(state => state.user?.role)
  const canLink = canWriteAgent(role)
  const queryClient = useQueryClient()
  const [filters, setFilters] = useState<AssetFilters>(() => ({ page: 1, page_size: 20, asset_id: assetID || undefined }))
  const [selected, setSelected] = useState<UnifiedAsset>()
  useEffect(() => {
    setFilters(current => ({ ...current, page: 1, asset_id: assetID || undefined }))
    setSelected(undefined)
  }, [assetID])
  const list = useQuery({ queryKey: unifiedAssetKeys.list(scope, filters), queryFn: () => unifiedAssetsApi.list(filters), retry: false })
  const linkLookup = useQuery({
    queryKey: sourceRef ? unifiedAssetKeys.nativeReferenceLink(scope, sourceID, refHash) : ['agent', scope, 'native-reference-asset-link', 'none'],
    queryFn: () => unifiedAssetsApi.nativeReferenceLink(sourceID, refHash),
    enabled: !!sourceRef,
    retry: false,
  })
  const linkMutation = useMutation({
    mutationFn: (targetAssetID: string) => unifiedAssetsApi.linkSource(targetAssetID, sourceRef!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: unifiedAssetKeys.nativeReferenceLink(scope, sourceID, refHash) }),
  })
  useEffect(() => {
    if (!assetID || !list.data) return
    const exact = list.data.items.find(asset => asset.id === assetID)
    if (exact) setSelected(exact)
  }, [assetID, list.data])
  const rows = list.isError ? [] : list.data?.items ?? []
  const count = (test: (asset: UnifiedAsset) => boolean) => list.isSuccess ? rows.filter(test).length : undefined
  return <div className="enterprise-page">
    <EnterprisePageHeader eyebrow="智能体安全" title="资产覆盖与风险体检" description="从资产发现、接入和来源历史检查覆盖缺口，沿真实端点与会话继续调查。" />
    <SectionPanel title="当前页覆盖" description="统计仅覆盖当前页资产，不代表全网覆盖率。扫描存在、端点在线和运行时控制分别判定。">
      <div className="enterprise-metric-grid">
        <MetricCard label="已发现" value={count(a => a.discovered) ?? '—'} tone="blue" />
        <MetricCard label="已接入" value={count(a => a.managed) ?? '—'} tone="blue" hint="含已接入但失联的端点" />
        <MetricCard label="在线" value="待核验" hint="在来源详情检查心跳" />
        <MetricCard label="可观测" value="未知" hint="缺少资产级运行时证据" />
        <MetricCard label="可控制" value={count(a => a.controlled && a.control_state === 'evidenced' && a.control_evidence_count > 0) ?? '—'} hint="仅计控制生效证据，0 不代表已证实不可控制" />
      </div>
    </SectionPanel>
    <Space wrap style={{ margin: '16px 0' }}>
      <Select aria-label="资产类型" allowClear placeholder="资产类型" style={{ width: 180 }} options={unifiedTypes} value={filters.asset_type} onChange={asset_type => { setFilters(f => ({ ...f, asset_type, page: 1 })); setSelected(undefined) }} />
      <Select aria-label="目录状态" allowClear placeholder="目录状态" style={{ width: 200 }} options={[{ value: 'unreviewed', label: '未审核' }, { value: 'approved', label: '已批准' }, { value: 'exception', label: '例外（含过期）' }, { value: 'expired', label: '例外已过期' }]} value={filters.catalog_status} onChange={catalog_status => { setFilters(f => ({ ...f, catalog_status, page: 1 })); setSelected(undefined) }} />
      <Link to="/agent/endpoints">检查端点接入与健康</Link>
      <Link to="/security/skills">查看资产准入管理</Link>
      {assetID && <Tag closable onClose={event => { event.preventDefault(); const next = new URLSearchParams(searchParams); next.delete('asset_id'); setSearchParams(next) }}>精确资产 {assetID}</Tag>}
    </Space>
    {sourceRef && <Card size="small" title="手工关联原生来源">
      <Descriptions size="small" column={1} items={[
        { key: 'namespace', label: '来源命名空间', children: 'native:' + sourceID },
        { key: 'reference', label: '完整 ref_hash', children: <Typography.Text code copyable>{refHash}</Typography.Text> },
      ]} />
      <Typography.Paragraph type="secondary">此操作只把来源明确声明的完整引用关联到你选择的现有资产，不按名称或时间推测，也不会自动创建资产。</Typography.Paragraph>
      {linkLookup.isError && <Alert type="error" showIcon message="当前映射状态加载失败，暂不能添加关联" action={<Button onClick={() => void linkLookup.refetch()}>重试</Button>} />}
      {linkLookup.data?.linked && linkLookup.data.asset_id && <Alert type="success" showIcon message="此引用已有操作员关联" description={<Link to={'/agent/assets?asset_id=' + encodeURIComponent(linkLookup.data.asset_id)}>打开资产 {linkLookup.data.asset_id}</Link>} />}
      {linkLookup.isSuccess && !linkLookup.data?.linked && !canLink && <Alert type="info" showIcon message="当前角色可查看映射；手工关联需要资产写入权限" />}
      {linkMutation.isError && <Alert type="error" showIcon message={assetError(linkMutation.error)} />}
    </Card>}
    {list.isError ? <Alert type="error" showIcon message={assetError(list.error)} action={<Button onClick={() => void list.refetch()}>重新加载</Button>} /> : <Table<UnifiedAsset> rowKey="id" loading={list.isPending} dataSource={rows} scroll={{ x: 1650 }}
      pagination={{ current: filters.page, pageSize: 20, total: list.data?.total ?? 0, showSizeChanger: false, showTotal: total => `筛选范围内共 ${total} 个资产`, onChange: page => { setFilters(f => ({ ...f, page })); setSelected(undefined) } }}
      locale={{ emptyText: <Empty description="暂无符合条件的资产；尚未发现不代表环境中不存在资产" /> }}
      columns={[
        { title: '资产', render: (_, row) => <Button type="link" onClick={() => setSelected(row)}>{row.name}</Button> },
        { title: '类型', render: (_, row) => label(unifiedTypes, row.asset_type) },
        { title: '已发现', render: (_, row) => row.discovered ? '是' : '无记录' },
        { title: '已接入', render: (_, row) => row.managed ? '是（含失联端点）' : '未关联有效端点' },
        { title: '在线', render: () => '待检查来源心跳' },
        { title: '可观测', render: () => '未知：无资产级运行时证据' },
        { title: '可控制', render: (_, row) => row.controlled && row.control_state === 'evidenced' && row.control_evidence_count > 0 ? '有控制生效证据' : '未知：无控制生效证据' },
        { title: '最新扫描存在', render: (_, row) => row.observed ? '是' : '未报告存在' },
        { title: '目录', render: (_, row) => <Tag color={row.catalog_status === 'expired' ? 'red' : undefined}>{catalogLabels[row.catalog_status] ?? '未知状态'}</Tag> },
        { title: '覆盖缺口', render: (_, row) => coverageGaps(row).join('；') },
        ...(sourceRef && canLink && linkLookup.isSuccess && !linkLookup.data?.linked ? [{
          title: '手工关联',
          render: (_: unknown, row: UnifiedAsset) => <Popconfirm
            title={'将此原生来源关联到“' + row.name + '”？'}
            description="只使用页面显示的 native 命名空间和完整 ref_hash。"
            okText="确认关联" cancelText="取消"
            onConfirm={() => linkMutation.mutate(row.id)}
          ><Button size="small" loading={linkMutation.isPending && linkMutation.variables === row.id} disabled={linkMutation.isPending}>关联此来源</Button></Popconfirm>,
        }] : []),
      ]} />}
    <Drawer title="资产详情与调查" open={!!selected} width={1000} onClose={() => setSelected(undefined)} destroyOnHidden>
      {selected && <AssetDetail key={scope + selected.id} asset={selected} scope={scope} />}
    </Drawer>
  </div>
}

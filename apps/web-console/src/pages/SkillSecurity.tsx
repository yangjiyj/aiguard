import { SEVERITY_LABELS } from '../utils/risk'
import { useState } from 'react'
import { Alert, Button, Descriptions, Drawer, Form, Input, Modal, Select, Space, Table, Tabs, Tag, Tooltip, Typography, message } from 'antd'
import { AuditOutlined, LinkOutlined, ReloadOutlined, ScanOutlined } from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { skillSecurityApi, type SkillAsset, type SkillAssetVersion, type SkillInvocationObservation } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { useSecurityExecutionMode } from '../hooks/useSecurityExecutionMode'
import { useAccess } from '../hooks/useAccess'
import ProtectionGroupSection from '../components/protection/ProtectionGroupSection'

const { Title, Text } = Typography
const statuses: Record<string, string> = { approved: '已批准', unverified: '待审核', quarantined: '已隔离', revoked: '已撤销' }
const sourceLabel = (source: string) => source === 'uploaded' ? '上传包' : source === 'observed' ? '定义声明' : '未知'
const tag = (value?: string) => <Tag color={value === 'quarantined' ? 'error' : value === 'approved' ? 'success' : undefined}>{statuses[value || ''] || '未知'}</Tag>
const time = (value?: string) => value && !Number.isNaN(Date.parse(value)) ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '未观测'
const fingerprint = (value?: string) => value ? <Text code copyable={{ text: value }}>{value.slice(0, 12)}...{value.slice(-8)}</Text> : <Text type="secondary">未知</Text>
const findingLabels: Record<string, string> = { dangerous_command: '破坏性命令', credential_path: '凭据路径', metadata_access: '云元数据访问', network_egress: '外部网络地址', install_hook: '安装 Hook', unbounded_dependency: '未固定依赖', hidden_instruction: '隐藏指令', dynamic_code_execution: '动态代码执行', obfuscated_payload: '混淆载荷', archive_violation: '压缩包违规', embedded_archive: '嵌套压缩包', manifest_missing: '缺少 Skill 清单' }

export default function SkillSecurity() {
  const client = useQueryClient()
  const access = useAccess()
  const tenant = useAuthStore((state) => state.user?.tenant_id)
  const actor = useAuthStore((state) => state.user?.id)
  const canManage = access.canManageSkillAdmission
  const mode = useSecurityExecutionMode()
  const [tab, setTab] = useState('assets')
  const [page, setPage] = useState(1)
  const [invokePage, setInvokePage] = useState(1)
  const [search, setSearch] = useState('')
  const [source, setSource] = useState<string>()
  const [status, setStatus] = useState<string>()
  const [invocationFilter, setInvocationFilter] = useState<{ asset_id?: string; version_id?: string }>({})
  const [asset, setAsset] = useState<SkillAsset | null>(null)
  const [version, setVersion] = useState<SkillAssetVersion | null>(null)
  const [scanOpen, setScanOpen] = useState(false)
  const [archive, setArchive] = useState<File | null>(null)
  const [scanForm] = Form.useForm()
  const [scanFailure, setScanFailure] = useState<string>()
  // force：扫描判为阻断或扫描失败的版本强制批准，审核理由同时作为强制批准原因提交。
  const [review, setReview] = useState<{ version: SkillAssetVersion; status: string; force?: boolean } | null>(null)
  const [reason, setReason] = useState('')
  const [conflict, setConflict] = useState<string>()
  const assetsQ = useQuery({ queryKey: ['skill-security', 'assets', tenant, actor, page, search, source, status], queryFn: () => skillSecurityApi.listAssets({ limit: 20, offset: (page - 1) * 20, query: search || undefined, source_type: source, admission_status: status }).then((response) => response.data) })
  const invocationsQ = useQuery({ queryKey: ['skill-security', 'invocations', tenant, actor, invokePage, invocationFilter], queryFn: () => skillSecurityApi.listInvocations({ limit: 20, offset: (invokePage - 1) * 20, ...invocationFilter }).then((response) => response.data), enabled: tab === 'invocations' })
  const versionsQ = useQuery({ queryKey: ['skill-security', 'versions', tenant, actor, asset?.id], queryFn: () => skillSecurityApi.listVersions(asset!.id).then((response) => response.data), enabled: Boolean(asset) })
  const assets = assetsQ.data?.items || []
  const versions = versionsQ.data?.items || []
  const selectedVersion = versions.find((item) => item.id === version?.id) || version
  const summary = assetsQ.data?.summary
  const refresh = () => client.invalidateQueries({ queryKey: ['skill-security'] })
  const openResult = (data: { version?: SkillAssetVersion; analysis_surface?: string }, failed: boolean) => {
    const scanned = data.version
    if (!scanned?.id || !scanned.asset_id) throw new Error('扫描回执缺少持久化版本')
    setAsset({ id: scanned.asset_id, canonical_name: String(scanForm.getFieldValue('canonical_name') || ''), display_name: String(scanForm.getFieldValue('display_name') || ''), source_type: data.analysis_surface === 'uploaded_scan' ? 'uploaded' : 'unknown', admission_status: scanned.admission_status })
    setVersion(scanned)
    setScanFailure(failed ? scanned.scan_error_code || '扫描未完成' : undefined)
    setScanOpen(false); setArchive(null); scanForm.resetFields(); setTab('assets')
  }
  const scan = useMutation({
    mutationFn: skillSecurityApi.scanArchive,
    onSuccess: async (response) => { openResult(response.data, false); await refresh() },
    onError: async (error: any) => {
      if (error.response?.status === 422 && error.response?.data?.version) { openResult(error.response.data, true); await refresh(); return }
      setScanFailure(error.response?.data?.error?.message || '扫描提交失败'); message.error('扫描未完成')
    },
  })
  const admission = useMutation({
    mutationFn: async () => {
      if (!review || !reason.trim()) throw new Error('请填写审核理由')
      return skillSecurityApi.setAdmission(review.version.id, review.status, { reason: reason.trim(), expected_status: review.version.admission_status, expected_bundle_hash: review.version.bundle_hash, ...(review.force ? { override_reason: reason.trim() } : {}) })
    },
    onSuccess: async () => { setReview(null); setReason(''); setConflict(undefined); await refresh(); message.success('审核已保存') },
    onError: async (error: any) => {
      if (error.response?.status === 409) { setReview(null); setConflict('版本状态已变化，请重新审核'); await refresh() }
      else message.error(error.message || '审核失败')
    },
  })
  const submitScan = (values: Record<string, string>) => {
    if (!archive || !archive.name.toLowerCase().endsWith('.zip') || archive.size > 20 * 1024 * 1024) { message.error('请选择不超过 20 MiB 的 ZIP'); return }
    const body = new FormData(); body.append('archive', archive)
    for (const key of ['canonical_name', 'display_name', 'declared_version', 'source_uri', 'publisher', 'source_commit']) { const value = String(values[key] || '').trim(); if (value) body.append(key, value) }
    scan.mutate(body)
  }
  // 扫描判为阻断或扫描失败的版本只能强制批准（必填原因）；签名无效、仅观测到的定义、还没扫描的不能批。
  const forceOnly = (item: SkillAssetVersion) => item.decision === 'block' || item.scan_status === 'failed'
  const approvable = (item: SkillAssetVersion) => canManage && asset?.source_type === 'uploaded' && Boolean(item.declared_version?.trim()) && /^[a-f0-9]{64}$/i.test(item.bundle_hash) && (item.scan_status === 'completed' || (item.scan_status === 'failed' && forceOnly(item))) && item.signature_status !== 'invalid' && item.admission_status !== 'approved'
  const showInvocations = (item: SkillAssetVersion) => { setInvocationFilter({ asset_id: item.asset_id, version_id: item.id }); setInvokePage(1); setTab('invocations'); setAsset(null); setVersion(null) }
  const versionActions = (item: SkillAssetVersion) => <Space wrap>
    <Button size="small" onClick={() => setVersion(item)}>完整结果</Button>
    <Button size="small" icon={<LinkOutlined aria-hidden="true" />} onClick={() => showInvocations(item)}>调用关联</Button>
    {forceOnly(item)
      ? <Button size="small" danger icon={<AuditOutlined aria-hidden="true" />} disabled={!approvable(item)} onClick={() => setReview({ version: item, status: 'approved', force: true })}>强制批准</Button>
      : <Button size="small" icon={<AuditOutlined aria-hidden="true" />} disabled={!approvable(item)} onClick={() => setReview({ version: item, status: 'approved' })}>批准</Button>}
    <Button size="small" danger disabled={!canManage || item.admission_status === 'quarantined'} onClick={() => setReview({ version: item, status: 'quarantined' })}>隔离</Button>
    <Button size="small" disabled={!canManage || item.admission_status === 'revoked'} onClick={() => setReview({ version: item, status: 'revoked' })}>撤销</Button>
  </Space>
  const statusOptions = Object.entries(statuses).map(([value, label]) => ({ value, label }))
  return <div className="enterprise-page">
    <Space wrap style={{ width: '100%', justifyContent: 'space-between', marginBottom: 16 }}>
      <Title level={4} style={{ margin: 0 }}>Skill 安全准入</Title>
      <Space wrap><Tooltip title="网关结果不能证明终端本地工具已完成"><Tag>端侧执行：未知</Tag></Tooltip><Tag>全局执行：{mode.isError ? '待确认' : mode.mode?.effective_mode === 'record' ? '仅记录' : mode.mode ? '执行策略' : '待确认'}</Tag><Button icon={<ReloadOutlined />} aria-label="刷新 Skill" onClick={refresh} /><Button icon={<ScanOutlined aria-hidden="true" />} type="primary" disabled={!canManage} onClick={() => { setScanFailure(undefined); setScanOpen(true) }}>提交扫描</Button></Space>
    </Space>
    <ProtectionGroupSection group="skill" title="调用防护" ariaLabel="Skill 调用防护" canManage={access.canManageSecurityPolicy} style={{ marginBottom: 16 }} />
    {assetsQ.isError && <Alert type="error" showIcon message="Skill 清单读取失败" />}
    <Space wrap style={{ marginBottom: 16 }}>
      {([['上传资产', 'uploaded_assets'], ['定义声明', 'observed_assets'], ['待审核版本', 'pending_versions'], ['已批准版本', 'approved_versions'], ['隔离版本', 'quarantined_versions'], ['扫描失败', 'failed_scans'], ['调用观察', 'invocations']] as const).map(([label, key]) => <Tag key={key}>{label}：{!assetsQ.isError && typeof summary?.[key] === 'number' ? summary[key] : '待核验'}</Tag>)}
    </Space>
    <Tabs activeKey={tab} onChange={setTab} items={[
      { key: 'assets', label: '资产与版本', children: <>
        <Space wrap style={{ marginBottom: 12 }}><Input.Search placeholder="搜索 Skill" allowClear onSearch={(value) => { setSearch(value); setPage(1) }} /><Select aria-label="Skill 来源筛选" style={{ width: 140 }} allowClear placeholder="全部来源" options={[{ value: 'uploaded', label: '上传包' }, { value: 'observed', label: '定义声明' }]} onChange={(value) => { setSource(value); setPage(1) }} /><Select aria-label="Skill 准入筛选" style={{ width: 140 }} allowClear placeholder="全部准入状态" options={statusOptions} onChange={(value) => { setStatus(value); setPage(1) }} /></Space>
        <Table<SkillAsset> rowKey="id" loading={assetsQ.isLoading} dataSource={assets} scroll={{ x: 850 }} pagination={{ current: page, pageSize: 20, total: assetsQ.data?.total ?? 0, showSizeChanger: false, onChange: setPage }} columns={[
          { title: 'Skill', render: (_: unknown, item: SkillAsset) => <Space direction="vertical" size={0}><Text strong>{item.display_name || item.canonical_name}</Text><Text code>{item.canonical_name}</Text></Space> },
          { title: '来源', dataIndex: 'source_type', render: sourceLabel }, { title: '发布者', dataIndex: 'publisher', render: (value?: string) => value || '未声明' }, { title: '准入', dataIndex: 'admission_status', render: tag }, { title: '最近观测', dataIndex: 'last_seen_at', render: time },
          { title: '操作', render: (_: unknown, item: SkillAsset) => <Button type="link" onClick={() => { setAsset(item); setVersion(null); setScanFailure(undefined) }}>查看版本</Button> },
        ]} />
      </> },
      { key: 'invocations', label: '调用关联', children: <>
        {(invocationFilter.asset_id || invocationFilter.version_id) && <Space style={{ marginBottom: 12 }}><Tag>精确版本：{invocationFilter.version_id}</Tag><Button onClick={() => { setInvocationFilter({}); setInvokePage(1) }}>全部调用</Button></Space>}
        {invocationsQ.isError && <Alert type="error" showIcon message="调用关联读取失败" />}
        <Table<SkillInvocationObservation> rowKey="id" loading={invocationsQ.isLoading} dataSource={invocationsQ.data?.items || []} scroll={{ x: 1150 }} pagination={{ current: invokePage, pageSize: 20, total: invocationsQ.data?.total ?? 0, showSizeChanger: false, onChange: setInvokePage }} columns={[
          { title: 'Skill / 版本', render: (_: unknown, item: SkillInvocationObservation) => <Space direction="vertical" size={0}><Text>{item.canonical_name || '未关联'} / {item.declared_version || '未知版本'}</Text><Text type="secondary">{item.asset_version_id || '无精确版本'}</Text></Space> },
          { title: '网关事实', dataIndex: 'status', render: (value: string) => ({ proposed: '拟调用', confirmed: '进入确认', blocked: '网关阻断', forwarded: '网关转发' }[value] || '未知') },
          { title: '原始判定', dataIndex: 'raw_decision', render: (value: string) => ({ allow: '放行', audit: '记录', confirm: '需确认', block: '应阻断' }[value] || '未知') },
          { title: '实际动作', dataIndex: 'effective_decision', render: (value: string) => ({ allow: '放行', audit: '记录', confirm: '需确认', block: '阻断' }[value] || '未知') },
          { title: '结果观察', render: (_: unknown, item: SkillInvocationObservation) => <Space direction="vertical" size={0}><Text>{item.result_observed_at ? `已收到 · ${item.result_status || '未分类'}` : '未收到'}</Text><Text type="secondary">端侧执行：未知</Text></Space> },
          { title: '归因', render: (_: unknown, item: SkillInvocationObservation) => <Tooltip title={item.tool_call_id || '缺少工具调用 ID'}><Text>{item.attribution_mode === 'explicit' ? item.asset_version_id ? '精确版本关联' : '调用方声明' : item.attribution_mode === 'linked' ? '结果关联' : '未关联'}</Text></Tooltip> },
          { title: '调用时间', dataIndex: 'proposed_at', render: time },
          { title: '请求证据', render: (_: unknown, item: SkillInvocationObservation) => item.request_id ? <Link to={`/audit/access-retention?view=requests&request_id=${encodeURIComponent(item.request_id)}`}>{item.request_id}</Link> : '未关联' },
        ]} />
      </> },
    ]} />
    <Modal title="提交 Skill 压缩包扫描" open={scanOpen} okText="开始扫描" onOk={() => scanForm.submit()} confirmLoading={scan.isPending} onCancel={() => setScanOpen(false)} destroyOnHidden>
      <Tag>ZIP · 上限 20 MiB</Tag>{scanFailure && <Alert type="error" message={scanFailure} showIcon />}
      <Form form={scanForm} layout="vertical" onFinish={submitScan} style={{ marginTop: 12 }}>
        <Form.Item name="canonical_name" label="Skill 标识" rules={[{ required: true }]}><Input maxLength={255} /></Form.Item>
        <Form.Item name="display_name" label="显示名称"><Input maxLength={255} /></Form.Item>
        <Form.Item name="declared_version" label="声明版本" rules={[{ required: true }]}><Input maxLength={255} /></Form.Item>
        <Form.Item label="Skill 压缩包" required><input aria-label="Skill 压缩包" type="file" accept=".zip,application/zip" onChange={(event) => setArchive(event.target.files?.[0] || null)} /></Form.Item>
        <Form.Item name="source_uri" label="来源地址"><Input maxLength={2048} /></Form.Item>
        <Form.Item name="publisher" label="发布者"><Input maxLength={255} /></Form.Item>
        <Form.Item name="source_commit" label="来源 Commit"><Input maxLength={255} /></Form.Item>
      </Form>
    </Modal>
    <Drawer title={asset?.display_name || asset?.canonical_name || '版本结果'} open={Boolean(asset)} width={Math.min(1000, typeof window === 'undefined' ? 1000 : window.innerWidth)} onClose={() => { setAsset(null); setVersion(null) }}>
      <Space wrap style={{ marginBottom: 12 }}><Tag>来源：{sourceLabel(asset?.source_type || '')}</Tag><Tag>签名验证：未执行</Tag><Tag>端侧执行：未知</Tag></Space>
      {versionsQ.isError && <Alert type="error" showIcon message="版本读取失败" />}
      {scanFailure && <Alert type="error" showIcon message={`扫描失败：${scanFailure}`} />}
      {conflict && <Alert type="warning" showIcon message={conflict} />}
      <Table<SkillAssetVersion> rowKey="id" loading={versionsQ.isLoading} dataSource={versions} pagination={false} scroll={{ x: 800 }} columns={[
        { title: '版本', dataIndex: 'declared_version' }, { title: '扫描', render: (_: unknown, item: SkillAssetVersion) => item.scan_status === 'completed' ? '已完成' : item.scan_status === 'failed' ? `失败 · ${item.scan_error_code || '未知错误'}` : '未扫描' },
        { title: '准入', dataIndex: 'admission_status', render: tag }, { title: '包 / 定义指纹', dataIndex: 'bundle_hash', render: fingerprint }, { title: '操作', render: (_: unknown, item: SkillAssetVersion) => versionActions(item) },
      ]} />
      {selectedVersion && <section style={{ marginTop: 20 }}>
        <Space wrap style={{ marginBottom: 12 }}><Title level={5} style={{ margin: 0 }}>完整扫描结果</Title>{tag(selectedVersion.admission_status)}{versionActions(selectedVersion)}</Space>
        <Descriptions size="small" column={{ xs: 1, sm: 2 }}>
          <Descriptions.Item label="声明版本">{selectedVersion.declared_version}</Descriptions.Item><Descriptions.Item label="扫描状态">{selectedVersion.scan_status === 'completed' ? '已完成' : selectedVersion.scan_status === 'failed' ? '失败' : '未扫描'}</Descriptions.Item>
          <Descriptions.Item label="Bundle SHA256">{fingerprint(selectedVersion.bundle_hash)}</Descriptions.Item><Descriptions.Item label="文件树 SHA256">{fingerprint(selectedVersion.tree_hash)}</Descriptions.Item>
          <Descriptions.Item label="扫描判定">{selectedVersion.decision === 'block' ? '阻断级发现' : selectedVersion.decision === 'confirm' ? '需审核' : selectedVersion.decision === 'allow' ? '无阻断级发现' : selectedVersion.decision === 'audit' ? '审计' : '未知'}</Descriptions.Item><Descriptions.Item label="扫描等级">{SEVERITY_LABELS[selectedVersion.risk_level] || '未知'}</Descriptions.Item>
          <Descriptions.Item label="扫描错误">{selectedVersion.scan_error_code || '无'}</Descriptions.Item>
          <Descriptions.Item label="最近审核人">{selectedVersion.reviewed_by || '未审核'}</Descriptions.Item><Descriptions.Item label="审核时间">{time(selectedVersion.reviewed_at)}</Descriptions.Item>
          <Descriptions.Item label="审核理由" span={2}>{selectedVersion.review_reason || '未记录'}</Descriptions.Item>
          <Descriptions.Item label="批准人">{selectedVersion.approved_by || '未批准'}</Descriptions.Item><Descriptions.Item label="批准时间">{time(selectedVersion.approved_at)}</Descriptions.Item>
        </Descriptions>
        <Title level={5}>全部发现</Title>
        <Table rowKey={(_, index) => String(index)} dataSource={Array.isArray(selectedVersion.findings) ? selectedVersion.findings : []} pagination={{ pageSize: 10 }} scroll={{ x: 600 }} expandable={{ expandedRowRender: (item) => <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', margin: 0 }}>{JSON.stringify(item, null, 2)}</pre> }} columns={[
          { title: '发现', render: (_: unknown, item: any) => <Tooltip title={item.code || item.type}>{findingLabels[item.code || item.type] || item.code || item.type || '未分类'}</Tooltip> }, { title: '严重度', dataIndex: 'severity', render: (value: string) => SEVERITY_LABELS[value] || value || '未知' }, { title: '位置', render: (_: unknown, item: any) => `${item.file || item.field || item.path || '未定位'}${item.line ? ':' + item.line : ''}` }, { title: '证据预览', ellipsis: true, render: (_: unknown, item: any) => <Tooltip title={item.evidence_preview || item.message || item.evidence}><Text>{item.evidence_preview || item.message || item.evidence || '无预览'}</Text></Tooltip> },
        ]} />
        <Title level={5}>文件清单</Title><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 360, overflow: 'auto' }}>{JSON.stringify(selectedVersion.manifest || {}, null, 2)}</pre>
      </section>}
    </Drawer>
    <Modal title={review?.force ? '强制批准' : '审核精确 Skill 版本'} open={Boolean(review)} onCancel={() => setReview(null)} okText={review?.force ? '强制批准' : '保存审核'} confirmLoading={admission.isPending} okButtonProps={{ 'aria-label': review?.force ? '强制批准' : '保存审核', danger: Boolean(review?.force), disabled: !reason.trim() || !canManage }} onOk={() => admission.mutate()}>
      {review?.force ? <p>{review.version.scan_status === 'failed' ? '该版本扫描失败，批准后可以被调用' : '该版本扫描判为阻断，批准后可以被调用'}</p> : null}
      <Descriptions column={1} size="small"><Descriptions.Item label="目标版本">{review?.version.declared_version}</Descriptions.Item><Descriptions.Item label="包指纹">{fingerprint(review?.version.bundle_hash)}</Descriptions.Item><Descriptions.Item label="当前状态">{tag(review?.version.admission_status)}</Descriptions.Item><Descriptions.Item label="审核动作">{tag(review?.status)}</Descriptions.Item></Descriptions>
      <Form layout="vertical"><Form.Item label="审核理由" required><Input.TextArea aria-label="审核理由" value={reason} onChange={(event) => setReason(event.target.value)} maxLength={500} showCount /></Form.Item></Form>
    </Modal>
  </div>
}

import { useMemo, useRef, useState } from 'react'
import { Alert, Button, Descriptions, Drawer, Empty, Popconfirm, Progress, Space, Table, Tag, Tooltip, Typography, Upload, message, theme } from 'antd'
import { CloudUploadOutlined, DeleteOutlined, DownloadOutlined, FileSearchOutlined, ReloadOutlined, StopOutlined } from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { corpusDownloadUrl, corpusScanApi, uploadCorpusFile, type CorpusScanJob, type CorpusScanStatus, type CorpusTypeStat } from '../services/corpusScan'
import { useAuthStore } from '../stores/auth'

const { Title, Text, Paragraph } = Typography

const ACCEPT = '.jsonl,.csv,.txt,.docx,.pdf,.xlsx'
const TEXT_LIMIT = 2 * 1024 * 1024 * 1024
const DOC_LIMIT = 100 * 1024 * 1024
const DOC_FORMATS = ['docx', 'pdf', 'xlsx']

const statusLabels: Record<CorpusScanStatus, string> = {
  uploading: '上传中', queued: '排队中', running: '扫描中', succeeded: '已完成', failed: '失败', canceled: '已取消', interrupted: '已中断',
}
const statusColors: Partial<Record<CorpusScanStatus, string>> = { succeeded: 'success', failed: 'error', running: 'processing', queued: 'default', interrupted: 'warning' }
const terminal = (status?: CorpusScanStatus) => !!status && ['succeeded', 'failed', 'canceled', 'interrupted'].includes(status)

const errorLabels: Record<string, string> = {
  engine_unavailable: '安全引擎不可用',
  engine_result_mismatch: '检测结果与原文不一致',
  extract_failed: '文档无法提取文本（损坏、加密或类型不符）',
  source_unreadable: '原始文件读取失败',
  storage_error: '文件存储失败',
  report_failed: '报告生成失败',
  scan_failed: '扫描失败',
  worker_interrupted: '执行进程中断',
  canceled: '已取消',
}
const unscannedLabels: Record<string, string> = { unparsable: '无法解析', line_too_long: '单行超过 1 MB', field_too_large: '字段超过 4 MB' }
const noteLabels: Record<string, string> = { document_text_incomplete: '文档文本提取不完整（超出提取上限或部分内容无法读取），副本只包含已提取的部分' }
const uploadErrors: Record<string, string> = {
  local_storage_required: '训练语料扫描需要本地留存存储，当前配置为对象存储',
  unsupported_format: '只支持 jsonl、csv、txt、docx、pdf、xlsx',
  file_too_large: '文件超过大小上限',
  sha256_mismatch: '上传内容校验失败，请重新上传',
  engine_unavailable: '安全引擎未配置',
}

const bytes = (value: number) => {
  if (!Number.isFinite(value) || value < 0) return '-'
  const units = ['B', 'KB', 'MB', 'GB']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit++ }
  return `${unit === 0 ? size : size.toFixed(1)} ${units[unit]}`
}
const time = (value?: string | null) => value && !Number.isNaN(Date.parse(value)) ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '-'
const apiErrorCode = (error: any): string | undefined => error?.response?.data?.error?.code

function TypeBars({ stats }: { stats: CorpusTypeStat[] }) {
  const { token } = theme.useToken()
  const max = Math.max(1, ...stats.map((item) => item.hits))
  if (stats.length === 0) return <Text type="secondary">未发现敏感信息</Text>
  return <div role="table" aria-label="按类型统计">
    <div role="row" style={{ display: 'grid', gridTemplateColumns: '9em 1fr 7em 7em', gap: 8, color: token.colorTextSecondary, fontSize: token.fontSizeSM, paddingBottom: 4 }}>
      <span role="columnheader">类型</span><span role="columnheader" aria-hidden="true" /><span role="columnheader" style={{ textAlign: 'right' }}>命中次数</span><span role="columnheader" style={{ textAlign: 'right' }}>涉及条数</span>
    </div>
    {stats.map((item) => <div role="row" key={item.type} style={{ display: 'grid', gridTemplateColumns: '9em 1fr 7em 7em', gap: 8, alignItems: 'center', padding: '4px 0' }}>
      <span role="cell" style={{ color: token.colorText }}>{item.label}</span>
      <span role="cell" aria-hidden="true">
        <Tooltip title={`${item.label}：命中 ${item.hits} 次，涉及 ${item.records} 条`}>
          <span style={{ display: 'block', height: 10, width: `${Math.max(2, (item.hits / max) * 100)}%`, background: token.colorPrimary, borderRadius: '0 4px 4px 0' }} />
        </Tooltip>
      </span>
      <span role="cell" style={{ textAlign: 'right', color: token.colorText, fontVariantNumeric: 'tabular-nums' }}>{item.hits.toLocaleString('zh-CN')}</span>
      <span role="cell" style={{ textAlign: 'right', color: token.colorTextSecondary, fontVariantNumeric: 'tabular-nums' }}>{item.records.toLocaleString('zh-CN')}</span>
    </div>)}
  </div>
}

function ScanProgress({ job }: { job: CorpusScanJob }) {
  if (job.status === 'uploading') return <Progress size="small" percent={Math.floor((job.uploaded_bytes / Math.max(1, job.size_bytes)) * 100)} format={() => `已上传 ${bytes(job.uploaded_bytes)}`} />
  if (job.status === 'running' || job.status === 'queued') {
    const percent = DOC_FORMATS.includes(job.format) ? undefined : Math.min(99, Math.floor((job.processed_bytes / Math.max(1, job.size_bytes)) * 100))
    return <Progress size="small" status="active" percent={percent ?? 0} format={() => job.status === 'queued' ? '等待执行' : `已扫 ${job.scanned_records.toLocaleString('zh-CN')} 条`} />
  }
  return <Text>{job.total_records.toLocaleString('zh-CN')} 条 / 命中 {job.hit_records.toLocaleString('zh-CN')} 条</Text>
}

export default function CorpusScan() {
  const client = useQueryClient()
  const tenant = useAuthStore((state) => state.user?.tenant_id)
  const actor = useAuthStore((state) => state.user?.id)
  const [detailId, setDetailId] = useState<string | null>(null)
  const [upload, setUpload] = useState<{ name: string; phase: 'hash' | 'upload'; done: number; total: number } | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const listKey = ['corpus-scans', tenant, actor]

  const listQ = useQuery({
    queryKey: listKey,
    queryFn: () => corpusScanApi.list().then((response) => response.data),
    refetchInterval: (query) => {
      const items = query.state.data?.items || []
      return query.state.status === 'error' || items.every((item) => terminal(item.status) || item.status === 'uploading') ? false : 1000
    },
  })
  const detailQ = useQuery({
    queryKey: ['corpus-scans', 'detail', tenant, actor, detailId],
    queryFn: () => corpusScanApi.get(detailId!).then((response) => response.data),
    enabled: !!detailId,
    refetchInterval: (query) => terminal(query.state.data?.status) || query.state.status === 'error' ? false : 1000,
  })
  const storageMissing = apiErrorCode(listQ.error) === 'local_storage_required' || listQ.data?.local_storage === false
  const jobs = listQ.data?.items || []
  const refresh = () => client.invalidateQueries({ queryKey: ['corpus-scans'] })

  const cancel = useMutation({
    mutationFn: (id: string) => corpusScanApi.cancel(id),
    onSuccess: async () => { message.success('已请求取消'); await refresh() },
    onError: () => message.error('取消失败'),
  })
  const remove = useMutation({
    mutationFn: (id: string) => corpusScanApi.remove(id),
    onSuccess: async (_, id) => { if (detailId === id) setDetailId(null); message.success('已删除'); await refresh() },
    onError: (error: any) => message.error(apiErrorCode(error) === 'invalid_state' ? '运行中的任务请先取消' : '删除失败'),
  })

  const beforeUpload = (file: File) => {
    const ext = file.name.toLowerCase().split('.').pop() || ''
    if (!ACCEPT.split(',').includes(`.${ext}`)) { message.error(uploadErrors.unsupported_format); return Upload.LIST_IGNORE }
    const limit = DOC_FORMATS.includes(ext) ? DOC_LIMIT : TEXT_LIMIT
    if (file.size === 0) { message.error('文件为空'); return Upload.LIST_IGNORE }
    if (file.size > limit) { message.error(`${ext} 文件不能超过 ${bytes(limit)}`); return Upload.LIST_IGNORE }
    const controller = new AbortController()
    abortRef.current = controller
    setUpload({ name: file.name, phase: 'hash', done: 0, total: file.size })
    uploadCorpusFile(
      file,
      (done) => setUpload({ name: file.name, phase: 'upload', done, total: file.size }),
      (done) => setUpload({ name: file.name, phase: 'hash', done, total: file.size }),
      controller.signal,
    ).then(async (id) => {
      message.success('上传完成，已开始扫描')
      setDetailId(id)
      await refresh()
    }).catch(async (error) => {
      if (error?.name === 'AbortError') message.info('已取消上传')
      else message.error(uploadErrors[apiErrorCode(error) || ''] || '上传失败')
      await refresh()
    }).finally(() => { abortRef.current = null; setUpload(null) })
    return false
  }

  const columns = useMemo(() => [
    { title: '文件', dataIndex: 'file_name', key: 'file', render: (name: string, job: CorpusScanJob) => <Space direction="vertical" size={0}><Text strong>{name}</Text><Text type="secondary">{job.format.toUpperCase()} · {bytes(job.size_bytes)}</Text></Space> },
    { title: '状态', key: 'status', render: (_: unknown, job: CorpusScanJob) => <Space direction="vertical" size={0}>
      <Tag color={statusColors[job.status]}>{statusLabels[job.status] || job.status}</Tag>
      {job.cancel_requested && !terminal(job.status) && <Text type="secondary">正在取消</Text>}
      {job.error_code && job.status !== 'canceled' && <Text type="secondary">{errorLabels[job.error_code] || job.error_code}</Text>}
    </Space> },
    { title: '进度与结果', key: 'progress', width: 260, render: (_: unknown, job: CorpusScanJob) => <ScanProgress job={job} /> },
    { title: '创建时间', dataIndex: 'created_at', key: 'created', render: time },
    { title: '保留至', dataIndex: 'expires_at', key: 'expires', render: (value: string, job: CorpusScanJob) => terminal(job.status) ? time(value) : '-' },
    { title: '操作', key: 'actions', render: (_: unknown, job: CorpusScanJob) => <Space wrap>
      <Button size="small" icon={<FileSearchOutlined aria-hidden="true" />} onClick={() => setDetailId(job.job_id)}>查看报告</Button>
      {!terminal(job.status) && <Button size="small" icon={<StopOutlined aria-hidden="true" />} disabled={job.cancel_requested} loading={cancel.isPending && cancel.variables === job.job_id} onClick={() => cancel.mutate(job.job_id)}>取消扫描</Button>}
      {job.status !== 'running' && <Popconfirm title="删除任务和它的报告、副本？" okText="删除" cancelText="保留" onConfirm={() => remove.mutate(job.job_id)}>
        <Button size="small" danger icon={<DeleteOutlined aria-hidden="true" />}>删除</Button>
      </Popconfirm>}
    </Space> },
  ], [cancel, remove])

  const detail = detailQ.data
  return <div className="enterprise-page">
    <Space wrap style={{ width: '100%', justifyContent: 'space-between', marginBottom: 16 }}>
      <Title level={4} style={{ margin: 0 }}>训练语料扫描</Title>
      <Space wrap>
        <Button icon={<ReloadOutlined aria-hidden="true" />} aria-label="刷新任务" onClick={refresh} />
        <Upload accept={ACCEPT} showUploadList={false} beforeUpload={beforeUpload} disabled={storageMissing || !!upload}>
          <Button type="primary" icon={<CloudUploadOutlined aria-hidden="true" />} disabled={storageMissing || !!upload}>上传语料</Button>
        </Upload>
      </Space>
    </Space>
    <Paragraph type="secondary" style={{ maxWidth: 880 }}>
      上传私有模型的训练语料，扫描身份证号、手机号、银行卡号、密钥等敏感信息，生成报告和脱敏副本。敏感片段替换成类型标签（例如「[身份证号]」），替换不可逆。
      支持 jsonl、csv、txt（不超过 2 GB）和 docx、pdf、xlsx（不超过 100 MB，副本为 txt）。原始文件扫描结束后立即删除，报告和副本保留 7 天。
    </Paragraph>
    {storageMissing && <Alert type="warning" showIcon style={{ marginBottom: 16 }} message="训练语料扫描需要本地留存存储" description="当前留存存储配置为对象存储。对象存储后端会把整个文件读进内存，大语料无法处理，请在系统管理的留存存储中改用本地存储。" />}
    {listQ.isError && !storageMissing && <Alert type="error" showIcon style={{ marginBottom: 16 }} message="任务列表读取失败" />}
    {upload && <Alert type="info" showIcon style={{ marginBottom: 16 }} message={`${upload.phase === 'hash' ? '正在计算校验值' : '正在上传'}：${upload.name}`}
      description={<Space direction="vertical" style={{ width: '100%' }}>
        <Progress percent={Math.floor((upload.done / Math.max(1, upload.total)) * 100)} format={() => `${bytes(upload.done)} / ${bytes(upload.total)}`} />
        <Button size="small" onClick={() => abortRef.current?.abort()}>取消上传</Button>
      </Space>} />}
    <Table<CorpusScanJob> rowKey="job_id" loading={listQ.isLoading} dataSource={jobs} columns={columns} pagination={false}
      locale={{ emptyText: <Empty description="还没有扫描任务" /> }} />

    <Drawer open={!!detailId} width={760} title="扫描报告" onClose={() => setDetailId(null)} destroyOnClose>
      {detailQ.isError && <Alert type="error" showIcon message="报告读取失败" />}
      {detail && <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <Descriptions size="small" column={2} bordered items={[
          { key: 'file', label: '文件', children: detail.file_name, span: 2 },
          { key: 'status', label: '状态', children: <Tag color={statusColors[detail.status]}>{statusLabels[detail.status]}</Tag> },
          { key: 'error', label: '原因', children: detail.error_code ? errorLabels[detail.error_code] || detail.error_code : '-' },
          { key: 'total', label: '总条数', children: detail.total_records.toLocaleString('zh-CN') },
          { key: 'hit', label: '含敏感信息', children: detail.hit_records.toLocaleString('zh-CN') },
          { key: 'unscanned', label: '未扫描', children: detail.unscanned_records.toLocaleString('zh-CN') },
          { key: 'incomplete', label: '自定义规则未完成', children: detail.incomplete_records.toLocaleString('zh-CN') },
          { key: 'rules', label: '规则包版本', children: detail.rule_pack_version || '-' },
          { key: 'expires', label: '保留至', children: terminal(detail.status) ? time(detail.expires_at) : '-' },
        ]} />
        {!terminal(detail.status) && <ScanProgress job={detail} />}
        {detail.notes.map((note) => <Alert key={note} type="warning" showIcon message={noteLabels[note] || note} />)}
        {detail.status === 'succeeded' && <Space wrap>
          {detail.has_report && <Button icon={<DownloadOutlined aria-hidden="true" />} href={corpusDownloadUrl(detail.job_id, 'report')}>下载报告</Button>}
          {detail.has_masked && <Button type="primary" icon={<DownloadOutlined aria-hidden="true" />} href={corpusDownloadUrl(detail.job_id, 'masked')}>下载脱敏副本</Button>}
        </Space>}
        <div>
          <Title level={5}>按类型统计</Title>
          <TypeBars stats={detail.stats} />
        </div>
        <div>
          <Title level={5}>命中样例（前 200 条，只显示打码片段）</Title>
          <Table size="small" rowKey={(row) => `${row.line}:${row.field}:${row.start}`} pagination={{ pageSize: 20, hideOnSinglePage: true }}
            dataSource={detail.samples} locale={{ emptyText: '无' }} columns={[
              { title: '行号', dataIndex: 'line', width: 80 },
              { title: '字段', dataIndex: 'field', render: (value: string) => <Text code>{value}</Text> },
              { title: '类型', dataIndex: 'label' },
              { title: '位置', key: 'pos', render: (_: unknown, row) => `第 ${row.start}–${row.end} 字` },
              { title: '片段', dataIndex: 'preview', render: (value: string) => <Text code>{value}</Text> },
            ]} />
        </div>
        {detail.unscanned.length > 0 && <div>
          <Title level={5}>未扫描的行（原样保留在副本里）</Title>
          <Space wrap>{detail.unscanned.map((row) => <Tag key={row.line}>第 {row.line} 行：{unscannedLabels[row.reason] || row.reason}</Tag>)}</Space>
          {detail.unscanned_records > detail.unscanned.length && <Paragraph type="secondary" style={{ marginTop: 8 }}>共 {detail.unscanned_records.toLocaleString('zh-CN')} 行未扫描，这里列出前 {detail.unscanned.length} 行，完整清单见报告文件。</Paragraph>}
        </div>}
      </Space>}
    </Drawer>
  </div>
}

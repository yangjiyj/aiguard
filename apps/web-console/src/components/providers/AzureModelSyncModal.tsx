import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Alert,
  Button,
  Checkbox,
  Input,
  Modal,
  Progress,
  Segmented,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  modelApi,
  type AzureModelSyncCandidate,
  type AzureModelSyncVerification,
} from '../../services/api'

const { Text } = Typography

// 每次向后端提交的部署数。后端单次最多 50 个、同时探测 4 个；
// 小批次让进度按批推进，停止也能尽快生效。
const VERIFY_CHUNK_SIZE = 8

interface AzureProvider {
  id: string
  name: string
}

interface AzureModelSyncModalProps {
  provider: AzureProvider | null
  open: boolean
  onClose: () => void
  onCommitted: () => void
}

type VerifyStatus = 'queued' | 'testing' | 'enabled' | 'failed'
type StatusFilter = 'all' | 'active' | 'inactive' | 'failed'

interface SyncRow extends AzureModelSyncCandidate {
  selected: boolean
  protocols?: string[]
  verifyStatus?: VerifyStatus
  errorKind?: string
}

interface RunSummary {
  enabled: number
  failed: number
  stopped: number
}

const errorLabels: Record<string, string> = {
  unauthorized: 'Azure 凭据无效或无权访问',
  not_deployed: '部署名称错误或尚未开通',
  rate_limited: '上游限流，请稍后重试',
  timeout: '连接 Azure 超时，请稍后重试',
  cancelled: '验证已取消，请重试',
  invalid_request: '部署不支持最小测试请求',
  upstream_error: 'Azure 上游异常，请稍后重试',
  skipped_after_unauthorized: '凭据验证失败，未测试',
  commit_failed: '启用失败，请重试',
  config_changed: '渠道配置已变化，请重试',
}

function isConfigConflict(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false
  const response = (error as {
    response?: {
      status?: number
      data?: { error?: { code?: string } }
    }
  }).response
  const code = response?.data?.error?.code
  return response?.status === 409 || code === 'sync_conflict' || code === 'invalid_verification'
}

function resetVerification(row: SyncRow): SyncRow {
  return { ...row, verifyStatus: undefined, errorKind: undefined }
}

function AzureModelSyncModal({ provider, open, onClose, onCommitted }: AzureModelSyncModalProps) {
  const [rows, setRows] = useState<SyncRow[]>([])
  const [catalogUnavailable, setCatalogUnavailable] = useState(false)
  const [catalogTruncated, setCatalogTruncated] = useState(false)
  const [loadingPreview, setLoadingPreview] = useState(false)
  const [previewError, setPreviewError] = useState(false)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [manualOpen, setManualOpen] = useState(false)
  const [manualModel, setManualModel] = useState('')
  const [manualDeployment, setManualDeployment] = useState('')
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState({ done: 0, total: 0 })
  const [summary, setSummary] = useState<RunSummary | null>(null)
  const [pageSize, setPageSize] = useState(20)
  const requestGeneration = useRef(0)
  const stopRequested = useRef(false)

  useEffect(() => {
    const generation = ++requestGeneration.current
    stopRequested.current = false
    setRunning(false)
    if (!open || !provider) return
    let cancelled = false
    setRows([])
    setCatalogUnavailable(false)
    setCatalogTruncated(false)
    setPreviewError(false)
    setSearch('')
    setStatusFilter('all')
    setManualOpen(false)
    setSummary(null)
    setProgress({ done: 0, total: 0 })
    setLoadingPreview(true)
    modelApi.previewVerifiedSync(provider.id)
      .then(({ data }) => {
        if (cancelled || generation !== requestGeneration.current) return
        // 已启用的排在前面，其余保持上游目录顺序。
        const candidates = [...data.candidates].sort((a, b) =>
          Number(b.current_status === 'active') - Number(a.current_status === 'active'))
        setRows(candidates.map((candidate) => ({ ...candidate, selected: false })))
        setCatalogUnavailable(data.catalog_unavailable)
        setCatalogTruncated(data.catalog_truncated)
      })
      .catch(() => {
        if (cancelled || generation !== requestGeneration.current) return
        setCatalogUnavailable(true)
        setPreviewError(true)
      })
      .finally(() => {
        if (!cancelled && generation === requestGeneration.current) setLoadingPreview(false)
      })
    return () => {
      cancelled = true
      if (requestGeneration.current === generation) {
        requestGeneration.current += 1
      }
    }
  }, [open, provider])

  const counts = useMemo(() => ({
    all: rows.length,
    active: rows.filter((row) => row.current_status === 'active').length,
    inactive: rows.filter((row) => row.current_status !== 'active').length,
    failed: rows.filter((row) => row.verifyStatus === 'failed').length,
  }), [rows])

  const filteredRows = useMemo(() => {
    const keyword = search.trim().toLowerCase()
    return rows.filter((row) => {
      if (statusFilter === 'active' && row.current_status !== 'active') return false
      if (statusFilter === 'inactive' && row.current_status === 'active') return false
      if (statusFilter === 'failed' && row.verifyStatus !== 'failed') return false
      if (!keyword) return true
      return row.catalog_model_id.toLowerCase().includes(keyword)
        || row.display_name.toLowerCase().includes(keyword)
        || row.deployment_name.toLowerCase().includes(keyword)
    })
  }, [rows, search, statusFilter])

  const selectedCount = rows.filter((row) => row.selected).length
  const allFilteredSelected = filteredRows.length > 0 && filteredRows.every((row) => row.selected)
  const someFilteredSelected = filteredRows.some((row) => row.selected)

  const updateRow = (catalogModelID: string, update: (row: SyncRow) => SyncRow) => {
    setRows((current) => current.map((row) => row.catalog_model_id === catalogModelID ? update(row) : row))
  }

  const toggleRow = (catalogModelID: string, selected: boolean) => {
    updateRow(catalogModelID, (row) => ({ ...row, selected }))
  }

  const toggleAllFiltered = (selected: boolean) => {
    const visible = new Set(filteredRows.map((row) => row.catalog_model_id))
    setRows((current) => current.map((row) => visible.has(row.catalog_model_id) ? { ...row, selected } : row))
  }

  const updateDeployment = (catalogModelID: string, deploymentName: string) => {
    updateRow(catalogModelID, (row) => ({ ...resetVerification(row), deployment_name: deploymentName }))
  }

  const updateProtocols = (catalogModelID: string, values: string[]) => {
    const protocols = values.filter((value) => value === 'chat_completions' || value === 'responses')
    updateRow(catalogModelID, (row) => ({ ...resetVerification(row), protocols: protocols.length > 0 ? protocols : undefined }))
  }

  const addManual = () => {
    const catalogModelID = manualModel.trim()
    const deploymentName = manualDeployment.trim()
    if (!catalogModelID || !deploymentName) {
      message.warning('请填写模型标识和部署名称')
      return
    }
    if (rows.some((row) => row.catalog_model_id === catalogModelID)) {
      message.warning('该模型标识已在列表中')
      return
    }
    setRows((current) => [{
      catalog_model_id: catalogModelID,
      display_name: catalogModelID,
      deployment_name: deploymentName,
      selected: true,
    }, ...current])
    setManualModel('')
    setManualDeployment('')
    setManualOpen(false)
    setStatusFilter('all')
    setSearch('')
  }

  const verifyAndEnable = async () => {
    if (!provider || running) return
    const generation = requestGeneration.current
    const providerID = provider.id
    const targets = rows.filter((row) => row.selected)
    if (targets.length === 0) return
    if (targets.some((row) => !row.deployment_name.trim())) {
      message.warning('部署名称不能为空')
      return
    }
    const isCurrent = () => generation === requestGeneration.current
    const targetIDs = new Set(targets.map((row) => row.catalog_model_id))
    stopRequested.current = false
    setSummary(null)
    setRunning(true)
    setProgress({ done: 0, total: targets.length })
    setRows((current) => current.map((row) => targetIDs.has(row.catalog_model_id)
      ? { ...row, verifyStatus: 'queued', errorKind: undefined }
      : row))

    const enabledIDs = new Set<string>()
    const failures = new Map<string, string>()
    let processed = 0
    let anyCommitted = false
    let abortKind = ''

    try {
      for (let start = 0; start < targets.length; start += VERIFY_CHUNK_SIZE) {
        if (stopRequested.current || abortKind) break
        const chunk = targets.slice(start, start + VERIFY_CHUNK_SIZE)
        const chunkIDs = new Set(chunk.map((row) => row.catalog_model_id))
        setRows((current) => current.map((row) => chunkIDs.has(row.catalog_model_id) ? { ...row, verifyStatus: 'testing' } : row))

        let results: AzureModelSyncVerification[] = []
        try {
          const { data } = await modelApi.verifySyncCandidates(providerID, chunk.map((row) => ({
            catalog_model_id: row.catalog_model_id,
            deployment_name: row.deployment_name.trim(),
            ...(row.protocols && row.protocols.length > 0 ? { protocols: row.protocols } : {}),
          })))
          results = data.results
        } catch {
          if (!isCurrent()) return
          chunk.forEach((row) => failures.set(row.catalog_model_id, 'upstream_error'))
        }
        if (!isCurrent()) return

        const byModel = new Map(results.map((result) => [result.catalog_model_id, result]))
        const proofs: string[] = []
        const proofIDs: string[] = []
        const verifiedProtocols = new Map<string, string[] | undefined>()
        chunk.forEach((row) => {
          if (failures.has(row.catalog_model_id)) return
          const result = byModel.get(row.catalog_model_id)
          if (!result || result.deployment_name !== row.deployment_name.trim()) {
            failures.set(row.catalog_model_id, 'upstream_error')
            return
          }
          if (result.status === 'success' && result.proof_token) {
            proofs.push(result.proof_token)
            proofIDs.push(row.catalog_model_id)
            verifiedProtocols.set(row.catalog_model_id, result.protocols?.map((protocol) => protocol === 'responses_native' ? 'responses' : protocol))
            return
          }
          const kind = result.error_kind || 'upstream_error'
          failures.set(row.catalog_model_id, kind)
          if (kind === 'unauthorized') abortKind = 'unauthorized'
        })

        if (proofs.length > 0) {
          try {
            await modelApi.commitVerifiedSync(providerID, proofs)
            if (!isCurrent()) return
            proofIDs.forEach((id) => enabledIDs.add(id))
            anyCommitted = true
          } catch (error) {
            if (!isCurrent()) return
            const kind = isConfigConflict(error) ? 'config_changed' : 'commit_failed'
            proofIDs.forEach((id) => failures.set(id, kind))
            if (kind === 'config_changed') abortKind = kind
          }
        }

        processed += chunk.length
        setProgress({ done: processed, total: targets.length })
        setRows((current) => current.map((row) => {
          if (!chunkIDs.has(row.catalog_model_id)) return row
          if (enabledIDs.has(row.catalog_model_id)) {
            return {
              ...row,
              selected: false,
              current_status: 'active',
              protocols: verifiedProtocols.get(row.catalog_model_id) ?? row.protocols,
              verifyStatus: 'enabled',
              errorKind: undefined,
            }
          }
          return { ...row, verifyStatus: 'failed', errorKind: failures.get(row.catalog_model_id) || 'upstream_error' }
        }))
      }
    } finally {
      if (isCurrent()) {
        const remaining = targets.length - processed
        if (remaining > 0) {
          const untouched = new Set(targets.slice(processed).map((row) => row.catalog_model_id))
          setRows((current) => current.map((row) => untouched.has(row.catalog_model_id)
            ? (abortKind === 'unauthorized'
              ? { ...row, verifyStatus: 'failed', errorKind: 'skipped_after_unauthorized' }
              : resetVerification(row))
            : row))
        }
        const failedCount = abortKind === 'unauthorized' ? failures.size + remaining : failures.size
        setSummary({
          enabled: enabledIDs.size,
          failed: failedCount,
          stopped: abortKind === 'unauthorized' ? 0 : remaining,
        })
        setRunning(false)
        if (anyCommitted) onCommitted()
      }
    }
  }

  const statusOptions = [
    { label: `全部 ${counts.all}`, value: 'all' },
    { label: `已启用 ${counts.active}`, value: 'active' },
    { label: `未启用 ${counts.inactive}`, value: 'inactive' },
    ...(counts.failed > 0 ? [{ label: `验证失败 ${counts.failed}`, value: 'failed' }] : []),
  ]

  const columns: ColumnsType<SyncRow> = [
    {
      title: (
        <Checkbox
          aria-label="全选当前筛选结果"
          checked={allFilteredSelected}
          indeterminate={!allFilteredSelected && someFilteredSelected}
          disabled={running || filteredRows.length === 0}
          onChange={(event) => toggleAllFiltered(event.target.checked)}
        />
      ),
      key: 'selected',
      width: 48,
      render: (_, row) => (
        <Checkbox
          aria-label={`选择 ${row.catalog_model_id}`}
          checked={row.selected}
          disabled={running}
          onChange={(event) => toggleRow(row.catalog_model_id, event.target.checked)}
        />
      ),
    },
    {
      title: '模型',
      key: 'model',
      width: 220,
      ellipsis: true,
      render: (_, row) => (
        <Space direction="vertical" size={0}>
          <Text strong>{row.display_name}</Text>
          {row.display_name !== row.catalog_model_id && (
            <Text type="secondary" style={{ fontSize: 12 }}>{row.catalog_model_id}</Text>
          )}
        </Space>
      ),
    },
    {
      title: '部署名称',
      dataIndex: 'deployment_name',
      key: 'deployment_name',
      width: 220,
      render: (value, row) => (
        <Input
          aria-label={`${row.catalog_model_id} 部署名称`}
          value={value}
          maxLength={255}
          disabled={running}
          onChange={(event) => updateDeployment(row.catalog_model_id, event.target.value)}
        />
      ),
    },
    {
      title: <Tooltip title="不勾选时按 Chat 接口验证">协议</Tooltip>,
      key: 'protocols',
      width: 190,
      render: (_, row) => (
        <Checkbox.Group
          aria-label={`${row.catalog_model_id} 协议`}
          value={row.protocols || []}
          options={[
            { label: 'Chat', value: 'chat_completions' },
            { label: 'Responses', value: 'responses' },
          ]}
          disabled={running}
          onChange={(values) => updateProtocols(row.catalog_model_id, values as string[])}
        />
      ),
    },
    {
      title: '状态',
      key: 'status',
      width: 230,
      render: (_, row) => {
        if (row.verifyStatus === 'queued') return <Tag>等待验证</Tag>
        if (row.verifyStatus === 'testing') return <Tag color="processing">验证中</Tag>
        if (row.verifyStatus === 'enabled') return <Tag color="success">已启用</Tag>
        if (row.verifyStatus === 'failed') {
          return (
            <Space direction="vertical" size={0}>
              <Text type="danger">{errorLabels[row.errorKind || 'upstream_error'] || '验证失败'}</Text>
              {row.current_status === 'active' && <Text type="secondary" style={{ fontSize: 12 }}>仍保持启用</Text>}
            </Space>
          )
        }
        return row.current_status === 'active' ? <Tag color="green">已启用</Tag> : <Tag>未启用</Tag>
      },
    },
  ]

  const percent = progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0

  return (
    <Modal
      title="Azure 模型验证同步"
      open={open}
      onCancel={onClose}
      width={1040}
      maskClosable={!running}
      footer={(
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16 }}>
          <Space size="middle">
            {running ? (
              <Space size="middle">
                <Progress percent={percent} size="small" style={{ width: 200, margin: 0 }} format={() => `${progress.done}/${progress.total}`} />
                <Button onClick={() => { stopRequested.current = true }}>停止</Button>
              </Space>
            ) : (
              <>
                <Text type="secondary">已选 {selectedCount} 个</Text>
                {selectedCount > 0 && <Button type="link" size="small" onClick={() => setRows((current) => current.map((row) => ({ ...row, selected: false })))}>清空</Button>}
              </>
            )}
          </Space>
          <Space>
            <Button onClick={onClose} disabled={running}>关闭</Button>
            <Button type="primary" loading={running} disabled={selectedCount === 0} onClick={verifyAndEnable}>
              验证并启用 {selectedCount} 个
            </Button>
          </Space>
        </div>
      )}
      destroyOnHidden
    >
      <Space direction="vertical" size={12} style={{ width: '100%' }}>
        <Text type="secondary">渠道：{provider?.name || ''}</Text>
        {catalogUnavailable && (
          <Alert
            type="warning"
            showIcon
            message="无法读取 Azure 模型目录"
            description={previewError ? '目录请求失败，可手工添加已开通的部署。' : '上游未返回目录，可手工添加已开通的部署。'}
          />
        )}
        {catalogTruncated && <Alert type="warning" showIcon message="目录条目较多，仅展示前 2000 条，可搜索或手工添加。" />}
        {summary && !running && (
          <Alert
            type={summary.failed > 0 ? 'warning' : 'success'}
            showIcon
            message={[
              `已启用 ${summary.enabled} 个`,
              summary.failed > 0 ? `${summary.failed} 个失败，原状态不变` : '',
              summary.stopped > 0 ? `${summary.stopped} 个未验证` : '',
            ].filter(Boolean).join('，')}
            action={summary.failed > 0 && counts.failed > 0 ? (
              <Button size="small" onClick={() => {
                setRows((current) => current.map((row) => ({ ...row, selected: row.verifyStatus === 'failed' })))
                setStatusFilter('failed')
              }}>
                选中失败项
              </Button>
            ) : undefined}
          />
        )}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <Space wrap>
            <Input.Search
              aria-label="搜索模型"
              placeholder="搜索模型或部署名称"
              allowClear
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              style={{ width: 280 }}
            />
            <Segmented
              aria-label="按状态筛选"
              value={statusFilter}
              options={statusOptions}
              onChange={(value) => setStatusFilter(value as StatusFilter)}
            />
          </Space>
          <Button disabled={running} onClick={() => setManualOpen((value) => !value)}>手工添加部署</Button>
        </div>
        {manualOpen && (
          <Space wrap>
            <Input aria-label="模型标识" placeholder="模型标识" value={manualModel} disabled={running} onChange={(event) => setManualModel(event.target.value)} />
            <Input aria-label="部署名称" placeholder="部署名称" value={manualDeployment} disabled={running} onChange={(event) => setManualDeployment(event.target.value)} />
            <Button type="primary" disabled={running} onClick={addManual}>添加并勾选</Button>
          </Space>
        )}
        <Table
          rowKey="catalog_model_id"
          columns={columns}
          dataSource={filteredRows}
          loading={loadingPreview}
          pagination={{
            pageSize,
            showSizeChanger: true,
            pageSizeOptions: [20, 50, 100],
            onShowSizeChange: (_, size) => setPageSize(size),
            showTotal: (total) => `共 ${total} 个`,
          }}
          scroll={{ x: 900, y: 440 }}
          size="small"
        />
      </Space>
    </Modal>
  )
}

export default AzureModelSyncModal

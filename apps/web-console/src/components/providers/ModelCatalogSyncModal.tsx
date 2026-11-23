import { useEffect, useMemo, useRef, useState } from 'react'
import { Alert, Button, Checkbox, Input, Modal, Segmented, Space, Table, Tag, Select, Typography, message } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { modelApi, type ModelCatalogSyncCandidate, type ModelCatalogSyncResult } from '../../services/api'
import { extractApiError } from '../../utils/apiError'
import { isRequestTimeout } from '../../utils/requestTimeout'

const { Text } = Typography

const DEFAULT_MAX_SELECTION = 200

interface CatalogProvider {
  id: string
  name: string
}

interface ModelCatalogSyncModalProps {
  provider: CatalogProvider | null
  open: boolean
  onClose: () => void
  onSynced: (result: ModelCatalogSyncResult) => void
}

interface CatalogRow extends ModelCatalogSyncCandidate {
  selected: boolean
}

type StatusFilter = 'all' | 'active' | 'other'

function statusLabel(status?: string) {
  if (status === 'active') return <Tag color="green">已纳入</Tag>
  if (status === 'upstream_removed') return <Tag color="red">上游已移除</Tag>
  if (status === 'pending') return <Tag color="orange">待纳入</Tag>
  if (status === 'disabled') return <Tag>已停用</Tag>
  return <Tag color="blue">未纳入</Tag>
}

function ModelCatalogSyncModal({ provider, open, onClose, onSynced }: ModelCatalogSyncModalProps) {
  const [rows, setRows] = useState<CatalogRow[]>([])
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [pageSize, setPageSize] = useState(20)
  const [loadingPreview, setLoadingPreview] = useState(false)
  const [previewError, setPreviewError] = useState(false)
  const [catalogUnavailable, setCatalogUnavailable] = useState(false)
  const [catalogTruncated, setCatalogTruncated] = useState(false)
  const [maxSelection, setMaxSelection] = useState(DEFAULT_MAX_SELECTION)
  const [submitting, setSubmitting] = useState(false)
  const [summary, setSummary] = useState<ModelCatalogSyncResult | null>(null)
  const [syncState, setSyncState] = useState<any>(null)
  const requestGeneration = useRef(0)
  // 同步在途时的引用守卫：同一渲染周期内的快速重复点击也要被挡住，
  // 否则管理员会因为迟迟没结果而打出多个并发同步请求。
  const submittingRef = useRef(false)

  useEffect(() => {
    const generation = ++requestGeneration.current
    setSubmitting(false)
    if (!open || !provider) return
    let cancelled = false
    setRows([])
    setSearch('')
    setStatusFilter('all')
    setPreviewError(false)
    setCatalogUnavailable(false)
    setCatalogTruncated(false)
    setMaxSelection(DEFAULT_MAX_SELECTION)
    setSummary(null)
    setLoadingPreview(true)
    setSyncState(null)
    modelApi.catalogSyncState(provider.id).then(({data}) => {
      if (!cancelled && generation === requestGeneration.current) setSyncState(data)
    }).catch(() => {})
    modelApi.previewCatalogSync(provider.id)
      .then(({ data }) => {
        if (cancelled || generation !== requestGeneration.current) return
        // 已纳入的排在前面，其余保持上游目录顺序。
        const candidates = [...(data.candidates || [])].sort((a, b) =>
          Number(b.current_status === 'active') - Number(a.current_status === 'active'))
        setRows(candidates.map((candidate) => ({ ...candidate, selected: false })))
        setCatalogUnavailable(Boolean(data.catalog_unavailable))
        setCatalogTruncated(Boolean(data.catalog_truncated))
        setMaxSelection(data.max_selection || DEFAULT_MAX_SELECTION)
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

  const activeCount = rows.filter((row) => row.current_status === 'active').length
  const filteredRows = useMemo(() => {
    const keyword = search.trim().toLowerCase()
    return rows.filter((row) => {
      if (statusFilter === 'active' && row.current_status !== 'active') return false
      if (statusFilter === 'other' && row.current_status === 'active') return false
      if (!keyword) return true
      return row.catalog_model_id.toLowerCase().includes(keyword)
        || row.display_name.toLowerCase().includes(keyword)
    })
  }, [rows, search, statusFilter])

  const selected = rows.filter((row) => row.selected)
  const allFilteredSelected = filteredRows.length > 0 && filteredRows.every((row) => row.selected)
  const newCount = selected.filter((row) => !row.current_status).length
  const refreshCount = selected.length - newCount

  const toggleRow = (catalogModelID: string, next: boolean) => {
    if (next && selected.length >= maxSelection) {
      message.warning(`每次最多选择 ${maxSelection} 个模型`)
      return
    }
    setRows((current) => current.map((row) =>
      row.catalog_model_id === catalogModelID ? { ...row, selected: next } : row))
  }

  const toggleAllFiltered = (next: boolean) => {
    const visibleIds = new Set(filteredRows.map((row) => row.catalog_model_id))
    if (!next) {
      setRows((current) => current.map((row) =>
        visibleIds.has(row.catalog_model_id) ? { ...row, selected: false } : row))
      return
    }
    // 只按当前筛选结果补齐，避免搜索状态下"全选"意外选中看不到的行。
    const selectedOutsideFilter = selected.filter((row) => !visibleIds.has(row.catalog_model_id)).length
    const capacity = maxSelection - selectedOutsideFilter
    if (capacity <= 0) {
      message.warning(`已勾选 ${maxSelection} 个，达到单次上限；请先取消部分勾选`)
      return
    }
    // 目录比上限大时不做"全选失败"：按顺序勾到上限，并说清还剩多少，
    // 管理员可以缩小搜索范围后分批同步。
    const picked = new Set(filteredRows.slice(0, capacity).map((row) => row.catalog_model_id))
    setRows((current) => current.map((row) => visibleIds.has(row.catalog_model_id)
      ? { ...row, selected: picked.has(row.catalog_model_id) }
      : row))
    if (filteredRows.length > capacity) {
      message.warning(`已勾选 ${capacity} 个（单次上限 ${maxSelection}），还有 ${filteredRows.length - capacity} 个未勾选；请缩小搜索范围后分批同步`)
    }
  }

  const sync = async (catalogModelIDs: string[]) => {
    if (!provider) return
    if (submittingRef.current) return
    submittingRef.current = true
    const generation = requestGeneration.current
    setSubmitting(true)
    try {
      const { data } = await modelApi.sync(
        provider.id,
        catalogModelIDs.length > 0 ? catalogModelIDs : undefined
      )
      if (generation !== requestGeneration.current) return
      setSummary(data)
      onSynced(data)
      const state = await modelApi.catalogSyncState(provider.id).catch(() => null)
      if (state && generation === requestGeneration.current) setSyncState(state.data)
    } catch (error) {
      if (generation !== requestGeneration.current) return
      if (isRequestTimeout(error)) {
        // 达到同步专用预算时后台通常仍在跑，不能笼统报「同步失败」。
        message.warning('同步仍可能在后台进行，请稍后刷新模型列表查看结果')
      } else if ((error as any)?.response?.data?.error?.code === 'provider_unsupported') {
        message.warning('该渠道不支持模型目录同步')
      } else if ((error as any)?.response?.data?.error?.code === 'sync_in_progress') {
        message.warning('该渠道正在同步，请等待完成后重试')
      } else {
        message.error(extractApiError(error) || '同步失败')
      }
    } finally {
      submittingRef.current = false
      if (generation === requestGeneration.current) setSubmitting(false)
    }
  }

  const columns: ColumnsType<CatalogRow> = [
    {
      title: (
        <Checkbox
          aria-label="全选当前筛选结果"
          checked={allFilteredSelected}
          indeterminate={!allFilteredSelected && filteredRows.some((row) => row.selected)}
          disabled={submitting || filteredRows.length === 0}
          onChange={(event) => toggleAllFiltered(event.target.checked)}
        />
      ),
      key: 'selected',
      width: 64,
      render: (_, row) => (
        <Checkbox
          aria-label={`选择 ${row.catalog_model_id}`}
          checked={row.selected}
          disabled={submitting}
          onChange={(event) => toggleRow(row.catalog_model_id, event.target.checked)}
        />
      ),
    },
    {
      title: '模型',
      key: 'model',
      render: (_, row) => (
        <Space direction="vertical" size={0}>
          <Text strong>{row.display_name}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>{row.catalog_model_id}</Text>
        </Space>
      ),
    },
    {
      title: '当前状态',
      dataIndex: 'current_status',
      key: 'current_status',
      width: 110,
      render: (value?: string) => statusLabel(value),
    },
  ]

  return (
    <Modal
      title="选择要同步的模型"
      open={open}
      onCancel={onClose}
      width={880}
      footer={summary
        ? <Button type="primary" onClick={onClose}>关闭</Button>
        : (
          <Space>
            <Button onClick={onClose}>取消</Button>
            <Button loading={submitting} disabled={loadingPreview} onClick={() => sync([])}>
              刷新目录并清理失效模型
            </Button>
            <Button
              type="primary"
              loading={submitting}
              disabled={selected.length === 0}
              onClick={() => sync(selected.map((row) => row.catalog_model_id))}
            >
              同步已选 {selected.length} 个模型
            </Button>
          </Space>
        )}
      destroyOnHidden
    >
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Alert
          type="info"
          showIcon
          message={`渠道：${provider?.name || ''}`}
          description="勾选的模型会真实调用一次验证，通过后纳入；未勾选的已纳入模型保持不变，只有上游目录里已不存在的才会移除。"
        />
        {syncState && <Space direction="vertical" size={6}>
          <Text type="secondary">最近同步：{syncState.finished_at ? new Date(syncState.finished_at).toLocaleString() : '尚未同步'} · {syncState.status === 'success' ? '成功' : syncState.status === 'failed' ? `失败：${syncState.error}` : syncState.status === 'running' ? '进行中' : '尚未同步'}</Text>
          <Space><Text>周期刷新</Text><Select aria-label="目录同步周期" value={syncState.interval_seconds} disabled={submitting} style={{width:160}}
            options={[{value:0,label:'关闭'},{value:300,label:'每 5 分钟'},{value:3600,label:'每小时'},{value:21600,label:'每 6 小时'},{value:86400,label:'每天'}]}
            onChange={async (value:number) => { if (!provider) return; try {const {data}=await modelApi.setCatalogSyncInterval(provider.id,value);setSyncState(data)} catch(error) {message.error(extractApiError(error) || '周期保存失败')} }} /></Space>
          {syncState.result && <Text type="secondary">上次成功回执：新增 {syncState.result.created || 0} · 更新 {syncState.result.updated || 0} · 移除 {syncState.result.deactivated || 0} · 验证失败 {syncState.result.verification_failed || 0}</Text>}
        </Space>}
        {catalogUnavailable && (
          <Alert
            type="warning"
            showIcon
            message="无法读取上游模型目录"
            description={previewError
              ? '目录请求失败会保留上次状态；请重试或在模型管理中手工维护。'
              : '当前目录为空或不可读取；仅明确、完整的空数组可清理同步来源。缺字段、异常响应和未完成分页均保留原目录。'}
            action={(
              <Button size="small" loading={submitting} onClick={() => sync([])}>
                重试同步
              </Button>
            )}
          />
        )}
        {catalogTruncated && (
          <Alert type="warning" showIcon message="目录条目较多，当前仅展示前 2000 条；可用搜索缩小范围。" />
        )}
        {summary && (
          <Alert
            type={summary.verification_failed ? "warning" : "success"}
            showIcon
            message={summary.verification_failed ? "目录已同步，部分模型验证失败" : "同步完成"}
            description={`新增 ${summary.created}，更新 ${summary.updated}，协议验证 ${summary.verified || 0}，沿用验证 ${summary.reused || 0}，验证失败 ${summary.verification_failed || 0}，移除 ${summary.deactivated}，重新出现 ${summary.reappeared || 0}，待纳入 ${summary.pending || 0}，跳过 ${summary.skipped}`
              + (summary.not_found_model_ids && summary.not_found_model_ids.length > 0
                ? `；上游已不存在：${summary.not_found_model_ids.join('、')}`
                : '')}
          />
        )}
        {summary?.verification_failures?.map((item) => <Alert key={item.model_id} type="warning" showIcon message={`${item.upstream_model_id}：验证失败`} description={item.reason.split('/').map((reason) => ({unauthorized:'上游鉴权失败',timeout:'探测超时',rate_limited:'上游限流',upstream_error:'上游错误',invalid_request:'地址或请求无法验证',not_deployed:'接口或标识不可访问',unknown:'探测结果未知',not_verified:'尚未完成验证'} as Record<string,string>)[reason] || '探测失败').join('；') + '。保留目录关联和人工设置；当前异常不会认定为下架。'} />)}
        <Space wrap>
          <Input.Search
            aria-label="搜索模型"
            placeholder="搜索模型名称或标识"
            allowClear
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            style={{ width: 280 }}
          />
          <Segmented
            aria-label="按状态筛选"
            value={statusFilter}
            onChange={(value) => setStatusFilter(value as StatusFilter)}
            options={[
              { label: `全部 ${rows.length}`, value: 'all' },
              { label: `已纳入 ${activeCount}`, value: 'active' },
              { label: `未纳入 ${rows.length - activeCount}`, value: 'other' },
            ]}
          />
          <Text type="secondary">已勾选 {selected.length}/{maxSelection}</Text>
          {selected.length > 0 && (
            <Text type="secondary">新增 {newCount} · 刷新 {refreshCount}</Text>
          )}
        </Space>
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
          scroll={{ y: 440 }}
          size="small"
        />
      </Space>
    </Modal>
  )
}

export default ModelCatalogSyncModal

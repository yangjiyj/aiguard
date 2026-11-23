import { useState } from 'react'
import { Card, Table, Tag, Button, Select, Switch, Space, Typography, Badge, message, Segmented } from 'antd'
import { BellOutlined, CheckOutlined, CheckSquareOutlined } from '@ant-design/icons'
import { keepPreviousData, useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { alertApi, ws8AlertInboxApi } from '../services/api'
import { AuditDateRangeFilter, ServerExportButton } from '../components/AuditExportControls'
import type { AuditDateRange } from '../components/AuditExportControls'
import { auditRangeParams, formatInTimezone, useReportContext } from '../utils/ws8ReportRange'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import { DOMAIN_CONFIG, SEVERITY_CONFIG, SOURCE_LABELS, normalizeInboxItem, sourceLabel } from '../utils/alertInboxDisplay'
import NotifyChannelsMissingBanner from '../components/NotifyChannelsMissingBanner'
import AlertGroupBacklog from '../components/AlertGroupBacklog'
import AlertInboxFoldedTable from '../components/AlertInboxFolded'
import AlertInboxBulkRead from '../components/AlertInboxBulkRead'
import { useAuthStore } from '../stores/auth'
import { isConsoleAdministratorRole } from '../utils/access'

const { Title, Text } = Typography

// 展示方式：按天折叠（默认，同类消息折成一行）/ 逐条明细（原有行为，原样保留）。
type ViewMode = 'fold' | 'detail'
const fmtNum = (n: number) => (Number(n) || 0).toLocaleString('en-US')

export default function AlertInbox() {
  const auditIdentity = useAuditQueryIdentity()
  const qc = useQueryClient()
  const [onlyUnread, setOnlyUnread] = useState(true)
  const [viewMode, setViewMode] = useState<ViewMode>('fold')
  const [bulkOpen, setBulkOpen] = useState(false)
  // 批量已读入口仅控制台管理员可见（与后端 roles.IsConsoleAdministrator 对齐）；后端才是真正的闸门。
  const canBulkRead = useAuthStore((s) => isConsoleAdministratorRole(s.user?.role))
  const reportCtx = useReportContext()
  const tz = reportCtx.timezone
  // W8 8.7：时间 / 严重度 / 来源筛选走服务端分页（返回 total）；未设筛选时保持原有接口与行为。
  const [range, setRange] = useState<AuditDateRange>(null)
  const [severity, setSeverity] = useState<string | undefined>()
  const [sourceType, setSourceType] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  // 风险域筛选（客户端过滤当前已加载页）：all=全部，其余取值见 DOMAIN_CONFIG。
  const [domainFilter, setDomainFilter] = useState<string>('all')
  const filtered = Boolean(range || severity || sourceType)
  const filters = {
    ...auditRangeParams(range, tz),
    ...(severity ? { severity } : {}),
    ...(sourceType ? { type: sourceType } : {}),
  }
  const exportFilters = { ...filters, ...(onlyUnread ? { unread: true } : {}) }
  const resetPage = () => setPage(1)

  const inboxQ = useQuery({
    queryKey: ['alerts-inbox', auditIdentity, onlyUnread, filters, filtered ? page : 0, filtered ? pageSize : 0],
    queryFn: () => filtered
      ? ws8AlertInboxApi.list({ ...exportFilters, limit: pageSize, offset: (page - 1) * pageSize })
      : alertApi.inbox(onlyUnread),
    enabled: viewMode === 'detail',
    refetchInterval: 10000,
    placeholderData: keepPreviousData,
  })

  // 折叠视图：服务端按「组」分页；筛选（未读/日期/严重度/来源）与逐条视图同口径，风险域在客户端按 sample 过滤当前页。
  const foldedQ = useQuery({
    queryKey: ['alerts-inbox', auditIdentity, 'folded', onlyUnread, filters, page, pageSize],
    queryFn: () => ws8AlertInboxApi.folded({ ...exportFilters, limit: pageSize, offset: (page - 1) * pageSize }),
    enabled: viewMode === 'fold',
    refetchInterval: 10000,
    placeholderData: keepPreviousData,
  })
  const foldedData = foldedQ.data?.data
  const foldedGroups = Array.isArray(foldedData?.groups) ? foldedData.groups : []

  const markReadMutation = useMutation({
    mutationFn: (id: string) => alertApi.markRead(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alerts-inbox'] })
      message.success('已标记为已读')
    },
    onError: () => message.error('操作失败'),
  })

  const inboxData: any = inboxQ.data?.data
  const rawItems: any[] = Array.isArray(inboxData?.items) ? inboxData.items : []
  const normalizedItems = rawItems.map(normalizeInboxItem)
  const items = domainFilter === 'all'
    ? normalizedItems
    : normalizedItems.filter((item: any) => item.domain === domainFilter)
  const serverTotal = filtered ? Number(inboxData?.total) || 0 : items.length
  const foldMode = viewMode === 'fold'
  const headerUnread = foldMode ? Number(foldedData?.unread_count) || 0 : items.filter(i => !i.read).length

  const columns = [
    {
      title: '严重度',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (v: string) => {
        const cfg = SEVERITY_CONFIG[v] || { color: 'default', label: '信息' }
        return <Tag color={cfg.color}>{cfg.label}</Tag>
      },
    },
    {
      title: '内容',
      dataIndex: 'message',
      key: 'message',
      ellipsis: true,
      render: (_: any, r: any) => (
        <div>
          <div style={{ fontWeight: 500 }}>{r.title || r.message || '-'}</div>
          {r.detail && <Text type="secondary" style={{ fontSize: 12 }}>{r.detail}</Text>}
        </div>
      ),
    },
    {
      title: '风险域',
      dataIndex: 'domain',
      key: 'domain',
      width: 110,
      render: (v?: string) => {
        const cfg = DOMAIN_CONFIG[v || 'content'] || DOMAIN_CONFIG.content
        return <Tag color={cfg.color}>{cfg.label}</Tag>
      },
    },
    { title: '来源', dataIndex: 'source', key: 'source', width: 120, render: (v?: string) => v ? <Tag>{sourceLabel(v)}</Tag> : '-' },
    {
      title: '时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 160,
      render: (v: string) => formatInTimezone(v, tz),
    },
    {
      title: '状态',
      dataIndex: 'read',
      key: 'read',
      width: 80,
      render: (v?: boolean) => v ? <Badge status="default" text="已读" /> : <Badge status="processing" text="未读" />,
    },
    {
      title: '操作',
      key: 'action',
      width: 100,
      render: (_: any, r: any) => (
        !r.read ? (
          <Button
            type="link"
            size="small"
            icon={<CheckOutlined />}
            loading={markReadMutation.isPending}
            onClick={() => markReadMutation.mutate(r.id)}
          >
            标记已读
          </Button>
        ) : null
      ),
    },
  ]

  return (
    <div>
      <NotifyChannelsMissingBanner />
      <div className="page-header" style={{ marginBottom: 16 }}>
        <Title level={4} style={{ margin: 0 }}>
          <Space>
            <BellOutlined />
            消息中心
            {headerUnread > 0 && (
              <Badge count={headerUnread} overflowCount={9999999} size="small" />
            )}
          </Space>
        </Title>
        <Text type="secondary">系统告警与预算超限通知，每 30 秒自动刷新</Text>
      </div>

      <Card>
        <div style={{ marginBottom: 12, display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
          <Space wrap>
            <Segmented
              aria-label="消息展示方式"
              value={viewMode}
              onChange={(value) => { setViewMode(value as ViewMode); resetPage() }}
              options={[
                { value: 'fold', label: '按天折叠' },
                { value: 'detail', label: '逐条明细' },
              ]}
            />
            <Text>仅显示未读</Text>
            <Switch checked={onlyUnread} onChange={(value) => { setOnlyUnread(value); resetPage() }} />
            <AuditDateRangeFilter value={range} onChange={(next) => { setRange(next); resetPage() }} timezone={tz} />
            <Select
              allowClear
              aria-label="按严重度筛选"
              placeholder="全部严重度"
              style={{ width: 130 }}
              value={severity}
              onChange={(value) => { setSeverity(value); resetPage() }}
              options={Object.entries(SEVERITY_CONFIG).map(([value, cfg]) => ({ value, label: cfg.label }))}
            />
            <Select
              allowClear
              aria-label="按来源筛选"
              placeholder="全部来源"
              style={{ width: 150 }}
              value={sourceType}
              onChange={(value) => { setSourceType(value); resetPage() }}
              options={Object.entries(SOURCE_LABELS).map(([value, label]) => ({ value, label }))}
            />
            <Segmented
              aria-label="按风险域筛选"
              value={domainFilter}
              onChange={(value) => { setDomainFilter(String(value)); resetPage() }}
              options={[
                { value: 'all', label: '全部' },
                ...Object.entries(DOMAIN_CONFIG).map(([value, cfg]) => ({ value, label: cfg.label })),
              ]}
            />
            <Text type="secondary" style={{ fontSize: 12 }}>
              {foldMode
                ? `共 ${fmtNum(Number(foldedData?.total_groups) || 0)} 组 / ${fmtNum(Number(foldedData?.total_items) || 0)} 条${onlyUnread ? '未读' : ''}消息`
                : `共 ${serverTotal} 条${onlyUnread ? '未读' : ''}消息`}
            </Text>
          </Space>
          <Space wrap>
            {canBulkRead && (
              <Button icon={<CheckSquareOutlined />} onClick={() => setBulkOpen(true)}>批量标为已读…</Button>
            )}
            <ServerExportButton name="消息中心" timezone={tz} run={(format) => ws8AlertInboxApi.export(format, exportFilters)} />
          </Space>
        </div>
        {foldMode ? (
          <AlertInboxFoldedTable
            groups={foldedGroups}
            loading={foldedQ.isLoading}
            timezone={tz}
            onlyUnread={onlyUnread}
            domainFilter={domainFilter}
            page={page}
            pageSize={pageSize}
            totalGroups={Number(foldedData?.total_groups) || 0}
            onPageChange={(next, size) => { setPage(next); setPageSize(size) }}
          />
        ) : (
        <Table
          size="small"
          dataSource={items}
          columns={columns}
          rowKey={(r: any) => r.id || r.created_at || r.title}
          loading={inboxQ.isLoading}
          pagination={filtered ? {
            current: page,
            pageSize,
            total: serverTotal,
            showSizeChanger: true,
            onChange: (next: number, size: number) => { setPage(next); setPageSize(size) },
          } : { defaultPageSize: 20, showSizeChanger: true }}
          locale={{ emptyText: onlyUnread ? '暂无未读消息' : '暂无消息' }}
          rowClassName={(r: any) => !r.read ? 'ant-table-row-selected' : ''}
        />
        )}
      </Card>
      {canBulkRead && <AlertInboxBulkRead open={bulkOpen} onClose={() => setBulkOpen(false)} timezone={tz} />}
      <AlertGroupBacklog timezone={tz} />
    </div>
  )
}

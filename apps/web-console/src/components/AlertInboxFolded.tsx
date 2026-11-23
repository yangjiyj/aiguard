import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { Badge, Button, Table, Tag, Typography, message } from 'antd'
import {
  CheckOutlined, CloseCircleFilled, DownOutlined, ExclamationCircleFilled, InfoCircleFilled, RightOutlined, WarningFilled,
} from '@ant-design/icons'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { alertApi, ws8AlertInboxApi } from '../services/api'
import type { AlertInboxFoldedGroup } from '../services/api'
import { DOMAIN_CONFIG, SEVERITY_CONFIG, normalizeInboxItem, sourceLabel } from '../utils/alertInboxDisplay'
import { formatInTimezone } from '../utils/ws8ReportRange'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'

const { Text } = Typography

const DETAIL_PAGE_SIZE = 20

// 图标自带的 aria-label 是英文图标名（如 close-circle），读屏会念出英文：隐藏图标，由外层 Tag 的中文 aria-label 承担语义。
const iconProps = { 'aria-hidden': true, 'aria-label': undefined } as const
const SEVERITY_ICONS: Record<string, ReactNode> = {
  critical: <CloseCircleFilled {...iconProps} />,
  high: <ExclamationCircleFilled {...iconProps} />,
  medium: <WarningFilled {...iconProps} />,
  warning: <WarningFilled {...iconProps} />,
  low: <InfoCircleFilled {...iconProps} />,
  info: <InfoCircleFilled {...iconProps} />,
}

// 严重度不能只靠颜色：图标 + 文字标签 + aria-label（如「严重度：高危」）。
function SeverityTag({ severity }: { severity?: string }) {
  const key = (severity || '').toLowerCase()
  const cfg = SEVERITY_CONFIG[key] || { color: 'default', label: '信息' }
  return (
    <Tag color={cfg.color} icon={SEVERITY_ICONS[key] || SEVERITY_ICONS.info} role="img" aria-label={`严重度：${cfg.label}`}>
      {cfg.label}
    </Tag>
  )
}

const fmtCount = (n: number) => (Number(n) || 0).toLocaleString('en-US')

// 展开某一组：按组原值向后端取该组全部原始明细，分页，不丢任何一条。只在首次展开（组件挂载）时请求。
function FoldedGroupItems({ group, onlyUnread, timezone }: { group: AlertInboxFoldedGroup; onlyUnread: boolean; timezone?: string }) {
  const qc = useQueryClient()
  const identity = useAuditQueryIdentity()
  const [page, setPage] = useState(1)

  const itemsQ = useQuery({
    queryKey: ['alerts-inbox', identity, 'folded-items', group.key, group.day_start, onlyUnread, page],
    queryFn: () => ws8AlertInboxApi.foldedItems({
      key: group.key,
      type: group.type,
      severity: group.severity,
      day_start: group.day_start,
      day_end: group.day_end,
      ...(onlyUnread ? { unread: true } : {}),
      limit: DETAIL_PAGE_SIZE,
      offset: (page - 1) * DETAIL_PAGE_SIZE,
    }),
    placeholderData: keepPreviousData,
  })

  const markRead = useMutation({
    mutationFn: (id: string) => alertApi.markRead(id),
    onSuccess: () => {
      // 折叠列表与明细的 queryKey 都以 alerts-inbox 开头，一次刷新两处。
      qc.invalidateQueries({ queryKey: ['alerts-inbox'] })
      message.success('已标记为已读')
    },
    onError: () => message.error('操作失败'),
  })

  const data: any = itemsQ.data?.data
  const rows = (Array.isArray(data?.items) ? data.items : []).map((raw: Record<string, any>) => normalizeInboxItem(raw))
  const total = Number(data?.total) || 0

  const columns = [
    { title: '时间', dataIndex: 'created_at', key: 'created_at', width: 170, render: (v: string) => formatInTimezone(v, timezone) },
    { title: '严重度', dataIndex: 'severity', key: 'severity', width: 110, render: (v: string) => <SeverityTag severity={v} /> },
    {
      title: '标题 / 详情',
      key: 'content',
      render: (_: unknown, r: any) => (
        <div>
          <div style={{ fontWeight: 500 }}>{r.title || r.message || '-'}</div>
          {r.detail && <Text type="secondary" style={{ fontSize: 12 }}>{r.detail}</Text>}
        </div>
      ),
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
      width: 110,
      render: (_: unknown, r: any) => (!r.read ? (
        <Button
          type="link"
          size="small"
          icon={<CheckOutlined />}
          loading={markRead.isPending && markRead.variables === r.id}
          onClick={() => markRead.mutate(r.id)}
        >
          标记已读
        </Button>
      ) : null),
    },
  ]

  return (
    <div aria-label="原始消息明细">
      <div style={{ marginBottom: 8 }}>
        <Text strong>{`共 ${fmtCount(total)} 条原始消息`}</Text>
        {!itemsQ.isLoading && total !== group.count && (
          <Text type="warning" style={{ fontSize: 12, marginLeft: 8 }}>
            {`折叠计数为 ${fmtCount(group.count)} 条，期间消息有更新，列表刷新后会一致`}
          </Text>
        )}
      </div>
      <Table
        size="small"
        rowKey={(r: any) => r.id || r.created_at}
        dataSource={rows}
        columns={columns}
        loading={itemsQ.isLoading}
        pagination={{ current: page, pageSize: DETAIL_PAGE_SIZE, total, showSizeChanger: false, hideOnSinglePage: true, onChange: (next: number) => setPage(next) }}
        locale={{ emptyText: '该组暂无符合条件的消息' }}
        rowClassName={(r: any) => !r.read ? 'ant-table-row-selected' : ''}
      />
    </div>
  )
}

export interface AlertInboxFoldedTableProps {
  groups: AlertInboxFoldedGroup[]
  loading?: boolean
  timezone?: string
  onlyUnread: boolean
  // 风险域客户端过滤（按 sample 推导的域，仅作用于当前页的组）：all 表示不过滤。
  domainFilter: string
  page: number
  pageSize: number
  totalGroups: number
  onPageChange: (page: number, pageSize: number) => void
}

// 「按天折叠」表格：每行是一个组（同 type + 同严重度 + 同标题 + 同天 + 同关键字段），服务端按组分页。
export default function AlertInboxFoldedTable({
  groups, loading, timezone, onlyUnread, domainFilter, page, pageSize, totalGroups, onPageChange,
}: AlertInboxFoldedTableProps) {
  const rows = useMemo(() => {
    const all = groups.map((group) => ({ group, view: normalizeInboxItem(group.sample || {}) }))
    return domainFilter === 'all' ? all : all.filter((r) => r.view.domain === domainFilter)
  }, [groups, domainFilter])

  type Row = (typeof rows)[number]
  const columns = [
    { title: '严重度', key: 'severity', width: 110, render: (_: unknown, r: Row) => <SeverityTag severity={r.group.severity} /> },
    {
      title: '内容',
      key: 'content',
      ellipsis: true,
      render: (_: unknown, r: Row) => (
        <div>
          <div style={{ fontWeight: 500 }}>{r.view.title || r.view.message || '-'}</div>
          {r.view.detail && <Text type="secondary" style={{ fontSize: 12 }}>{`最近一条：${r.view.detail}`}</Text>}
        </div>
      ),
    },
    {
      title: '风险域',
      key: 'domain',
      width: 110,
      render: (_: unknown, r: Row) => {
        const cfg = DOMAIN_CONFIG[r.view.domain || 'content'] || DOMAIN_CONFIG.content
        return <Tag color={cfg.color}>{cfg.label}</Tag>
      },
    },
    { title: '来源', key: 'source', width: 130, render: (_: unknown, r: Row) => r.view.source ? <Tag>{sourceLabel(r.view.source)}</Tag> : '-' },
    { title: '日期', key: 'day', width: 110, render: (_: unknown, r: Row) => r.group.day },
    {
      title: '条数',
      key: 'count',
      width: 110,
      render: (_: unknown, r: Row) => (
        <div>
          <div style={{ fontWeight: 600 }}>{`×${fmtCount(r.group.count)}`}</div>
          <Text type="secondary" style={{ fontSize: 12 }}>{`未读 ${fmtCount(r.group.unread_count)}`}</Text>
        </div>
      ),
    },
    {
      title: '首末时间',
      key: 'span',
      width: 210,
      render: (_: unknown, r: Row) => (
        <Text style={{ fontSize: 12 }}>
          {`首次 ${formatInTimezone(r.group.first_at, timezone, 'HH:mm:ss')} · 末次 ${formatInTimezone(r.group.last_at, timezone, 'HH:mm:ss')}`}
        </Text>
      ),
    },
  ]

  return (
    <Table
      size="small"
      dataSource={rows}
      columns={columns}
      rowKey={(r: Row) => `${r.group.key}:${r.group.day_start}`}
      loading={loading}
      expandable={{
        columnWidth: 48,
        expandedRowRender: (r: Row) => <FoldedGroupItems group={r.group} onlyUnread={onlyUnread} timezone={timezone} />,
        expandIcon: ({ expanded, onExpand, record }) => (
          <Button
            type="text"
            size="small"
            aria-label={expanded ? '收起明细' : '展开明细'}
            aria-expanded={expanded}
            icon={expanded ? <DownOutlined /> : <RightOutlined />}
            onClick={(e) => onExpand(record, e)}
          />
        ),
      }}
      pagination={{
        current: page,
        pageSize,
        total: totalGroups,
        showSizeChanger: true,
        onChange: (next: number, size: number) => onPageChange(next, size),
      }}
      locale={{ emptyText: onlyUnread ? '暂无未读消息' : '暂无消息' }}
      rowClassName={(r: Row) => r.group.unread_count > 0 ? 'ant-table-row-selected' : ''}
    />
  )
}

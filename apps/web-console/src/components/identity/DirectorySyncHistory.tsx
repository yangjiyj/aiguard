import { Alert, Card, Table, Tag, Tooltip, Typography } from 'antd'
import type { DirectorySyncRun } from '../../services/api'

const { Text } = Typography

// 目录同步历史 — 展示状态、耗时、操作者、失败摘要。
//
// 安全：失败摘要只展示后端 error_code 的中文映射，绝不展示原始 DB 错误
// （pq: / SQLSTATE / connection refused 等）。后端已在 directorySyncRunDTO
// 去除原始错误体，前端再兜一道脱敏。
const ERROR_CODE_CN: Record<string, string> = {
  directory_list_failed: '目录读取失败',
  directory_bind_failed: '目录绑定失败',
  directory_search_failed: '目录查询失败',
  activation_link_failed: '账号绑定失败',
  finalize_activation_failed: '同步收尾失败',
  incremental_bind_lookup_failed: '增量绑定查询失败',
  config_drifted: '目录配置已变化',
  preview_expired: '预览已过期',
  preview_not_ready: '预览不可激活',
  invalid_request: '请求参数错误',
  not_tested: '请先通过目录连接测试',
}

const STATUS_CN: Record<string, { label: string; color: string }> = {
  succeeded: { label: '成功', color: 'green' },
  failed: { label: '失败', color: 'red' },
  running: { label: '运行中', color: 'processing' },
  pending: { label: '排队中', color: 'default' },
}

const RUN_KIND_CN: Record<string, string> = {
  full: '全量同步',
  changed: '增量同步',
  preview: '预览',
}

function formatDuration(startedAt?: string, finishedAt?: string): string {
  if (!startedAt || !finishedAt) return '—'
  const start = new Date(startedAt).getTime()
  const end = new Date(finishedAt).getTime()
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) return '—'
  const seconds = Math.round((end - start) / 1000)
  if (seconds < 60) return `${seconds} 秒`
  const minutes = Math.floor(seconds / 60)
  const rem = seconds % 60
  return rem === 0 ? `${minutes} 分` : `${minutes} 分 ${rem} 秒`
}

function actorLabel(actorUserId?: string): string {
  if (!actorUserId) return '—'
  // 不展示数据库 user_id 原文（UUID），统一显示「管理员」+ 脱敏后缀。
  const tail = actorUserId.length > 6 ? actorUserId.slice(-4) : actorUserId
  return `管理员（…${tail}）`
}

export interface DirectorySyncHistoryProps {
  runs: DirectorySyncRun[]
  loading?: boolean
}

export default function DirectorySyncHistory({ runs, loading }: DirectorySyncHistoryProps) {
  const columns = [
    {
      title: '开始时间', dataIndex: 'started_at', key: 'started_at',
      render: (v: string) => v ? new Date(v).toLocaleString('zh-CN') : '—',
    },
    {
      title: '类型', dataIndex: 'kind', key: 'kind', width: 100,
      render: (v: string) => RUN_KIND_CN[v] || v || '—',
    },
    {
      title: '状态', dataIndex: 'status', key: 'status', width: 90,
      render: (s: string) => {
        const meta = STATUS_CN[s] || { label: s || '—', color: 'default' }
        return <Tag color={meta.color}>{meta.label}</Tag>
      },
    },
    {
      title: '耗时', key: 'duration', width: 100,
      render: (_: unknown, row: DirectorySyncRun) => formatDuration(row.started_at, row.finished_at),
    },
    {
      title: '影响',
      key: 'impact',
      width: 200,
      render: (_: unknown, row: DirectorySyncRun) => (
        <Text type='secondary' style={{ fontSize: 12 }}>
          新增 {row.created} · 更新 {row.updated} · 禁用 {row.disabled} · 冲突 {row.conflict}
        </Text>
      ),
    },
    {
      title: '操作者', key: 'actor_user_id', width: 140,
      render: (_: unknown, row: DirectorySyncRun) => actorLabel(row.actor_user_id),
    },
    {
      title: '失败摘要', dataIndex: 'error_code', key: 'error_code',
      render: (code: string) => {
        if (!code) return <Text type='secondary'>—</Text>
        const cn = ERROR_CODE_CN[code] || code
        return (
          <Tooltip title={`错误代码：${code}`}>
            <Text type='danger'>{cn}</Text>
          </Tooltip>
        )
      },
    },
  ]

  return (
    <Card title='同步策略与历史'>
      <Alert
        style={{ marginBottom: 12 }}
        type='info'
        showIcon
        message='同步策略'
        description='激活预览后立即执行一次全量同步；后续由平台按策略增量同步，停用已消失账号但不删除审计历史。'
      />
      <Table
        dataSource={runs}
        columns={columns}
        rowKey='id'
        size='small'
        loading={loading}
        pagination={false}
        locale={{ emptyText: '暂无同步历史' }}
      />
    </Card>
  )
}

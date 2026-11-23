import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Space, Table, Tag, Typography } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { agentApi, type GatewayAgentSession } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { useAuditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import { formatAgentType, getAgentColor } from '../utils/agents'
import { EnterprisePageHeader, SectionPanel } from '../components/EnterpriseUI'

const PAGE_SIZE = 20

function formatTime(value: string) {
  return value && !Number.isNaN(Date.parse(value))
    ? new Date(value).toLocaleString('zh-CN', { hour12: false })
    : '未记录'
}

export default function GatewayAgentSessions() {
  const { user } = useAuthStore()
  const identity = useAuditQueryIdentity()
  const [pagination, setPagination] = useState({ identity, page: 1 })
  const page = pagination.identity === identity ? pagination.page : 1
  const allTenants = user?.role === 'platform_admin'
  const canQuery = Boolean(user && (allTenants || user.tenant_id))
  const sessions = useQuery({
    queryKey: ['gateway-agent-sessions', identity, page, PAGE_SIZE],
    queryFn: async () => (await agentApi.list({
      tenant_scope: allTenants ? 'all' : 'tenant',
      limit: PAGE_SIZE,
      offset: (page - 1) * PAGE_SIZE,
    })).data,
    enabled: canQuery,
  })

  return <div className="enterprise-page">
    <EnterprisePageHeader
      eyebrow="审计中心"
      title="智能体会话"
      description="查看经过网关的智能体模型请求与会话风险。终端本地行为在独立智能体安全平台查看。"
      meta={<Tag>{allTenants ? '所有租户' : '当前单位'}</Tag>}
      actions={<Button icon={<ReloadOutlined />} loading={sessions.isFetching} disabled={!canQuery} onClick={() => void sessions.refetch()}>刷新</Button>}
    />
    {!canQuery ? <Alert type="info" showIcon message="当前账号未关联单位，无法查询会话" /> : null}
    {sessions.isError ? <Alert type="error" showIcon message="会话审计加载失败" description="请重试；若仍然失败，请检查账号权限和服务状态。" action={<Button aria-label="重试" onClick={() => void sessions.refetch()}>重试</Button>} style={{ marginBottom: 16 }} /> : null}
    <SectionPanel title="网关会话记录" description="会话编号、智能体类型、模型请求次数和风险分均来自网关审计记录。">
      <Table<GatewayAgentSession>
        rowKey={record => `${record.session_id}:${record.workspace_id}:${record.first_request}`}
        loading={sessions.isLoading && canQuery}
        dataSource={sessions.data?.data ?? []}
        scroll={{ x: 1100 }}
        locale={{ emptyText: sessions.isError ? '会话数据暂不可用' : '暂无网关会话记录' }}
        pagination={{
          current: page,
          pageSize: PAGE_SIZE,
          total: sessions.data?.total ?? 0,
          showSizeChanger: false,
          showTotal: total => `共 ${total} 条会话`,
          onChange: nextPage => setPagination({ identity, page: nextPage }),
        }}
        columns={[
          { title: '会话编号', dataIndex: 'session_id', render: value => <Typography.Text code copyable style={{ overflowWrap: 'anywhere' }}>{value}</Typography.Text> },
          { title: '智能体', dataIndex: 'agent_type', render: value => <Tag color={getAgentColor(value)}>{formatAgentType(value)}</Tag> },
          { title: '工作区', dataIndex: 'workspace_id', render: value => value || '未记录' },
          { title: '模型请求次数', dataIndex: 'request_count' },
          { title: '风险分', dataIndex: 'risk_score', render: value => <Space>{value ?? '未记录'}</Space> },
          { title: '开始时间', dataIndex: 'first_request', render: formatTime },
          { title: '最后活动', dataIndex: 'last_request', render: formatTime },
        ]}
      />
    </SectionPanel>
  </div>
}

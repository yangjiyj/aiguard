import { useMemo } from 'react'
import { useAuthStore } from '../../stores/auth'
import { UserModelAccessCard } from './UserModelAccessCard'
import { Card, Descriptions, Table, Tag, Space, Spin, Alert, Typography, Button } from 'antd'
import { ControlOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { userApi, policyApi, mcpPolicyApi, agentGuardApi } from '../../services/api'
import { formatCountQuota, formatMoneyQuota } from './quotaDisplay'

const { Text } = Typography

function unpack(raw: any): any[] {
  if (Array.isArray(raw?.items)) return raw.items
  if (Array.isArray(raw?.data)) return raw.data
  return Array.isArray(raw) ? raw : []
}

// 模型权限读取后端统一裁决并支持管理员修改个人名单；其他策略按来源展示。
export function UserAiPermissionsTab({ userId }: { userId: string }) {
  const detailQ = useQuery({ queryKey: ['user-detail', userId], queryFn: () => userApi.getDetail(userId), enabled: !!userId })
  const quotaQ = useQuery({ queryKey: ['quota-policy', 'user', userId], queryFn: () => policyApi.getQuota({ scope_type: 'user', scope_id: userId }), enabled: !!userId })
  const mcpQ = useQuery({ queryKey: ['aiperm-mcp-policies'], queryFn: () => mcpPolicyApi.list() })
  const agQ = useQuery({ queryKey: ['agentguard-policies'], queryFn: () => agentGuardApi.listPolicies() })

  const detail: any = detailQ.data?.data
  const projects: string[] = useMemo(() => Array.isArray(detail?.projects) ? detail.projects : [], [detail?.projects])
  const canEditModels = useAuthStore(state => state.user?.role === 'platform_admin' || state.user?.role === 'tenant_admin')

  const quota: any = quotaQ.data?.data || {}
  const mcpRows = useMemo(() => {
    const all = unpack(mcpQ.data?.data)
    // 对齐后端 matchesScope：scope_ref==='' 表示该档位通配（对全部用户/项目生效）。
    return all.filter((p: any) =>
      (p.scope_type === 'user' && (p.scope_ref === '' || p.scope_ref === userId))
      || p.scope_type === 'tenant'
      || (p.scope_type === 'project' && (p.scope_ref === '' || projects.includes(p.scope_ref)))
      // key 档仅纳通配（scope_ref==='' 对全部密钥生效）；具体 key_prefix 策略因 detail 不返回该用户密钥而诚实略过
      || (p.scope_type === 'key' && p.scope_ref === ''))
  }, [mcpQ.data, userId, projects])
  const agPolicies = unpack(agQ.data?.data)

  const loading = detailQ.isLoading
  if (loading) return <Spin />

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Alert type="warning" showIcon
        message="有效权限与策略说明"
        description="模型名单由服务端按部门权限、个人收窄和个人额外授权统一计算；配额、工具和风险策略以运行时最严格解析为准。具体密钥的工具策略请在密钥维度查看。" />

      <UserModelAccessCard userId={userId} canEdit={canEditModels} />

      <Card
        size="small"
        title="速率与配额（用户级，只读）"
        extra={(
          <Button
            type="link"
            size="small"
            icon={<ControlOutlined />}
            href={'/cost/budgets?scope_type=user&scope_id=' + encodeURIComponent(userId)}
          >
            去配置
          </Button>
        )}
      >
        <Descriptions column={2} size="small" bordered>
          <Descriptions.Item label="RPM 上限">{formatCountQuota(quota.rpm_limit, quota.rpm_blocked)}</Descriptions.Item>
          <Descriptions.Item label="TPM 上限">{formatCountQuota(quota.tpm_limit, quota.tpm_blocked)}</Descriptions.Item>
          <Descriptions.Item label="并发上限">{formatCountQuota(quota.concurrency_limit, quota.concurrency_blocked)}</Descriptions.Item>
          <Descriptions.Item label="日 Token">{formatCountQuota(quota.daily_token_limit, quota.daily_token_blocked)}</Descriptions.Item>
          <Descriptions.Item label="月费用预算">{formatMoneyQuota(quota, 'monthly')}</Descriptions.Item>
        </Descriptions>
      </Card>

      <Card size="small" title="MCP 工具权限（匹配该员工的策略）">
        <Table size="small" rowKey="id" pagination={false} dataSource={mcpRows}
          locale={{ emptyText: '无匹配该员工的 MCP 策略（默认审计放行）' }}
          columns={[
            { title: '作用域', dataIndex: 'scope_type', key: 'scope_type' },
            { title: '工具模式', dataIndex: 'tool_pattern', key: 'tool_pattern', render: (v: string) => v || '全部工具' },
            { title: '处置', dataIndex: 'default_action', key: 'default_action', render: (v: string) => <Tag>{v}</Tag> },
            { title: '启用', dataIndex: 'enabled', key: 'enabled', render: (v: boolean) => v ? '是' : '否' },
          ]} />
      </Card>

      <Card size="small" title="工具风险处置态势（AgentGuard）">
        <Text type="secondary">当前生效护栏策略 {agPolicies.length} 条（平台只审计是统一执行上限；原始判定仍完整留证）。</Text>
      </Card>
    </Space>
  )
}

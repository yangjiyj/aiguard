import { useMemo, useState } from 'react'
import { Drawer, Tabs, Descriptions, Tag, Table, Button, Modal, Form, Select, message, DatePicker, Space, Empty, Spin, Tooltip, Typography } from 'antd'
import { ArrowUpOutlined, ArrowDownOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { userApi, orgApi, projectApi, roleApi, operationAuditApi, keyApi } from '../services/api'
import type { UsageRangeParams, UsageRecord } from '../services/api'
import { CompactNumber, MetricCard, SectionPanel } from './EnterpriseUI'
import { TrendArea } from './Charts'
import { useCurrencyStore } from '../stores/currency'
import { useAuthStore } from '../stores/auth'
import { platformRoleLabel, normalizeSystemRole, systemRoleLabel } from '../utils/roles'
import { extractApiError } from '../utils/apiError'
import { formatLatencySeconds } from '../utils/modelProbe'
import {UserAccountMergeCard} from './UserAccountMergeCard'
import { UserAiPermissionsTab } from './ai-permissions/UserAiPermissionsTab'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import 'dayjs/locale/zh-cn'

dayjs.extend(relativeTime)
dayjs.locale('zh-cn')

const { Text } = Typography
const { RangePicker } = DatePicker

interface UserDetailDrawerProps {
  open: boolean
  userId: string | null
  onClose: () => void
  // 初始激活的 Tab key；用于下钻闭环（如从用量排行点进来直接定位到「用量」）。
  initialTab?: string
}

const scopeTypeLabels: Record<string, string> = {
  tenant: '单位',
  team: '部门',
  project: '应用',
}

// 操作日志（每用户预览）——动作/对象中文映射。
// 键必须与后端 logAudit 实际写入的 action_type/target_type 对齐（多为点号命名），
// 否则真实操作会落到中文兜底、丢失具体操作名。未收录的落中文兜底，绝不露原始英文枚举。
const OP_ACTION_LABELS: Record<string, string> = {
  // 用户 / 权限 / 部门（后端点号命名：rbac_handlers.go、org_handler.go、iam_handler.go、users.go）
  'user.account.merged':'合并账号',
  'user.identity.rebound':'换绑身份',
  'user.model_extra.granted':'新增个人额外授权',
  'user.model_extra.revoked':'撤销个人额外授权',
  'user.model_extra.expired':'个人额外授权到期',
  'user.status.update': '启用/禁用用户',
  'change_password': '修改密码',
  'user.personal_budget.update': '调整个人预算',
  'permission.grant': '授予角色',
  'permission.revoke': '撤销授权',
  'team.create': '创建部门',
  'team.delete': '删除部门',
  'team.member.add': '添加部门成员',
  'team.member.remove': '移除部门成员',
  'team.members.batch_add': '批量添加部门成员',
  // 会话（与完整操作日志页保持一致）
  'login': '登录',
  'logout': '退出登录',
  // 应用与密钥（后端下划线命名：handler.go）
  'create_project': '创建应用',
  'update_project': '修改应用',
  'delete_project': '删除应用',
  'create_key': '创建密钥',
  'revoke_key': '吊销密钥',
  'delete_key': '删除密钥',
}
const opActionLabel = (a?: string) => (a ? (OP_ACTION_LABELS[a] || '其他操作') : '-')
const OP_TARGET_LABELS: Record<string, string> = {
  user: '用户', permission_grant: '授权记录', team: '部门',
  project: '应用', key: '密钥', internal_key: '密钥',
  system: '系统配置', settings: '系统设置', rule: '安全规则', provider: '模型渠道', model: '模型',
}
const opTargetLabel = (t?: string) => (t ? (OP_TARGET_LABELS[t] || '业务对象') : '-')

const ADMIN_ROLES = new Set(['platform_admin', 'tenant_owner', 'tenant_admin', 'admin'])

// 环比箭头：正值红涨、负值绿降、null 不显示。
function ChangeBadge({ value, suffix = '%' }: { value: number | null | undefined; suffix?: string }) {
  if (value === null || value === undefined) return <span style={{ color: '#999', fontSize: 12 }}>-</span>
  const up = value >= 0
  const color = up ? 'var(--status-danger)' : 'var(--status-ok)'
  const Icon = up ? ArrowUpOutlined : ArrowDownOutlined
  return (
    <span style={{ color, fontSize: 12 }}>
      <Icon /> {Math.abs(value).toFixed(1)}{suffix}
    </span>
  )
}

interface UsageSummaryResp {
  requests: number
  success_requests: number
  input_tokens: number
  output_tokens: number
  total_tokens: number
  total_cost: number
  success_rate: number
  avg_latency_ms: number
  requests_change: number | null
  input_tokens_change: number | null
  output_tokens_change: number | null
  total_cost_change: number | null
  total_tokens_change: number | null
}

interface TrendPoint { date: string; requests: number; input_tokens: number; output_tokens: number; total_cost: number }
interface ModelRow {
  id: string; name: string; model_id: string
  requests: number; input_tokens: number; output_tokens: number; total_cost: number; cost_percent: number
}

// 个人用量看板 Tab 内容。仅 admin 可见。
function UserUsageTab({ userId }: { userId: string }) {
  const [dateRange, setDateRange] = useState<[dayjs.Dayjs, dayjs.Dayjs]>([dayjs().subtract(30, 'days'), dayjs()])
  const { format: formatCurrency } = useCurrencyStore()
  const rangeParams = useMemo<UsageRangeParams>(
    () => ({ start_date: dateRange[0].format('YYYY-MM-DD'), end_date: dateRange[1].format('YYYY-MM-DD') }),
    [dateRange]
  )

  const summaryQ = useQuery({
    queryKey: ['user-usage-summary', userId, rangeParams],
    queryFn: () => userApi.usage.summary(userId, rangeParams),
    enabled: !!userId,
  })
  const trendQ = useQuery({
    queryKey: ['user-usage-trend', userId, rangeParams],
    queryFn: () => userApi.usage.trend(userId, rangeParams),
    enabled: !!userId,
  })
  const byModelQ = useQuery({
    queryKey: ['user-usage-by-model', userId, rangeParams],
    queryFn: () => userApi.usage.byModel(userId, rangeParams),
    enabled: !!userId,
  })
  const recordsQ = useQuery({
    queryKey: ['user-usage-records', userId, rangeParams],
    queryFn: () => userApi.usage.records(userId, { start_date: rangeParams.start_date, end_date: rangeParams.end_date, limit: 10 }),
    enabled: !!userId,
  })

  if (summaryQ.isLoading) return <Spin />
  if (summaryQ.isError) return <Empty description="用量数据加载失败" />

  const s = (summaryQ.data?.data ?? {}) as UsageSummaryResp
  const trend = (trendQ.data?.data?.data ?? []) as TrendPoint[]
  const models = (byModelQ.data?.data ?? []) as ModelRow[]
  const records = (recordsQ.data?.data?.records ?? []) as UsageRecord[]

  const noData = s.requests === 0 && s.total_cost === 0 && trend.length === 0
  if (noData) {
    return (
      <div>
        <Space style={{ marginBottom: 12 }}>
          <RangePicker
            value={dateRange}
            onChange={(d) => { if (d?.[0] && d?.[1]) setDateRange([d[0], d[1]]) }}
            size="small"
            allowClear={false}
          />
        </Space>
        <Empty description="该用户在所选时段内暂无用量" />
      </div>
    )
  }

  const costFmt = (v: number) => formatCurrency(v || 0, 4)

  return (
    <div>
      <Space style={{ marginBottom: 12 }}>
        <RangePicker
          value={dateRange}
          onChange={(d) => { if (d?.[0] && d?.[1]) setDateRange([d[0], d[1]]) }}
          size="small"
          allowClear={false}
        />
      </Space>

      {/* 概览卡 */}
      <div className="enterprise-metric-grid enterprise-metric-grid--drawer">
        <MetricCard label="请求数" valueNumber={s.requests || 0} tone="blue"
          footer={<ChangeBadge value={s.requests_change} />} />
        <MetricCard label="输入 Token" valueNumber={s.input_tokens || 0}
          footer={<ChangeBadge value={s.input_tokens_change} />} />
        <MetricCard label="输出 Token" valueNumber={s.output_tokens || 0}
          footer={<ChangeBadge value={s.output_tokens_change} />} />
        <MetricCard label="总成本" value={costFmt(s.total_cost || 0)} tone="orange"
          footer={<ChangeBadge value={s.total_cost_change} />} />
        <MetricCard label="成功率" value={`${(s.success_rate || 0).toFixed(1)}%`} tone="green"
          footer={<span style={{ color: '#999', fontSize: 12 }}>均时延 {formatLatencySeconds(s.avg_latency_ms || 0)}</span>} />
      </div>

      {/* 趋势 */}
      <SectionPanel title="成本与 Token 趋势" description="按天聚合的成本与 Token 用量">
        {trend.length === 0 ? (
          <Empty description="暂无趋势数据" />
        ) : (
          <TrendArea
            data={trend}
            height={220}
            currencyFormatter={(v) => formatCurrency(v, 4)}
            series={[
              { key: 'total_cost', label: '成本', color: 'var(--chart-3)' },
              { key: 'total_tokens', label: 'Token' },
            ]}
          />
        )}
      </SectionPanel>

      {/* 模型分布 */}
      <div style={{ marginTop: 16 }}>
        <SectionPanel title="按模型分布" description="该用户各模型的请求数与成本占比">
          <Table
            dataSource={models}
            rowKey={(r) => r.model_id || r.id}
            size="small"
            pagination={false}
            locale={{ emptyText: '暂无模型数据' }}
            columns={[
              { title: '模型', dataIndex: 'name', key: 'name', ellipsis: true,
                render: (v: string) => v || '已删除或不可见模型' },
              { title: '请求数', dataIndex: 'requests', key: 'requests',
                render: (v: number) => <CompactNumber value={v} /> },
              { title: 'Token', key: 'tokens',
                render: (_: unknown, r) => <CompactNumber value={(r.input_tokens || 0) + (r.output_tokens || 0)} /> },
              { title: '成本', dataIndex: 'total_cost', key: 'total_cost', render: (v: number) => costFmt(v || 0) },
              { title: '成本占比', dataIndex: 'cost_percent', key: 'cost_percent',
                render: (v: number) => v ? `${v.toFixed(1)}%` : '-' },
            ]}
          />
        </SectionPanel>
      </div>

      {/* 最近调用 */}
      <div style={{ marginTop: 16 }}>
        <SectionPanel title="最近调用" description="该用户最近的调用明细（最多 10 条）">
          <Table
            dataSource={records}
            rowKey="id"
            size="small"
            pagination={false}
            locale={{ emptyText: '暂无调用记录' }}
            columns={[
              { title: '时间', dataIndex: 'created_at', key: 'created_at', width: 140,
                render: (v: string) => v ? dayjs(v).format('MM-DD HH:mm:ss') : '-' },
              { title: '模型', dataIndex: 'model_name', key: 'model_name', ellipsis: true,
                render: (v: string) => v || '已删除或不可见模型' },
              { title: 'Token', key: 'tokens', width: 120,
                render: (_: unknown, r) => <CompactNumber value={(r.input_tokens || 0) + (r.output_tokens || 0)} /> },
              { title: '账单', key: 'billing', width: 130,
                render: (_: unknown, r: UsageRecord) => r.billing_state === 'settled' && r.billing_amount_micros != null ? `${r.billing_currency} ${(r.billing_amount_micros / 1_000_000).toFixed(2)}` : (r.billing_state === 'exception' ? '需处理' : r.billing_state === 'reserved' ? '预占中' : r.billing_state === 'released' ? '已释放' : '未计费') },
              { title: '状态', dataIndex: 'request_status', key: 'request_status', width: 80,
                render: (v: string) => {
                  const ok = v === 'success'
                  return <Tag color={ok ? 'green' : 'red'}>{ok ? '成功' : (v || '未知')}</Tag>
                } },
            ]}
          />
        </SectionPanel>
      </div>
    </div>
  )
}

export function UserDetailDrawer({ open, userId, onClose, initialTab }: UserDetailDrawerProps) {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [grantModalOpen, setGrantModalOpen] = useState(false)
  const [grantForm] = Form.useForm()
  const [activeTab, setActiveTab] = useState(initialTab || '1')
  const currentUser = useAuthStore((s) => s.user)
  const canViewUsage = !!(currentUser?.role && ADMIN_ROLES.has(currentUser.role))
  const grantScopeType = Form.useWatch('scope_type', grantForm)

  // 关闭抽屉后再跳转，避免遮罩残留。
  const go = (path: string) => { onClose(); navigate(path) }

  const detailQuery = useQuery({
    queryKey: ['user-detail', userId],
    queryFn: () => userApi.getDetail(userId!),
    enabled: !!userId && open,
  })

  const grantsQuery = useQuery({
    queryKey: ['user-grants', userId],
    queryFn: () => userApi.listGrants(userId!),
    enabled: !!userId && open,
  })

  const loginHistoryQuery = useQuery({
    queryKey: ['user-login-history', userId],
    queryFn: () => userApi.getLoginHistory(userId!, 20),
    enabled: !!userId && open,
  })

  const opLogQuery = useQuery({
    queryKey: ['user-op-log', userId],
    queryFn: () => operationAuditApi.list({ user_id: userId!, limit: 50 }).then(r => r.data),
    enabled: !!userId && open,
  })

  const keysQuery = useQuery({
    queryKey: ['user-keys', userId],
    queryFn: () => userApi.listKeys(userId!),
    enabled: !!userId && open,
  })

  const revealKey = async (keyId: string) => {
    try {
      const r: any = await keyApi.reveal(keyId)
      const full = r?.data?.full_key ?? r?.data?.data?.full_key
      if (full) {
        Modal.info({ title: '完整密钥（请妥善保管，勿外泄）', width: 560, content: <Text copyable>{full}</Text> })
      } else {
        message.warning(r?.data?.reason || '该密钥无法揭示（改造前的老密钥原文已丢，请重置密钥）')
      }
    } catch {
      message.error('揭示失败')
    }
  }

  // 解析可读名所需的字典：应用、部门、系统角色、用户名。与各自页面共享缓存。
  const projectsQuery = useQuery({ queryKey: ['projects'], queryFn: () => projectApi.list(), enabled: open })
  const teamsQuery = useQuery({ queryKey: ['teams'], queryFn: () => orgApi.listTeams(), enabled: open })
  const rolesQuery = useQuery({ queryKey: ['system-roles'], queryFn: () => roleApi.list(), enabled: open })
  const allUsersQuery = useQuery({ queryKey: ['users'], queryFn: () => userApi.list(), enabled: open })

  const createGrantMutation = useMutation({
    mutationFn: (data: { scope_type: string; scope_id: string; role: string }) =>
      userApi.createGrant(userId!, data),
    onSuccess: () => {
      message.success('授权成功')
      queryClient.invalidateQueries({ queryKey: ['user-grants', userId] })
      setGrantModalOpen(false)
      grantForm.resetFields()
    },
    onError: (e: any) => message.error(extractApiError(e) || '授权失败'),
  })

  const deleteGrantMutation = useMutation({
    mutationFn: (grantId: string) => userApi.deleteGrant(userId!, grantId),
    onSuccess: () => {
      message.success('撤销成功')
      queryClient.invalidateQueries({ queryKey: ['user-grants', userId] })
    },
    onError: (e: any) => message.error(extractApiError(e) || '撤销失败'),
  })

  const detail = detailQuery.data?.data
  const user = detail?.user
  const grants = Array.isArray(grantsQuery.data?.data?.data) ? grantsQuery.data.data.data : []
  const loginHistory = Array.isArray(loginHistoryQuery.data?.data?.data) ? loginHistoryQuery.data.data.data : []
  const opRows = Array.isArray(opLogQuery.data?.data) ? opLogQuery.data.data : []
  const projects = Array.isArray(detail?.projects) ? detail.projects : []

  // 字典构建
  const projectsMap = useMemo(() => {
    const raw = (projectsQuery.data as any)?.data
    const list = Array.isArray(raw?.items) ? raw.items : Array.isArray(raw?.data) ? raw.data : Array.isArray(raw) ? raw : []
    const m: Record<string, string> = {}
    for (const p of list) if (p?.id) m[p.id] = p.name || p.code || p.id
    return m
  }, [projectsQuery.data])

  const teamsMap = useMemo(() => {
    const list = (teamsQuery.data as any)?.data?.data
    const m: Record<string, string> = {}
    if (Array.isArray(list)) for (const t of list) if (t?.id) m[t.id] = t.name || t.id
    return m
  }, [teamsQuery.data])

  const usersMap = useMemo(() => {
    const list = (allUsersQuery.data as any)?.data?.data
    const m: Record<string, string> = {}
    if (Array.isArray(list)) for (const u of list) if (u?.id) m[u.id] = u.username || u.id
    return m
  }, [allUsersQuery.data])

  const normalizedRoles = useMemo(() => {
    const list = (rolesQuery.data as any)?.data?.data
    return Array.isArray(list) ? list.map(normalizeSystemRole) : []
  }, [rolesQuery.data])
  const grantRoleOptions = useMemo(() => normalizedRoles.map(r => ({ value: r.code, label: r.label })), [normalizedRoles])
  const roleDynamic = useMemo(() => {
    const m: Record<string, string> = {}
    for (const r of normalizedRoles) m[r.code] = r.label
    return m
  }, [normalizedRoles])

  // 授权范围对象的可读名；解析不到时保留原始标识并加说明（诚实回显，不臆造）。
  const renderScopeName = (scopeType: string, scopeId: string) => {
    if (scopeType === 'tenant') return <span>{scopeId === 'tenant_default' || !scopeId ? '本单位' : scopeId}</span>
    const map = scopeType === 'team' ? teamsMap : scopeType === 'project' ? projectsMap : null
    if (map && map[scopeId]) return <span>{map[scopeId]}</span>
    return (
      <Tooltip title="未能解析该对象名称（可能已删除或无权查看），显示原始标识">
        <span style={{ color: 'var(--text-tertiary)' }}>{scopeId || '-'}</span>
      </Tooltip>
    )
  }

  const renderGrantedBy = (id?: string) => {
    if (!id) return <Text type="secondary">系统</Text>
    if (usersMap[id]) return <span>{usersMap[id]}</span>
    return (
      <Tooltip title="未能解析授权人（用户可能已删除），显示原始标识">
        <span style={{ color: 'var(--text-tertiary)' }}>{id}</span>
      </Tooltip>
    )
  }

  const items = [
    {
      key: '1',
      label: '基本信息',
      children: (
        <Descriptions column={2} bordered size="small">
          <Descriptions.Item label="用户名">{user?.username || '-'}</Descriptions.Item>
          <Descriptions.Item label="邮箱">{user?.email || '-'}</Descriptions.Item>
          <Descriptions.Item label="手机">{user?.phone || '-'}</Descriptions.Item>
          <Descriptions.Item label="平台角色">
            <Tag>{platformRoleLabel(user?.role)}</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="状态">
            <Tag color={user?.status === 'active' ? 'green' : 'red'}>
              {user?.status === 'active' ? '启用' : '禁用'}
            </Tag>
          </Descriptions.Item>
          <Descriptions.Item label="所属部门">
            {user?.department_assignment_mode === 'emergency'
              ? '仅控制台应急访问，不可使用 Chat/模型'
              : (user?.department_name || '-')}
          </Descriptions.Item>
          <Descriptions.Item label="用户ID">
            <Text copyable={{ text: user?.id }} style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>{user?.id || '-'}</Text>
          </Descriptions.Item>
        </Descriptions>
      ),
    },
    {
      key: '2',
      label: '部门归属',
      children: (
        <div>
          {!user?.department_name ? (
            <div style={{ color: '#999', padding: 8 }}>暂无部门归属</div>
          ) : (
            <Space size={[4, 8]} wrap>
              <Tag color="blue"
                style={{ cursor: user.department_id ? 'pointer' : 'default', marginBottom: 4 }}
                onClick={() => user.department_id && go(`/organizations?team_id=${user.department_id}`)}>
                {user.department_name}
              </Tag>
            </Space>
          )}
        </div>
      ),
    },
    {
      key: '3',
      label: '应用授权',
      children: (
        <div>
          {projects.length === 0 ? (
            <div style={{ color: '#999', padding: 8 }}>暂无应用授权</div>
          ) : (
            <Space size={[4, 8]} wrap>
              {projects.map((pid: string) => (
                <Tag key={pid} color="purple" style={{ cursor: 'pointer', marginBottom: 4 }}
                  onClick={() => go(`/apps?project_id=${pid}`)}>
                  {projectsMap[pid] || (
                    <Tooltip title="未能解析应用名称（可能已删除），显示原始标识">
                      <span>{pid}</span>
                    </Tooltip>
                  )}
                </Tag>
              ))}
            </Space>
          )}
        </div>
      ),
    },
    {
      key: 'keys',
      label: '密钥',
      children: (() => {
        const raw: any = keysQuery.data?.data
        const userKeys = Array.isArray(raw?.data) ? raw.data : Array.isArray(raw) ? raw : []
        return (
          <div>
            <div style={{ marginBottom: 8 }}>
              <Button size="small" onClick={() => go('/keys')}>在密钥管理中打开</Button>
              <Text type="secondary" style={{ marginLeft: 8, fontSize: 12 }}>点前缀跳到密钥列表并高亮，点应用名进入应用详情</Text>
            </div>
            <Table
              dataSource={userKeys}
              rowKey="id"
              loading={keysQuery.isLoading}
              size="small"
              pagination={false}
              locale={{ emptyText: '暂无密钥（员工首次使用对话门户时自动签发并绑定）' }}
              columns={[
                {
                  title: '前缀', dataIndex: 'key_prefix', key: 'key_prefix',
                  render: (v: string, row: any) => (
                    <Button type="link" size="small" style={{ padding: 0 }}
                      onClick={() => go(`/keys?key_id=${row.id}${row.project_id ? `&project_id=${row.project_id}` : ''}`)}>
                      <Text code>{v || '-'}</Text>
                    </Button>
                  ),
                },
                { title: '名称', dataIndex: 'name', key: 'name', ellipsis: true, render: (v: string) => v || '-' },
                {
                  title: '所属应用', dataIndex: 'project_id', key: 'project_id', ellipsis: true,
                  render: (pid: string) => pid ? (
                    <Button type="link" size="small" style={{ padding: 0 }} onClick={() => go(`/apps?project_id=${pid}`)}>
                      {projectsMap[pid] || pid}
                    </Button>
                  ) : '-',
                },
                { title: '状态', dataIndex: 'status', key: 'status', render: (s: string) => <Tag color={s === 'active' ? 'green' : 'default'}>{s === 'active' ? '启用' : (s || '-')}</Tag> },
                { title: '创建时间', dataIndex: 'created_at', key: 'created_at', render: (v: string) => v ? new Date(v).toLocaleString() : '-' },
                { title: '操作', key: 'action', render: (_: any, row: any) => <Button type="link" size="small" onClick={() => revealKey(row.id)}>揭示</Button> },
              ]}
            />
          </div>
        )
      })(),
    },
    {
      key: '4',
      label: '角色授权',
      children: (
        <div>
          <Button
            type="primary"
            size="small"
            onClick={() => setGrantModalOpen(true)}
            style={{ marginBottom: 12 }}
          >
            授予角色
          </Button>
          <Table
            dataSource={grants}
            rowKey="id"
            size="small"
            pagination={false}
            columns={[
              {
                title: '范围',
                key: 'scope',
                render: (_: any, r: any) => (
                  <span>{scopeTypeLabels[r.scope_type] || r.scope_type}：{renderScopeName(r.scope_type, r.scope_id)}</span>
                ),
              },
              {
                title: '角色', dataIndex: 'role', key: 'role',
                render: (role: string) => <Tag color="blue">{systemRoleLabel(role, roleDynamic)}</Tag>,
              },
              { title: '授权人', dataIndex: 'granted_by', key: 'granted_by', render: (v: string) => renderGrantedBy(v) },
              {
                title: '操作',
                key: 'action',
                render: (_: any, r: any) => (
                  <Button
                    type="link"
                    danger
                    size="small"
                    onClick={() => deleteGrantMutation.mutate(r.id)}
                  >
                    撤销
                  </Button>
                ),
              },
            ]}
          />
        </div>
      ),
    },
    {
      key: '5',
      label: '操作日志',
      children: (
        <div>
          <div style={{ marginBottom: 12 }}>
            <Button size="small" onClick={() => go(`/system/audit-operations?user_id=${userId}`)}>
              查看完整操作日志
            </Button>
            <Text type="secondary" style={{ marginLeft: 8, fontSize: 12 }}>仅展示该用户最近 50 条</Text>
          </div>
          <Table
            dataSource={opRows}
            rowKey="id"
            size="small"
            loading={opLogQuery.isLoading}
            pagination={false}
            locale={{ emptyText: '暂无操作记录' }}
            columns={[
              {
                title: '时间', dataIndex: 'created_at', key: 'created_at', width: 150,
                render: (t: string) => (t ? dayjs(t).format('MM-DD HH:mm:ss') : '-'),
              },
              {
                title: '操作', dataIndex: 'action_type', key: 'action_type',
                render: (a: string) => <Tag>{opActionLabel(a)}</Tag>,
              },
              {
                title: '影响对象', dataIndex: 'target_type', key: 'target_type',
                render: (t: string) => opTargetLabel(t),
              },
              { title: '来源 IP', dataIndex: 'ip_address', key: 'ip_address', width: 130, render: (v: string) => v || '-' },
            ]}
          />
        </div>
      ),
    },
    {
      key: '6',
      label: '登录历史',
      children: (
        <Table
          dataSource={loginHistory}
          rowKey="id"
          size="small"
          pagination={false}
          locale={{ emptyText: '暂无登录记录' }}
          columns={[
            {
              title: '时间',
              dataIndex: 'logged_at',
              key: 'logged_at',
              render: (t: string) => dayjs(t).format('MM-DD HH:mm:ss'),
            },
            { title: 'IP', dataIndex: 'ip', key: 'ip' },
            {
              title: '结果',
              dataIndex: 'success',
              key: 'success',
              render: (s: boolean) => (
                <Tag color={s ? 'green' : 'red'}>{s ? '成功' : '失败'}</Tag>
              ),
            },
            { title: '失败原因', dataIndex: 'failure_reason', key: 'failure_reason', render: (v: string) => v || '-' },
          ]}
        />
      ),
    },
  ]

  // 仅管理员可见「用量」Tab（个人用量看板，下钻到指定用户）。
  if (canViewUsage && userId) {
    items.push({
      key: '7',
      label: '用量',
      children: <UserUsageTab userId={userId} />,
    })
  }

  // 仅管理员可见「AI 权限」Tab（只读有效权限视图，聚合模型/速率/MCP/AgentGuard；支持 initialTab='ai-perms' 下钻）。
  if (canViewUsage && userId) {
    items.push({
      key: 'ai-perms',
      label: 'AI 权限',
      children: <UserAiPermissionsTab userId={userId} />,
    })
  }

  if(userId&&(currentUser?.role==='platform_admin'||currentUser?.role==='tenant_admin'))items.push({key:'account-merge',label:'账号合并',children:<UserAccountMergeCard userId={userId}/>})

  // scope_id 联动选项：单位固定「本单位」，部门/应用从各自列表拉。
  const scopeIdOptions = grantScopeType === 'team'
    ? Object.entries(teamsMap).map(([value, label]) => ({ value, label }))
    : grantScopeType === 'project'
      ? Object.entries(projectsMap).map(([value, label]) => ({ value, label }))
      : grantScopeType === 'tenant'
        ? [{ value: 'tenant_default', label: '本单位' }]
        : []

  return (
    <>
      <Drawer
        title={`用户详情 - ${user?.username || '加载中'}`}
        width={920}
        open={open}
        onClose={onClose}
        destroyOnClose
      >
        <Tabs items={items} activeKey={activeTab} onChange={setActiveTab} />
      </Drawer>

      <Modal
        zIndex={1100}
        title="授予角色"
        open={grantModalOpen}
        onOk={() => grantForm.submit()}
        onCancel={() => { setGrantModalOpen(false); grantForm.resetFields() }}
        okText="确认授权"
        confirmLoading={createGrantMutation.isPending}
      >
        <Form
          form={grantForm}
          layout="vertical"
          onFinish={(values) => createGrantMutation.mutate(values)}
        >
          <Form.Item name="scope_type" label="范围类型" rules={[{ required: true }]}>
            <Select
              placeholder="选择授权范围"
              onChange={() => grantForm.setFieldValue('scope_id', undefined)}
              options={[
                { value: 'tenant', label: '单位' },
                { value: 'team', label: '部门' },
                { value: 'project', label: '应用' },
              ]}
            />
          </Form.Item>
          <Form.Item name="scope_id" label="授权对象" rules={[{ required: true }]}>
            <Select
              placeholder={grantScopeType ? '选择具体对象' : '请先选择范围类型'}
              disabled={!grantScopeType}
              showSearch
              optionFilterProp="label"
              options={scopeIdOptions}
            />
          </Form.Item>
          <Form.Item name="role" label="角色" rules={[{ required: true }]}
            tooltip="此处为按范围授予的 RBAC 角色（来自系统角色表），与用户的「平台角色」是两套体系。">
            <Select
              placeholder="选择角色"
              loading={rolesQuery.isLoading}
              options={grantRoleOptions}
            />
          </Form.Item>
        </Form>
      </Modal>
    </>
  )
}

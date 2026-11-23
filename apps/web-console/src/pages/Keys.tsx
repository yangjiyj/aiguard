import { useEffect, useState } from 'react'
import GatewayAccess from '../components/GatewayAccess'
import {useGatewayAccess} from '../hooks/useGatewayAccess'
import dayjs from 'dayjs'
import { Table, Button, Space, Modal, Form, Input, Select, Tag, Typography, message, Popconfirm, Tooltip, Checkbox, Drawer, Alert, Descriptions } from 'antd'
import { PlusOutlined, CopyOutlined, ExclamationCircleOutlined, DeleteOutlined, ApiOutlined, RedoOutlined, ControlOutlined, FundOutlined, SearchOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import api, { keyApi, projectApi, userApi, budgetApi } from '../services/api'
import { useAuthStore } from '../stores/auth'

const { Title, Text } = Typography

type TrafficClass = '' | 'evaluation' | 'coding'
interface Key { id: string; project_id: string; user_id: string; name?: string; key_prefix: string; full_key?: string; scopes?: string[]; status: string; created_at: string; traffic_class?: TrafficClass }

// 流量类别只决定安全告警页如何分组，不改变检测、放行或任何拦截行为。
const TRAFFIC_CLASS_OPTIONS: { value: TrafficClass; label: string; hint: string }[] = [
  { value: '', label: '普通业务', hint: '正常业务流量，告警按严重度进入「需行动」或「观察」' },
  { value: 'evaluation', label: '测评流量', hint: '测评/红队平台使用的凭据，其攻击样本进入告警页「测评流量」车道' },
  { value: 'coding', label: '编程助手', hint: '编程助手使用的凭据，其内容规则命中进入「观察」车道' },
]

interface User { id: string; username: string; role?: string }
type KeyProductPermission = 'model' | 'mcp'
interface CreateKeyForm {
  project_id: string
  user_id: string
  name?: string
  permissions: KeyProductPermission[]
}

const MODEL_KEY_SCOPES = ['chat', 'responses', 'embeddings', 'models']

function permissionsToScopes(permissions: KeyProductPermission[] = ['model']): string[] {
  const scopes = permissions.includes('model') ? [...MODEL_KEY_SCOPES] : []
  if (permissions.includes('mcp')) scopes.push('mcp')
  return scopes
}

function copyWithTextarea(value: string): boolean {
  const textarea = document.createElement('textarea')
  textarea.value = value
  textarea.setAttribute('readonly', '')
  textarea.style.position = 'fixed'
  textarea.style.top = '0'
  textarea.style.left = '0'
  textarea.style.opacity = '0'
  document.body.appendChild(textarea)
  textarea.focus()
  textarea.select()
  // iOS/部分 Safari 下只读 textarea 的 select() 不生效，补 setSelectionRange 兜底
  try {
    textarea.setSelectionRange(0, value.length)
  } catch {
    // 某些浏览器对只读元素不支持，忽略
  }

  try {
    return document.execCommand('copy')
  } catch {
    return false
  } finally {
    document.body.removeChild(textarea)
  }
}

// 写剪贴板：优先安全上下文的 Clipboard API，退化到 execCommand。仅返回是否成功，不弹提示，
// 让调用方决定失败后的处理（例如 reveal 复制失败时改弹窗展示密钥供手动复制）。
async function writeClipboard(value: string): Promise<boolean> {
  const writeText = navigator.clipboard?.writeText?.bind(navigator.clipboard)
  if (writeText) {
    try {
      await writeText(value)
      return true
    } catch {
      // HTTP/非安全上下文或权限被拒 → 退化到 execCommand
    }
  }
  return copyWithTextarea(value)
}

async function copyToClipboard(value: string, label = '内容'): Promise<boolean> {
  const ok = await writeClipboard(value)
  if (ok) message.success(label + '已复制')
  else message.error('复制失败，请手动复制')
  return ok
}

const USAGE_QUOTA_TITLE = '用量与额度'
const COST_QUALITY_META: Record<string, { label: string; color: string }> = {
  estimated: { label: '含估算价', color: 'orange' },
  unpriced: { label: '含未定价请求', color: 'red' },
  unknown: { label: '待核实', color: 'default' },
}
const finiteEvidence = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value)
const evidenceNumber = (value: unknown, available = true) => available && finiteEvidence(value) ? value.toLocaleString('zh-CN') : '未知'
const evidenceMoney = (value: unknown, currency: unknown, available = true) => {
  if (!available || !finiteEvidence(value) || typeof currency !== 'string' || !/^[A-Z]{3}$/.test(currency)) return '待核实'
  try {
    return new Intl.NumberFormat('zh-CN', {
      style: 'currency', currency, currencyDisplay: 'code', minimumFractionDigits: 2, maximumFractionDigits: 2,
    }).format(value / 1_000_000)
  } catch {
    return '待核实'
  }
}
const costEvidenceAvailable = (quality: any) => quality?.observed_available === true && quality?.fields_present?.cost_micros === true
const renderCostQuality = (quality: any) => {
  const fields = quality?.fields_present
  const estimated = fields?.cost_estimated_requests === true ? quality?.estimated_requests : undefined
  const unpriced = fields?.cost_unpriced_requests === true ? quality?.unpriced_requests : undefined
  const observed = finiteEvidence(unpriced) && unpriced > 0 ? 'unpriced' : finiteEvidence(estimated) && estimated > 0 ? 'estimated' : 'unknown'
  const meta = COST_QUALITY_META[observed]
  return <Space size={4} wrap>
    <Tag color={meta.color}>{meta.label}</Tag>
    {finiteEvidence(estimated) && estimated > 0 ? <Tag color="orange">估算 {estimated} 笔</Tag> : null}
    {finiteEvidence(unpriced) && unpriced > 0 ? <Tag color="red">未定价 {unpriced} 笔</Tag> : null}
  </Space>
}

function Keys() {
  const queryClient = useQueryClient()
  const [searchParams] = useSearchParams()
  const { user: currentUser } = useAuthStore()
  const isAdmin = currentUser?.role === 'platform_admin' || currentUser?.role === 'admin' || currentUser?.role === 'tenant_owner' || currentUser?.role === 'tenant_admin'
  const [modalOpen, setModalOpen] = useState(false)
  // 一次性展示完整密钥的弹窗：'created' = 新建/重置刚签发（关闭后不可再看）；
  // 'revealed' = HTTP 页无法自动复制时揭示存量密钥供手动复制（可反复揭示）。
  const [shownKey, setShownKey] = useState<{ value: string; mode: 'created' | 'revealed' } | null>(null)
  const [form] = Form.useForm()
  const [selProject, setSelProject] = useState<string | undefined>(undefined)
  // 列表检索：关键字（ID/前缀/备注/应用/用户）+ 状态，纯前端过滤，避免几十条密钥里肉眼翻找
  // 从“去处理”（用户删除占用、诊断建议）带着 key_id 过来：直接把这把密钥搜出来，
  // 不用在分页列表里翻找。
  const [keySearch, setKeySearch] = useState(searchParams.get('key_id') || '')
  const [keyStatusFilter, setKeyStatusFilter] = useState<string | undefined>(undefined)
  const projectIDParam = searchParams.get('project_id') || undefined
  const keyIDParam = searchParams.get('key_id') || undefined

  useEffect(() => {
    if (projectIDParam) {
      setSelProject(projectIDParam)
    }
  }, [projectIDParam])
  useEffect(() => {
    if (keyIDParam) setKeySearch(keyIDParam)
  }, [keyIDParam])

  useEffect(() => {
    // 非管理员打开创建弹窗时，默认填入自己
    if (modalOpen && !isAdmin && currentUser?.id) {
      form.setFieldValue('user_id', currentUser.id)
    }
  }, [modalOpen, isAdmin, currentUser, form])

  const projectsQuery = useQuery({ queryKey: ['projects'], queryFn: () => projectApi.list() })
  const usersQuery = useQuery({ queryKey: ['users'], queryFn: () => userApi.list(), enabled: isAdmin })
  const keysQuery = useQuery({ queryKey: ['keys', selProject], queryFn: () => keyApi.list(selProject) })
  const settingsQuery = useQuery({ queryKey: ['system-settings'], queryFn: () => api.get('/system/settings').then((r) => r.data) })

  // 预算核查抽屉：读取密钥预算读模型（真实证据），无证据字段如实展示
  const [budgetKey, setBudgetKey] = useState<Key | null>(null)
  const budgetReadQ = useQuery({
    queryKey: ['budget-key-readmodel', budgetKey?.id],
    queryFn: () => budgetApi.keyReadModel(budgetKey!.id),
    enabled: !!budgetKey,
    retry: false,
  })

  const createMutation = useMutation({
    mutationFn: ({ permissions, ...data }: CreateKeyForm) => keyApi.create({
      ...data,
      scopes: permissionsToScopes(permissions),
    }),
    onSuccess: (r) => { message.success('密钥创建成功'); queryClient.invalidateQueries({ queryKey: ['keys'] }); setShownKey({ value: r.data.full_key, mode: 'created' }); setModalOpen(false); form.resetFields() },
    onError: () => message.error('创建失败'),
  })
  const revokeMutation = useMutation({
    mutationFn: (id: string) => keyApi.revoke(id),
    onSuccess: () => { message.success('密钥已撤销'); queryClient.invalidateQueries({ queryKey: ['keys'] }) },
    onError: () => message.error('撤销失败'),
  })
  const deleteMutation = useMutation({
    mutationFn: (id: string) => keyApi.delete(id),
    onSuccess: () => { message.success('密钥已删除'); queryClient.invalidateQueries({ queryKey: ['keys'] }) },
    onError: () => message.error('删除失败'),
  })
  // 重置密钥：先撤销旧 key，再用同应用/用户/名称/scopes 重新签发一把新 key，
  // 复用「密钥已创建」一次性弹窗展示新的完整密钥（旧 key 立即失效）。
  const resetMutation = useMutation({
    mutationFn: async (r: Key) => {
      await keyApi.revoke(r.id)
      return keyApi.create({ project_id: r.project_id, user_id: r.user_id, name: r.name, scopes: r.scopes })
    },
    onSuccess: (r) => { message.success('密钥已重置，请保存新密钥'); queryClient.invalidateQueries({ queryKey: ['keys'] }); setShownKey({ value: r.data.full_key, mode: 'created' }) },
    onError: () => message.error('重置失败'),
  })

  // 更新备注/名称（列表行内编辑）。失败回滚由 react-query 重新拉取列表兜底。
  const trafficClassMutation = useMutation({
    mutationFn: (data: { id: string; trafficClass: TrafficClass }) => keyApi.setTrafficClass(data.id, data.trafficClass),
    onSuccess: () => { message.success('流量类别已更新'); queryClient.invalidateQueries({ queryKey: ['keys'] }) },
    onError: () => { message.error('流量类别保存失败，请重试'); queryClient.invalidateQueries({ queryKey: ['keys'] }) },
  })
  const updateMutation = useMutation({
    mutationFn: (data: { id: string; name: string }) => keyApi.update(data.id, { name: data.name }),
    onSuccess: () => { message.success('备注已更新'); queryClient.invalidateQueries({ queryKey: ['keys'] }) },
    onError: () => message.error('备注更新失败'),
  })

  // 复制完整密钥：走受保护 reveal 端点按需解密。命中密文 → 复制明文；
  // 存量老 key（加密上线前创建，原文已丢）→ 弹提示引导用「重置密钥」获取新密钥。
  const handleRevealCopy = async (id: string) => {
    try {
      const res = await keyApi.reveal(id)
      const fullKey: string | null | undefined = res?.data?.full_key
      if (fullKey) {
        // reveal 需先联网取密钥，await 之后用户手势已失效：
        //  - HTTPS/安全上下文 → Clipboard API 仍可写，直接复制成功；
        //  - HTTP 明文页 → 无法自动复制，改弹窗展示密钥，由弹内按钮(全新手势)或手动选中复制。
        if (await writeClipboard(fullKey)) {
          message.success('完整密钥已复制')
        } else {
          setShownKey({ value: fullKey, mode: 'revealed' })
        }
        return
      }
      Modal.info({
        title: '无法复制完整密钥',
        icon: <ExclamationCircleOutlined style={{ color: 'var(--status-warn)' }} />,
        content: '该密钥创建于加密功能上线前，完整值不可恢复，请用「重置密钥」获取新密钥。',
        okText: '知道了',
      })
    } catch {
      message.error('获取完整密钥失败')
    }
  }

  const handleRevoke = (id: string) => {
    Modal.confirm({ title: '确认撤销', icon: <ExclamationCircleOutlined style={{ color: 'var(--status-warn)' }} />, content: '撤销后密钥将无法恢复，确定要撤销此密钥吗？', okText: '撤销', okType: 'danger', cancelText: '取消', onOk: () => revokeMutation.mutate(id) })
  }
  const handleDelete = (id: string) => {
    Modal.confirm({ title: '确认删除', icon: <ExclamationCircleOutlined style={{ color: 'var(--status-danger)' }} />, content: '删除后密钥立即失效并从列表移除，历史调用与费用记录保留。确定要删除吗？', okText: '删除', okType: 'danger', cancelText: '取消', onOk: () => deleteMutation.mutateAsync(id) })
  }
  const _keysProjectsRaw = projectsQuery.data?.data
  const projects = Array.isArray(_keysProjectsRaw?.items) ? _keysProjectsRaw.items
                 : Array.isArray(_keysProjectsRaw?.data) ? _keysProjectsRaw.data
                 : Array.isArray(_keysProjectsRaw) ? _keysProjectsRaw
                 : []
  const projectMap: Map<string, string> = new Map(projects.map((p: any) => [p.id as string, (p.name as string) || '']))

  const _usersRaw = usersQuery.data?.data
  const users: User[] = Array.isArray(_usersRaw?.items) ? _usersRaw.items
              : Array.isArray(_usersRaw?.data) ? _usersRaw.data
              : Array.isArray(_usersRaw) ? _usersRaw
              : []
  const userMap: Map<string, string> = new Map(users.map((u) => [u.id, u.username || u.id]))
  // 非管理员时，把自己的 id→username 也放进 map（避免查不到用户名时只显示 id）
  if (currentUser?.id && !userMap.has(currentUser.id)) {
    userMap.set(currentUser.id, currentUser.username || currentUser.id)
  }
  const userOptions = users.map((u) => ({ value: u.id, label: `${u.username}（${u.id.slice(0, 12)}）` }))

  const columns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 120, ellipsis: true, render: (v: string) => <Tooltip title={v}><Text style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{v.slice(0, 12)}...</Text></Tooltip> },
    { title: '前缀', dataIndex: 'key_prefix', key: 'key_prefix', width: 110, render: (v: string) => <Text code>{v}</Text> },
    // 备注：行内可编辑（点铅笔改）。空值展示占位「＋ 备注」但编辑框起始为空，避免把占位文本填进去。
    { title: '备注', dataIndex: 'name', key: 'name', width: 170, render: (v: string, r: Key) => (
      <Text
        editable={{
          text: v || '',
          tooltip: '编辑备注',
          maxLength: 128,
          onChange: (val: string) => {
            const next = (val || '').trim()
            if (next === (v || '')) return
            updateMutation.mutate({ id: r.id, name: next })
          },
        }}
        style={{ margin: 0, fontSize: 13, color: v ? 'var(--text-primary)' : 'var(--text-tertiary)' }}
      >
        {v || '＋ 备注'}
      </Text>
    ) },
    { title: <Tooltip title="只改变安全告警页的分组：测评平台、编程助手的凭据可以分开显示，不影响检测、放行或拦截。">流量类别</Tooltip>, dataIndex: 'traffic_class', key: 'traffic_class', width: 150, render: (v: TrafficClass | undefined, r: Key) => {
      const current = (v || '') as TrafficClass
      const label = TRAFFIC_CLASS_OPTIONS.find((option) => option.value === current)?.label || '普通业务'
      return <span data-testid={`traffic-class-${r.id}`}>
        {isAdmin && r.status === 'active' ? <Select size="small" style={{ width: 120 }} value={current} loading={trafficClassMutation.isPending && trafficClassMutation.variables?.id === r.id}
          options={TRAFFIC_CLASS_OPTIONS.map((option) => ({ value: option.value, label: option.label, title: option.label }))}
          onChange={(next: TrafficClass) => { if (next !== current) trafficClassMutation.mutate({ id: r.id, trafficClass: next }) }} />
          : <Tag color={current === 'evaluation' ? 'blue' : current === 'coding' ? 'purple' : 'default'}>{label}</Tag>}
      </span>
    } },
    { title: '应用', dataIndex: 'project_id', key: 'project_id', width: 140, render: (v: string) => {
      const projectName = projectMap.get(v)
      // 应用已被删除（列表里没有了）：写“已删除应用”，别把内部 ID 当名字露出来。
      const gone = !projectName && !!v && projectsQuery.isSuccess
      const displayName = projectName || (v ? (gone ? '已删除应用' : v.slice(0, 12)) : '-')
      return <Tooltip title={gone ? v : undefined}><Text strong={!gone} type={gone ? 'secondary' : undefined} style={gone ? undefined : { color: 'var(--text-primary)' }}>{displayName}</Text></Tooltip>
    } },
    { title: '用户', dataIndex: 'user_id', key: 'user_id', width: 140, ellipsis: true, render: (v: string) => {
      // 用户已被删除/退役（用户列表里没有了）：同样不露内部 ID。只有拿到完整用户列表（管理员）时才下这个结论。
      const goneUser = !userMap.get(v) && !!v && isAdmin && usersQuery.isSuccess
      const name = userMap.get(v) || (v ? (goneUser ? '已删除用户' : v.slice(0, 12)) : '-')
      return <Tooltip title={v}><Text style={{ color: 'var(--text-secondary)' }}>{name}</Text></Tooltip>
    } },
    { title: '状态', dataIndex: 'status', key: 'status', width: 90, render: (s: string) => <Tag color={s === 'active' ? 'success' : 'error'}>{s === 'active' ? '活跃' : '已撤销'}</Tag> },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 170, render: (v: string) => <Text style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{dayjs(v).format('YYYY-MM-DD HH:mm:ss')}</Text> },
    { title: '操作', key: 'action', width: 360, render: (_: any, r: Key) => (
      <Space size={4} wrap>
        <Tooltip title={USAGE_QUOTA_TITLE}>
          <Button
            type="text"
            size="small"
            icon={<FundOutlined />}
            aria-label={USAGE_QUOTA_TITLE + ' ' + r.key_prefix}
            onClick={() => setBudgetKey(r)}
          />
        </Tooltip>
        <Tooltip title="钱包与限流">
          <Button
            type="text"
            size="small"
            icon={<ControlOutlined />}
            aria-label={'钱包与限流 ' + r.key_prefix}
            href={'/cost/budgets?scope_type=key&scope_id=' + encodeURIComponent(r.id)}
          />
        </Tooltip>
        <Tooltip title="复制完整密钥">
          <Button
            type="text"
            size="small"
            icon={<CopyOutlined />}
            aria-label={`复制完整密钥 ${r.key_prefix}`}
            onClick={() => void handleRevealCopy(r.id)}
          />
        </Tooltip>
        {r.status === 'active' && (
          <Popconfirm
            title="重置密钥"
            description="将吊销当前密钥并生成新密钥，旧密钥立即失效，正在使用的调用会中断，确认？"
            onConfirm={() => resetMutation.mutate(r)}
            okText="确认重置"
            cancelText="取消"
            okButtonProps={{ danger: true }}
          >
            <Button type="link" size="small" icon={<RedoOutlined />} loading={resetMutation.isPending}>重置</Button>
          </Popconfirm>
        )}
        {r.status === 'active' && <Button type="link" size="small" danger onClick={() => handleRevoke(r.id)}>撤销</Button>}
        <Button type="link" size="small" danger icon={<DeleteOutlined />} onClick={() => handleDelete(r.id)} loading={deleteMutation.isPending && deleteMutation.variables === r.id}>删除</Button>
      </Space>
    ) },
  ]
  const _keysRaw = keysQuery.data?.data
  const keysData = Array.isArray(_keysRaw?.items) ? _keysRaw.items
                 : Array.isArray(_keysRaw?.data) ? _keysRaw.data
                 : Array.isArray(_keysRaw) ? _keysRaw
                 : []
  const keySearchLower = keySearch.trim().toLowerCase()
  const filteredKeys = keysData.filter((k: any) => {
    if (keyStatusFilter && k.status !== keyStatusFilter) return false
    if (!keySearchLower) return true
    // 多关键字以空格分隔 = AND 语义；命中任意字段（ID/前缀/备注/应用名/用户名）即保留
    const haystack = [k.id, k.key_prefix, k.name, projectMap.get(k.project_id), userMap.get(k.user_id)]
      .filter(Boolean).join(' ').toLowerCase()
    return keySearchLower.split(/\s+/).every((token) => haystack.includes(token))
  })

  const gatewayAccess = useGatewayAccess(settingsQuery.data)

  return (
    <div>
      <div className="page-header">
        <Title level={4} style={{ margin: 0, fontSize: 20, fontWeight: 600, color: 'var(--text-primary)' }}>密钥管理</Title>
        <Text style={{ fontSize: 13, color: 'var(--text-secondary)' }}>创建和管理 API 访问密钥</Text>
      </div>
      <div className="table-card" style={{ marginBottom: 16 }}>
        <div style={{ padding: '14px 20px' }}>
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <Space wrap>
              <ApiOutlined style={{ color: 'var(--brand-blue)' }} />
              <Text strong style={{ fontSize: 14, color: 'var(--text-primary)' }}>接入说明</Text>
              <Text style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>使用下方创建的密钥接入本网关</Text>
            </Space>
            <Space direction="vertical" size={8} style={{ width: '100%' }}>
              {settingsQuery.isPending && <Text type="secondary">正在读取调用地址…</Text>}
              {settingsQuery.isError && <Text type="danger">调用地址读取失败，请刷新重试或联系管理员。</Text>}
              {!settingsQuery.isPending && !settingsQuery.isError && <GatewayAccess access={gatewayAccess} onCopy={value=>copyToClipboard(value,'调用地址')}/>}

            </Space>
            {isAdmin && <Text type="secondary" style={{ fontSize: 12 }}>其他网络的入口由管理员配置，<a href="/system/settings">修改对外调用地址</a>。</Text>}
            <Text style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>鉴权：在请求头加 <Text code style={{ fontSize: 12 }}>Authorization: Bearer &lt;你的密钥&gt;</Text></Text>
          </Space>
        </div>
      </div>
      <div className="table-card">
        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Space>
            <Text strong style={{ fontSize: 14, color: 'var(--text-primary)' }}>密钥列表</Text>
            <Input
              allowClear
              prefix={<SearchOutlined />}
              placeholder="搜索 ID / 前缀 / 备注 / 应用 / 用户"
              value={keySearch}
              onChange={(event) => setKeySearch(event.target.value)}
              style={{ width: 240 }}
              size="small"
            />
            <Select placeholder="筛选应用" style={{ width: 180 }} allowClear size="small" value={selProject} onChange={setSelProject} options={projects.map((p: any) => ({ value: p.id, label: p.name }))} />
            <Select
              placeholder="全部状态"
              style={{ width: 120 }}
              allowClear
              size="small"
              value={keyStatusFilter}
              onChange={setKeyStatusFilter}
              options={[{ value: 'active', label: '活跃' }, { value: 'revoked', label: '已撤销' }]}
            />
            <Text style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>共 {filteredKeys.length} 条</Text>
          </Space>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => { setShownKey(null); form.resetFields(); setModalOpen(true) }}>创建密钥</Button>
        </div>
        <div style={{ padding: '0 20px' }}>
          <Text type="secondary" style={{ display: 'block', fontSize: 12, marginBottom: 8 }}>「流量类别」只改变安全告警页的分组：把测评平台、编程助手使用的凭据标出来，它们的命中会进入「测评流量」「观察」车道；不影响检测、放行或拦截。</Text>
          <Table columns={columns} dataSource={filteredKeys} rowKey="id" loading={keysQuery.isLoading}
            scroll={{ x: 'max-content' }}
            locale={keyIDParam ? { emptyText: '没有找到这把密钥，可能已被删除' } : undefined}
            onRow={(record) => ({ style: record.id === keyIDParam ? { background: 'rgba(22, 119, 255, 0.08)' } : undefined })}
            pagination={{ defaultPageSize: 10, showSizeChanger: true, showTotal: (t) => `共 ${t} 条` }}
          />
        </div>
      </div>
      <Modal title="创建密钥" open={modalOpen} onCancel={() => setModalOpen(false)} footer={null} width={460}>
        <Form form={form} onFinish={(v) => createMutation.mutate(v)} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="project_id" label="应用" rules={[{ required: true, message: '请选择应用' }]}><Select placeholder="请选择应用" options={projects.map((p: any) => ({ value: p.id, label: p.name }))} /></Form.Item>
          <Form.Item name="user_id" label="所属用户" rules={[{ required: true, message: '请选择用户' }]}>
            {isAdmin ? (
              <Select placeholder="请选择用户" showSearch optionFilterProp="label" options={userOptions} />
            ) : (
              <Select disabled options={[{ value: currentUser?.id, label: currentUser?.username || '' }]} />
            )}
          </Form.Item>
          <Form.Item name="name" label="备注" rules={[{ max: 128, message: '备注最长 128 字' }]} tooltip="给这把密钥起个名，方便区分用途（可选）">
            <Input placeholder="如：门户对接 / alice 的测试 key / WorkBuddy 生产" maxLength={128} allowClear />
          </Form.Item>
          <Form.Item name="permissions" label="调用权限" initialValue={['model']} rules={[{ required: true, message: '请至少选择一种调用权限' }]}>
            <Checkbox.Group>
              <Space direction="vertical">
                <Checkbox value="model">模型 API（对话、响应、向量与模型列表）</Checkbox>
                <Checkbox value="mcp">MCP 网关（远程工具调用）</Checkbox>
              </Space>
            </Checkbox.Group>
          </Form.Item>
          <Form.Item style={{ marginBottom: 0 }}>
            <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
              <Button onClick={() => setModalOpen(false)}>取消</Button>
              <Button type="primary" htmlType="submit" loading={createMutation.isPending}>创建</Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
      {shownKey && (
        <Modal
          title={shownKey.mode === 'created' ? '密钥已创建' : '完整密钥'}
          open={!!shownKey}
          onCancel={() => setShownKey(null)}
          footer={<Button type="primary" onClick={() => setShownKey(null)}>{shownKey.mode === 'created' ? '我已复制并保存' : '关闭'}</Button>}
          width={560}
        >
          <div style={{ background: 'rgba(250,173,20,0.08)', border: '1px solid rgba(250,173,20,0.2)', borderRadius: 8, padding: '10px 14px', marginBottom: 14, display: 'flex', gap: 8, alignItems: 'center' }}>
            <ExclamationCircleOutlined style={{ color: 'var(--status-warn)' }} />
            <Text style={{ fontSize: 13 }}>
              {shownKey.mode === 'created'
                ? '请立即复制并妥善保存，关闭后将无法再次查看完整密钥。'
                : '当前页面无法自动写入剪贴板（明文 HTTP 页），请点下方按钮或手动选中复制。'}
            </Text>
          </div>
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <Input.TextArea autoSize={{ minRows: 2, maxRows: 4 }} value={shownKey.value} readOnly autoFocus onFocus={(e) => e.currentTarget.select()} />
            <Button type="primary" icon={<CopyOutlined />} onClick={() => void copyToClipboard(shownKey.value, '完整密钥')}>复制完整密钥</Button>
          </Space>
        </Modal>
      )}
      <Drawer
        title={budgetKey ? (USAGE_QUOTA_TITLE + ' · ' + (budgetKey.name || budgetKey.key_prefix)) : USAGE_QUOTA_TITLE}
        width="min(560px, 100vw)"
        open={!!budgetKey}
        onClose={() => setBudgetKey(null)}
        destroyOnClose
      >
        {budgetKey && (() => {
          const read = budgetReadQ.data?.data?.data
          const confirmed = read?.confirmed_usage
          const window_ = read?.window
          const quota = read?.effective_quota
          const currency = confirmed?.cost_currency_available === true ? confirmed.cost_currency : undefined
          const ownerWallets: any[] = Array.isArray(read?.in_flight?.owner_wallets) ? read.in_flight.owner_wallets : []
          const attributionLabels: Record<string, string> = { user: '归属用户', project: '归属应用', unattributed: '未归属' }
          return <>
            {budgetReadQ.isError ? (
              <Alert type="error" showIcon style={{ marginBottom: 12 }} message="用量信息暂不可用" description="请稍后重试或联系管理员。" />
            ) : budgetReadQ.isLoading || !read ? (
              <Text type="secondary">正在加载…</Text>
            ) : (
              <>
                <Descriptions size="small" column={1} bordered styles={{ label: { width: 104, whiteSpace: 'nowrap' }, content: { overflowWrap: 'anywhere' } }} style={{ marginBottom: 12 }}>
                  <Descriptions.Item label="密钥">{budgetKey.key_prefix}（{budgetKey.name || '无备注'}）</Descriptions.Item>
                  <Descriptions.Item label="归属">{attributionLabels[read?.key?.attribution] || '未归属'}</Descriptions.Item>
                  {read?.generated_at ? <Descriptions.Item label="生成时间">{new Date(read.generated_at).toLocaleString()}</Descriptions.Item> : null}
                </Descriptions>
                <Text strong>已确认用量</Text>
                {confirmed?.available ? (
                  <Descriptions size="small" column={1} bordered styles={{ label: { width: 104, whiteSpace: 'nowrap' }, content: { overflowWrap: 'anywhere' } }} style={{ margin: '8px 0 12px' }}>
                    <Descriptions.Item label="本月">{`${evidenceNumber(confirmed.month_tokens, confirmed.month_tokens_available === true)} tokens · ${evidenceNumber(confirmed.month_requests, confirmed.month_requests_available === true)} 次请求 · ${evidenceMoney(confirmed.month_cost_micros, currency, costEvidenceAvailable(confirmed.month_cost_quality))}`}</Descriptions.Item>
                    <Descriptions.Item label="今日">{`${evidenceNumber(confirmed.day_tokens, confirmed.day_tokens_available === true)} tokens · ${evidenceNumber(confirmed.day_requests, confirmed.day_requests_available === true)} 次请求 · ${evidenceMoney(confirmed.day_cost_micros, currency, costEvidenceAvailable(confirmed.day_cost_quality))}`}</Descriptions.Item>
                    <Descriptions.Item label="RPM / 并发">{`${evidenceNumber(confirmed.rpm)} / ${evidenceNumber(confirmed.concurrency)}`}</Descriptions.Item>
                    <Descriptions.Item label="本月费用质量">{renderCostQuality(confirmed.month_cost_quality)}</Descriptions.Item>
                    <Descriptions.Item label="今日费用质量">{renderCostQuality(confirmed.day_cost_quality)}</Descriptions.Item>
                    {confirmed.bucket_timezone ? <Descriptions.Item label="统计时区">
                      {confirmed.bucket_timezone}
                    </Descriptions.Item> : null}
                    <Descriptions.Item label="费用说明"><Text type="secondary" style={{ fontSize: 12 }}>含估算或未定价请求时，总额不等于实际账单。币种或计价信息不足的金额待核实。</Text></Descriptions.Item>
                  </Descriptions>
                ) : (
                  <Alert type="info" showIcon style={{ margin: '8px 0 12px' }} message="用量暂不可用" />
                )}
                <Text strong>窗口与配额</Text>
                <Descriptions size="small" column={1} bordered styles={{ label: { width: 104, whiteSpace: 'nowrap' }, content: { overflowWrap: 'anywhere' } }} style={{ margin: '8px 0 12px' }}>
                  {window_?.available ? (
                    <>
                      <Descriptions.Item label="日窗口">{`${new Date(window_.day_started_at).toLocaleString()} 起，${new Date(window_.day_reset_at).toLocaleString()} 重置`}</Descriptions.Item>
                      <Descriptions.Item label="月窗口">{`${new Date(window_.month_started_at).toLocaleString()} 起，${new Date(window_.month_reset_at).toLocaleString()} 重置`}</Descriptions.Item>
                    </>
                  ) : (
                    <Descriptions.Item label="窗口"><Text type="secondary">暂不可用</Text></Descriptions.Item>
                  )}
                  <Descriptions.Item label="生效配额">{quota ? `${evidenceNumber(quota.daily_token_limit)} tokens/日 · ${evidenceNumber(quota.monthly_token_limit)} tokens/月` : '未配置'}</Descriptions.Item>
                </Descriptions>
                <Text strong>在途金额</Text>
                <Text type="secondary" style={{ display: 'block', margin: '8px 0' }}>在途金额按用户钱包统计，未细分到密钥。</Text>
                {read?.in_flight?.owner_level_available ? (
                  <Table
                    rowKey="wallet_id"
                    size="small"
                    style={{ marginTop: 8 }}
                    scroll={{ x: 500 }}
                    columns={[
                      { title: '级别', dataIndex: 'level', render: (v: string) => <Tag>{v === 'user' ? '用户级' : v}</Tag> },
                      { title: '钱包', dataIndex: 'wallet_id', render: (v: string) => <Text code>{v}</Text> },
                      { title: '币种', dataIndex: 'currency' },
                      { title: '余额', dataIndex: 'balance_micros', render: (v: unknown, wallet: any) => evidenceMoney(v, wallet.currency) },
                      { title: '预占', dataIndex: 'reserved_micros', render: (v: unknown, wallet: any) => evidenceMoney(v, wallet.currency) },
                      { title: '可用', dataIndex: 'available_micros', render: (v: unknown, wallet: any) => evidenceMoney(v, wallet.currency) },
                    ]}
                    dataSource={ownerWallets}
                    pagination={false}
                    locale={{ emptyText: '暂无钱包证据' }}
                  />
                ) : (
                  <Text type="secondary" style={{ display: 'block', marginTop: 8 }}>暂无所属用户的钱包信息</Text>
                )}
              </>
            )}
          </>
        })()}
      </Drawer>
    </div>
  )
}

export default Keys

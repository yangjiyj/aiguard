import { useMemo, useState } from 'react'
import { Table, Button, Space, Modal, Form, Input, Select, Tag, Typography, Alert, message, Switch, Tooltip, Popconfirm } from 'antd'
import { CheckCircleOutlined, DeleteOutlined, PlusOutlined, SearchOutlined, StopOutlined, SwapOutlined, UserOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { userApi, orgApi, tenantApi } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { UserDetailDrawer } from '../components/UserDetailDrawer'
import { showUserDeleteBlockerModal } from '../components/UserDeleteBlockerModal'
import { PLATFORM_ROLE_OPTIONS, DEFAULT_PLATFORM_ROLE, platformRoleMeta, platformRoleLabel } from '../utils/roles'
import { extractApiError } from '../utils/apiError'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import 'dayjs/locale/zh-cn'

dayjs.extend(relativeTime)
dayjs.locale('zh-cn')

const { Text, Title } = Typography

interface User {
  id: string
  possible_duplicate_user_ids?:string[]
  username: string
  email?: string
  phone?: string
  role: string
  status: string
  tenant_id?: string
  department_id?: string
  department_name?: string
  department_assignment_mode?: string
  department_assignment_source?: string
  last_login_at?: string
  projects_count?: number
  grants_count?: number
}

const EMPTY_USERS: User[] = []

function Users() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const currentTenantID = useAuthStore((state) => state.user?.tenant_id)
  const [modalOpen, setModalOpen] = useState(false)
  const [resetPwdOpen, setResetPwdOpen] = useState(false)
  const [editingUser, setEditingUser] = useState<User | null>(null)
  const [resetUserId, setResetUserId] = useState<string>('')
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [drawerUserId, setDrawerUserId] = useState<string | null>(null)
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([])
  const [keyword, setKeyword] = useState('')
  const [departmentFilter, setDepartmentFilter] = useState<string>()
  const [statusFilter, setStatusFilter] = useState<string>()
  const [roleFilter, setRoleFilter] = useState<string>()
  const [loginFilter, setLoginFilter] = useState<string>()
  const [batchDepartmentOpen, setBatchDepartmentOpen] = useState(false)
  const [batchDepartmentID, setBatchDepartmentID] = useState<string>()
  const [form] = Form.useForm()
  const [pwdForm] = Form.useForm()
  const selectedRole = Form.useWatch('role', form)
  const isEmergencyRole = selectedRole === 'platform_admin'

  const query = useQuery({
    queryKey: ['users'],
    queryFn: () => userApi.list(),
  })

  const targetTenantID = editingUser?.tenant_id
  const isCrossTenantEdit = !!targetTenantID && targetTenantID !== currentTenantID
  // 创建和本租户编辑复用组织缓存；跨租户编辑按目标租户隔离缓存。
  const teamsQuery = useQuery({
    queryKey: ['teams', isCrossTenantEdit ? targetTenantID : 'current'],
    queryFn: () => isCrossTenantEdit ? tenantApi.listTeams(targetTenantID) : orgApi.listTeams(),
    enabled: modalOpen || batchDepartmentOpen || !!departmentFilter,
  })
  const teamOptions = useMemo(() => {
    const raw = (teamsQuery.data as any)?.data?.data
    return Array.isArray(raw) ? raw.map((t: any) => ({ value: t.id, label: t.name })) : []
  }, [teamsQuery.data])

  const createMutation = useMutation({
    mutationFn: (data: any) => {
      const payload = { ...data }
      delete payload.initial_team_id
      return userApi.create(payload)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setModalOpen(false)
      form.resetFields()
      message.success('用户已创建')
    },
    onError: (e: any) => message.error(extractApiError(e) || '创建失败'),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, ...data }: { id: string; username?: string; email?: string; phone?: string; role?: string; department_id?: string }) =>
      userApi.update(id, data),
    onSuccess: () => {
      message.success('更新成功')
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setModalOpen(false)
      setEditingUser(null)
      form.resetFields()
    },
    onError: (e: any) => message.error(extractApiError(e) || '更新失败'),
  })

  const toggleStatusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: 'active' | 'disabled' }) =>
      userApi.toggleStatus(id, status),
    onSuccess: () => {
      message.success('状态更新成功')
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
    onError: (e: any) => message.error(extractApiError(e) || '状态更新失败'),
  })

  const resetPwdMutation = useMutation({
    mutationFn: (data: { id: string; password: string }) =>
      userApi.resetPassword(data.id, data.password),
    onSuccess: () => {
      message.success('密码重置成功')
      setResetPwdOpen(false)
      setResetUserId('')
      pwdForm.resetFields()
    },
    onError: (e: any) => message.error(extractApiError(e) || '密码重置失败'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => userApi.delete(id),
    onSuccess: (_data, id) => {
      message.success('用户已注销；计费与审计历史已安全保留')
      setSelectedRowKeys((keys) => keys.filter((key) => key !== id))
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
    onError: (e: any) => {
      const err = e?.response?.data?.error
      if (err?.code === 'user_has_references') {
        showUserDeleteBlockerModal(err, navigate)
        return
      }
      message.error(extractApiError(e) || '删除失败')
    },
  })

  const batchDepartmentMutation = useMutation({
    mutationFn: async ({ ids, departmentID }: { ids: string[]; departmentID: string }) => {
      const results = await Promise.allSettled(ids.map((id) => userApi.update(id, { department_id: departmentID })))
      return { success: results.filter((item) => item.status === 'fulfilled').length, failed: results.filter((item) => item.status === 'rejected').length }
    },
    onSuccess: ({ success, failed }) => {
      if (success) message.success(`已将 ${success} 个用户转入新部门`)
      if (failed) message.warning(`${failed} 个用户未能转换，请检查跨租户或身份源限制`)
      setBatchDepartmentOpen(false)
      setBatchDepartmentID(undefined)
      setSelectedRowKeys([])
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })

  const batchStatusMutation = useMutation({
    mutationFn: async ({ ids, status }: { ids: string[]; status: 'active' | 'disabled' }) => {
      const results = await Promise.allSettled(ids.map((id) => userApi.toggleStatus(id, status)))
      return { status, success: results.filter((item) => item.status === 'fulfilled').length, failed: results.filter((item) => item.status === 'rejected').length }
    },
    onSuccess: ({ status, success, failed }) => {
      if (success) message.success(`已${status === 'active' ? '启用' : '禁用'} ${success} 个用户`)
      if (failed) message.warning(`${failed} 个用户处理失败`)
      setSelectedRowKeys([])
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })

  const batchDeleteMutation = useMutation({
    mutationFn: async (ids: string[]) => {
      const results = await Promise.allSettled(ids.map((id) => userApi.delete(id)))
      return { success: results.filter((item) => item.status === 'fulfilled').length, failed: results.filter((item) => item.status === 'rejected').length }
    },
    onSuccess: ({ success, failed }) => {
      if (success) message.success(`已注销 ${success} 个用户，计费与审计历史已安全保留`)
      if (failed) message.warning(`${failed} 个用户仍负责应用、持有密钥或受权限限制，未注销`)
      setSelectedRowKeys([])
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })

  const handleCreate = () => {
    setEditingUser(null)
    form.resetFields()
    form.setFieldsValue({ role: DEFAULT_PLATFORM_ROLE })
    setModalOpen(true)
  }

  const handleEdit = (record: User) => {
    setEditingUser(record)
    form.resetFields()
    form.setFieldsValue(record)
    setModalOpen(true)
  }

  const handleResetPwd = (id: string) => {
    setResetUserId(id)
    pwdForm.resetFields()
    setResetPwdOpen(true)
  }

  const handleShowDetail = (userId: string) => {
    setDrawerUserId(userId)
    setDrawerOpen(true)
  }

  const handleModalOk = () => {
    form.validateFields().then((values) => {
      if (editingUser) {
        const rest = { ...values }
        delete rest.initial_team_id
        const payload: any = { id: editingUser.id, ...rest }
        // 角色未改动（含历史遗留取值）时不回传，避免触发后端平台角色白名单校验而误拦编辑。
        if (payload.role === editingUser.role) delete payload.role
        updateMutation.mutate(payload)
      } else {
        createMutation.mutate(values)
      }
    })
  }

  // 编辑存量用户时，其历史角色可能不在权威 4 值内：补一个中文选项占位，
  // 既不露原始英文，也允许管理员改选为权威角色。
  const roleOptions = useMemo(() => {
    const base = [...PLATFORM_ROLE_OPTIONS]
    if (editingUser?.role && !base.some(o => o.value === editingUser.role)) {
      base.unshift({ value: editingUser.role, label: platformRoleLabel(editingUser.role) })
    }
    return base
  }, [editingUser])

  const users: User[] = Array.isArray(query.data?.data?.data) ? query.data.data.data : EMPTY_USERS
  const departmentOptions = useMemo(() => {
    const fromUsers = users
      .filter((user) => user.department_id && user.department_name)
      .map((user) => ({ value: user.department_id!, label: user.department_name! }))
    return Array.from(new Map([...teamOptions, ...fromUsers].map((option) => [option.value, option])).values())
  }, [teamOptions, users])
  const filteredUsers = useMemo(() => {
    const search = keyword.trim().toLowerCase()
    return users.filter((user) => {
      if (search && ![user.username, user.email, user.phone].some((value) => value?.toLowerCase().includes(search))) return false
      if (departmentFilter === '__unassigned__' && user.department_id) return false
      if (departmentFilter && departmentFilter !== '__unassigned__' && user.department_id !== departmentFilter) return false
      if (statusFilter && user.status !== statusFilter) return false
      if (roleFilter && user.role !== roleFilter) return false
      if (loginFilter === 'never' && user.last_login_at) return false
      if (loginFilter === 'recent7' && (!user.last_login_at || dayjs().diff(dayjs(user.last_login_at), 'day') > 7)) return false
      if (loginFilter === 'inactive30' && user.last_login_at && dayjs().diff(dayjs(user.last_login_at), 'day') < 30) return false
      return true
    })
  }, [users, keyword, departmentFilter, statusFilter, roleFilter, loginFilter])
  const selectedUsers = users.filter((user) => selectedRowKeys.includes(user.id))
  const batchDepartmentUsers = selectedUsers.filter((user) => user.role !== 'platform_admin')
  const hasFilters = !!(keyword || departmentFilter || statusFilter || roleFilter || loginFilter)
  const resetFilters = () => {
    setKeyword('')
    setDepartmentFilter(undefined)
    setStatusFilter(undefined)
    setRoleFilter(undefined)
    setLoginFilter(undefined)
  }

  const columns = [
    {
      title: '用户名',
      dataIndex: 'username',
      key: 'username',
      width: 200,
      ellipsis: { showTitle: false },
      render: (text: string, record: User) => (
        <Tooltip title={text}>
          <Button type="link" size="small" onClick={() => handleShowDetail(record.id)} style={{ padding: 0 }}>
            <UserOutlined /> <span style={{ display: 'inline-block', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', verticalAlign: 'bottom' }}>{text}</span>
          </Button>
          {record.possible_duplicate_user_ids?.length?<Tag color="orange">疑似重复账号</Tag>:null}
        </Tooltip>
      ),
    },
    { title: '邮箱', dataIndex: 'email', key: 'email', width: 220, ellipsis: { showTitle: false }, render: (v: string) => v ? <Tooltip title={v}><span>{v}</span></Tooltip> : <span style={{ color: 'var(--text-tertiary)' }}>-</span> },
    { title: '手机', dataIndex: 'phone', key: 'phone', width: 130, render: (v: string) => v || <span style={{ color: 'var(--text-tertiary)' }}>-</span> },
    {
      title: '部门',
      dataIndex: 'department_name',
      key: 'department',
      width: 200,
      render: (name: string, record: User) => name ? (
        <Tag color="blue" style={{ cursor: record.department_id ? 'pointer' : 'default' }}
          onClick={() => record.department_id && navigate(`/organizations?team_id=${record.department_id}`)}>
          {name}
        </Tag>
      ) : <span style={{ color: 'var(--text-tertiary)' }}>-</span>,
    },
    {
      title: '应用数',
      dataIndex: 'projects_count',
      key: 'projects_count',
      width: 80,
      render: (v: number) => v ?? 0,
    },
    {
      title: '授权数',
      dataIndex: 'grants_count',
      key: 'grants_count',
      width: 80,
      render: (v: number) => v ?? 0,
    },
    {
      title: '平台角色',
      dataIndex: 'role',
      key: 'role',
      width: 130,
      render: (role: string) => {
        const rm = platformRoleMeta(role)
        return <Tag color={rm.color}>{rm.label}</Tag>
      },
    },
    {
      title: '最后登录',
      dataIndex: 'last_login_at',
      key: 'last_login_at',
      width: 130,
      render: (t?: string) => t ? (
        <Tooltip title={dayjs(t).format('YYYY-MM-DD HH:mm:ss')}>
          <span>{dayjs(t).fromNow()}</span>
        </Tooltip>
      ) : '-',
    },
    {
      title: '状态',
      key: 'status',
      width: 110,
      render: (_: any, record: User) => (
        <Switch
          checked={record.status === 'active'}
          checkedChildren="启用"
          unCheckedChildren="禁用"
          loading={toggleStatusMutation.isPending}
          onChange={(checked) => {
            toggleStatusMutation.mutate({
              id: record.id,
              status: checked ? 'active' : 'disabled',
            })
          }}
        />
      ),
    },
    {
      title: '操作',
      key: 'action',
      width: 300,
      fixed: 'right' as const,
      render: (_: any, record: User) => (
        <Space size={4}>
          <Button size="small" onClick={() => handleShowDetail(record.id)}>
            详情
          </Button>
          <Button size="small" onClick={() => handleEdit(record)}>
            编辑
          </Button>
          <Button size="small" onClick={() => handleResetPwd(record.id)}>
            重置密码
          </Button>
          <Popconfirm
            title={`删除用户「${record.username}」?`}
            description="账号将立即禁用并从用户列表移除；计费和审计历史会脱敏保留。若仍负责应用或持有密钥，请先按提示处理。"
            okText="删除"
            cancelText="取消"
            okType="danger"
            onConfirm={() => deleteMutation.mutate(record.id)}
          >
            <Button danger size="small" icon={<DeleteOutlined />} loading={deleteMutation.isPending}>
              删除
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <Title level={4} style={{ margin: 0 }}>用户管理</Title>
        <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
          创建用户
        </Button>
      </div>

      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 10, padding: 16, marginBottom: 16 }}>
        <Space wrap size={[10, 10]} style={{ width: '100%' }}>
          <Input
            allowClear
            prefix={<SearchOutlined />}
            placeholder="搜索用户名 / 邮箱 / 手机"
            value={keyword}
            onChange={(event) => setKeyword(event.target.value)}
            style={{ width: 260 }}
          />
          <Select
            allowClear
            showSearch
            optionFilterProp="label"
            placeholder="全部部门"
            value={departmentFilter}
            onChange={setDepartmentFilter}
            options={[{ value: '__unassigned__', label: '未分配部门' }, ...departmentOptions]}
            style={{ width: 180 }}
          />
          <Select
            allowClear
            placeholder="全部状态"
            value={statusFilter}
            onChange={setStatusFilter}
            options={[{ value: 'active', label: '已启用' }, { value: 'disabled', label: '已禁用' }]}
            style={{ width: 140 }}
          />
          <Select
            allowClear
            placeholder="全部角色"
            value={roleFilter}
            onChange={setRoleFilter}
            options={PLATFORM_ROLE_OPTIONS}
            style={{ width: 160 }}
          />
          <Select
            allowClear
            placeholder="登录活跃度"
            value={loginFilter}
            onChange={setLoginFilter}
            options={[
              { value: 'recent7', label: '近 7 天登录' },
              { value: 'inactive30', label: '30 天未登录' },
              { value: 'never', label: '从未登录' },
            ]}
            style={{ width: 160 }}
          />
          {hasFilters && <Button onClick={resetFilters}>重置筛选</Button>}
          <Text type="secondary" style={{ marginLeft: 'auto' }}>共 {filteredUsers.length} 个用户</Text>
        </Space>
      </div>

      {selectedRowKeys.length > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', marginBottom: 12, borderRadius: 8, border: '1px solid color-mix(in srgb, var(--brand-blue) 45%, var(--border-color))', background: 'color-mix(in srgb, var(--brand-blue) 10%, var(--bg-card))' }}>
          <Text strong>已选择 {selectedRowKeys.length} 个用户</Text>
          <Button icon={<SwapOutlined />} onClick={() => { setBatchDepartmentID(undefined); setBatchDepartmentOpen(true) }}>
            转换部门
          </Button>
          <Popconfirm title={`启用选中的 ${selectedRowKeys.length} 个用户？`} onConfirm={() => batchStatusMutation.mutate({ ids: selectedRowKeys.map(String), status: 'active' })}>
            <Button icon={<CheckCircleOutlined />} loading={batchStatusMutation.isPending}>批量启用</Button>
          </Popconfirm>
          <Popconfirm title={`禁用选中的 ${selectedRowKeys.length} 个用户？`} description="禁用后用户将无法登录，但账号和历史审计数据仍保留。" onConfirm={() => batchStatusMutation.mutate({ ids: selectedRowKeys.map(String), status: 'disabled' })}>
            <Button icon={<StopOutlined />} loading={batchStatusMutation.isPending}>批量禁用</Button>
          </Popconfirm>
          <Popconfirm title={`注销选中的 ${selectedRowKeys.length} 个用户？`} description="账号将立即禁用并移出列表；计费和审计历史脱敏保留。仍负责应用或持有密钥的账号不会注销，并会提示失败数量。" okText="注销" cancelText="取消" okType="danger" onConfirm={() => batchDeleteMutation.mutate(selectedRowKeys.map(String))}>
            <Button danger icon={<DeleteOutlined />} loading={batchDeleteMutation.isPending}>批量注销</Button>
          </Popconfirm>
          <Button type="text" onClick={() => setSelectedRowKeys([])} style={{ marginLeft: 'auto' }}>取消选择</Button>
        </div>
      )}

      <Table
        columns={columns} dataSource={filteredUsers} rowKey="id" scroll={{ x: 1500 }} size="middle"
        loading={query.isLoading}
        rowSelection={{
          selectedRowKeys,
          onChange: setSelectedRowKeys,
          selections: [Table.SELECTION_ALL, Table.SELECTION_INVERT, Table.SELECTION_NONE],
          getCheckboxProps: (record) => ({ disabled: record.id === useAuthStore.getState().user?.id, title: record.id === useAuthStore.getState().user?.id ? '当前登录账号不可批量操作' : undefined }),
        }}
        pagination={{ showSizeChanger: true, showQuickJumper: true, showTotal: (total) => `共 ${total} 条`, defaultPageSize: 20 }}
        locale={{ emptyText: hasFilters ? '没有符合筛选条件的用户' : '暂无用户' }}
        onRow={(record) => ({
          onDoubleClick: () => handleShowDetail(record.id),
          style: { cursor: 'pointer' },
        })}
      />

      {/* Create/Edit User Modal */}
      <Modal
        title={editingUser ? '编辑用户' : '创建用户'}
        open={modalOpen}
        onOk={handleModalOk}
        onCancel={() => { setModalOpen(false); setEditingUser(null); form.resetFields() }}
        okText={editingUser ? '保存' : '创建'}
        confirmLoading={createMutation.isPending || updateMutation.isPending}
      >
        <Form form={form} layout="vertical" initialValues={{ role: DEFAULT_PLATFORM_ROLE }}>
          <Form.Item name="username" label="用户名" rules={[{ required: !editingUser }]}>
            <Input />
          </Form.Item>
          {!editingUser && (
            <Form.Item name="password" label="密码" rules={[{ required: true }]}>
              <Input.Password />
            </Form.Item>
          )}
          <Form.Item name="email" label="邮箱">
            <Input />
          </Form.Item>
          <Form.Item name="phone" label="手机">
            <Input />
          </Form.Item>
          <Form.Item name="role" label="平台角色" rules={[{ required: true }]}
            tooltip="普通用户仅使用 Chat。其余角色承担对应后台职责；部门和应用内的细分权限请在组织管理、应用管理单独分配。">
            <Select options={roleOptions} onChange={(role) => {
              if (role === 'platform_admin') form.setFieldValue('department_id', undefined)
            }} />
          </Form.Item>
          {!editingUser && selectedRole === 'chat_user' && (
            <Alert type="info" showIcon message="普通用户默认进入 Chat，继承所属部门已授权的模型。"
              description="个人模型权限可进一步收窄，始终受部门授权范围限制。" style={{ marginBottom: 12 }} />
          )}
          {!isEmergencyRole && (
            <Alert type="warning" showIcon message="部门尚未授权模型时，用户进入 Chat 后无法调用模型。"
              description="请管理员在「组织管理 → 部门 → 模型权限」选择需要开放的模型，再配置个人使用范围。创建用户不会自动开放全部模型。" style={{ marginBottom: 12 }} />
          )}
          {isEmergencyRole ? (
            <Text type="warning">仅控制台应急访问，不可使用 Chat/模型</Text>
          ) : (
            <Form.Item name="department_id" label="所属部门"
              rules={[{ required: true, message: '请选择所属部门' }]}>
              <Select showSearch optionFilterProp="label"
                placeholder="请选择所属部门"
                loading={teamsQuery.isLoading} options={teamOptions} />
            </Form.Item>
          )}
        </Form>
      </Modal>

      <Modal
        title="批量转换部门"
        open={batchDepartmentOpen}
        okText="确认转换"
        cancelText="取消"
        okButtonProps={{ disabled: !batchDepartmentID || batchDepartmentUsers.length === 0 }}
        confirmLoading={batchDepartmentMutation.isPending}
        onCancel={() => { setBatchDepartmentOpen(false); setBatchDepartmentID(undefined) }}
        onOk={() => batchDepartmentID && batchDepartmentMutation.mutate({ ids: batchDepartmentUsers.map((user) => user.id), departmentID: batchDepartmentID })}
      >
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          <Text>将 {batchDepartmentUsers.length} 个普通用户批量转入目标部门。</Text>
          {batchDepartmentUsers.length !== selectedUsers.length && (
            <Text type="warning">已自动排除 {selectedUsers.length - batchDepartmentUsers.length} 个平台管理员；应急管理员不能归属业务部门。</Text>
          )}
          <Select
            showSearch
            optionFilterProp="label"
            placeholder="请选择目标部门"
            value={batchDepartmentID}
            onChange={setBatchDepartmentID}
            loading={teamsQuery.isLoading}
            options={departmentOptions}
            style={{ width: '100%' }}
          />
          <Text type="secondary">跨租户用户、由外部身份源强制托管的账号可能无法转换，系统会保留失败账号并汇总提示。</Text>
        </Space>
      </Modal>

      {/* Reset Password Modal */}
      <Modal
        title="重置密码"
        open={resetPwdOpen}
        onOk={() => pwdForm.validateFields().then((v) => resetPwdMutation.mutate({ id: resetUserId, password: v.password }))}
        onCancel={() => { setResetPwdOpen(false); setResetUserId(''); pwdForm.resetFields() }}
        okText="重置"
        confirmLoading={resetPwdMutation.isPending}
      >
        <Form form={pwdForm} layout="vertical">
          <Form.Item name="password" label="新密码" rules={[{ required: true }]}>
            <Input.Password />
          </Form.Item>
        </Form>
      </Modal>

      {/* User Detail Drawer */}
      <UserDetailDrawer
        open={drawerOpen}
        userId={drawerUserId}
        onClose={() => { setDrawerOpen(false); setDrawerUserId(null) }}
      />
    </div>
  )
}

export default Users

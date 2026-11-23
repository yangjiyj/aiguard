import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Row, Col, Card, Drawer, Table, Select, Button, Tag, Divider, Spin, Space, Typography, message, Popconfirm, Form, Input, Modal } from 'antd'
import { PlusOutlined, UserAddOutlined, SettingOutlined, DeleteOutlined, EditOutlined, ControlOutlined, SearchOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { projectApi, userApi, modelApi, orgApi } from '../services/api'

const { Title, Text } = Typography

interface Project {
  id: string
  name: string
  code?: string
  environment?: string
  status: string
  model_whitelist?: string[]
  quota_limits?: Record<string, any>
  team_id?: string
}

interface ProjectUser {
  user_id: string
  username: string
  email?: string
  role: string
  created_at?: string
}

const envColor: Record<string, string> = { production: 'red', staging: 'orange', development: 'blue' }
const envLabel: Record<string, string> = { production: '生产', staging: '预发布', development: '开发' }
const roleLabel: Record<string, string> = { owner: '负责人', developer: '开发者', viewer: '观察者' }
const roleColor: Record<string, string> = { owner: 'gold', developer: 'blue', viewer: 'default' }

function Apps() {
  const queryClient = useQueryClient()
  const [searchParams] = useSearchParams()
  const openedProjectParamRef = useRef<string | null>(null)
  const [drawer, setDrawer] = useState<{ open: boolean; project: Project | null }>({ open: false, project: null })
  const [createModalOpen, setCreateModalOpen] = useState(false)
  const [editModalOpen, setEditModalOpen] = useState(false)
  const [addUserModalOpen, setAddUserModalOpen] = useState(false)
  const [form] = Form.useForm()
  const [editForm] = Form.useForm()
  const [addUserForm] = Form.useForm()

  // State for model config editing
  const [whitelist, setWhitelist] = useState<string[]>([])
  const [quotaLimits, setQuotaLimits] = useState<Record<string, any>>({})
  const [projectTeamID, setProjectTeamID] = useState('')
  // 应用卡片检索：按名称/代码/ID 过滤（纯前端，应用数量有限无需后端分页）
  const [appSearch, setAppSearch] = useState('')

  // Queries
  const projectsQuery = useQuery({ queryKey: ['projects'], queryFn: () => projectApi.list() })
  const usersQuery = useQuery({ queryKey: ['users'], queryFn: () => userApi.list() })
  const modelsQuery = useQuery({ queryKey: ['models', 'available'], queryFn: () => modelApi.list({ available_only: true }) })
  const teamsQuery = useQuery({ queryKey: ['teams'], queryFn: () => orgApi.listTeams() })

  // Project users query (only when drawer is open)
  const projectUsersQuery = useQuery({
    queryKey: ['project-users', drawer.project?.id],
    queryFn: () => projectApi.listUsers(drawer.project!.id),
    enabled: drawer.open && drawer.project !== null,
  })

  // Mutations
  const createMutation = useMutation({
    mutationFn: (data: { name: string; code?: string; environment?: string }) => projectApi.create(data),
    onSuccess: () => { message.success('创建成功'); queryClient.invalidateQueries({ queryKey: ['projects'] }); setCreateModalOpen(false); form.resetFields() },
    onError: () => message.error('创建失败'),
  })

  const updateMutation = useMutation({
    mutationFn: (data: { id: string; name?: string; code?: string; environment?: string; status?: string }) => projectApi.update(data.id, data),
    onSuccess: () => { message.success('更新成功'); queryClient.invalidateQueries({ queryKey: ['projects'] }); setEditModalOpen(false); editForm.resetFields() },
    onError: () => message.error('更新失败'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => projectApi.delete(id),
    onSuccess: () => { message.success('删除成功'); queryClient.invalidateQueries({ queryKey: ['projects'] }); handleCloseDrawer() },
    onError: () => message.error('删除失败'),
  })

  const bindUserMutation = useMutation({
    mutationFn: (data: { projectId: string; userId: string; role: string }) => projectApi.bindUser(data.projectId, data.userId, data.role),
    onSuccess: () => { message.success('用户绑定成功'); queryClient.invalidateQueries({ queryKey: ['project-users', drawer.project?.id] }); setAddUserModalOpen(false); addUserForm.resetFields() },
    onError: () => message.error('绑定失败'),
  })

  const unbindUserMutation = useMutation({
    mutationFn: (data: { projectId: string; userId: string }) => projectApi.unbindUser(data.projectId, data.userId),
    onSuccess: () => { message.success('用户解绑成功'); queryClient.invalidateQueries({ queryKey: ['project-users', drawer.project?.id] }) },
    onError: () => message.error('解绑失败'),
  })

  const updateModelConfigMutation = useMutation({
    mutationFn: async (data: { projectId: string; whitelist: string[]; quotaLimits: Record<string, any>; teamId: string }) => {
      await Promise.all([
        projectApi.updateModelConfig(data.projectId, data.whitelist, data.quotaLimits),
        orgApi.patchProjectTeam(data.projectId, data.teamId),
      ])
    },
    onSuccess: () => { message.success('模型配置更新成功'); queryClient.invalidateQueries({ queryKey: ['projects'] }) },
    onError: () => message.error('更新失败'),
  })

  const handleOpenDrawer = useCallback((project: Project) => {
    setDrawer({ open: true, project })

    projectApi.get(project.id).then((projectResult) => {
      const fullProject = projectResult.data?.data || projectResult.data
      const parsedWhitelist = Array.isArray(fullProject?.model_whitelist) ? fullProject.model_whitelist : []
      const parsedQuotaLimits = typeof fullProject?.quota_limits === 'object' && fullProject.quota_limits !== null ? fullProject.quota_limits : {}

      setWhitelist(parsedWhitelist)
      setQuotaLimits(parsedQuotaLimits)
      setProjectTeamID(fullProject?.team_id || project.team_id || '')
    }).catch(() => {
      setWhitelist([])
      setQuotaLimits({})
      setProjectTeamID(project.team_id || '')
    })
  }, [])

  const handleCloseDrawer = () => {
    setDrawer({ open: false, project: null })
    setWhitelist([])
    setQuotaLimits({})
    setProjectTeamID('')
  }

  const handleAddUser = (values: any) => {
    if (drawer.project) {
      bindUserMutation.mutate({ projectId: drawer.project.id, userId: values.user_id, role: values.role })
    }
  }

  const handleUnbindUser = (userId: string) => {
    if (drawer.project) {
      unbindUserMutation.mutate({ projectId: drawer.project.id, userId })
    }
  }

  const handleSaveModelConfig = () => {
    if (drawer.project) {
      updateModelConfigMutation.mutate({ projectId: drawer.project.id, whitelist, quotaLimits, teamId: projectTeamID })
    }
  }

  const handleCreateProject = async (values: any) => {
    const { team_id, ...projectData } = values
    createMutation.mutate(projectData, {
      onSuccess: async (resp) => {
        const projectId = resp?.data?.id || resp?.data?.data?.id
        if (team_id && projectId) {
          try { await orgApi.patchProjectTeam(projectId, team_id) } catch (_e) { /* ignore */ }
        }
      }
    })
  }

  const handleEditProject = (project: Project) => {
    editForm.setFieldsValue({
      name: project.name,
      code: project.code,
      environment: project.environment,
      status: project.status,
    })
    setEditModalOpen(true)
  }

  const handleUpdateProject = (values: any) => {
    if (drawer.project) {
      updateMutation.mutate({ id: drawer.project.id, ...values })
    }
  }

  const handleDeleteProject = () => {
    if (drawer.project) {
      deleteMutation.mutate(drawer.project.id)
    }
  }

  // User table columns
  const userColumns = [
    { title: '用户名', dataIndex: 'username', key: 'username', render: (v: string) => <Text strong style={{ color: 'var(--text-primary)' }}>{v}</Text> },
    { title: '邮箱', dataIndex: 'email', key: 'email', render: (v: string) => v || '-' },
    { title: '角色', dataIndex: 'role', key: 'role', render: (v: string) => <Tag color={roleColor[v] || 'default'}>{roleLabel[v] || v}</Tag> },
    { title: '操作', key: 'action', width: 80, render: (_: any, r: ProjectUser) => (
      <Popconfirm title="确定解绑此用户?" onConfirm={() => handleUnbindUser(r.user_id)} okText="确定" cancelText="取消">
        <Button type="link" size="small" danger icon={<DeleteOutlined />}>解绑</Button>
      </Popconfirm>
    ) },
  ]

  // Available models for whitelist selection
  const _modelsRaw = modelsQuery.data?.data
  const _modelsArr = Array.isArray(_modelsRaw?.items) ? _modelsRaw.items
                   : Array.isArray(_modelsRaw?.data) ? _modelsRaw.data
                   : Array.isArray(_modelsRaw) ? _modelsRaw
                   : []
  const modelOptions = _modelsArr.map((m: any) => ({
    value: m.id || m.model_name,
    label: m.model_label || m.model_name,
  }))

  // Available users for binding
  const _appsUsersRaw = usersQuery.data?.data
  const _appsUsersArr = Array.isArray(_appsUsersRaw?.items) ? _appsUsersRaw.items
                       : Array.isArray(_appsUsersRaw?.data) ? _appsUsersRaw.data
                       : Array.isArray(_appsUsersRaw) ? _appsUsersRaw
                       : []
  const userOptions = _appsUsersArr.map((u: any) => ({
    value: u.id,
    label: `${u.username} (${u.email || '无邮箱'})`,
  }))

  const _projectsRaw = projectsQuery.data?.data
  const projects = useMemo(() => (Array.isArray(_projectsRaw?.items) ? _projectsRaw.items
                 : Array.isArray(_projectsRaw?.data) ? _projectsRaw.data
                 : Array.isArray(_projectsRaw) ? _projectsRaw
                 : []), [_projectsRaw])
  const filteredProjects = useMemo(() => {
    const search = appSearch.trim().toLowerCase()
    if (!search) return projects
    return projects.filter((p: Project) => [p.name, p.code, p.id]
      .some((value) => value?.toLowerCase().includes(search)))
  }, [projects, appSearch])

  useEffect(() => {
    // project_id 是用户删除占用清单、诊断建议用的参数；highlight 是部门“应用”标签页里点应用名用的。
    const projectID = searchParams.get('project_id') || searchParams.get('highlight')
    if (!projectID || openedProjectParamRef.current === projectID || drawer.project?.id === projectID || !projectsQuery.isSuccess) {
      return
    }
    openedProjectParamRef.current = projectID
    const target = projects.find((project: Project) => project.id === projectID)
    if (target) handleOpenDrawer(target)
    // 应用已被删除或不存在：明说，而不是停在一个什么都没发生的应用列表上。
    else message.info('该应用已不存在')
  }, [drawer.project?.id, handleOpenDrawer, projects, projectsQuery.isSuccess, searchParams])

  // 部门“应用”标签页的“新建应用”带 team_id 过来：直接打开新建窗口并选好所属部门。
  const openedTeamParamRef = useRef<string | null>(null)
  const teamIDParam = searchParams.get('team_id')
  useEffect(() => {
    if (!teamIDParam || openedTeamParamRef.current === teamIDParam) return
    openedTeamParamRef.current = teamIDParam
    setCreateModalOpen(true)
  }, [teamIDParam])
  // 表单要等窗口打开、挂上之后才能回填。
  useEffect(() => {
    if (createModalOpen && teamIDParam && !form.getFieldValue('team_id')) form.setFieldsValue({ team_id: teamIDParam })
  }, [createModalOpen, teamIDParam, form])

  return (
    <div>
      {/* Page Header */}
      <div className="page-header">
        <Title level={4} style={{ margin: 0, fontSize: 20, fontWeight: 600, color: 'var(--text-primary)' }}>应用管理</Title>
        <Text style={{ fontSize: 13, color: 'var(--text-secondary)' }}>管理接入网关的应用、用户绑定与模型配置</Text>
      </div>

      {/* Toolbar */}
      <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Space size={12}>
          <Input
            allowClear
            prefix={<SearchOutlined />}
            placeholder="搜索应用名称 / 代码 / ID"
            value={appSearch}
            onChange={(event) => setAppSearch(event.target.value)}
            style={{ width: 260 }}
          />
          <Text style={{ color: 'var(--text-secondary)' }}>{appSearch.trim() ? `${filteredProjects.length} / ${projects.length} 个应用` : `共 ${projects.length} 个应用`}</Text>
        </Space>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateModalOpen(true)}>新建应用</Button>
      </div>

      {/* Project Cards Grid */}
      <Spin spinning={projectsQuery.isLoading}>
        <Row gutter={[16, 16]}>
          {filteredProjects.map((p: Project) => (
            <Col span={8} key={p.id}>
              <Card
                hoverable
                onClick={() => handleOpenDrawer(p)}
                style={{ background: 'var(--bg-card)', borderColor: 'var(--border-color)' }}
                styles={{ body: { padding: 16 } }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                  <div>
                    <Text strong style={{ fontSize: 16, color: 'var(--text-primary)' }}>{p.name}</Text>
                    <Text style={{ fontSize: 12, color: 'var(--text-tertiary)', marginLeft: 8 }}>{p.code || '-'}</Text>
                  </div>
                  <Tag color={p.status === 'active' ? 'success' : 'default'}>{p.status === 'active' ? '启用' : '禁用'}</Tag>
                </div>
                <Divider style={{ margin: '12px 0' }} />
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  {p.environment ? <Tag color={envColor[p.environment] || 'default'}>{envLabel[p.environment] || p.environment}</Tag> : <span style={{ color: 'var(--text-tertiary)' }}>-</span>}
                  <Text style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>ID: {p.id.slice(0, 12)}...</Text>
                </div>
              </Card>
            </Col>
          ))}
        </Row>
      </Spin>

      {/* Create Project Modal */}
      <Modal title="新建应用" open={createModalOpen} onCancel={() => setCreateModalOpen(false)} footer={null} width={460}>
        <Form form={form} onFinish={handleCreateProject} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input placeholder="请输入应用名称" /></Form.Item>
          <Form.Item name="code" label="代码"><Input placeholder="应用代码标识（选填）" /></Form.Item>
          <Form.Item name="environment" label="环境">
            <Select placeholder="请选择环境" options={[{ value: 'production', label: '生产' }, { value: 'staging', label: '预发布' }, { value: 'development', label: '开发' }]} />
          </Form.Item>
          <Form.Item name="team_id" label="所属部门" rules={[{ required: false }]}>
            <Select
              placeholder="选择部门（推荐）"
              allowClear
              options={(() => { const r = teamsQuery.data?.data; return (Array.isArray(r?.items) ? r.items : Array.isArray(r?.data) ? r.data : Array.isArray(r) ? r : []).map((t: any) => ({ value: t.id, label: t.name })) })()}
            />
          </Form.Item>
          <Form.Item style={{ marginBottom: 0 }}>
            <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
              <Button onClick={() => setCreateModalOpen(false)}>取消</Button>
              <Button type="primary" htmlType="submit" loading={createMutation.isPending}>提交</Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* Project Detail Drawer */}
      <Drawer
        title={<span style={{ color: 'var(--text-primary)' }}>{drawer.project?.name || '应用详情'}</span>}
        open={drawer.open}
        onClose={handleCloseDrawer}
        width={600}
        styles={{ body: { background: 'var(--bg-elevated)' } }}
        extra={
          <Space>
            <Button type="link" size="small" icon={<EditOutlined />} onClick={() => drawer.project && handleEditProject(drawer.project)}>编辑</Button>
            <Popconfirm title="确定删除此应用?" description="应用将从列表移除，所有密钥会立即撤销；历史审计记录会保留" onConfirm={handleDeleteProject} okText="删除" cancelText="取消" okType="danger">
              <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
            </Popconfirm>
          </Space>
        }
      >
        {drawer.project && (
          <div>
            {/* Basic Info Card */}
            <Card title="基本信息" style={{ marginBottom: 16, background: 'var(--bg-card)', borderColor: 'var(--border-color)' }} styles={{ header: { color: 'var(--text-primary)' } }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div><Text type="secondary">名称：</Text><Text strong style={{ color: 'var(--text-primary)' }}>{drawer.project.name}</Text></div>
                <div><Text type="secondary">代码：</Text><Text style={{ color: 'var(--text-primary)' }}>{drawer.project.code || '-'}</Text></div>
                <div><Text type="secondary">环境：</Text>{drawer.project.environment ? <Tag color={envColor[drawer.project.environment]}>{envLabel[drawer.project.environment]}</Tag> : '-'}</div>
                <div><Text type="secondary">状态：</Text><Tag color={drawer.project.status === 'active' ? 'success' : 'default'}>{drawer.project.status === 'active' ? '启用' : '禁用'}</Tag></div>
                <div><Text type="secondary">ID：</Text><Text style={{ color: 'var(--text-primary)' }}>{drawer.project.id}</Text></div>
              </div>
            </Card>

            {/* Users Card */}
            <Card
              title={<span style={{ color: 'var(--text-primary)' }}>关联用户</span>}
              extra={<Button type="link" size="small" icon={<UserAddOutlined />} onClick={() => setAddUserModalOpen(true)}>添加用户</Button>}
              style={{ marginBottom: 16, background: 'var(--bg-card)', borderColor: 'var(--border-color)' }}
            >
              <Table
                columns={userColumns}
                dataSource={(() => { const r = projectUsersQuery.data?.data; return Array.isArray(r?.items) ? r.items : Array.isArray(r?.data) ? r.data : Array.isArray(r) ? r : [] })()}
                rowKey="user_id"
                loading={projectUsersQuery.isLoading}
                pagination={false}
                size="small"
              />
            </Card>

            {/* Model Config Card */}
            <Card
              title={<span style={{ color: 'var(--text-primary)' }}>模型配置</span>}
              extra={(
                <Space size={4}>
                  <Button
                    type="link"
                    size="small"
                    icon={<ControlOutlined />}
                    href={'/cost/budgets?scope_type=project&scope_id=' + encodeURIComponent(drawer.project.id)}
                  >
                    钱包与限流
                  </Button>
                  <Button type="link" size="small" icon={<SettingOutlined />} onClick={handleSaveModelConfig} loading={updateModelConfigMutation.isPending}>
                    保存模型
                  </Button>
                </Space>
              )}
              style={{ background: 'var(--bg-card)', borderColor: 'var(--border-color)' }}
            >
              <Text strong style={{ color: 'var(--text-primary)', marginBottom: 8, display: 'block' }}>模型白名单</Text>
              <Select
                mode="multiple"
                placeholder="选择允许使用的模型"
                value={whitelist}
                onChange={setWhitelist}
                options={modelOptions}
                style={{ width: '100%' }}
                maxTagCount={5}
              />
              <Divider style={{ margin: '16px 0' }} />
              <Text strong style={{ color: 'var(--text-primary)', marginBottom: 8, display: 'block' }}>所属部门</Text>
              <Select
                value={projectTeamID || undefined}
                onChange={(value) => setProjectTeamID(value || '')}
                options={[
                  { value: '', label: '无（不分配部门）' },
                  ...(() => {
                    const result = teamsQuery.data?.data
                    const teams = Array.isArray(result?.items) ? result.items : Array.isArray(result?.data) ? result.data : Array.isArray(result) ? result : []
                    return teams.map((team: any) => ({ value: team.id, label: team.name }))
                  })(),
                ]}
                allowClear
                placeholder="选择部门"
                style={{ width: '100%' }}
              />
            </Card>
          </div>
        )}

        {/* Add User Modal (nested in Drawer) */}
        <Modal title="添加用户" open={addUserModalOpen} onCancel={() => setAddUserModalOpen(false)} footer={null} width={400}>
          <Form form={addUserForm} onFinish={handleAddUser} layout="vertical" style={{ marginTop: 16 }}>
            <Form.Item name="user_id" label="用户" rules={[{ required: true }]}>
              <Select placeholder="选择用户" options={userOptions} showSearch filterOption={(input, option) => String(option?.label ?? '').toLowerCase().includes(input.toLowerCase())} />
            </Form.Item>
            <Form.Item name="role" label="角色" initialValue="developer">
              <Select options={[{ value: 'owner', label: '负责人' }, { value: 'developer', label: '开发者' }, { value: 'viewer', label: '观察者' }]} />
            </Form.Item>
            <Form.Item style={{ marginBottom: 0 }}>
              <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
                <Button onClick={() => setAddUserModalOpen(false)}>取消</Button>
                <Button type="primary" htmlType="submit" loading={bindUserMutation.isPending}>绑定</Button>
              </Space>
            </Form.Item>
          </Form>
        </Modal>
      </Drawer>

      {/* Edit Project Modal */}
      <Modal title="编辑应用" open={editModalOpen} onCancel={() => setEditModalOpen(false)} footer={null} width={460}>
        <Form form={editForm} onFinish={handleUpdateProject} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input placeholder="请输入应用名称" /></Form.Item>
          <Form.Item name="code" label="代码"><Input placeholder="应用代码标识（选填）" /></Form.Item>
          <Form.Item name="environment" label="环境">
            <Select placeholder="请选择环境" options={[{ value: 'production', label: '生产' }, { value: 'staging', label: '预发布' }, { value: 'development', label: '开发' }]} />
          </Form.Item>
          <Form.Item name="status" label="状态">
            <Select placeholder="请选择状态" options={[{ value: 'active', label: '启用' }, { value: 'disabled', label: '禁用' }]} />
          </Form.Item>
          <Form.Item style={{ marginBottom: 0 }}>
            <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
              <Button onClick={() => setEditModalOpen(false)}>取消</Button>
              <Button type="primary" htmlType="submit" loading={updateMutation.isPending}>保存</Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default Apps

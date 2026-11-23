import { useState, useMemo, useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Tree, Button, Modal, Form, Input, Select, Row, Col, Tabs, message, Popconfirm, Typography, Empty, List, Tag, Tooltip, Space, Switch, Alert } from 'antd'
import { PlusOutlined, DeleteOutlined, BankOutlined, EditOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { orgApi, tenantApi } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { useOrgLabels } from '../stores/orgLabels'
import { extractApiError } from '../utils/apiError'
import { MembersTab } from '../components/team-tabs/MembersTab'
import { AppsTab } from '../components/team-tabs/AppsTab'
import { BudgetModelsTab } from '../components/team-tabs/BudgetModelsTab'
import { UsageTab } from '../components/team-tabs/UsageTab'
import { TenantUsersTab } from '../components/tenant-tabs/TenantUsersTab'
import { TenantProjectsTab } from '../components/tenant-tabs/TenantProjectsTab'
import { TenantKeysTab } from '../components/tenant-tabs/TenantKeysTab'
import { TenantOverviewTab } from '../components/tenant-tabs/TenantOverviewTab'

const { Title, Text } = Typography

interface Tenant { id: string; name: string; edition?: string; status?: string }
interface Team { id: string; name: string; parent_team_id?: string }

function buildTree(teams: Team[]) {
  const map = new Map<string, any>()
  teams.forEach(t => map.set(t.id, { key: t.id, title: t.name, children: [] }))
  const roots: any[] = []
  teams.forEach(t => {
    if (t.parent_team_id && map.has(t.parent_team_id)) map.get(t.parent_team_id).children.push(map.get(t.id))
    else roots.push(map.get(t.id))
  })
  return roots
}

export default function Organizations() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const { tier1, tier2 } = useOrgLabels()
  const [selectedTenantId, setSelectedTenantId] = useState('')
  const [selectedTeamId, setSelectedTeamId] = useState('')
  const [searchParams] = useSearchParams()
  const teamIdParam = searchParams.get('team_id') || ''
  const [newTeamOpen, setNewTeamOpen] = useState(false)
  const [teamForm] = Form.useForm()
  const [editTenantOpen, setEditTenantOpen] = useState(false)
  const [editForm] = Form.useForm()

  const tenantsQ = useQuery({ queryKey: ['tenants'], queryFn: () => tenantApi.list() })
  const tenants = useMemo<Tenant[]>(() => {
    const raw = tenantsQ.data?.data
    return Array.isArray(raw?.data) ? raw.data : Array.isArray(raw) ? raw : []
  }, [tenantsQ.data])
  const selectedTenant = tenants.find(t => t.id === selectedTenantId)
  const isOwnTenant = !!selectedTenantId && selectedTenantId === user?.tenant_id

  const ownTeamsQ = useQuery({ queryKey: ['teams'], enabled: isOwnTenant, queryFn: () => orgApi.listTeams() })
  const otherTeamsQ = useQuery({ queryKey: ['tenant-teams', selectedTenantId], enabled: !!selectedTenantId && !isOwnTenant, queryFn: () => tenantApi.listTeams(selectedTenantId) })
  const teams = useMemo<Team[]>(() => {
    const raw = (isOwnTenant ? ownTeamsQ.data : otherTeamsQ.data)?.data
    return Array.isArray(raw?.data) ? raw.data : Array.isArray(raw) ? raw : []
  }, [isOwnTenant, ownTeamsQ.data, otherTeamsQ.data])
  const treeData = useMemo(() => buildTree(teams), [teams])

  // 从用户列表/详情点部门标签跳过来（/organizations?team_id=…）：自动选中本单位和那个部门；
  // 部门已经不存在就明说，而不是停在“请选择”的空页上。只处理一次，之后用户自己点哪就是哪。
  const appliedTeamParam = useRef('')
  useEffect(() => {
    if (!teamIdParam || appliedTeamParam.current === teamIdParam) return
    const ownTenantId = user?.tenant_id
    if (!ownTenantId || !tenants.some(t => t.id === ownTenantId)) return
    if (selectedTenantId !== ownTenantId) { setSelectedTenantId(ownTenantId); return }
    if (!ownTeamsQ.isSuccess) return
    appliedTeamParam.current = teamIdParam
    if (teams.some(t => t.id === teamIdParam)) setSelectedTeamId(teamIdParam)
    else message.info(`该${tier2}已不存在`)
  }, [teamIdParam, user?.tenant_id, tenants, selectedTenantId, ownTeamsQ.isSuccess, teams, tier2])

  const createTeamM = useMutation({
    mutationFn: (d: { name: string; parent_team_id?: string; create_app?: boolean }) => orgApi.createTeam(d),
    onSuccess: (res: any) => {
      const app = res?.data?.app
      message.success(app ? `${tier2}已创建，专属应用「${app.name}」已就绪` : `${tier2}已创建`)
      qc.invalidateQueries({ queryKey: ['teams'] })
      qc.invalidateQueries({ queryKey: ['projects'] })
      setNewTeamOpen(false); teamForm.resetFields()
    },
    onError: () => message.error('创建失败'),
  })
  const deleteTeamM = useMutation({
    mutationFn: (id: string) => orgApi.deleteTeam(id),
    onSuccess: () => { message.success('已删除'); qc.invalidateQueries({ queryKey: ['teams'] }); setSelectedTeamId('') },
    // 后端 writeErrorWithStatus 输出嵌套结构 {error:{code,message}}，
    // 少读一层会把真实原因吞成笼统的"删除失败"。
    onError: (e: any) => {
      const err = e?.response?.data?.error
      if (err?.code === 'team_not_empty') {
        // 按当前叫法（部门/科室…）改写服务端的中性提示，并写清楚去哪处理。
        const parts = [
          err.details?.members > 0 ? `${err.details.members} 名成员` : '',
          err.details?.child_teams > 0 ? `${err.details.child_teams} 个下级${tier2}` : '',
        ].filter(Boolean)
        if (parts.length > 0) { message.error(`该${tier2}下还有 ${parts.join('、')}，请先移走成员、处理下级${tier2}后再删除`); return }
      }
      message.error(extractApiError(e) || '删除失败')
    },
  })
  const deleteTenantM = useMutation({
    mutationFn: (id: string) => tenantApi.delete(id),
    onSuccess: () => { message.success(`${tier1}已删除`); qc.invalidateQueries({ queryKey: ['tenants'] }); setSelectedTenantId(''); setSelectedTeamId('') },
    onError: (e: any) => message.error(extractApiError(e) || '删除失败'),
  })
  const editTenantM = useMutation({
    mutationFn: (d: { id: string; name: string; edition: string; status: string }) => tenantApi.update(d.id, { name: d.name, edition: d.edition, status: d.status }),
    onSuccess: () => { message.success(`${tier1}已更新`); qc.invalidateQueries({ queryKey: ['tenants'] }); setEditTenantOpen(false) },
    onError: () => message.error('更新失败'),
  })
  const openEditTenant = () => {
    if (!selectedTenant) return
    editForm.setFieldsValue({ name: selectedTenant.name, edition: selectedTenant.edition || 'enterprise', status: selectedTenant.status || 'active' })
    setEditTenantOpen(true)
  }

  const selectedTeam = teams.find(t => t.id === selectedTeamId)

  const deptTab = (
    <div>
      {isOwnTenant && (
        <div style={{ marginBottom: 12, textAlign: 'right' }}>
          <Button size="small" type="primary" icon={<PlusOutlined />} onClick={() => setNewTeamOpen(true)}>新建{tier2}</Button>
        </div>
      )}
      {!isOwnTenant && <Text type="secondary" style={{ fontSize: 12 }}>跨{tier1}仅可查看结构；写操作（新建/管理{tier2}）属下一阶段。</Text>}
      <Row gutter={16} style={{ marginTop: 8 }}>
        <Col span={8}>
          {teams.length === 0 ? <Empty description={`暂无${tier2}`} /> : (
            <Tree treeData={treeData} blockNode defaultExpandAll
              selectedKeys={selectedTeamId ? [selectedTeamId] : []}
              onSelect={(k) => setSelectedTeamId((k[0] as string) || '')} />
          )}
        </Col>
        <Col span={16}>
          {isOwnTenant && selectedTeam ? (
            <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 8, padding: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
                <Title level={5} style={{ margin: 0, color: 'var(--text-primary)' }}>{selectedTeam.name}</Title>
                <Popconfirm title={`删除此${tier2}?`} okText="删除" cancelText="取消" okType="danger" onConfirm={() => deleteTeamM.mutate(selectedTeamId)}>
                  <Button danger size="small" icon={<DeleteOutlined />}>删除</Button>
                </Popconfirm>
              </div>
              <Tabs defaultActiveKey="members" items={[
                { key: 'members', label: '成员', children: <MembersTab teamId={selectedTeamId} /> },
                { key: 'apps', label: '应用', children: <AppsTab teamId={selectedTeamId} /> },
                { key: 'budget', label: '模型权限', children: <BudgetModelsTab teamId={selectedTeamId} /> },
                { key: 'usage', label: '部门用量', children: <UsageTab teamId={selectedTeamId} /> },
              ]} />
            </div>
          ) : <Empty description={isOwnTenant ? `← 选择${tier2}查看详情` : `跨${tier1}结构（只读）`} />}
        </Col>
      </Row>
    </div>
  )

  return (
    <div style={{ padding: 24, background: 'var(--bg-primary)', minHeight: '100vh' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <Title level={4} style={{ margin: 0, color: 'var(--text-primary)' }}>组织管理</Title>
      </div>
      <Row gutter={24}>
        <Col span={6}>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 8, padding: 16, minHeight: 400 }}>
            <div style={{ marginBottom: 12, color: 'var(--text-secondary)', fontSize: 12 }}>
              <BankOutlined style={{ marginRight: 4 }} />{tier1}列表 ({tenants.length})
            </div>
            {tenants.length === 0 ? <Empty description={`暂无${tier1}`} /> : (
              <List size="small" dataSource={tenants} rowKey="id"
                renderItem={(t) => (
                  <List.Item style={{ cursor: 'pointer', background: t.id === selectedTenantId ? 'var(--bg-hover)' : 'transparent', borderRadius: 6, padding: '8px 10px' }}
                    onClick={() => { setSelectedTenantId(t.id); setSelectedTeamId('') }}>
                    <div>
                      <div style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{t.name}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>
                        <Tag>{t.edition || 'enterprise'}</Tag>
                        <Tag color={t.status === 'active' ? 'success' : 'default'}>{t.status === 'active' ? '启用' : t.status}</Tag>
                      </div>
                    </div>
                  </List.Item>
                )} />
            )}
          </div>
        </Col>
        <Col span={18}>
          {selectedTenant ? (
            <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 8, padding: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <Title level={5} style={{ margin: 0, color: 'var(--text-primary)' }}>{selectedTenant.name}{isOwnTenant && <Tag color="blue" style={{ marginLeft: 8 }}>本{tier1}</Tag>}</Title>
                {user?.role === 'platform_admin' && (
                  <Space>
                    <Button size="small" icon={<EditOutlined />} onClick={openEditTenant}>编辑</Button>
                    {isOwnTenant ? (
                      <Tooltip title={`不能删除你自己所在的主${tier1}`}>
                        <Button danger size="small" icon={<DeleteOutlined />} disabled>删除{tier1}</Button>
                      </Tooltip>
                    ) : (
                      <Popconfirm title={`删除${tier1}「${selectedTenant.name}」?`} description={`仅可删除无用户/应用的空${tier1}（否则请先清空）`} okText="删除" cancelText="取消" okType="danger"
                        onConfirm={() => deleteTenantM.mutate(selectedTenant.id)}>
                        <Button danger size="small" icon={<DeleteOutlined />} loading={deleteTenantM.isPending}>删除{tier1}</Button>
                      </Popconfirm>
                    )}
                  </Space>
                )}
              </div>
              <Tabs defaultActiveKey="depts" items={[
                { key: 'depts', label: tier2, children: deptTab },
                { key: 'users', label: '用户', children: <TenantUsersTab tenantId={selectedTenantId} /> },
                { key: 'projects', label: '应用', children: <TenantProjectsTab tenantId={selectedTenantId} /> },
                { key: 'keys', label: '密钥', children: <TenantKeysTab tenantId={selectedTenantId} /> },
                { key: 'overview', label: '概览', children: <TenantOverviewTab tenantId={selectedTenantId} isOwn={isOwnTenant} /> },
              ]} />
            </div>
          ) : (
            <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 8, padding: 60, textAlign: 'center' }}>
              <BankOutlined style={{ fontSize: 48, color: 'var(--text-tertiary)', marginBottom: 16 }} />
              <div style={{ color: 'var(--text-tertiary)' }}>← 选择左侧{tier1}查看详情</div>
            </div>
          )}
        </Col>
      </Row>

      <Modal title={`新建${tier2}`} open={newTeamOpen} onCancel={() => setNewTeamOpen(false)} footer={null} width={420}>
        <Form form={teamForm} layout="vertical" style={{ marginTop: 16 }} onFinish={(v) => createTeamM.mutate(v)}>
          <Form.Item name="name" label={`${tier2}名称`} rules={[{ required: true, message: `请输入${tier2}名称` }]}>
            <Input placeholder="例如：研发-AI 平台" />
          </Form.Item>
          <Form.Item name="parent_team_id" label={`上级${tier2}（可选）`}>
            <Select allowClear placeholder={`留空为一级${tier2}`} options={teams.map(t => ({ value: t.id, label: t.name }))} />
          </Form.Item>
          <Form.Item name="create_app" label="同时创建专属应用" valuePropName="checked" initialValue={true}
            tooltip={`勾选后自动为该${tier2}建一个专属应用（模型白名单/预算/用量/告警都归本${tier2}），部门主管开箱即可见本${tier2}数据；不勾则员工走默认应用、部门主管看不到本${tier2}切片`}>
            <Switch />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(p, c) => p.create_app !== c.create_app}>
            {({ getFieldValue }) => getFieldValue('create_app') ? null : (
              <Alert type="warning" showIcon style={{ marginBottom: 16 }}
                message={`不建专属应用：该${tier2}员工走默认应用，部门主管看不到本${tier2}的用量/告警切片`} />
            )}
          </Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Button onClick={() => setNewTeamOpen(false)} style={{ marginRight: 8 }}>取消</Button>
            <Button type="primary" htmlType="submit" loading={createTeamM.isPending}>创建</Button>
          </Form.Item>
        </Form>
      </Modal>

      <Modal title={`编辑${tier1}`} open={editTenantOpen} onCancel={() => setEditTenantOpen(false)} footer={null} width={420}>
        <Form form={editForm} layout="vertical" style={{ marginTop: 16 }} onFinish={(v) => selectedTenant && editTenantM.mutate({ id: selectedTenant.id, name: v.name, edition: v.edition, status: v.status })}>
          <Form.Item name="name" label={`${tier1}名称`} rules={[{ required: true, message: `请输入${tier1}名称` }]}>
            <Input placeholder="例如：某某市数据局 / 某子公司" />
          </Form.Item>
          <Form.Item name="edition" label="版本">
            <Select options={[{ value: 'enterprise', label: '企业版' }, { value: 'cloud', label: '云版' }]} />
          </Form.Item>
          <Form.Item name="status" label="状态">
            <Select options={[{ value: 'active', label: '启用' }, { value: 'disabled', label: '停用' }]} />
          </Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Button onClick={() => setEditTenantOpen(false)} style={{ marginRight: 8 }}>取消</Button>
            <Button type="primary" htmlType="submit" loading={editTenantM.isPending}>保存</Button>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

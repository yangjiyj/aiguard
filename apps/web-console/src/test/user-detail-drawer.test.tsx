import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { UserDetailDrawer } from '../components/UserDetailDrawer'
import * as api from '../services/api'

function renderDrawer() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <UserDetailDrawer open userId="u1" onClose={() => {}} />
      </QueryClientProvider>
    </MemoryRouter>
  )
}

describe('用户详情抽屉 - 名称解析（M4/m5/m6）', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(api.userApi, 'getDetail').mockResolvedValue({
      data: {
        user: {
          id: 'u1', username: '张三', email: '', phone: '', role: 'developer', status: 'active',
          department_id: 'dept-sensitive', department_name: '安全研发部', external_subject: 'subject-sensitive',
        },
        teams: [{ team_id: 't1', team_name: '研发部', name: '研发部', role: 'member' }],
        projects: ['p1'],
      },
    } as any)
    vi.spyOn(api.userApi, 'listGrants').mockResolvedValue({
      data: { data: [{ id: 'g1', scope_type: 'team', scope_id: 't1', role: 'auditor', granted_by: 'admin1' }] },
    } as any)
    vi.spyOn(api.userApi, 'getLoginHistory').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.operationAuditApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.projectApi, 'list').mockResolvedValue({ data: { items: [{ id: 'p1', name: '风控应用' }] } } as any)
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({ data: { data: [{ id: 't1', name: '研发部' }] } } as any)
    // /roles 无 json tag，返回首字母大写键——组件需兼容
    vi.spyOn(api.roleApi, 'list').mockResolvedValue({ data: { data: [{ Code: 'auditor', Name: 'auditor', Description: '审计员' }] } } as any)
    vi.spyOn(api.userApi, 'list').mockResolvedValue({ data: { data: [{ id: 'admin1', username: '管理员老王' }] } } as any)
  })

  it('基本信息平台角色显示中文 label（m5）', async () => {
    renderDrawer()
    expect(await screen.findByText('张三')).toBeInTheDocument()
    expect(await screen.findByText('开发者')).toBeInTheDocument()
    // 不露原始英文角色
    expect(screen.queryByText('developer')).not.toBeInTheDocument()
  })

  it('基本信息显示权威部门名称，不显示部门ID或外部subject', async () => {
    renderDrawer()
    expect(await screen.findByText('安全研发部')).toBeInTheDocument()
    expect(screen.queryByText('dept-sensitive')).not.toBeInTheDocument()
    expect(screen.queryByText('subject-sensitive')).not.toBeInTheDocument()
  })

  it('角色授权表格：范围显部门中文名、角色显中文、授权人显用户名而非UUID（M4/m6）', async () => {
    renderDrawer()
    // 切到「角色授权」tab
    fireEvent.click(await screen.findByRole('tab', { name: '角色授权' }))
    // 部门名（研发部）而非 team_id
    expect(await screen.findByText('研发部')).toBeInTheDocument()
    expect(screen.queryByText('t1')).not.toBeInTheDocument()
    // 系统角色 auditor -> 审计员（description）
    expect(await screen.findByText('审计员')).toBeInTheDocument()
    expect(screen.queryByText('auditor')).not.toBeInTheDocument()
    // 授权人解析为用户名
    expect(await screen.findByText('管理员老王')).toBeInTheDocument()
    expect(screen.queryByText('admin1')).not.toBeInTheDocument()
  })

  it('应用授权：应用ID解析为应用名（m5）', async () => {
    renderDrawer()
    fireEvent.click(await screen.findByRole('tab', { name: '应用授权' }))
    expect(await screen.findByText('风控应用')).toBeInTheDocument()
    expect(screen.queryByText('p1')).not.toBeInTheDocument()
  })
})

describe('用户详情抽屉 - 操作日志动作/对象中文映射（m8）', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(api.userApi, 'getDetail').mockResolvedValue({
      data: { user: { id: 'u1', username: '张三', role: 'developer', status: 'active' }, teams: [], projects: [] },
    } as any)
    vi.spyOn(api.userApi, 'listGrants').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.userApi, 'getLoginHistory').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.projectApi, 'list').mockResolvedValue({ data: { items: [] } } as any)
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.roleApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.userApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    // 后端 logAudit 实际写入的点号命名动作：状态变更 / 授权 / 撤权 / 部门成员
    vi.spyOn(api.operationAuditApi, 'list').mockResolvedValue({
      data: { data: [
        { id: 'op1', action_type: 'user.status.update', target_type: 'user', created_at: '2026-07-01T10:00:00Z', ip_address: '10.0.0.1' },
        { id: 'op2', action_type: 'permission.grant', target_type: 'permission_grant', created_at: '2026-07-01T10:01:00Z', ip_address: '10.0.0.1' },
        { id: 'op3', action_type: 'permission.revoke', target_type: 'permission_grant', created_at: '2026-07-01T10:02:00Z', ip_address: '10.0.0.1' },
        { id: 'op4', action_type: 'team.member.add', target_type: 'team', created_at: '2026-07-01T10:03:00Z', ip_address: '10.0.0.1' },
      ] },
    } as any)
  })

  it('真实点号动作渲染为具体中文，不落“其他操作”兜底', async () => {
    renderDrawer()
    fireEvent.click(await screen.findByRole('tab', { name: '操作日志' }))
    expect(await screen.findByText('启用/禁用用户')).toBeInTheDocument()
    expect(await screen.findByText('授予角色')).toBeInTheDocument()
    expect(await screen.findByText('撤销授权')).toBeInTheDocument()
    expect(await screen.findByText('添加部门成员')).toBeInTheDocument()
    // 全部命中真实字典，不应出现兜底
    expect(screen.queryByText('其他操作')).not.toBeInTheDocument()
  })

  it('影响对象 permission_grant 渲染为“授权记录”，不落“业务对象”兜底', async () => {
    renderDrawer()
    fireEvent.click(await screen.findByRole('tab', { name: '操作日志' }))
    // grant + revoke 两行的影响对象都是 permission_grant，故用 findAllByText
    expect((await screen.findAllByText('授权记录')).length).toBeGreaterThan(0)
    expect(screen.queryByText('业务对象')).not.toBeInTheDocument()
  })
})

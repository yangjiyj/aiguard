import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import Users from '../pages/Users'
import * as api from '../services/api'

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <Users />
      </QueryClientProvider>
    </MemoryRouter>
  )
}

describe('用户管理列表 - 平台角色列（M2/b）', () => {
  beforeEach(() => vi.restoreAllMocks())

  it('列头为「平台角色」，权威取值渲染中文，历史取值也不露原始英文', async () => {
    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: {
        data: [
          { id: 'u1', username: '张三', role: 'developer', status: 'active' },
          { id: 'u2', username: '李四', role: 'operator', status: 'active' },
        ],
      },
    } as any)

    renderPage()

    // 列头改为「平台角色」（antd 带 scroll/fixed 时表头可能重复渲染，用 findAll 容错）
    expect((await screen.findAllByText('平台角色')).length).toBeGreaterThan(0)
    // 权威取值中文
    expect((await screen.findAllByText('开发者')).length).toBeGreaterThan(0)
    // 历史遗留取值回显中文（含「历史」），且绝不出现原始英文枚举
    expect((await screen.findAllByText(/操作员（历史）/)).length).toBeGreaterThan(0)
    expect(screen.queryAllByText('operator')).toHaveLength(0)
    expect(screen.queryAllByText('developer')).toHaveLength(0)
  })
})

describe('用户管理 - 权威部门归属', () => {
  beforeEach(() => vi.restoreAllMocks())

  it('列表只显示权威部门名称，不显示旧成员聚合、部门ID或外部subject', async () => {
    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: {
        data: [{
          id: 'u1', username: '张三', role: 'developer', status: 'active',
          department_id: 'dept-sensitive', department_name: '安全研发部',
          external_subject: 'subject-sensitive', teams_csv: '旧部门',
        }],
      },
    } as any)

    renderPage()

    expect(await screen.findByText('安全研发部')).toBeInTheDocument()
    expect(screen.queryByText('旧部门')).not.toBeInTheDocument()
    expect(screen.queryByText('dept-sensitive')).not.toBeInTheDocument()
    expect(screen.queryByText('subject-sensitive')).not.toBeInTheDocument()
  })

  it('创建普通用户直接提交必填department_id，不再二次添加部门成员', async () => {
    vi.spyOn(api.userApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({
      data: { data: [{ id: 'dept-1', name: '安全研发部' }] },
    } as any)
    const create = vi.spyOn(api.userApi, 'create').mockResolvedValue({ data: { id: 'u1' } } as any)
    const addMember = vi.spyOn(api.orgApi, 'addMember').mockResolvedValue({} as any)
    renderPage()

    fireEvent.click(await screen.findByText('创建用户'))
    expect(await screen.findByText(/普通用户默认进入 Chat/)).toBeInTheDocument()
    expect(await screen.findByText(/部门尚未授权模型/)).toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: '用户名' }), { target: { value: 'alice' } })
    fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'initial-secret' } })
    fireEvent.mouseDown(await screen.findByRole('combobox', { name: '所属部门' }))
    fireEvent.click(await screen.findByText('安全研发部'))
    fireEvent.click(screen.getByRole('button', { name: /^创\s*建$/ }))

    await waitFor(() => expect(create).toHaveBeenCalledWith(expect.objectContaining({
      username: 'alice', department_id: 'dept-1', role: 'chat_user',
    })))
    expect(create.mock.calls[0][0]).not.toHaveProperty('initial_team_id')
    expect(addMember).not.toHaveBeenCalled()
  })

  it('编辑用户时可选择权威部门', async () => {
    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [{
        id: 'u1', username: '张三', role: 'developer', status: 'active',
        department_id: 'dept-1', department_name: '安全研发部',
      }] },
    } as any)
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({
      data: { data: [{ id: 'dept-1', name: '安全研发部' }] },
    } as any)
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /编\s*辑/ }))

    expect(await screen.findByRole('combobox', { name: '所属部门' })).toBeInTheDocument()
    expect((await screen.findAllByText('安全研发部')).length).toBeGreaterThan(0)
  })
  it('编辑跨租户用户时读取目标租户的部门', async () => {
    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [{
        id: 'u-other', username: '李四', role: 'developer', status: 'active',
        tenant_id: 'tenant-other', department_id: 'dept-other', department_name: '外部研发部',
      }] },
    } as any)
    const ownTeams = vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({ data: { data: [] } } as any)
    const targetTeams = vi.spyOn(api.tenantApi, 'listTeams').mockResolvedValue({
      data: { data: [{ id: 'dept-other', name: '外部研发部' }] },
    } as any)
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /编\s*辑/ }))

    await waitFor(() => expect(targetTeams).toHaveBeenCalledWith('tenant-other'))
    expect(ownTeams).not.toHaveBeenCalled()
    expect(await screen.findByRole('combobox', { name: '所属部门' })).toBeInTheDocument()
  })

  it('平台管理员显示应急访问边界并隐藏部门选择', async () => {
    vi.spyOn(api.userApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({ data: { data: [] } } as any)
    renderPage()

    fireEvent.click(await screen.findByText('创建用户'))
    fireEvent.mouseDown(screen.getByRole('combobox', { name: /平台角色/ }))
    fireEvent.click(await screen.findByText('平台管理员（账号、资源与系统管理）'))

    expect(await screen.findByText('仅控制台应急访问，不可使用 Chat/模型')).toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: '所属部门' })).not.toBeInTheDocument()
  })

  it('promoting a business user clears the department from the update payload', async () => {
    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [{
        id: 'u1', username: 'alice', role: 'developer', status: 'active',
        department_id: 'dept-1', department_name: 'Engineering',
      }] },
    } as any)
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({
      data: { data: [{ id: 'dept-1', name: 'Engineering' }] },
    } as any)
    const update = vi.spyOn(api.userApi, 'update').mockResolvedValue({ data: {} } as any)
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /编\s*辑/ }))
    fireEvent.mouseDown(screen.getByRole('combobox', { name: /平台角色/ }))
    const adminOptions = await screen.findAllByText('平台管理员（账号、资源与系统管理）')
    fireEvent.click(adminOptions[adminOptions.length - 1])
    expect(screen.queryByRole('combobox', { name: '所属部门' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /保\s*存/ }))

    await waitFor(() => expect(update).toHaveBeenCalledWith('u1', expect.objectContaining({
      role: 'platform_admin',
    })))
    expect(update.mock.calls[0][1]).not.toHaveProperty('department_id')
  })

  it('demoting an emergency administrator requires and submits a department', async () => {
    vi.spyOn(api.userApi, 'list').mockResolvedValue({
      data: { data: [{
        id: 'u1', username: 'admin', role: 'platform_admin', status: 'active',
        department_assignment_mode: 'emergency',
      }] },
    } as any)
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({
      data: { data: [{ id: 'dept-1', name: 'Engineering' }] },
    } as any)
    const update = vi.spyOn(api.userApi, 'update').mockResolvedValue({ data: {} } as any)
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /编\s*辑/ }))
    fireEvent.mouseDown(screen.getByRole('combobox', { name: /平台角色/ }))
    fireEvent.click(await screen.findByText('只读（后台业务查看）'))
    fireEvent.mouseDown(await screen.findByRole('combobox', { name: '所属部门' }))
    fireEvent.click(await screen.findByText('Engineering'))
    fireEvent.click(screen.getByRole('button', { name: /保\s*存/ }))

    await waitFor(() => expect(update).toHaveBeenCalledWith('u1', expect.objectContaining({
      role: 'viewer', department_id: 'dept-1',
    })))
  })
})

describe('用户管理 - 筛选与批量操作', () => {
  beforeEach(() => vi.restoreAllMocks())

  const users = [
    { id: 'u1', username: 'alice', email: 'alice@example.com', role: 'developer', status: 'active', department_id: 'dept-1', department_name: '研发部', last_login_at: new Date().toISOString() },
    { id: 'u2', username: 'bob', email: 'bob@example.com', role: 'viewer', status: 'disabled', department_id: 'dept-2', department_name: '安全部' },
  ]

  it('支持按用户名、邮箱或手机号关键字筛选', async () => {
    vi.spyOn(api.userApi, 'list').mockResolvedValue({ data: { data: users } } as any)
    renderPage()

    expect(await screen.findByText('alice')).toBeInTheDocument()
    fireEvent.change(screen.getByPlaceholderText('搜索用户名 / 邮箱 / 手机'), { target: { value: 'bob@example.com' } })
    expect(screen.queryByText('alice')).not.toBeInTheDocument()
    expect(screen.getByText('bob')).toBeInTheDocument()
    expect(screen.getByText('共 1 个用户')).toBeInTheDocument()
  })

  it('选择用户后可批量转换部门', async () => {
    vi.spyOn(api.userApi, 'list').mockResolvedValue({ data: { data: users } } as any)
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({ data: { data: [{ id: 'dept-3', name: '交付部' }] } } as any)
    const update = vi.spyOn(api.userApi, 'update').mockResolvedValue({ data: {} } as any)
    renderPage()

    await screen.findByText('alice')
    fireEvent.click(screen.getAllByRole('checkbox')[1])
    expect(screen.getByText('已选择 1 个用户')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /转换部门/ }))
    const dialog = await screen.findByRole('dialog', { name: '批量转换部门' })
    fireEvent.mouseDown(dialog.querySelector('.ant-select-selector') as HTMLElement)
    fireEvent.click(await screen.findByText('交付部'))
    fireEvent.click(screen.getByRole('button', { name: /确认转换/ }))

    await waitFor(() => expect(update).toHaveBeenCalledWith('u1', { department_id: 'dept-3' }))
  })

  it('批量禁用会调用用户生命周期接口', async () => {
    vi.spyOn(api.userApi, 'list').mockResolvedValue({ data: { data: users } } as any)
    const toggle = vi.spyOn(api.userApi, 'toggleStatus').mockResolvedValue({ data: {} } as any)
    renderPage()

    await screen.findByText('alice')
    fireEvent.click(screen.getAllByRole('checkbox')[1])
    fireEvent.click(screen.getByRole('button', { name: /批量禁用/ }))
    const confirm = document.querySelector('.ant-popconfirm-buttons .ant-btn-primary') as HTMLButtonElement
    expect(confirm).toBeTruthy()
    fireEvent.click(confirm)

    await waitFor(() => expect(toggle).toHaveBeenCalledWith('u1', 'disabled'))
  })
})

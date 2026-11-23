import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { message } from 'antd'
import Organizations from '../pages/Organizations'
import * as api from '../services/api'

vi.mock('antd', async () => { const a = await vi.importActual('antd'); return { ...a, message: { success: vi.fn(), error: vi.fn(), info: vi.fn() } } })
vi.mock('../stores/auth', () => ({ useAuthStore: () => ({ user: { tenant_id: 'tenant_default', role: 'platform_admin' } }) }))
vi.mock('../stores/orgLabels', () => ({ useOrgLabels: () => ({ tier1: '单位', tier2: '部门' }) }))

const ok = (b: any) => ({ data: b, status: 200, statusText: 'OK', headers: {}, config: {} } as any)

describe('组织管理 单位/部门 master-detail', () => {
  let qc: QueryClient
  beforeEach(() => { qc = new QueryClient({ defaultOptions: { queries: { retry: false } } }); vi.clearAllMocks() })
  const renderPage = (url = '/organizations') => render(<QueryClientProvider client={qc}><MemoryRouter initialEntries={[url]}><Organizations /></MemoryRouter></QueryClientProvider>)

  it('names department tabs by model permissions and usage while retaining the scoped quota link', async () => {
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue(ok({ data: [{ id: 'tenant_default', name: 'Tenant fixture', status: 'active' }] }))
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue(ok({ data: [{ id: 'team/scoped', name: 'Department fixture' }] }))
    vi.spyOn(api.orgApi, 'listMembers').mockResolvedValue(ok({ data: [] }))
    vi.spyOn(api.userApi, 'list').mockResolvedValue(ok({ data: [] }))
    vi.spyOn(api.orgApi, 'getEffective').mockResolvedValue(ok({ models: [], projects: [], members: [] }))
    vi.spyOn(api.modelApi, 'list').mockResolvedValue(ok({ data: [] }))
    vi.spyOn(api.policyApi, 'getQuota').mockResolvedValue(ok({}))
    const getUsage = vi.spyOn(api.orgApi, 'getUsage').mockResolvedValue(ok({}))
    renderPage()
    await userEvent.click(await screen.findByText('Tenant fixture'))
    await userEvent.click(await screen.findByText('Department fixture'))
    expect(await screen.findByRole('tab', { name: '\u6a21\u578b\u6743\u9650' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '\u90e8\u95e8\u7528\u91cf' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: '\u6a21\u578b\u6743\u9650' }))
    expect(await screen.findByRole('link', { name: /去配置$/ })).toHaveAttribute('href', '/cost/budgets?scope_type=team&scope_id=team%2Fscoped')
    await userEvent.click(screen.getByRole('tab', { name: '\u90e8\u95e8\u7528\u91cf' }))
    await waitFor(() => expect(getUsage).toHaveBeenCalledWith('team/scoped', '30d'))
  })

  it('渲染单位列表且禁止新增单位', async () => {
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue(ok({ data: [{ id: 'tenant_default', name: '示例科技', edition: 'enterprise', status: 'active' }] }))
    renderPage()
    expect(await screen.findByText('示例科技')).toBeInTheDocument()
    expect(screen.queryByText('新建单位')).not.toBeInTheDocument()
  })

  it('点单位 → 出现 用户/应用 Tab', async () => {
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue(ok({ data: [{ id: 'tenant_default', name: '示例科技', status: 'active' }] }))
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue(ok({ data: [] }))
    renderPage()
    await userEvent.click(await screen.findByText('示例科技'))
    expect(await screen.findByRole('tab', { name: '用户' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '应用' })).toBeInTheDocument()
  })

  it('单位用户 Tab 支持删除用户', async () => {
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue(ok({ data: [{ id: 'tenant_child', name: '子单位', status: 'active' }] }))
    vi.spyOn(api.tenantApi, 'listTeams').mockResolvedValue(ok({ data: [] }))
    vi.spyOn(api.tenantApi, 'listUsers').mockResolvedValue(ok({ data: [{ id: 'user_child', username: 'alice', role: 'developer', status: 'active' }] }))
    vi.spyOn(api.tenantApi, 'listProjects').mockResolvedValue(ok({ data: [] }))
    vi.spyOn(api.tenantApi, 'listKeys').mockResolvedValue(ok({ data: [] }))
    const deleteUser = vi.spyOn(api.userApi, 'delete').mockResolvedValue(ok({}))
    renderPage()

    await userEvent.click(await screen.findByText('子单位'))
    await userEvent.click(await screen.findByRole('tab', { name: '用户' }))
    expect(await screen.findByText('alice')).toBeInTheDocument()
    const row = screen.getByRole('row', { name: /alice/ })
    await userEvent.click(within(row).getByRole('button', { name: /删\s*除/ }))
    const confirm = await screen.findByRole('tooltip')
    await userEvent.click(within(confirm).getByRole('button', { name: /删\s*除/ }))
    await waitFor(() => expect(deleteUser).toHaveBeenCalledWith('user_child'))
  })

  it('单位用户删除被资源占用时展示具体资源和跳转入口', async () => {
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue(ok({ data: [{ id: 'tenant_child', name: '子单位', status: 'active' }] }))
    vi.spyOn(api.tenantApi, 'listTeams').mockResolvedValue(ok({ data: [] }))
    vi.spyOn(api.tenantApi, 'listUsers').mockResolvedValue(ok({ data: [{ id: 'user_child', username: 'alice', role: 'developer', status: 'active' }] }))
    vi.spyOn(api.tenantApi, 'listProjects').mockResolvedValue(ok({ data: [] }))
    vi.spyOn(api.tenantApi, 'listKeys').mockResolvedValue(ok({ data: [] }))
    vi.spyOn(api.userApi, 'delete').mockRejectedValue({
      response: {
        data: {
          error: {
            code: 'user_has_references',
            message: '无法删除用户：该用户仍有资源占用。',
            details: {
              blockers: [
                {
                  kind: 'project_owner',
                  label: '应用负责人',
                  count: 1,
                  entry: '应用管理',
                  action: '先移交负责人给其他用户，或删除该应用',
                  route: '/apps?project_id=project_delete_user_ref',
                  items: [{ id: 'project_delete_user_ref', name: 'referenced project', route: '/apps?project_id=project_delete_user_ref' }],
                },
              ],
            },
          },
        },
      },
    })
    renderPage()

    await userEvent.click(await screen.findByText('子单位'))
    await userEvent.click(await screen.findByRole('tab', { name: '用户' }))
    const row = await screen.findByRole('row', { name: /alice/ })
    await userEvent.click(within(row).getByRole('button', { name: /删\s*除/ }))
    const confirm = await screen.findByRole('tooltip')
    await userEvent.click(within(confirm).getByRole('button', { name: /删\s*除/ }))

    expect(await screen.findByText('referenced project')).toBeInTheDocument()
    const link = await screen.findByRole('link', { name: /去处理/ })
    expect(link).toHaveAttribute('href', '/apps?project_id=project_delete_user_ref')
    const card = screen.getByTestId('user-delete-blocker-project_owner')
    expect(card).not.toHaveStyle({ background: 'var(--bg-card)' })

    await userEvent.click(link)
    await waitFor(() => expect(screen.queryByText('用户无法删除')).not.toBeInTheDocument())
  })

  it('平台管理员可在单位应用 Tab 软删除跨单位应用', async () => {
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue(ok({ data: [{ id: 'tenant_child', name: '子单位', status: 'active' }] }))
    vi.spyOn(api.tenantApi, 'listTeams').mockResolvedValue(ok({ data: [] }))
    vi.spyOn(api.tenantApi, 'listProjects').mockResolvedValue(ok({ data: [{ id: 'project_child', name: '子单位应用', status: 'active' }] }))
    const deleteProject = vi.spyOn(api.tenantApi, 'deleteProject').mockResolvedValue(ok({}))
    renderPage()

    await userEvent.click(await screen.findByText('子单位'))
    await userEvent.click(await screen.findByRole('tab', { name: '应用' }))
    const row = await screen.findByRole('row', { name: /子单位应用/ })
    await userEvent.click(within(row).getByRole('button', { name: /删\s*除/ }))
    const confirm = await screen.findByRole('tooltip')
    await userEvent.click(within(confirm).getByRole('button', { name: /删\s*除/ }))

    await waitFor(() => expect(deleteProject).toHaveBeenCalledWith('tenant_child', 'project_child'))
  })

  it('平台管理员可确认删除非本单位', async () => {
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue(ok({ data: [{ id: 'tenant_child', name: '子单位', status: 'active' }] }))
    vi.spyOn(api.tenantApi, 'listTeams').mockResolvedValue(ok({ data: [] }))
    const deleteTenant = vi.spyOn(api.tenantApi, 'delete').mockResolvedValue(ok({}))
    renderPage()

    await userEvent.click(await screen.findByText('子单位'))
    await userEvent.click(await screen.findByRole('button', { name: /删除单位/ }))
    const confirm = await screen.findByRole('tooltip')
    await userEvent.click(within(confirm).getByRole('button', { name: /删\s*除/ }))

    await waitFor(() => expect(deleteTenant).toHaveBeenCalledWith('tenant_child'))
  })

  it('跨单位概览并行展示资源规模且不查询用量', async () => {
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue(ok({ data: [{ id: 'tenant_child', name: '子单位', status: 'active' }] }))
    const listTeams = vi.spyOn(api.tenantApi, 'listTeams').mockResolvedValue(ok({ data: [{ id: 'team_1' }, { id: 'team_2' }] }))
    const listUsers = vi.spyOn(api.tenantApi, 'listUsers').mockResolvedValue(ok({ data: [{ id: 'user_1' }, { id: 'user_2' }, { id: 'user_3' }] }))
    const listProjects = vi.spyOn(api.tenantApi, 'listProjects').mockResolvedValue(ok({ data: [{ id: 'project_1' }] }))
    const listKeys = vi.spyOn(api.tenantApi, 'listKeys').mockResolvedValue(ok({ data: [{ id: 'key_1' }, { id: 'key_2' }, { id: 'key_3' }, { id: 'key_4' }] }))
    const usageTrend = vi.spyOn(api.usageApi, 'trend')
    const budgetSnapshot = vi.spyOn(api.budgetApi, 'snapshot')
    renderPage()

    await userEvent.click(await screen.findByText('子单位'))
    await userEvent.click(await screen.findByRole('tab', { name: '概览' }))

    expect(await screen.findByText('跨单位仅展示资源规模，不展示用量/费用')).toBeInTheDocument()
    await waitFor(() => {
      expect(listTeams).toHaveBeenCalledWith('tenant_child')
      expect(listUsers).toHaveBeenCalledWith('tenant_child')
      expect(listProjects).toHaveBeenCalledWith('tenant_child')
      expect(listKeys).toHaveBeenCalledWith('tenant_child')
    })
    expect(screen.getByText('部门数').parentElement).toHaveTextContent('2')
    expect(screen.getByText('用户数').parentElement).toHaveTextContent('3')
    expect(screen.getByText('应用数').parentElement).toHaveTextContent('1')
    expect(screen.getByText('密钥数').parentElement).toHaveTextContent('4')
    expect(usageTrend).not.toHaveBeenCalled()
    expect(budgetSnapshot).not.toHaveBeenCalled()
  })

  // 用户列表/详情里点部门标签会跳到 /organizations?team_id=…，以前页面不认这个参数，停在“请选择”的空页上。
  const mockOwnTenantWithTeams = (teams: any[]) => {
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue(ok({ data: [{ id: 'tenant_default', name: '本单位', status: 'active' }] }))
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue(ok({ data: teams }))
    vi.spyOn(api.orgApi, 'listMembers').mockResolvedValue(ok({ data: [] }))
    vi.spyOn(api.userApi, 'list').mockResolvedValue(ok({ data: [] }))
  }

  it('带 team_id 进入时自动选中本单位和该部门', async () => {
    mockOwnTenantWithTeams([{ id: 'team_a', name: '研发部' }, { id: 'team_b', name: '市场部' }])
    renderPage('/organizations?team_id=team_b')
    expect(await screen.findByRole('tab', { name: '部门用量' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '市场部' })).toBeInTheDocument()
    expect(message.info).not.toHaveBeenCalled()
  })

  it('team_id 指向已不存在的部门时明说，而不是停在空白选择页', async () => {
    mockOwnTenantWithTeams([{ id: 'team_a', name: '研发部' }])
    renderPage('/organizations?team_id=team_gone')
    await waitFor(() => expect(message.info).toHaveBeenCalledWith('该部门已不存在'))
    expect(screen.queryByRole('tab', { name: '部门用量' })).not.toBeInTheDocument()
  })

  it('删除有成员/下级的部门：按当前叫法提示数量，不再显示笼统失败', async () => {
    mockOwnTenantWithTeams([{ id: 'team_a', name: '研发部' }])
    vi.spyOn(api.orgApi, 'deleteTeam').mockRejectedValue({
      response: { status: 409, data: { error: { code: 'team_not_empty', message: '还有 2 名成员、1 个下级，请先移走成员、处理下级后再删除', details: { members: 2, child_teams: 1 } } } },
    })
    renderPage('/organizations?team_id=team_a')
    await screen.findByRole('tab', { name: '部门用量' })
    const detail = screen.getByRole('heading', { name: '研发部' }).parentElement as HTMLElement
    await userEvent.click(within(detail).getByRole('button', { name: /删\s*除/ }))
    const confirm = await screen.findByRole('tooltip')
    await userEvent.click(within(confirm).getByRole('button', { name: /删\s*除/ }))
    await waitFor(() => expect(message.error).toHaveBeenCalledWith('该部门下还有 2 名成员、1 个下级部门，请先移走成员、处理下级部门后再删除'))
  })

  it('删除单位被后端拒绝且原因只有英文时，不直出英文，给中文默认提示', async () => {
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue(ok({ data: [{ id: 'tenant_child', name: '子单位', status: 'active' }] }))
    vi.spyOn(api.tenantApi, 'listTeams').mockResolvedValue(ok({ data: [] }))
    vi.spyOn(api.tenantApi, 'delete').mockRejectedValue({ response: { status: 403, data: { error: { code: 'forbidden', message: 'cannot delete your own unit' } } } })
    renderPage()

    await userEvent.click(await screen.findByText('子单位'))
    await userEvent.click(await screen.findByRole('button', { name: /删除单位/ }))
    const confirm = await screen.findByRole('tooltip')
    await userEvent.click(within(confirm).getByRole('button', { name: /删\s*除/ }))

    await waitFor(() => expect(message.error).toHaveBeenCalledWith('删除失败'))
  })

  it('单位为空不白屏', async () => {
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue(ok({ data: null }))
    renderPage()
    await waitFor(() => expect(screen.getByText('组织管理')).toBeInTheDocument())
  })

  it('新建部门不再暴露 SSO 映射配置，创建请求也不携带 sso_department', async () => {
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue(ok({ data: [{ id: 'tenant_default', name: '示例科技', status: 'active' }] }))
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue(ok({ data: [] }))
    const createTeam = vi.spyOn(api.orgApi, 'createTeam').mockResolvedValue(ok({ app: { name: '研发专属应用' } }))
    renderPage()

    await userEvent.click(await screen.findByText('示例科技'))
    await userEvent.click(await screen.findByRole('button', { name: /新建部门/ }))

    expect(screen.queryByText(/员工 SSO 部门值/)).not.toBeInTheDocument()
    expect(screen.queryByText(/分组映射/)).not.toBeInTheDocument()

    await userEvent.type(screen.getByLabelText('部门名称'), '研发部')
    await userEvent.click(screen.getByRole('button', { name: /创\s*建/ }))

    await waitFor(() => expect(createTeam).toHaveBeenCalledTimes(1))
    expect(Object.prototype.hasOwnProperty.call(createTeam.mock.calls[0][0], 'sso_department')).toBe(false)
  })

  it('新建部门不创建专属应用时仍提示默认应用与可见性影响', async () => {
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue(ok({ data: [{ id: 'tenant_default', name: '示例科技', status: 'active' }] }))
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue(ok({ data: [] }))
    renderPage()

    await userEvent.click(await screen.findByText('示例科技'))
    await userEvent.click(await screen.findByRole('button', { name: /新建部门/ }))
    await userEvent.click(screen.getByRole('switch', { name: /同时创建专属应用/ }))

    expect(await screen.findByText('不建专属应用：该部门员工走默认应用，部门主管看不到本部门的用量/告警切片')).toBeInTheDocument()
  })
})

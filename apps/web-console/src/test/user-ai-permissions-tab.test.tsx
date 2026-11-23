import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { UserAiPermissionsTab } from '../components/ai-permissions/UserAiPermissionsTab'
import { UserDetailDrawer } from '../components/UserDetailDrawer'
import { useAuthStore } from '../stores/auth'
import * as api from '../services/api'
import { userModelAccessApi } from '../services/userModelAccess'

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <UserAiPermissionsTab userId="u1" />
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

// 顶层 beforeEach：聚合四源的 mock（对全文件所有用例生效）
beforeEach(() => {
  vi.restoreAllMocks()
  vi.spyOn(userModelAccessApi, 'get').mockResolvedValue({ data: { data: {user_id:'u1',department_id:'t1',department_name:'研发部',department_models:['gpt-4o'],effective_models:['gpt-4o'],mode:'inherit',model_names:[],version:0,department_version:1,chat_allowed:true} } } as any)
  vi.spyOn(api.userApi, 'getDetail').mockResolvedValue({
    data: { user: { id: 'u1', username: '张三', role: 'developer' }, teams: [{ team_id: 't1', name: '研发部' }], projects: ['p1'] },
  } as any)
  vi.spyOn(api.orgApi, 'getEffective').mockResolvedValue({
    data: { team: { monthly_budget_cny: 500 }, models: [{ model_id: 'gpt-4o', allowed: true }, { model_id: 'sonnet', allowed: false }] },
  } as any)
  vi.spyOn(api.modelApi, 'list').mockResolvedValue({ data: { data: [{ id: 'gpt-4o', model_name: 'gpt-4o', model_label: 'GPT-4o' }] } } as any)
  vi.spyOn(api.policyApi, 'getQuota').mockResolvedValue({ data: { rpm_limit: 60, tpm_limit: 12000, monthly_budget_limit: 300 } } as any)
  vi.spyOn(api.mcpPolicyApi, 'list').mockResolvedValue({
    data: { data: [{ id: 'mp1', scope_type: 'user', scope_ref: 'u1', tool_pattern: 'file.*', default_action: 'audit', enabled: true }] },
  } as any)
  vi.spyOn(api.agentGuardApi, 'listPolicies').mockResolvedValue({ data: { data: [{ id: 'ag1', name: '默认护栏' }] } } as any)
})

describe('UserAiPermissionsTab 有效权限只读视图', () => {
  it('聚合展示 模型/速率/MCP/AgentGuard 四段', async () => {
    renderTab()
    expect(await screen.findByText('GPT-4o')).toBeInTheDocument()
    expect(await screen.findByText(/RPM/)).toBeInTheDocument()
    expect(await screen.findByText(/TPM/)).toBeInTheDocument()
    expect(screen.getByText('12000')).toBeInTheDocument()
    expect(await screen.findByText('file.*')).toBeInTheDocument()
    expect(await screen.findByText(/工具风险/)).toBeInTheDocument()
    expect(await screen.findByText(/以运行时最严格解析为准/)).toBeInTheDocument()
    expect((await screen.findByText('去配置')).closest('a')).toHaveAttribute(
      'href',
      '/cost/budgets?scope_type=user&scope_id=u1',
    )
  })

  it('调用了正确的 admin 端点（不触碰内部/门户 effective 端点）', async () => {
    renderTab()
    await screen.findByText('GPT-4o')
    expect(userModelAccessApi.get).toHaveBeenCalledWith('u1')
    expect(api.policyApi.getQuota).toHaveBeenCalledWith(expect.objectContaining({ scope_type: 'user', scope_id: 'u1' }))
    expect(api.mcpPolicyApi.list).toHaveBeenCalled()
    expect(api.agentGuardApi.listPolicies).toHaveBeenCalled()
  })

  it('MCP 段纳入 scope_ref 为空的档位通配策略，排除他人专属策略', async () => {
    vi.spyOn(api.mcpPolicyApi, 'list').mockResolvedValue({ data: { data: [
      { id: 'w1', scope_type: 'user', scope_ref: '', tool_pattern: 'net.*', default_action: 'audit', enabled: true },     // 用户档通配 → 该员工也命中
      { id: 'o1', scope_type: 'user', scope_ref: 'someone-else', tool_pattern: 'secret.*', default_action: 'block', enabled: true }, // 他人专属 → 不该显示
    ] } } as any)
    renderTab()
    expect(await screen.findByText('net.*')).toBeInTheDocument()
    expect(screen.queryByText('secret.*')).not.toBeInTheDocument()
  })

  it('MCP 段纳入 key 档通配（对全部密钥生效），但不列举具体密钥级策略', async () => {
    vi.spyOn(api.mcpPolicyApi, 'list').mockResolvedValue({ data: { data: [
      { id: 'kw', scope_type: 'key', scope_ref: '', tool_pattern: 'shell.*', default_action: 'block', enabled: true },
      { id: 'ks', scope_type: 'key', scope_ref: 'sk-specific', tool_pattern: 'db.*', default_action: 'block', enabled: true },
    ] } } as any)
    renderTab()
    expect(await screen.findByText('shell.*')).toBeInTheDocument()
    expect(screen.queryByText('db.*')).not.toBeInTheDocument()
  })
})

describe('UserDetailDrawer 集成「AI 权限」Tab', () => {
  // 注意：本 describe 的 beforeEach 不要再调 vi.restoreAllMocks()，否则会清掉顶层的聚合 mock。
  beforeEach(() => {
    useAuthStore.setState({ user: { id: 'admin', username: 'admin', role: 'platform_admin' } as any, isAuthenticated: true, token: 't' } as any)
    vi.spyOn(api.userApi, 'listGrants').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.userApi, 'getLoginHistory').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.operationAuditApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.projectApi, 'list').mockResolvedValue({ data: { items: [] } } as any)
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.roleApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
    vi.spyOn(api.userApi, 'list').mockResolvedValue({ data: { data: [] } } as any)
  })
  afterEach(() => {
    useAuthStore.setState({ user: null, isAuthenticated: false, token: null } as any)
  })

  it('admin 打开抽屉并 initialTab=ai-perms 直达有效权限视图', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <MemoryRouter>
        <QueryClientProvider client={qc}>
          <UserDetailDrawer open userId="u1" onClose={() => {}} initialTab="ai-perms" />
        </QueryClientProvider>
      </MemoryRouter>,
    )
    expect(await screen.findByRole('tab', { name: 'AI 权限' })).toBeInTheDocument()
    expect(await screen.findByText(/有效权限与策略说明/)).toBeInTheDocument()
  })
})

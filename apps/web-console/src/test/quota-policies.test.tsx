import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import QuotaPolicies from '../pages/QuotaPolicies'
import * as api from '../services/api'
import { useAuthStore } from '../stores/auth'

// 任务 1.6（P1-7）：team/user/key 维度配额后端已有、前端缺失。
// 本测试即规格：独立「配额策略」页必须暴露这些维度，并按 scope_type/scope_id 读写。
describe('QuotaPolicies multi-dimension quota editor', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    useAuthStore.setState({
      token: 'test-token',
      user: { id: 'admin', username: 'admin', role: 'platform_admin', tenant_id: 'tenant_default' },
      isAuthenticated: true,
    })
    vi.clearAllMocks()
    vi.spyOn(api.orgApi, 'listTeams').mockResolvedValue({ data: { data: [{ id: 'team_001', name: '研发团队' }] } } as any)
    vi.spyOn(api.contentAuditApi, 'listUsers').mockResolvedValue({
      data: { data: [{ id: 'user_001', username: 'alice', department_name: '研发团队' }], has_more: false },
    } as any)
    vi.spyOn(api.keyApi, 'list').mockResolvedValue({ data: { data: [{ id: 'key_001', name: 'k1', key_prefix: 'sk-abc' }] } } as any)
    vi.spyOn(api.projectApi, 'list').mockResolvedValue({ data: { data: [{ id: 'proj_001', name: '客服助手' }] } } as any)
    vi.spyOn(api.policyApi, 'getQuota').mockResolvedValue({ data: { scope_type: 'team', scope_id: 'team_001', daily_token_limit: 1000, monthly_token_limit: 30000, monthly_budget_limit: 200, rpm_limit: 60, tpm_limit: 12000, concurrency_limit: 5, overage_action: 'rate_limit', enforcement_mode: 'soft' } } as any)
    vi.spyOn(api.policyApi, 'setQuota').mockResolvedValue({ data: {} } as any)
  })

  const renderPage = () => render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <QuotaPolicies />
      </QueryClientProvider>
    </MemoryRouter>,
  )

  it('exposes team/user/key quota dimensions on a standalone page', async () => {
    renderPage()
    expect(await screen.findByText('配额策略')).toBeInTheDocument()
    // 新维度选择器：部门/用户/密钥 必须可见（后端已有、前端原本缺失的维度；
    // 术语已对齐组织菜单：团队→部门、Key→密钥）
    expect(screen.getByText('部门')).toBeInTheDocument()
    expect(screen.getByText('用户')).toBeInTheDocument()
    expect(screen.getByText('密钥')).toBeInTheDocument()
  })

  it('lets a tenant admin choose tenant-scoped objects without calling the platform user API', async () => {
    useAuthStore.setState({
      token: 'test-token',
      user: { id: 'tenant-admin', username: 'tenant-admin', role: 'tenant_admin', tenant_id: 'tenant_default' },
      isAuthenticated: true,
    })
    const platformUsers = vi.spyOn(api.userApi, 'list')

    renderPage()
    fireEvent.click(await screen.findByText('用户'))
    const selector = await screen.findByRole('combobox')
    fireEvent.change(selector, { target: { value: 'ali' } })

    await waitFor(() => expect(api.contentAuditApi.listUsers).toHaveBeenCalledWith(expect.objectContaining({
      q: 'ali',
      limit: 100,
      signal: expect.any(AbortSignal),
    })))
    expect(platformUsers).not.toHaveBeenCalled()
    expect(await screen.findByText('alice · 研发团队')).toBeInTheDocument()
  })

  it('loads and saves a team-scoped quota via scope_type/scope_id', async () => {
    renderPage()
    await screen.findByText('配额策略')

    // 默认维度=团队，此时只有 scope 对象选择器一个 combobox
    fireEvent.mouseDown(screen.getByRole('combobox'))
    fireEvent.click(await screen.findByText('研发团队'))

    // 选定后按 scope 拉取该团队配额
    await waitFor(() => expect(api.policyApi.getQuota).toHaveBeenCalledWith(
      expect.objectContaining({ scope_type: 'team', scope_id: 'team_001' }),
    ))

    // 已有值载入表单
    await waitFor(() => expect(screen.getByLabelText('月费用预算（元）')).toHaveValue('200.00'))
    expect(screen.getByLabelText('每分钟 Token（TPM）数值')).toHaveValue('12000')

    // 编辑并保存
    const budgetInput = screen.getByLabelText('月费用预算（元）')
    fireEvent.change(budgetInput, { target: { value: '500' } })
    fireEvent.blur(budgetInput)
    fireEvent.click(await screen.findByRole('button', { name: /保存/ }))

    await waitFor(() => expect(api.policyApi.setQuota).toHaveBeenCalledWith(expect.objectContaining({
      scope_type: 'team',
      scope_id: 'team_001',
      monthly_budget_micros: 500_000_000,
      tpm_limit: 12000,
      overage_action: 'rate_limit',
      quota_timezone: 'Asia/Shanghai',
    })))
  }, 20000)

  it('从入口页深链带 scope_type/scope_id 时预选并按该 scope 拉取', async () => {
    render(
      <MemoryRouter initialEntries={['/cost/quota-policies?scope_type=user&scope_id=user_001']}>
        <QueryClientProvider client={queryClient}>
          <QuotaPolicies />
        </QueryClientProvider>
      </MemoryRouter>,
    )
    await screen.findByText('配额策略')
    await waitFor(() => expect(api.policyApi.getQuota).toHaveBeenCalledWith(
      expect.objectContaining({ scope_type: 'user', scope_id: 'user_001' })))
  }, 20000)

  it('uses stable key id as payload and shows name with masked prefix', async () => {
    renderPage()
    fireEvent.click(screen.getByText('密钥'))
    const selector = await screen.findByRole('combobox')
    fireEvent.mouseDown(selector)
    fireEvent.click(await screen.findByText('k1 · sk-abc…'))
    await waitFor(() => expect(api.policyApi.getQuota).toHaveBeenCalledWith(
      expect.objectContaining({ scope_type: 'key', scope_id: 'key_001' }),
    ))
    fireEvent.click(await screen.findByRole('button', { name: /保存/ }))
    await waitFor(() => expect(api.policyApi.setQuota).toHaveBeenCalledWith(
      expect.objectContaining({ scope_type: 'key', scope_id: 'key_001' }),
    ))
  })

  it('round-trips inherit, unlimited, blocked, and timezone states', async () => {
    vi.mocked(api.policyApi.getQuota).mockResolvedValueOnce({
      data: {
        scope_type: 'team',
        scope_id: 'team_001',
        daily_token_limit: null,
        daily_token_blocked: false,
        monthly_token_limit: null,
        monthly_token_blocked: true,
        daily_budget_micros: 0,
        daily_budget_blocked: false,
        monthly_budget_micros: null,
        monthly_budget_blocked: true,
        rpm_limit: 0,
        rpm_blocked: false,
        tpm_limit: null,
        tpm_blocked: false,
        concurrency_limit: null,
        concurrency_blocked: true,
        overage_action: 'notify',
        enforcement_mode: 'enforce',
        quota_timezone: 'UTC',
      },
    } as any)
    render(
      <MemoryRouter initialEntries={['/cost/quota-policies?scope_type=team&scope_id=team_001']}>
        <QueryClientProvider client={queryClient}>
          <QuotaPolicies />
        </QueryClientProvider>
      </MemoryRouter>,
    )

    fireEvent.click(await screen.findByRole('button', { name: /保存/ }))
    await waitFor(() => expect(api.policyApi.setQuota).toHaveBeenCalledWith(expect.objectContaining({
      daily_token_limit: null,
      daily_token_blocked: false,
      monthly_token_limit: null,
      monthly_token_blocked: true,
      daily_budget_micros: 0,
      daily_budget_blocked: false,
      monthly_budget_micros: null,
      monthly_budget_blocked: true,
      rpm_limit: 0,
      rpm_blocked: false,
      tpm_limit: null,
      tpm_blocked: false,
      concurrency_limit: null,
      concurrency_blocked: true,
      quota_timezone: 'UTC',
    })))
  })
})

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TenantOverviewTab } from '../components/tenant-tabs/TenantOverviewTab'
import { useCurrencyStore } from '../stores/currency'
import * as api from '../services/api'

// 回归保护：TenantOverviewTab 必须读取后端实际返回的字段名
// (month_cost/month_tokens/day_tokens + effective_quota.*_limit)，
// 不能再用早期 POC 阶段虚构的 budget_used/monthly_used/daily_used。
// 字段名 mismatch 时 UI 会全显示 0，客户看不到自己单位的真实消耗。
describe('TenantOverviewTab', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    vi.clearAllMocks()
    // 后端 snapshot 的 cost 字段是 USD 原值；currency store 默认 CNY(×7.24) 会把
    // ¥3.25 / ¥5000 换算成别的数字，导致金额断言不确定。测里固定成 USD(×1)，
    // 让 format() 变成恒等，断言校验的就是组件从 snapshot 读到的原值。
    useCurrencyStore.setState({ currentCurrency: 'USD' })
  })

  const renderTab = (isOwn = true) =>
    render(
      <QueryClientProvider client={queryClient}>
        <TenantOverviewTab tenantId="tenant_default" isOwn={isOwn} />
      </QueryClientProvider>,
    )

  it('reads month_cost / month_tokens / day_tokens from snapshot payload', async () => {
    vi.spyOn(api.budgetApi, 'snapshot').mockResolvedValue({
      data: {
        scope_type: 'tenant',
        scope_id: 'tenant_default',
        month_tokens: 23389511,
        month_cost: 3.25,
        day_tokens: 23389511,
        day_cost: 3.25,
        effective_quota: {
          monthly_budget_limit: 5000,
          monthly_token_limit: 0,
          daily_budget_limit: 200,
          daily_token_limit: 0,
        },
      },
    } as any)

    renderTab()

    // 「本月预算消耗」标题在 loading 态就渲染了，等它不代表查询已解析。
    // 必须等真实数据落进 DOM（月度 token 紧凑值 2339万）再断言，否则读到的
    // 还是 monthCost=0 的 loading 快照（¥0.00）。
    await waitFor(() => {
      expect(document.body.textContent).toMatch(/2339万/)
    })
    const body = document.body.textContent || ''
    // 预算消耗显示真实月度 cost，不再恒为 0.00（USD 下 format 恒等 → 3.25）
    expect(body).toMatch(/3\.25/)
    // 预算上限来自 effective_quota.monthly_budget_limit；
    // 组件用 format(limit, 0)，0 位小数不加千分位，所以 5000 → "5000"
    expect(body).toMatch(/5,?000/)
    // 月度 token 用量正确渲染（已改为万/亿紧凑展示，完整值在 tooltip 里）
    expect(body).toMatch(/2339万/)
  })

  it('returns 0 across all cards when snapshot has no quota configured (no crash)', async () => {
    vi.spyOn(api.budgetApi, 'snapshot').mockResolvedValue({
      data: {
        scope_type: 'tenant',
        scope_id: 'tenant_default',
        month_tokens: 0,
        month_cost: 0,
        day_tokens: 0,
        day_cost: 0,
        effective_quota: null,
      },
    } as any)

    renderTab()

    await waitFor(() => {
      // 进度条按 0/0 不炸（pct 返回 0）
      expect(screen.getAllByText('0%').length).toBeGreaterThan(0)
    })
  })

  it('shows cross-tenant resource counts without querying usage or budget', async () => {
    const listTeams = vi.spyOn(api.tenantApi, 'listTeams').mockResolvedValue({ data: { data: [{ id: 't1' }] } } as any)
    const listUsers = vi.spyOn(api.tenantApi, 'listUsers').mockResolvedValue({ data: { data: [{ id: 'u1' }, { id: 'u2' }] } } as any)
    const listProjects = vi.spyOn(api.tenantApi, 'listProjects').mockResolvedValue({ data: { data: [{ id: 'p1' }, { id: 'p2' }, { id: 'p3' }] } } as any)
    const listKeys = vi.spyOn(api.tenantApi, 'listKeys').mockResolvedValue({ data: { data: [{ id: 'k1' }, { id: 'k2' }, { id: 'k3' }, { id: 'k4' }] } } as any)
    const usageTrend = vi.spyOn(api.usageApi, 'trend')
    const budgetSnapshot = vi.spyOn(api.budgetApi, 'snapshot')

    renderTab(false)

    expect(await screen.findByText('跨单位仅展示资源规模，不展示用量/费用')).toBeInTheDocument()
    await waitFor(() => {
      expect(listTeams).toHaveBeenCalledWith('tenant_default')
      expect(listUsers).toHaveBeenCalledWith('tenant_default')
      expect(listProjects).toHaveBeenCalledWith('tenant_default')
      expect(listKeys).toHaveBeenCalledWith('tenant_default')
    })
    expect(screen.getByText('部门数').parentElement).toHaveTextContent('1')
    expect(screen.getByText('用户数').parentElement).toHaveTextContent('2')
    expect(screen.getByText('应用数').parentElement).toHaveTextContent('3')
    expect(screen.getByText('密钥数').parentElement).toHaveTextContent('4')
    expect(usageTrend).not.toHaveBeenCalled()
    expect(budgetSnapshot).not.toHaveBeenCalled()
  })
})

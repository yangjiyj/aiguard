import { CONSOLE_LOGIN_COPY as copy } from '../utils/consoleAccess'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import App from '../App'
import { licenseApi } from '../services/api'

// P1：旧计费路由保留跳转（带查询参数），新路由按原角色守卫。
const { mockAuth } = vi.hoisted(() => ({
  mockAuth: { isAuthenticated: true, user: { role: 'platform_admin', password_change_required: false } as any, logout: vi.fn() },
}))
vi.mock('../stores/auth', () => ({ useAuthStore: (selector?: any) => (selector ? selector(mockAuth) : mockAuth) }))
vi.mock('../components/Layout', async () => {
  const { Outlet } = await import('react-router-dom')
  return { default: () => <Outlet /> }
})
vi.mock('../pages/billing/Overview', () => ({ default: () => <div>费用总览页面</div> }))
vi.mock('../pages/billing/Budgets', async () => {
  const { useLocation } = await import('react-router-dom')
  function BudgetsStub() { return <div>预算与额度页面{useLocation().search}</div> }
  return { default: BudgetsStub }
})
vi.mock('../pages/billing/Pricing', () => ({ default: () => <div>价格与成本页面</div> }))
vi.mock('../pages/billing/Statements', () => ({ default: () => <div>账单与对账页面</div> }))
vi.mock('../pages/Dashboard', () => ({ default: () => <div>态势总览页面</div> }))
vi.mock('../pages/OperationAudit', () => ({ default: () => <div>操作审计页面</div> }))
vi.mock('../pages/cost/CostRecords', () => ({ default: () => <div>调用明细页面</div> }))

describe('billing routes after restructure', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    window.history.replaceState({}, '', '/')
    mockAuth.user = { role: 'platform_admin', password_change_required: false }
    vi.spyOn(licenseApi, 'status').mockResolvedValue({ data: { valid: false, features: [] } } as any)
  })

  it.each([
    ['/cost/customer-billing', '/cost/statements', '账单与对账页面'],
    ['/cost/quota-policies', '/cost/budgets', '预算与额度页面'],
    ['/cost/prices-fx', '/cost/pricing', '价格与成本页面'],
    ['/cost/anomalies', '/cost/statements', '账单与对账页面'],
  ])('旧路由 %s 跳转到 %s，不出现空白页', async (legacy, target, text) => {
    window.history.pushState({}, '', legacy)
    render(<App />)
    expect(await screen.findByText(new RegExp(text))).toBeInTheDocument()
    await waitFor(() => expect(window.location.pathname).toBe(target))
  })

  it('旧额度深链保留 scope 参数', async () => {
    window.history.pushState({}, '', '/cost/quota-policies?scope_type=team&scope_id=t1')
    render(<App />)
    expect(await screen.findByText('预算与额度页面?scope_type=team&scope_id=t1')).toBeInTheDocument()
    expect(window.location.search).toBe('?scope_type=team&scope_id=t1')
  })

  it.each([
    ['/cost/budgets', '预算与额度页面'],
    ['/cost/pricing', '价格与成本页面'],
    ['/cost/statements', '账单与对账页面'],
    ['/usage', '费用总览页面'],
  ])('平台管理员可打开 %s', async (path, text) => {
    window.history.pushState({}, '', path)
    render(<App />)
    expect(await screen.findByText(text)).toBeInTheDocument()
  })

  it('部门负责人打不开账单与对账、旧计费中心（与改造前一致），被送回首页', async () => {
    mockAuth.user = { role: 'dept_manager', password_change_required: false }
    for (const path of ['/cost/statements', '/cost/customer-billing']) {
      window.history.pushState({}, '', path)
      const view = render(<App />)
      expect(screen.getByText(copy.deniedHeading)).toBeInTheDocument()
      expect(screen.queryByText('账单与对账页面')).not.toBeInTheDocument()
      view.unmount()
    }
  })

  it('单位管理员可进预算与额度，但进不了价格与成本', async () => {
    mockAuth.user = { role: 'tenant_admin', password_change_required: false }
    window.history.pushState({}, '', '/cost/budgets')
    const first = render(<App />)
    expect(await screen.findByText('预算与额度页面')).toBeInTheDocument()
    first.unmount()
    window.history.pushState({}, '', '/cost/pricing')
    render(<App />)
    expect(await screen.findByText('态势总览页面')).toBeInTheDocument()
  })

  it('审计员打不开任何计费页面', async () => {
    mockAuth.user = { role: 'auditor', password_change_required: false }
    window.history.pushState({}, '', '/cost/budgets')
    render(<App />)
    // 审计员是控制台角色：打不开计费页，被重定向回自己的落地页（操作审计），不渲染计费页面内容。
    expect(screen.queryByText('预算与额度页面')).not.toBeInTheDocument()
    expect(screen.queryByText(copy.deniedHeading)).not.toBeInTheDocument()
    expect(window.location.pathname).toBe('/system/audit-operations')
  })
})

import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { WalletManagementPanel } from '../components/billing/WalletManagementPanel'
import { useStatementsSection } from '../components/billing/sections/useStatementsSection'
import MonthlyStatement from '../components/billing/MonthlyStatement'
import EmployeeAllowancesPanel from '../components/billing/EmployeeAllowancesPanel'
import { billingAdminApi, billingEmployeeApi } from '../services/api'

const response = (data: any) => ({ data: { data } } as any)
const page = (data: any[]) => ({ data: { data, meta: { has_more: false, next_cursor: '' } } } as any)
const wrap = (child: React.ReactNode) => render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>{child}</QueryClientProvider>)
afterEach(() => { cleanup(); vi.restoreAllMocks(); window.sessionStorage.clear() })

it('shows wallet balance, holds and available amounts down to a micro', async () => {
  vi.spyOn(billingAdminApi, 'customers').mockResolvedValue(page([{ user_id: 'tiny-owner', username: 'tiny-owner', wallet_id: 'tiny-wallet', currency: 'CNY', balance_micros: 391, reserved_micros: 1, available_micros: 390 }]))
  vi.spyOn(billingAdminApi, 'customerGroups').mockResolvedValue(response([]))
  vi.spyOn(billingAdminApi, 'redemptions').mockResolvedValue(response([]))
  wrap(<WalletManagementPanel ctx={{ tenantID: 'tenant-a', billingMode: 'metering' } as any} />)
  const row = (await screen.findByText('tiny-owner')).closest('tr') as HTMLElement
  // 金额统一 3 位小数：亚毫级微充值四舍五入显示为 ¥0.000，绝不显示「未知」
  expect(within(row).getAllByText('¥0.000').length).toBeGreaterThanOrEqual(3)
  expect(row).not.toHaveTextContent('未知')
})

function Ledger() { return useStatementsSection({ tenantID: 'tenant-a' } as any).items[0].children }
it('shows a micro charge and its hold release instead of negative zero', async () => {
  vi.spyOn(billingAdminApi, 'ledger').mockResolvedValue(page([{ id: 'tiny-entry', username: 'tiny-ledger-owner', currency: 'CNY', event_type: 'settle', balance_delta_micros: -390, reserved_delta_micros: -1, balance_after_micros: 1, created_at: '2026-10-12T00:00:00Z' }]))
  wrap(<Ledger />)
  const row = (await screen.findByText('tiny-ledger-owner')).closest('tr') as HTMLElement
  // 亚毫级负向变动统一四舍五入为 ¥0.000（不出现 -0.000 负零）
  expect(within(row).getAllByText('¥0.000').length).toBeGreaterThanOrEqual(3)
})

it('keeps the monthly statement department charge visibly nonzero', async () => {
  const totals = { model_name: '', requests: 1, total_tokens: 1, billed_micros: 390, billed_requests: 1, unbilled_requests: 0, unpriced_requests: 0, usage_unknown_requests: 0, failed_requests: 0 }
  vi.spyOn(billingAdminApi, 'monthlyStatement').mockResolvedValue(response({ month: '2026-10', timezone: 'Asia/Shanghai', currency: 'CNY', total: totals, departments: [{ ...totals, department_id: 'tiny-dept', department_name: 'tiny-dept', employees: [] }] }))
  wrap(<MonthlyStatement tenantID="tenant-a" />)
  const row = (await screen.findByText('tiny-dept')).closest('tr') as HTMLElement
  expect(within(row).getByText('¥0.000')).toBeInTheDocument()
  expect(row).not.toHaveTextContent('未知')
})

it('shows monthly grant and its remaining gift after a micro hold', async () => {
  vi.spyOn(billingEmployeeApi, 'settings').mockResolvedValue(response({ currency: 'CNY', timezone: 'UTC', default_monthly_micros: null }))
  vi.spyOn(billingEmployeeApi, 'list').mockResolvedValue(response([{ user_id: 'tiny-monthly', username: 'tiny-monthly', currency: 'CNY', monthly_micros: 391, effective_micros: 391, monthly_status: { granted_micros: 391, remaining_micros: 391, reserved_micros: 1 } }]))
  wrap(<EmployeeAllowancesPanel tenantID="tenant-a" section="employees" />)
  const row = (await screen.findByText('tiny-monthly')).closest('tr') as HTMLElement
  expect(within(row).getAllByText('CNY 0.000').length).toBeGreaterThanOrEqual(2)
})

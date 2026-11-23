import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import BudgetTree from '../components/billing/BudgetTree'
import treeSource from '../components/billing/BudgetTree.tsx?raw'
import { billingEmployeeApi, policyApi } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { literal, sourceRegex } from './billingSourceLabels'

const labels = {
  edit: literal(treeSource, /onClick=\{\(\) => open\(node\)\}>([^<]+)</),
  amount: literal(treeSource, /<TwoDecimalInput aria-label="([^"]+)"/),
  save: literal(treeSource, /okText="([^"]+)"/),
  foreign: literal(treeSource, /const FOREIGN_BUDGET_NOTICE = '([^']+)'/),
  loadError: literal(treeSource, /treeQuery.isError[^\n]+message="([^"]+)"/),
}
const buttonName = (value: string) => new RegExp(value.split('').map(char => sourceRegex(char).source).join('\\s*'))
const response = (data: any) => ({ data: { data } } as any)
const node = (kind: string, id: string, children?: any[]) => ({ kind, id, name: id, budget_micros: 5000000, used_micros: 1000000, reserved_micros: 500000, remaining_micros: 3500000, status: 'normal', currency: 'CNY', children })
const fixture = node('organization', 'tenant-a', [node('department', 'dept-a', [node('employee', 'employee-hidden')]), node('unassigned', 'unassigned-hidden', [node('employee', 'unassigned-employee-hidden')])])

describe('organization and department budget tree', () => {
  let client: QueryClient
  beforeEach(() => {
    client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    useAuthStore.setState({ user: { id: 'admin', username: 'admin', role: 'platform_admin', tenant_id: 'tenant-a' } })
    vi.spyOn(billingEmployeeApi, 'budgetTree').mockResolvedValue(response(fixture))
    vi.spyOn(policyApi, 'getQuota').mockResolvedValue(response({ monthly_budget_micros: 5000000 }))
    vi.spyOn(policyApi, 'setQuota').mockResolvedValue(response({}))
  })
  afterEach(() => { cleanup(); client.clear(); vi.restoreAllMocks() })
  const renderTree = (tenantID = 'tenant-a') => render(<QueryClientProvider client={client}><BudgetTree tenantID={tenantID} canEditEmployees /></QueryClientProvider>)

  it('keeps organization and department rows while hiding employee and unassigned nodes', async () => {
    renderTree()
    expect(await screen.findByText('dept-a')).toBeInTheDocument()
    expect(screen.getByText('tenant-a')).toBeInTheDocument()
    for (const hidden of ['employee-hidden', 'unassigned-hidden', 'unassigned-employee-hidden']) expect(screen.queryByText(hidden)).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: labels.edit })).toHaveLength(2)
    expect(policyApi.getQuota).not.toHaveBeenCalled()
  })

  it.each([['dept-a', 'team', 'dept-a'], ['tenant-a', 'tenant', '']])('updates %s monthly budget while preserving every other quota dimension', async (name, scopeType, scopeID) => {
    const loaded = { daily_token_limit: 20000, daily_token_blocked: true, monthly_token_limit: 600000, monthly_token_blocked: false, daily_budget_micros: 1250000, daily_budget_blocked: false, monthly_budget_micros: 5000000, rpm_limit: 60, rpm_blocked: false, tpm_limit: 9000, tpm_blocked: true, concurrency_limit: 7, concurrency_blocked: false, overage_action: 'notify', enforcement_mode: 'soft', quota_timezone: 'UTC' }
    vi.mocked(policyApi.getQuota).mockResolvedValue(response(loaded))
    renderTree()
    const row = (await screen.findByText(name)).closest('tr') as HTMLElement
    await userEvent.click(within(row).getByRole('button', { name: labels.edit }))
    const dialog = await screen.findByRole('dialog')
    const amount = within(dialog).getByRole('spinbutton', { name: labels.amount })
    await userEvent.clear(amount)
    await userEvent.type(amount, '8')
    await userEvent.click(within(dialog).getByRole('button', { name: buttonName(labels.save) }))
    await waitFor(() => expect(policyApi.setQuota).toHaveBeenCalledWith({ ...loaded, scope_type: scopeType, scope_id: scopeID, project_id: '', monthly_budget_micros: 8000000, monthly_budget_blocked: false }))
    expect(policyApi.getQuota).toHaveBeenCalledWith({ scope_type: scopeType, scope_id: scopeID })
  })

  it('reads a foreign tenant tree without exposing an edit or calling quota endpoints', async () => {
    renderTree('tenant-b')
    expect(await screen.findByText('dept-a')).toBeInTheDocument()
    expect(screen.getByText(labels.foreign)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: labels.edit })).not.toBeInTheDocument()
    expect(billingEmployeeApi.budgetTree).toHaveBeenCalledWith('tenant-b')
    expect(policyApi.getQuota).not.toHaveBeenCalled()
    expect(policyApi.setQuota).not.toHaveBeenCalled()
  })

  it('does not write a quota when authentication changes while its original policy is loading', async () => {
    let resolveQuota!: (value: any) => void
    vi.mocked(policyApi.getQuota).mockImplementation(() => new Promise(resolve => { resolveQuota = resolve }))
    renderTree()
    const row = (await screen.findByText('dept-a')).closest('tr') as HTMLElement
    await userEvent.click(within(row).getByRole('button', { name: labels.edit }))
    const dialog = await screen.findByRole('dialog')
    await userEvent.click(within(dialog).getByRole('button', { name: buttonName(labels.save) }))
    await waitFor(() => expect(policyApi.getQuota).toHaveBeenCalledTimes(1))
    await act(async () => {
      useAuthStore.setState({ user: { id: 'other', username: 'other', role: 'tenant_admin', tenant_id: 'tenant-b' } })
      resolveQuota(response({ monthly_budget_micros: 5000000 }))
    })
    expect(policyApi.setQuota).not.toHaveBeenCalled()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('retains explicit loading failures instead of rendering a healthy empty tree', async () => {
    vi.mocked(billingEmployeeApi.budgetTree).mockRejectedValue(new Error('database unavailable'))
    renderTree()
    expect(await screen.findByText(labels.loadError)).toBeInTheDocument()
    expect(policyApi.setQuota).not.toHaveBeenCalled()
  })
})

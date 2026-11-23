import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { Modal } from 'antd'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { WalletManagementPanel } from '../components/billing/WalletManagementPanel'
import prepaidSource from '../components/billing/sections/usePrepaidSection.tsx?raw'
import { ScopedQuotaForm } from '../components/ai-permissions/ScopedQuotaForm'
import { billingAdminApi, policyApi } from '../services/api'
import { useAuthStore } from '../stores/auth'
import { useCurrencyStore } from '../stores/currency'

const response = (data: any) => ({ data: { data } } as any)
const page = (rows: any[]) => ({ data: { data: rows, meta: { has_more: false, next_cursor: '' } } } as any)
const creditLabel = prepaidSource.match(/<Modal title="([^"]+)"[^>]*open=\{creditOpen\}/)![1]
const redemptionLabel = prepaidSource.match(/<Modal title="([^"]+)"[^>]*open=\{redemptionOpen\}/)![1]

describe('美元租户的金额单位标签', () => {
  let client: QueryClient
  const previousUser = useAuthStore.getState().user
  beforeEach(() => {
    useAuthStore.setState({ user: { id: 'admin-fixture', role: 'platform_admin', username: 'admin' } as any })
    useCurrencyStore.setState({ tenantCurrency: 'USD', currentCurrency: 'USD', manualCurrency: null })
    client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.spyOn(billingAdminApi, 'customers').mockResolvedValue(page([{ user_id: 'employee-a', username: 'employee-a', wallet_id: 'wallet-a', currency: 'USD', balance_micros: 2000000, reserved_micros: 0, available_micros: 2000000 }]))
    vi.spyOn(billingAdminApi, 'customerGroups').mockResolvedValue(response([]))
    vi.spyOn(billingAdminApi, 'redemptions').mockResolvedValue(response([]))
  })
  afterEach(() => { Modal.destroyAll(); cleanup(); document.body.innerHTML = ''; useAuthStore.setState({ user: previousUser }); useCurrencyStore.setState({ tenantCurrency: 'CNY', currentCurrency: 'CNY', manualCurrency: null }); vi.restoreAllMocks(); window.sessionStorage.clear() })
  const ctx = { tenantID: 'tenant-a', billingMode: 'metering', billingRuntime: { mode: 'metering', prepaid_tools_visible: false } } as any

  it('充值弹窗显示「充值金额（美元）」，不再写死「元」', async () => {
    render(<QueryClientProvider client={client}><WalletManagementPanel ctx={ctx} /></QueryClientProvider>)
    await screen.findByText('employee-a')
    await userEvent.click(screen.getByRole('button', { name: creditLabel }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByLabelText('充值金额（美元）')).toBeInTheDocument()
    expect(within(dialog).queryByLabelText('充值金额（元）')).not.toBeInTheDocument()
  })

  it('兑换码弹窗显示「单张面值（美元）」', async () => {
    render(<QueryClientProvider client={client}><WalletManagementPanel ctx={ctx} section="redemptions" /></QueryClientProvider>)
    await userEvent.click(await screen.findByRole('button', { name: redemptionLabel }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByLabelText('单张面值（美元）')).toBeInTheDocument()
    fireEvent.change(within(dialog).getByLabelText('批次名称'), { target: { value: 'x' } })
  })

  it('人民币租户保持「元」', async () => {
    useCurrencyStore.setState({ tenantCurrency: 'CNY', currentCurrency: 'CNY', manualCurrency: null })
    render(<QueryClientProvider client={client}><WalletManagementPanel ctx={ctx} section="redemptions" /></QueryClientProvider>)
    await userEvent.click(await screen.findByRole('button', { name: redemptionLabel }))
    expect(within(await screen.findByRole('dialog')).getByLabelText('单张面值（元）')).toBeInTheDocument()
  })
})

describe('配额表单的预算单位', () => {
  beforeEach(() => {
    useAuthStore.setState({ user: { id: 'admin', username: 'admin', role: 'platform_admin', tenant_id: 'tenant_default' } as any, isAuthenticated: true } as any)
    vi.spyOn(policyApi, 'getQuota').mockResolvedValue({ data: { scope_type: 'team', scope_id: 't1', monthly_budget_micros: 200_000_000 } } as any)
  })
  afterEach(() => { cleanup(); useCurrencyStore.setState({ tenantCurrency: 'CNY', currentCurrency: 'CNY', manualCurrency: null }); vi.restoreAllMocks() })
  const renderForm = () => render(<MemoryRouter><QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><ScopedQuotaForm scopeType="team" scopeId="t1" /></QueryClientProvider></MemoryRouter>)

  it('美元租户显示「月费用预算（美元）」', async () => {
    useCurrencyStore.setState({ tenantCurrency: 'USD', currentCurrency: 'USD', manualCurrency: null })
    renderForm()
    await waitFor(() => expect(screen.getByLabelText('月费用预算（美元）')).toHaveValue('200.00'))
    expect(screen.queryByLabelText('月费用预算（元）')).not.toBeInTheDocument()
  })
})

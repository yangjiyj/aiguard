import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { Modal } from 'antd'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { WalletManagementPanel } from '../components/billing/WalletManagementPanel'
import prepaidSource from '../components/billing/sections/usePrepaidSection.tsx?raw'
import { billingAdminApi } from '../services/api'
import { useAuthStore } from '../stores/auth'

const creditLabel = prepaidSource.match(/<Modal title="([^"]+)"[^>]*open=\{creditOpen\}/)![1]
const redemptionLabel = prepaidSource.match(/<Modal title="([^"]+)"[^>]*open=\{redemptionOpen\}/)![1]
const response = (data: any) => ({ data: { data } } as any)
const page = (rows: any[]) => ({ data: { data: rows, meta: { has_more: false, next_cursor: '' } } } as any)

describe('wallet management in metering mode', () => {
  let client: QueryClient
  const previousUser = useAuthStore.getState().user
  beforeEach(() => {
    useAuthStore.setState({ user: { id: 'admin-fixture', role: 'platform_admin', username: 'admin' } as any })
    client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.spyOn(billingAdminApi, 'customers').mockResolvedValue(page([{user_id:'employee-a',username:'employee-a',wallet_id:'wallet-a',currency:'CNY',balance_micros:2000000,reserved_micros:500000,available_micros:1500000}]))
    vi.spyOn(billingAdminApi, 'customerGroups').mockResolvedValue(response([]))
    vi.spyOn(billingAdminApi, 'redemptions').mockResolvedValue(response([]))
  })
  afterEach(() => { Modal.destroyAll(); cleanup(); document.body.innerHTML = ''; useAuthStore.setState({ user: previousUser }); vi.restoreAllMocks(); window.sessionStorage.clear() })
  const ctx = { tenantID: 'tenant-a', billingMode: 'metering', billingRuntime: { mode: 'metering', prepaid_tools_visible: false } } as any

  it('displays actual wallet balances and recharge without a visibility flag', async () => {
    render(<QueryClientProvider client={client}><WalletManagementPanel ctx={ctx} /></QueryClientProvider>)
    expect(await screen.findByText('employee-a')).toBeInTheDocument()
    expect(screen.getByText('¥1.500')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', {name:creditLabel}))
    expect(await screen.findByRole('dialog')).toHaveTextContent(creditLabel)
  })

  it('offers redemption generation through its direct management section', async () => {
    render(<QueryClientProvider client={client}><WalletManagementPanel ctx={ctx} section="redemptions" /></QueryClientProvider>)
    await userEvent.click(await screen.findByRole('button', {name:redemptionLabel}))
    expect(await screen.findByRole('dialog')).toHaveTextContent(redemptionLabel)
    await waitFor(() => expect(billingAdminApi.redemptions).toHaveBeenCalledWith('tenant-a',expect.objectContaining({page:1,page_size:20})))
  })
  it.each(['active', 'redeemed', 'voided'])('removes a %s redemption from management without changing wallet funds', async status => {
    vi.mocked(billingAdminApi.redemptions).mockResolvedValue(response([{ id: 'redemption-a', code_hint: 'JJD-hidden', status, amount_micros: 1000000 }]))
    const remove = vi.spyOn(billingAdminApi, 'deleteRedemption').mockImplementation(async () => {
      vi.mocked(billingAdminApi.redemptions).mockResolvedValue(response([]))
      return { status: 204 } as any
    })
    const credit = vi.spyOn(billingAdminApi, 'credit')
    render(<QueryClientProvider client={client}><WalletManagementPanel ctx={ctx} section="redemptions" /></QueryClientProvider>)
    await screen.findByText('JJD-hidden')
    await userEvent.click(screen.getByRole('button', { name: '删除' }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('已入账的充值和资金流水保留')
    expect(remove).not.toHaveBeenCalled()
    await userEvent.click(within(dialog).getByRole('button', { name: /删\s*除/ }))
    await waitFor(() => expect(remove).toHaveBeenCalledWith('tenant-a', 'redemption-a'))
    await waitFor(() => expect(screen.queryByText('JJD-hidden')).not.toBeInTheDocument())
    expect(credit).not.toHaveBeenCalled()
  })

  it('hides redemption deletion for a viewer', async () => {
    useAuthStore.setState({ user: { id: 'viewer-fixture', role: 'viewer', username: 'viewer' } as any })
    vi.mocked(billingAdminApi.redemptions).mockResolvedValue(response([{ id: 'redemption-a', code_hint: 'JJD-hidden', status: 'redeemed', amount_micros: 1000000 }]))
    render(<QueryClientProvider client={client}><WalletManagementPanel ctx={ctx} section="redemptions" /></QueryClientProvider>)
    await screen.findByText('JJD-hidden')
    expect(screen.queryByRole('button', { name: '删除' })).not.toBeInTheDocument()
  })

  it('submits a selected local expiration as an absolute ISO timestamp', async () => {
    const generate = vi.spyOn(billingAdminApi, 'createRedemptions').mockResolvedValue(response([]))
    render(<QueryClientProvider client={client}><WalletManagementPanel ctx={ctx} section="redemptions" /></QueryClientProvider>)
    await userEvent.click(await screen.findByRole('button', { name: redemptionLabel }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('批次名称'), { target: { value: 'expiry-fixture' } })
    fireEvent.change(within(dialog).getByLabelText('单张面值（元）'), { target: { value: '10' } })
    const expiration = within(dialog).getByPlaceholderText('选择到期日期和时间')
    fireEvent.change(expiration, { target: { value: '2035-12-31 23:59:59' } })
    fireEvent.keyDown(expiration, { key: 'Enter', code: 'Enter' })
    fireEvent.blur(expiration)
    await userEvent.click(within(dialog).getByRole('button', { name: /确认生成/ }))
    await waitFor(() => expect(generate).toHaveBeenCalledWith({ tenant_id: 'tenant-a', label: 'expiry-fixture', amount_micros: 10000000, count: 1, expires_at: new Date(2035, 11, 31, 23, 59, 59).toISOString() }))
  })

})

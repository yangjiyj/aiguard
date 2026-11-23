import { billingSourceLabels } from './billingSourceLabels'
import { BILLING_SECTION_LABELS as labels } from '../components/billing/sectionLabels'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import BillingPricing from '../pages/billing/Pricing'
import { BillingWalletTestHarness, BillingLedgerTestHarness } from './BillingWalletTestHarness'
import * as api from '../services/api'

const response = (data: any) => ({ data: { data } } as any)

describe('wallet customer groups', () => {
  let queryClient: QueryClient

  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.clearAllMocks()
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue({ data: [{ id: 'tenant-a', name: 'XX科技' }] } as any)
    vi.spyOn(api.billingAdminApi, 'runtime').mockResolvedValue(response({ mode: 'metering', description: '仅计量，不扣余额', generated_at: '2026-08-23T00:00:00Z' }))
    vi.spyOn(api.billingAdminApi, 'models').mockResolvedValue(response([{ model_name: 'gpt-5.6-sol', model_label: 'GPT 5.6 SOL', provider_name: '火线宝', status: 'active' }]))
    vi.spyOn(api.billingAdminApi, 'customers').mockResolvedValue(response([{
      user_id: 'user-a', username: 'Alice', email: 'alice@example.com', customer_group: 'vip',
      customer_group_name: 'VIP 客户', customer_group_status: 'active', balance_micros: 0,
      reserved_micros: 0, available_micros: 0, currency: 'CNY',
    }]))
    vi.spyOn(api.billingAdminApi, 'customerGroups').mockResolvedValue(response([
      { id: 'group-default', code: 'default', name: '默认客户组', description: '系统默认客户组', status: 'active', is_default: true, ratio_ppm: 1_000_000, member_count: 0 },
      { id: 'group-vip', code: 'vip', name: 'VIP 客户', description: '合同客户', status: 'active', is_default: false, ratio_ppm: 800_000, member_count: 1 },
    ]))
    vi.spyOn(api.billingAdminApi, 'ledger').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'prices').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'redemptions').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'tariffs').mockResolvedValue(response([{
      id: 'tariff-draft', name: '待发布方案', version: 2, status: 'draft', timezone: 'Asia/Shanghai', rules: [],
    }]))
    vi.spyOn(api.billingAdminApi, 'previewTariff').mockResolvedValue(response(null))
    vi.spyOn(api.billingAdminApi, 'deleteTariff').mockResolvedValue(response({ deleted: true }))
  })

  afterEach(() => {
    vi.restoreAllMocks()
    cleanup()
    document.body.innerHTML = ''
  })

  const renderPage = () => render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <BillingWalletTestHarness />
      </QueryClientProvider>
    </MemoryRouter>,
  )

  it('metering exposes wallet operations directly', async () => {
    renderPage()
    expect(await screen.findByRole('tab', { name: billingSourceLabels.accounts })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: billingSourceLabels.groups })).toBeInTheDocument()
  })

  it('prepaid keeps customer accounts available by default', async () => {
    vi.mocked(api.billingAdminApi.runtime).mockResolvedValue(response({ mode: 'prepaid', description: '预付费' }))
    renderPage()
    expect(await screen.findByRole('tab', { name: billingSourceLabels.accounts })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /展开客户账务/ })).not.toBeInTheDocument()
  })

  it('displays actual metering wallet amounts', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('tab', { name: billingSourceLabels.accounts }))
    await user.click(await screen.findByRole('tab', { name: billingSourceLabels.accounts }))
    expect(await screen.findAllByText('¥0.000')).not.toHaveLength(0)
  })
  it('keeps missing customer currency unknown instead of inventing CNY', async () => {
    vi.mocked(api.billingAdminApi.customers).mockResolvedValue(response([{
      user_id: 'user-a', username: 'missing-currency-customer', email: 'alice@example.com', customer_group: 'vip',
      customer_group_name: 'VIP 客户', customer_group_status: 'active', balance_micros: 0,
      reserved_micros: 0, available_micros: 0,
    }]))
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('tab', { name: billingSourceLabels.accounts }))
    await user.click(await screen.findByRole('tab', { name: billingSourceLabels.accounts }))
    const row = (await screen.findByText('missing-currency-customer')).closest('tr') as HTMLElement
    expect(within(row).getAllByText('0.000（未知币种）')).not.toHaveLength(0)
    expect(within(row).queryByText('¥0.000')).not.toBeInTheDocument()
  })

  it('shows each customer actual group and supports assigning a registered group', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('tab', { name: billingSourceLabels.accounts }))

    expect(await screen.findByText('VIP 客户')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '调整分组' }))

    const dialog = await screen.findByRole('dialog', { name: /调整客户组/ })
    expect(within(dialog).getByRole('combobox', { name: '客户组' })).toBeInTheDocument()
    expect(within(dialog).queryByRole('textbox', { name: '客户组' })).not.toBeInTheDocument()
  })

  it('manages one multiplier per customer group', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('tab', { name: billingSourceLabels.accounts }))
    await screen.findByText('VIP 客户')

    await user.click(screen.getByRole('tab', { name: billingSourceLabels.groups }))
    await waitFor(() => {
      expect(screen.getByText('合同客户')).toBeInTheDocument()
      expect(screen.getByText('vip')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /新增客户组/ })).toBeInTheDocument()
      expect(screen.getByText('0.80×')).toBeInTheDocument()
    })

    await user.click(screen.getAllByRole('button', { name: '编辑' })[1])
    const groupDialog = await screen.findByRole('dialog', { name: '编辑客户组' })
    expect(within(groupDialog).getByRole('spinbutton', { name: '统一计费倍率' })).toHaveDisplayValue('0.80')
  })

  it('deletes only a selected draft tariff after explicit confirmation', async () => {
    const user = userEvent.setup()
    render(<MemoryRouter><QueryClientProvider client={queryClient}><BillingPricing /></QueryClientProvider></MemoryRouter>)

    await user.click(await screen.findByRole('tab', { name: labels.tariffs }))
    await user.click(await screen.findByRole('button', { name: new RegExp(Array.from('删除').join('\\s*')) }))
    expect(await screen.findByText('确认删除草稿？')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '确认删除' }))

    await waitFor(() => expect(api.billingAdminApi.deleteTariff).toHaveBeenCalledWith('tenant-a', 'tariff-draft'))
  })

  it('keeps model pricing global without a customer-group selector', async () => {
    const user = userEvent.setup()
    render(<MemoryRouter><QueryClientProvider client={queryClient}><BillingPricing /></QueryClientProvider></MemoryRouter>)

    await user.click(await screen.findByRole('tab', { name: labels.prices }))
    expect(await screen.findByText('GPT 5.6 SOL')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /新增定价版本/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: '客户组' })).not.toBeInTheDocument()
    expect(screen.queryByText('客户组倍率')).not.toBeInTheDocument()
  })

  it('flags overdraft settlements in the billing ledger (D5)', async () => {
    vi.mocked(api.billingAdminApi.runtime).mockResolvedValue(response({ mode: 'prepaid', description: 'prepaid' }))
    vi.mocked(api.billingAdminApi.ledger).mockResolvedValue(response([
      { id: 'l-1', username: 'Alice', event_type: 'settle', balance_delta_micros: -500_000, reserved_delta_micros: -400_000, balance_after_micros: -300_000, request_id: 'req-over', metadata: { overdraft: true, available_after_micros: -300_000 }, created_at: '2026-09-30T00:00:00Z' },
      { id: 'l-2', username: 'Alice', event_type: 'settle', balance_delta_micros: -1, reserved_delta_micros: -1, balance_after_micros: 10, request_id: 'req-ok', metadata: {}, created_at: '2026-09-29T00:00:00Z' },
    ]))
    const user = userEvent.setup()
    render(<MemoryRouter><QueryClientProvider client={queryClient}><BillingLedgerTestHarness /></QueryClientProvider></MemoryRouter>)
    await user.click(await screen.findByRole('tab', { name: '计费账本' }))
    const overdrawn = (await screen.findByText('req-over')).closest('tr') as HTMLElement
    expect(within(overdrawn).getByText('透支')).toBeInTheDocument()
    const covered = screen.getByText('req-ok').closest('tr') as HTMLElement
    expect(within(covered).queryByText('透支')).not.toBeInTheDocument()
  })

})

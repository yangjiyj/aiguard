import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import BillingStatements from '../pages/billing/Statements'
import BillingPricing from '../pages/billing/Pricing'
import { WalletManagementPanel } from '../components/billing/WalletManagementPanel'
import { BILLING_SECTION_LABELS as labels } from '../components/billing/sectionLabels'
import { billingSourceLabels } from './billingSourceLabels'
import * as api from '../services/api'
import {useAuthStore} from '../stores/auth'

const response = (data: any) => ({ data: { data } } as any)
const cursorPage = (rows: any[]) => ({ data: { data: rows, meta: { has_more: false, next_cursor: '' } } } as any)

describe('simplified billing pages and metering wallet operations', () => {
  let queryClient: QueryClient
  beforeEach(() => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    vi.spyOn(api.tenantApi, 'list').mockResolvedValue({ data: [{ id: 'tenant-a', name: 'Fixture' }] } as any)
    vi.spyOn(api.billingAdminApi, 'runtime').mockResolvedValue(response({ mode: 'metering', prepaid_tools_visible: false }))
    vi.spyOn(api.billingAdminApi, 'models').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'customers').mockResolvedValue(cursorPage([{ user_id: 'employee-a', wallet_id: 'wallet-a', username: 'employee-a', currency: 'CNY', balance_micros: 2000000, reserved_micros: 500000, available_micros: 1500000 }]))
    vi.spyOn(api.billingAdminApi, 'customerGroups').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'ledger').mockResolvedValue(cursorPage([]))
    vi.spyOn(api.billingAdminApi, 'prices').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'redemptions').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'tariffs').mockResolvedValue(response([]))
    vi.spyOn(api.billingAdminApi, 'previewTariff').mockResolvedValue(response(null))
    vi.spyOn(api.billingAdminApi, 'monthlyStatement').mockResolvedValue(response({ month: '2026-10', timezone: 'Asia/Shanghai', currency: 'CNY', total: { requests: 0, total_tokens: 0, billed_micros: 0, billed_requests: 0, unbilled_requests: 0, unpriced_requests: 0, usage_unknown_requests: 0 }, departments: [] }))
    vi.spyOn(api.billingEmployeeApi, 'upstreamRates').mockResolvedValue(response([]))
    vi.spyOn(api.billingEmployeeApi, 'upstreamModels').mockResolvedValue(response([]))
    vi.spyOn(api.billingEmployeeApi, 'fixedCosts').mockResolvedValue({ data: { data: [], channels: [] } } as any)
    vi.spyOn(api.billingEmployeeApi, 'settings').mockResolvedValue(response({ currency: 'CNY' }))
  })
  afterEach(() => { vi.restoreAllMocks(); cleanup(); document.body.innerHTML = ''; window.sessionStorage.clear() })
  const renderWith = (node: JSX.Element) => render(<MemoryRouter><QueryClientProvider client={queryClient}>{node}</QueryClientProvider></MemoryRouter>)

  it('shows only monthly statements and ledger, without issuing wallet management queries', async () => {
    renderWith(<BillingStatements />)
    expect(await screen.findByRole('tab', { name: billingSourceLabels.statement, selected: true })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: billingSourceLabels.ledger })).toBeInTheDocument()
    expect(screen.getAllByRole('tab')).toHaveLength(2)
    expect(api.billingAdminApi.customers).not.toHaveBeenCalled()
    expect(api.billingAdminApi.customerGroups).not.toHaveBeenCalled()
    expect(api.billingAdminApi.redemptions).not.toHaveBeenCalled()
  })

  it('keeps two distinct cost categories next to price and tariff management', async () => {
    const user = userEvent.setup()
    renderWith(<BillingPricing />)
    expect(await screen.findByRole('tab', { name: labels.prices })).toBeInTheDocument()
    for (const name of [labels.tariffs, labels.upstream, labels.fixed]) expect(screen.getByRole('tab', { name })).toBeInTheDocument()
    expect(screen.getAllByRole('tab')).toHaveLength(4)
    await user.click(screen.getByRole('tab', { name: labels.upstream }))
    await waitFor(() => expect(api.billingEmployeeApi.upstreamRates).toHaveBeenCalledWith('tenant-a'))
    await user.click(screen.getByRole('tab', { name: labels.fixed }))
    await waitFor(() => expect(api.billingEmployeeApi.fixedCosts).toHaveBeenCalledWith('tenant-a'))
  })

  it('makes wallet balances and manual recharge available in metering mode without a visibility flag', async () => {
    const user = userEvent.setup()
    renderWith(<WalletManagementPanel ctx={{ tenantID: 'tenant-a', billingMode: 'metering' } as any} />)
    expect(await screen.findByText('employee-a')).toBeInTheDocument()
    expect(screen.getByText(billingSourceLabels.balance)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: billingSourceLabels.credit }))
    expect(await screen.findByRole('dialog')).toHaveTextContent(billingSourceLabels.credit)
    expect(api.billingAdminApi.customers).toHaveBeenCalledWith('tenant-a', '', expect.any(Number))
  })

  it('provides a direct redemption management section in metering mode', async () => {
    const user = userEvent.setup()
    renderWith(<WalletManagementPanel ctx={{ tenantID: 'tenant-a', billingMode: 'metering' } as any} section="redemptions" />)
    await user.click(await screen.findByRole('button', { name: billingSourceLabels.redemption }))
    expect(await screen.findByRole('dialog')).toHaveTextContent(billingSourceLabels.redemption)
    await waitFor(() => expect(api.billingAdminApi.redemptions).toHaveBeenCalledWith('tenant-a',expect.objectContaining({page:1,page_size:20})))
  })
  it('shows redemption creator/time and uses server paging with filters in metering mode',async()=>{
    vi.mocked(api.billingAdminApi.redemptions).mockResolvedValue({data:{data:[{id:'code-fixture',code_hint:'JJD-hint...end',label:'fixture-batch',amount_micros:2000000,status:'redeemed',created_by_name:'creator-fixture',created_at:'2026-10-14T00:00:00Z',redeemed_by:'redeemer-fixture',redeemed_department:'研发部',redeemed_at:'2026-10-14T01:00:00Z'}],meta:{total:21,page:1,page_size:20}}} as any)
    renderWith(<WalletManagementPanel ctx={{tenantID:'tenant-a',billingMode:'metering'} as any} section="redemptions"/>)
    expect(await screen.findByText('creator-fixture')).toBeInTheDocument()
    for(const name of [/创建人.*创建时间/,/兑换人.*兑换时间/])expect(screen.getByRole('columnheader',{name})).toBeInTheDocument()
    expect(screen.getByLabelText('批次筛选')).toBeInTheDocument()
    expect(screen.getByLabelText('兑换人筛选')).toBeInTheDocument()
    const user=userEvent.setup()
    await user.click(document.querySelector('.ant-pagination-next button')!)
    await waitFor(()=>expect(api.billingAdminApi.redemptions).toHaveBeenCalledWith('tenant-a',expect.objectContaining({page:2,page_size:20})))
  })

  it('admin copies a code through an explicit request and the list has no yellow one-time warning',async()=>{
    const prior=useAuthStore.getState().user;useAuthStore.setState({user:{id:'admin-fixture',role:'platform_admin'} as any});
    const copy=vi.fn().mockResolvedValue(undefined);Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:copy}})
    vi.spyOn(api.billingAdminApi,'revealRedemption').mockResolvedValue(response({code:'fixture-redemption-value'}))
    vi.mocked(api.billingAdminApi.redemptions).mockResolvedValue(response([{id:'code-fixture',code_hint:'masked',label:'fixture',amount_micros:1000000,status:'active'}]))
    try{
      renderWith(<WalletManagementPanel ctx={{tenantID:'tenant-a',billingMode:'metering'} as any} section="redemptions"/>);
      expect(screen.queryByText('完整兑换码仅显示一次，请及时保存。')).not.toBeInTheDocument();
      expect(api.billingAdminApi.revealRedemption).not.toHaveBeenCalled();
      await userEvent.click(await screen.findByRole('button',{name:'复制兑换码'}));
      await waitFor(()=>expect(copy).toHaveBeenCalledWith('fixture-redemption-value'));
      expect(api.billingAdminApi.revealRedemption).toHaveBeenCalledWith('tenant-a','code-fixture');
    }finally{cleanup();useAuthStore.setState({user:prior})}
  })
  it('a viewer has no copy-redemption control',async()=>{
    const prior=useAuthStore.getState().user;useAuthStore.setState({user:{id:'viewer-fixture',role:'viewer'} as any});
    vi.mocked(api.billingAdminApi.redemptions).mockResolvedValue(response([{id:'code-fixture',code_hint:'masked',label:'fixture',amount_micros:1000000,status:'active'}]));
    try{renderWith(<WalletManagementPanel ctx={{tenantID:'tenant-a',billingMode:'metering'} as any} section="redemptions"/>);await screen.findByText('masked');expect(screen.queryByRole('button',{name:'复制兑换码'})).not.toBeInTheDocument()}finally{cleanup();useAuthStore.setState({user:prior})}
  })

})

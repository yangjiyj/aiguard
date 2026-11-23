import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { message } from 'antd'
import ChannelFixedCostsPanel from '../components/billing/ChannelFixedCostsPanel'
import { billingEmployeeApi } from '../services/api'

const editLabel = String.fromCodePoint(32534,36753)
const removeLabel = String.fromCodePoint(21024,38500)
const confirmLabel = String.fromCodePoint(30830,35748,21024,38500)
const addLabel = String.fromCodePoint(26032,22686,28192,36947,22266,23450,36153,29992)
const amountLabel = String.fromCodePoint(37329,39069)
const response = (data: any) => ({ data: { data } } as any)
let cache: QueryClient
const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={cache}>{children}</QueryClientProvider>
const cost = { id: 'fixed-a', provider_id: 'provider-a', provider_name: 'Provider A', amount_micros: 250000000, currency: 'USD', period: 'month', effective_from: '2026-10-01', effective_to: '2026-11-01', note: 'contract-a' }
beforeEach(() => {
  cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  vi.spyOn(billingEmployeeApi, 'settings').mockResolvedValue(response({ currency: 'USD' }))
  vi.spyOn(billingEmployeeApi, 'fixedCosts').mockResolvedValue({ data: { data: [cost], channels: [{ provider_id: 'provider-a', provider_name: 'Provider A' }] } } as any)
  vi.spyOn(billingEmployeeApi, 'saveFixedCost').mockResolvedValue(response(cost))
  vi.spyOn(billingEmployeeApi, 'deleteFixedCost').mockResolvedValue(response({}))
})
afterEach(() => { cache.clear(); cleanup(); message.destroy(); vi.restoreAllMocks() })
describe('channel fixed costs', () => {
  it('preserves tenant denomination, half-open dates and note while editing an amount', async () => {
    const user = userEvent.setup()
    render(<ChannelFixedCostsPanel tenantID="tenant-a" />, { wrapper })
    const row = (await screen.findByText('Provider A')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: editLabel }))
    const dialog = screen.getByRole('dialog')
    const input = within(dialog).getByLabelText(amountLabel)
    await user.clear(input)
    await user.type(input, '500.25')
    await user.click(within(dialog).getByRole('button', { name: 'OK' }))
    await waitFor(() => expect(billingEmployeeApi.saveFixedCost).toHaveBeenCalledWith('tenant-a', {
      id: 'fixed-a', provider_id: 'provider-a', currency: 'USD', amount_micros: 500250000, period: 'month', effective_from: '2026-10-01', effective_to: '2026-11-01', note: 'contract-a',
    }))
  })
  it('requires explicit confirmation before deleting a channel cost', async () => {
    const user = userEvent.setup()
    render(<ChannelFixedCostsPanel tenantID="tenant-a" />, { wrapper })
    const row = (await screen.findByText('Provider A')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: removeLabel }))
    expect(billingEmployeeApi.deleteFixedCost).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: confirmLabel }))
    await waitFor(() => expect(billingEmployeeApi.deleteFixedCost).toHaveBeenCalledWith('tenant-a', 'fixed-a'))
  })
  it('disables creation when tenant currency cannot be loaded', async () => {
    vi.mocked(billingEmployeeApi.settings).mockRejectedValue(new Error('offline'))
    render(<ChannelFixedCostsPanel tenantID="tenant-a" />, { wrapper })
    await waitFor(() => expect(screen.getByRole('button', { name: addLabel })).toBeDisabled())
    expect(billingEmployeeApi.saveFixedCost).not.toHaveBeenCalled()
  })
})

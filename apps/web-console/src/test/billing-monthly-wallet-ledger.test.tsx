import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useStatementsSection } from '../components/billing/sections/useStatementsSection'
import ledgerSource from '../components/billing/sections/useStatementsSection.tsx?raw'
import { eventLabels } from '../components/billing/billingFormat'
import { billingAdminApi } from '../services/api'
import { literal } from './billingSourceLabels'

const grantLabel = literal(ledgerSource, /grant: '([^']+)'/)
const expireLabel = literal(ledgerSource, /expire: '([^']+)'/)
function Ledger() { return useStatementsSection({ tenantID: 'tenant-a' } as any).items[0].children }
afterEach(() => { cleanup(); vi.restoreAllMocks() })

it('distinguishes monthly grant and expiry from ordinary wallet credits', async () => {
  const base = { currency: 'CNY', balance_delta_micros: 1000000, reserved_delta_micros: 0, balance_after_micros: 1000000, created_at: '2026-10-12T00:00:00Z', event_type: 'credit' }
  vi.spyOn(billingAdminApi, 'ledger').mockResolvedValue({ data: { data: [
    { ...base, id: 'grant', username: 'monthly-grant', metadata: { monthly_wallet_event: 'grant' } },
    { ...base, id: 'expire', username: 'monthly-expire', balance_delta_micros: -1000000, event_type: 'adjustment', metadata: { monthly_wallet_event: 'expire' } },
    { ...base, id: 'manual', username: 'manual-credit', metadata: {} },
  ], meta: { has_more: false, next_cursor: '' } } } as any)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><Ledger /></QueryClientProvider>)
  for (const [username, expected] of [['monthly-grant', grantLabel], ['monthly-expire', expireLabel], ['manual-credit', eventLabels.credit]]) {
    const row = (await screen.findByText(username)).closest('tr') as HTMLElement
    expect(within(row).getByText(expected)).toBeInTheDocument()
  }
  client.clear()
})

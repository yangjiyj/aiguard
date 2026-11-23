import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import BillingBudgets from '../pages/billing/Budgets'
import BillingPricing from '../pages/billing/Pricing'
import { BILLING_SECTION_LABELS as labels } from '../components/billing/sectionLabels'
import { useAuthStore } from '../stores/auth'
import * as api from '../services/api'

vi.mock('../components/billing/BudgetTree', () => ({ default: () => <div data-testid="budget-tree">budget-tree</div> }))
vi.mock('../components/billing/WalletManagement', () => ({ useWalletManagement: () => ({
  accountsItem: { key: 'customers', label: labels.accounts, children: <div data-testid="wallet-accounts">accounts</div> },
  groupsItem: { key: 'customer-groups', label: labels.groups, children: <div data-testid="wallet-groups">groups</div> },
  redemptionsItem: { key: 'redemptions', label: labels.redemptions, children: <div data-testid="wallet-redemptions">redemptions</div> },
  modals: null,
}) }))
vi.mock('../components/billing/EmployeeAllowancesPanel', () => ({ default: ({ section = 'all' }: { section?: string }) => <div data-testid={`employee-${section}`}>{section}</div> }))
vi.mock('../pages/QuotaPolicies', () => ({ default: () => <div data-testid="limits-panel">limits</div> }))
vi.mock('../components/billing/ModelPricingTable', () => ({ default: () => <div data-testid="model-prices">model-prices</div> }))
vi.mock('../components/billing/UpstreamRatesPanel', () => ({ default: () => <div data-testid="upstream-rates">upstream-rates</div> }))
vi.mock('../components/billing/ChannelFixedCostsPanel', () => ({ default: () => <div data-testid="fixed-costs">fixed-costs</div> }))

const response = (data: unknown) => ({ data: { data } } as any)
let client: QueryClient
beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  useAuthStore.setState({ isAuthenticated: true, token: 'test-token', user: { id: 'admin', role: 'platform_admin', tenant_id: 'tenant-a' } as any })
  vi.spyOn(api.tenantApi, 'list').mockResolvedValue(response([{ id: 'tenant-a', name: 'Tenant A' }]))
  vi.spyOn(api.billingAdminApi, 'runtime').mockResolvedValue(response({ mode: 'metering' }))
  vi.spyOn(api.billingAdminApi, 'models').mockResolvedValue(response([{ model_name: 'model-a', model_label: 'Readable model' }]))
  vi.spyOn(api.billingAdminApi, 'prices').mockResolvedValue(response([]))
  vi.spyOn(api.billingAdminApi, 'tariffs').mockResolvedValue(response([]))
  vi.spyOn(api.billingAdminApi, 'previewTariff').mockResolvedValue(response(null))
})
afterEach(() => { cleanup(); client.clear(); vi.restoreAllMocks() })
const show = (page: React.ReactNode, entry = '/') => render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}>{page}</MemoryRouter></QueryClientProvider>)
const currentPanel = () => screen.getAllByRole('tabpanel').find(panel => !panel.hasAttribute('hidden') && panel.getAttribute('aria-hidden') !== 'true')!

it.each(['platform_admin', 'admin', 'tenant_admin', 'tenant_owner'])('keeps real money and redemption in horizontal wallet tabs for %s', async role => {
  useAuthStore.setState({ user: { id: 'admin', role, tenant_id: 'tenant-a' } as any })
  show(<BillingBudgets />)
  expect(await screen.findByTestId('wallet-accounts')).toBeVisible()
  for (const [label, testId] of [[labels.monthly, 'employee-all'], [labels.redemptions, 'wallet-redemptions'], [labels.groups, 'wallet-groups']]) {
    await userEvent.click(screen.getByRole('tab', { name: label }))
    expect(await within(currentPanel()).findByTestId(testId)).toBeVisible()
    expect(screen.getByTestId('wallet-accounts')).not.toBeVisible()
  }
})

it('keeps scoped quota deep links inside the limits tab', async () => {
  useAuthStore.setState({ user: { id: 'owner', role: 'tenant_admin', tenant_id: 'tenant-a' } as any })
  show(<BillingBudgets />, '/cost/budgets?scope_type=key&scope_id=key-a')
  expect(await screen.findByTestId('limits-panel')).toBeVisible()
  expect(await screen.findByTestId('budget-tree')).toBeVisible()
  expect(screen.getByRole('tab', { name: labels.redemptions })).toBeInTheDocument()
})

it('keeps pricing and the two upstream cost types in separate horizontal tabs', async () => {
  show(<BillingPricing />)
  expect(await screen.findByTestId('model-prices')).toBeVisible()
  for (const [label, testId] of [[labels.upstream, 'upstream-rates'], [labels.fixed, 'fixed-costs']]) {
    await userEvent.click(screen.getByRole('tab', { name: label }))
    expect(await within(currentPanel()).findByTestId(testId)).toBeVisible()
    const other = screen.queryByTestId(testId === 'upstream-rates' ? 'fixed-costs' : 'upstream-rates')
    if (other) expect(other).not.toBeVisible()
  }
})

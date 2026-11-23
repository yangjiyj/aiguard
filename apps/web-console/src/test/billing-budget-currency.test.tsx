import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import BudgetTree from '../components/billing/BudgetTree'
import { useAuthStore } from '../stores/auth'
import { billingEmployeeApi } from '../services/api'

afterEach(() => { cleanup(); vi.restoreAllMocks() })

it('uses the budget denomination in the amount editor', async () => {
  useAuthStore.setState({ user: { id: 'admin', username: 'admin', role: 'tenant_admin', tenant_id: 'qa' } })
  vi.spyOn(billingEmployeeApi, 'budgetTree').mockResolvedValue({ data: { data: {
    kind: 'organization', id: 'qa', name: 'QA-USD', budget_micros: 100000000, used_micros: 0,
    remaining_micros: 100000000, status: 'normal', currency: 'USD', children: [],
  } } } as any)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><BudgetTree tenantID="qa" canEditEmployees /></QueryClientProvider>)
  const row = (await screen.findByText('QA-USD')).closest('tr') as HTMLElement
  const edit = within(row).getAllByRole('button').find(button => !button.hasAttribute('aria-expanded'))
  expect(edit).toBeDefined()
  await userEvent.click(edit!)
  const dialog = await screen.findByRole('dialog')
  expect(dialog.querySelector('.ant-input-number-prefix')?.textContent).toBe('USD')
})

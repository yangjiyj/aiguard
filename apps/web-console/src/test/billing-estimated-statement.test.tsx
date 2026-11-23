import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import MonthlyStatement from '../components/billing/MonthlyStatement'
import statementSource from '../components/billing/MonthlyStatement.tsx?raw'
import { billingAdminApi } from '../services/api'

const estimatedLabel = /title: '([^']+)', key: 'estimated'/.exec(statementSource)![1]
const estimatedSuffix = /\{count\(line\.estimated_requests \|\| 0\)\}([^<]+)<\/Tag>/.exec(statementSource)![1]
afterEach(() => { cleanup(); vi.restoreAllMocks() })

it('shows conservative settlements separately while including them in billed totals', async () => {
  expect(Array.from(estimatedLabel).map(c => c.codePointAt(0))).toEqual([0x4f30, 0x7b97, 0x8ba1, 0x8d39])
  const totals = { model_name: '', requests: 3, total_tokens: 300, billed_micros: 1200000,
    billed_requests: 3, unbilled_requests: 0, unpriced_requests: 0, usage_unknown_requests: 0, failed_requests: 0, estimated_requests: 2 }
  vi.spyOn(billingAdminApi, 'monthlyStatement').mockResolvedValue({ data: { data: {
    month: '2026-10', timezone: 'Asia/Shanghai', currency: 'CNY', total: totals,
    departments: [{ ...totals, department_id: 'qa-dept', department_name: 'QA-Department', employees: [] }],
  } } } as any)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><MonthlyStatement tenantID="qa-tenant" /></QueryClientProvider>)
  const row = (await screen.findByText('QA-Department')).closest('tr') as HTMLElement
  expect(screen.getByRole('columnheader', { name: estimatedLabel })).toBeInTheDocument()
  expect(within(row).getByText('2' + estimatedSuffix)).toBeInTheDocument()
  expect(row).toHaveTextContent('1.20')
})

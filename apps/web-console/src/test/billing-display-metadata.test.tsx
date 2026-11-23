import { afterEach, expect, it } from 'vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import ModelCostDistribution from '../components/billing/ModelCostDistribution'
import EmployeeIdentity from '../components/billing/EmployeeIdentity'
import employeeSource from '../components/billing/EmployeeIdentity.tsx?raw'
import { BILLING_SECTION_LABELS } from '../components/billing/sectionLabels'
import { literal } from './billingSourceLabels'

afterEach(cleanup)

it('shows metadata labels for historical models while keeping every fact amount and original identifier accessible', async () => {
  const modelName = 'jjd-qa-local-model-with-a-long-request-identifier'
  const data = [
    { id: 'archived-model', name: modelName, model_label: 'Archived friendly label', billable_micros: 390 },
    ...Array.from({ length: 9 }, (_, i) => ({ id: 'historical-' + i, name: 'wallet-qa-model-' + i, billable_micros: 0 })),
  ]
  const { container } = render(<ModelCostDistribution data={data} currency="CNY" />)
  expect(container.querySelectorAll('.billing-model-cost-row')).toHaveLength(10)
  expect(container.querySelector('.billing-model-cost-name')).toHaveTextContent('Archived friendly label')
  expect(container.querySelector('.billing-model-cost-name')).not.toHaveTextContent(modelName)
  expect(screen.getAllByText('¥0.000').length).toBeGreaterThan(0)
  expect(screen.getByText('100.0%')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: BILLING_SECTION_LABELS.modelTrace + '：Archived friendly label' }))
  expect(await screen.findByText(modelName)).toBeInTheDocument()
  expect(screen.getByText('archived-model')).toBeInTheDocument()
})

it('keeps technical fallback names and exact dollar fees when no friendly metadata exists', () => {
  const { container } = render(<ModelCostDistribution data={[{ id: 'unlabeled', name: 'wallet-qa-unlabeled', billable_micros: '1' }]} currency="USD" />)
  expect(container.querySelector('.billing-model-cost-name')).toHaveTextContent('wallet-qa-unlabeled')
  expect(screen.getAllByText('USD 0.000').length).toBeGreaterThan(0)
})

it('uses real display fields first and discloses the unchanged login account, user ID and department', async () => {
  const username = 'wallet-qa-long-original-login-name'
  const detailsTitle = literal(employeeSource, /<Popover title="([^"]+)"/)
  const { container } = render(<EmployeeIdentity employee={{ display_name: 'Existing display name', name: 'Existing name', username, user_id: 'user-123', department_id: 'dept-456', department_name: 'Existing department' }} />)
  expect(container.querySelector('.billing-employee-name')).toHaveTextContent('Existing display name')
  expect(container.querySelector('.billing-employee-name')).not.toHaveTextContent(username)
  await userEvent.click(screen.getByRole('button', { name: detailsTitle + '：Existing display name' }))
  const popover = await screen.findByText(detailsTitle)
  const content = popover.closest('.ant-popover') as HTMLElement
  for (const value of [username, 'user-123', 'dept-456', 'Existing department']) expect(within(content).getByText(value)).toBeInTheDocument()
})

it('does not invent a personal name or department when the source only contains a login account', () => {
  const { container } = render(<EmployeeIdentity employee={{ username: 'wallet-qa-login-only' }} />)
  expect(container.querySelector('.billing-employee-name')).toHaveTextContent('wallet-qa-login-only')
})

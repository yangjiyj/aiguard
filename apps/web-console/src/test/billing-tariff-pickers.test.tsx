import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import TariffPlanEditor from '../components/billing/TariffPlanEditor'
import { newTariffRule, serializeTariffRules, tariffEditorCopy as copy } from '../components/billing/tariffTemplates'
afterEach(cleanup)
it('shows midnight in the time picker and saves the full last minute as end_minute 1440', async () => {
  const user = userEvent.setup()
  const save = vi.fn()
  const plan = { name: 'full-day', version: 1, status: 'draft', timezone: 'UTC', rules: serializeTariffRules([newTariffRule('model-a')]) }
  render(<TariffPlanEditor open plan={plan} modelOptions={[{ value: 'model-a', label: 'Model A' }]} loading={false} onCancel={vi.fn()} onSave={save} />)
  expect(screen.getByLabelText(copy.end(1))).toHaveValue('00:00')
  await user.click(screen.getByRole('button', { name: copy.saveDraft }))
  expect(save.mock.calls[0][0].rules[0]).toMatchObject({ start_minute: 0, end_minute: 1440 })
})

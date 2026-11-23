import { expect, it } from 'vitest'
import { billingModeColor, billingModeLabel } from '../components/billing/useBillingContext'

it('uses a valid presentation color and the monetary billing label', () => {
  expect(billingModeColor.metering).toBe('gold')
  expect(Array.from(billingModeLabel.metering).map(c => c.codePointAt(0))).toEqual([0x6309, 0x91cf, 0x8ba1, 0x8d39])
})

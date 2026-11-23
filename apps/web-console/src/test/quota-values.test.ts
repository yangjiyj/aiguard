import { describe, expect, it } from 'vitest'
import {
  cnyStringToMicros,
  MAX_SAFE_QUOTA_INTEGER,
  microsToCNYString,
} from '../components/ai-permissions/quotaValues'

describe('canonical quota money conversion', () => {
  it('converts decimal CNY to exact integer micros', () => {
    expect(cnyStringToMicros('0')).toBe(0)
    expect(cnyStringToMicros('12.345678')).toBe(12_345_678)
    expect(cnyStringToMicros('9007199254.740991')).toBe(MAX_SAFE_QUOTA_INTEGER)
  })

  it.each(['-1', '0.0000001', '1e3', '9007199254.740992', 'NaN'])(
    'rejects unsafe amount %s',
    (value) => expect(() => cnyStringToMicros(value)).toThrow(),
  )

  it('formats micros without binary-float rounding or forced trailing zeros', () => {
    expect(microsToCNYString(0)).toBe('0')
    expect(microsToCNYString(12_345_678)).toBe('12.345678')
    expect(microsToCNYString(200_000_000)).toBe('200')
  })
})

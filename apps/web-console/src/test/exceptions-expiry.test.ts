import { describe, it, expect } from 'vitest'
import { exceptionExpiryToPayload, formatExceptionExpiry } from '../utils/exceptions'

describe('例外有效期', () => {
  it('30d/90d 生成未来的 RFC3339，never 生成哨兵', () => {
    const now = new Date('2026-07-05T00:00:00Z')
    expect(exceptionExpiryToPayload('30d', now)).toBe('2026-08-04T00:00:00.000Z')
    expect(exceptionExpiryToPayload('90d', now)).toBe('2026-10-03T00:00:00.000Z')
    expect(exceptionExpiryToPayload('never', now)).toBe('never')
  })
  it('到期列渲染：null=永久，有值=本地时间', () => {
    expect(formatExceptionExpiry(null)).toBe('永久')
    expect(formatExceptionExpiry(undefined)).toBe('永久')
    expect(formatExceptionExpiry('2026-08-04T00:00:00Z')).not.toBe('永久')
  })
})

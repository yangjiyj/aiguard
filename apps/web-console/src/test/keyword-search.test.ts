import { describe, expect, it } from 'vitest'

import { minimumKeywordLength } from '../utils/keywordSearch'

describe('minimumKeywordLength', () => {
  it('requires three characters for ASCII-only keywords', () => {
    expect(minimumKeywordLength('login')).toBe(3)
    expect(minimumKeywordLength('A-7')).toBe(3)
  })

  it('requires two characters when a keyword contains non-ASCII text', () => {
    expect(minimumKeywordLength('登录')).toBe(2)
    expect(minimumKeywordLength('A登录')).toBe(2)
  })

  it('preserves the existing empty-input fallback', () => {
    expect(minimumKeywordLength('')).toBe(2)
  })
})

import { describe, expect, it } from 'vitest'
import { SEVERITY_LABELS, severityOptions } from '../utils/risk'

const OLD_NAMES = /极高危|严重风险|(?<![命最集])中风险|(?<![命最集])低风险/
const QUOTED_LABEL = /['"`](?:高风险|中风险|低风险|严重风险|极高危)['"`]/
const JSX_TEXT_LABEL = />\s*高风险\s*</
const sources = import.meta.glob<string>(['../**/*.{ts,tsx}', '!../test/**', '!../**/*.test.*'], {
  query: '?raw',
  import: 'default',
  eager: true,
})

const decodeUnicodeEscapes = (text: string) => text.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))

describe('severity labels', () => {
  it('uses one naming scheme', () => {
    expect(SEVERITY_LABELS).toMatchObject({ critical: '严重', high: '高危', medium: '中危', low: '低危' })
    expect(severityOptions().map((option) => option.label)).toEqual(['严重', '高危', '中危', '低危'])
  })

  it('never hard-codes the retired names', () => {
    expect(Object.keys(sources).length).toBeGreaterThan(50)
    const offenders = Object.entries(sources)
      .filter(([, text]) => OLD_NAMES.test(decodeUnicodeEscapes(text)))
      .map(([file]) => file.replace('..', 'src'))
    expect(offenders).toEqual([])
  })

  it('never uses a retired name as a quoted label', () => {
    const offenders = Object.entries(sources)
      .filter(([, text]) => QUOTED_LABEL.test(decodeUnicodeEscapes(text)))
      .map(([file]) => file.replace('..', 'src'))
    expect(offenders).toEqual([])
  })

  it('never uses the retired high-risk name as JSX text', () => {
    const offenders = Object.entries(sources)
      .filter(([, text]) => JSX_TEXT_LABEL.test(decodeUnicodeEscapes(text)))
      .map(([file]) => file.replace('..', 'src'))
    expect(offenders).toEqual([])
  })
})

import { describe, expect, it } from 'vitest'
import { availabilityFlag, firstEventLevel, isThin, msText, qualitySummary, rankAmong, sortQuality, speedLevel, splitUnrecognised } from '../utils/modelQuality'

const a = { provider_id: 'p', model_id: 'a', model_name: 'a', samples: 10, upstream_samples: 10, upstream_successes: 10, first_event_p50_ms: 800, output_tokens_per_sec_p50: 50, success_rate: 1, rpm: 2, tpm: 200 }
const b = { provider_id: 'p', model_id: 'b', model_name: 'b', samples: 30, upstream_samples: 30, upstream_successes: 27, first_event_p50_ms: 5000, output_tokens_per_sec_p50: 10, success_rate: 0.9, rpm: 1, tpm: 50, http_5xx: 3 }
const thin = { provider_id: 'p', model_id: 't', model_name: 't', samples: 3, upstream_samples: 3, upstream_successes: 1, first_event_p50_ms: 100, output_tokens_per_sec_p50: 99, success_rate: 0.33 }
const unknown = { provider_id: '', model_id: '', samples: 100, upstream_samples: 100, upstream_successes: 98, success_rate: 0.98 }

describe('model quality helpers', () => {
  it('keeps absolute latency and speed levels for the detail table', () => {
    expect(firstEventLevel(800)).toBe('good')
    expect(firstEventLevel(3000)).toBe('warn')
    expect(speedLevel(5)).toBe('bad')
    expect(speedLevel(null)).toBe('unknown')
  })
  it('flags only availability below 95% with enough upstream samples, naming the reason', () => {
    expect(availabilityFlag(a)).toBeNull()
    expect(availabilityFlag(b)).toBe('可用率 90.0%')
    expect(availabilityFlag(thin)).toBeNull()
    expect(availabilityFlag({ provider_id: 'p', model_id: 'x', samples: 10, availability: 0.8 })).toBe('可用率 80.0%')
    expect(availabilityFlag({ provider_id: 'p', model_id: 'x' })).toBeNull()
  })
  it('treats fewer than 5 requests as thin', () => {
    expect(isThin(thin)).toBe(true)
    expect(isThin(a)).toBe(false)
    expect(isThin({ provider_id: 'p', model_id: 'x' })).toBe(true)
  })
  it('ranks first token ascending and speed descending among non-thin models only', () => {
    const items = [a, b, thin]
    expect(rankAmong(items, a, 'first')).toEqual({ rank: 1, of: 2 })
    expect(rankAmong(items, b, 'first')).toEqual({ rank: 2, of: 2 })
    expect(rankAmong(items, a, 'speed')).toEqual({ rank: 1, of: 2 })
    expect(rankAmong(items, thin, 'speed')).toBeNull()
    expect(rankAmong([a, { ...b, output_tokens_per_sec_p50: null }], a, 'speed')).toEqual({ rank: 1, of: 1 })
  })
  it('separates entries without model name and id', () => {
    const { known, unknown: rest } = splitUnrecognised([a, unknown, b])
    expect(known.map((x) => x.model_id)).toEqual(['a', 'b'])
    expect(rest).toHaveLength(1)
  })
  it('summarises with sample weighting and counts flagged models as attention', () => {
    const summary = qualitySummary([a, b, thin])
    expect(summary.samples).toBe(43)
    expect(summary.successRate).toBeCloseTo(38 / 43)
    expect(summary.firstEventMs).toBeCloseTo((800 * 10 + 5000 * 30 + 100 * 3) / 43)
    expect(summary.rpm).toBe(3)
    expect(summary.errors).toBe(3)
    expect(summary.attention).toBe(1)
  })
  it('sorts by traffic, first token and speed', () => {
    expect(sortQuality([a, b], 'samples').map((x) => x.model_id)).toEqual(['b', 'a'])
    expect(sortQuality([b, a], 'first').map((x) => x.model_id)).toEqual(['a', 'b'])
    expect(sortQuality([b, a], 'speed').map((x) => x.model_id)).toEqual(['a', 'b'])
    expect(sortQuality([a, b], 'success').map((x) => x.model_id)).toEqual(['b', 'a'])
    expect(msText(12345)).toBe('12.35 s')
  })
})

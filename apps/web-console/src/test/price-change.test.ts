import { describe, expect, it } from 'vitest'
import { buildPriceChange, canonicalExtras, formatExpiry, formatPriceMicros, isZeroPrice, snapshotFromPayload, snapshotFromPrice, writeCount } from '../components/billing/priceChange'
import { directPricePayload, ratioPricePayload, type BillingPrice } from '../components/billing/modelPricing'

const direct = (patch: Partial<BillingPrice> = {}): BillingPrice => ({
  id: 'p1', model_name: 'm', version: 1, pricing_mode: 'direct', currency: 'CNY', status: 'active',
  effective_at: '2026-08-01T00:00:00Z', input_per_million_micros: 4_000_000, output_per_million_micros: 8_000_000,
  has_cached_input_price: false, has_cache_write_price: false, ...patch,
})
const ratio = (patch: Partial<BillingPrice> = {}): BillingPrice => ({
  id: 'r1', model_name: 'm', version: 1, pricing_mode: 'newapi_ratio', currency: 'CNY', status: 'active',
  effective_at: '2026-08-01T00:00:00Z', input_per_million_micros: 0, output_per_million_micros: 0,
  base_input_per_million_micros: 2_000_000, model_ratio_ppm: 1_000_000, completion_ratio_ppm: 4_000_000, ...patch,
})
const payload = (input: number, output: number, extra: Partial<Parameters<typeof directPricePayload>[2]> = {}) => directPricePayload('t', 'm', {
  inputPerMillionYuan: input, outputPerMillionYuan: output, cachedInputPerMillionYuan: null, cacheWritePerMillionYuan: null, pricingExtras: {}, ...extra,
})
const change = (current: BillingPrice | null, body: Record<string, unknown>) => buildPriceChange('m', '模型', current, body)

describe('priceChange 变更集', () => {
  it('完全相同的提交无变化', () => {
    const result = change(direct(), payload(4, 8))
    expect(result).toMatchObject({ changed: false, toZero: false, kind: 'unchanged', changedFields: [] })
    expect(writeCount([result])).toBe(0)
  })

  it('调整价格：保留旧值与新值快照', () => {
    const result = change(direct(), payload(2, 8))
    expect(result).toMatchObject({ changed: true, toZero: false, kind: 'adjust', changedFields: ['input'] })
    expect(result.old?.input).toBe(4_000_000)
    expect(result.next.input).toBe(2_000_000)
  })

  it('非零改成 0/0 判为「改成 0」；只有一侧为 0 不算', () => {
    expect(change(direct(), payload(0, 0))).toMatchObject({ toZero: true, kind: 'to_zero' })
    expect(change(direct(), payload(0, 8))).toMatchObject({ toZero: false, kind: 'adjust' })
    expect(change(direct(), payload(4, 0))).toMatchObject({ toZero: false })
  })

  it('旧价格输入输出一侧非零也算「存在非零」；旧价格本来就是 0/0 则不是改成 0', () => {
    expect(change(direct({ input_per_million_micros: 0 }), payload(0, 0)).toZero).toBe(true)
    expect(change(direct({ input_per_million_micros: 0, output_per_million_micros: 0 }), payload(0, 0))).toMatchObject({ toZero: false, changed: false })
  })

  it('没有旧价格：新增；首次配置 0/0 不算「改成 0」（与后端一致，不需要确认）', () => {
    expect(change(null, payload(1, 2))).toMatchObject({ changed: true, toZero: false, kind: 'new', old: null })
    expect(change(null, payload(0, 0))).toMatchObject({ changed: true, toZero: false, kind: 'new' })
  })

  it('缓存价区分「未设置」与「设置为 0」', () => {
    const none = change(direct(), payload(4, 8))
    expect(none.changed).toBe(false)
    const setZero = change(direct(), payload(4, 8, { cachedInputPerMillionYuan: 0 }))
    expect(setZero).toMatchObject({ changed: true, changedFields: ['cacheRead'] })
    expect(setZero.old?.cacheRead).toBeNull()
    expect(setZero.next.cacheRead).toBe(0)
    const oldSetZero = direct({ has_cached_input_price: true, cached_input_per_million_micros: 0 })
    expect(change(oldSetZero, payload(4, 8, { cachedInputPerMillionYuan: 0 })).changed).toBe(false)
    expect(change(oldSetZero, payload(4, 8)).changedFields).toEqual(['cacheRead'])
    const write = change(direct(), payload(4, 8, { cacheWritePerMillionYuan: 1 }))
    expect(write.changedFields).toEqual(['cacheWrite'])
  })

  it('币种与计费方式变化都算变化', () => {
    expect(change(direct({ currency: 'USD' }), payload(4, 8)).changedFields).toEqual(['currency'])
    expect(change(ratio(), payload(0, 0)).changedFields).toContain('mode')
  })

  it('倍率行：直接价字段恒为 0，不能当成零价格', () => {
    const old = snapshotFromPrice(ratio())
    expect(old.input).toBeNull()
    expect(isZeroPrice(old)).toBe(false)
    expect(change(ratio(), payload(0, 0))).toMatchObject({ toZero: true, kind: 'to_zero' })
    expect(change(ratio(), payload(3, 6))).toMatchObject({ toZero: false, kind: 'adjust' })
  })

  it('倍率模式：基础价=0 或 模型倍率=0 才算清零', () => {
    const ratioBody = (base: number, model: number, completion = 1) => ratioPricePayload('t', 'm', {
      baseInputPerMillionYuan: base, modelRatio: model, completionRatio: completion, cachedInputRatio: null, cacheWriteRatio: null, pricingExtras: {},
    })
    expect(isZeroPrice(snapshotFromPayload(ratioBody(0, 1)))).toBe(true)
    expect(isZeroPrice(snapshotFromPayload(ratioBody(2, 0)))).toBe(true)
    expect(isZeroPrice(snapshotFromPayload(ratioBody(2, 1, 0)))).toBe(false)
    expect(change(ratio(), ratioBody(2, 0, 4))).toMatchObject({ toZero: true, changedFields: ['modelRatioPpm'] })
    expect(change(ratio(), ratioBody(2, 1, 4))).toMatchObject({ changed: false })
    expect(change(ratio(), ratioBody(2, 1, 5)).changedFields).toEqual(['completionRatioPpm'])
    expect(change(ratio(), ratioBody(3, 1, 4)).changedFields).toEqual(['baseInput'])
    const cache = ratioPricePayload('t', 'm', { baseInputPerMillionYuan: 2, modelRatio: 1, completionRatio: 4, cachedInputRatio: 0.1, cacheWriteRatio: 0, pricingExtras: {} })
    expect(change(ratio(), cache).changedFields).toEqual(['cachedRatioPpm', 'cacheWriteRatioPpm'])
    expect(change(ratio({ has_cached_input_ratio: true, cached_input_ratio_ppm: 100_000, has_cache_write_ratio: true, cache_write_ratio_ppm: 0 }), cache).changed).toBe(false)
  })

  it('pricing_extras 用键排序后的规范化 JSON 比较，忽略 undefined；仅附加收费变化单独标记', () => {
    expect(canonicalExtras({ b: 1, a: { d: 2, c: undefined, e: 1 } })).toBe(canonicalExtras({ a: { e: 1, d: 2 }, b: 1 }))
    expect(canonicalExtras(undefined)).toBe(canonicalExtras({}))
    const old = direct({ pricing_extras: { request_per_call_micros: 5, tool_prices_per_thousand_micros: { a: 1, b: 2 } } })
    const same = payload(4, 8, { pricingExtras: { tool_prices_per_thousand_micros: { b: 2, a: 1 }, request_per_call_micros: 5, reasoning_per_million_micros: undefined } })
    expect(change(old, same).changed).toBe(false)
    const diff = payload(4, 8, { pricingExtras: { request_per_call_micros: 6, tool_prices_per_thousand_micros: { a: 1, b: 2 } } })
    expect(change(old, diff)).toMatchObject({ changed: true, extrasChanged: true, kind: 'extras_only', toZero: false })
    expect(change(old, payload(2, 8, { pricingExtras: old.pricing_extras }))).toMatchObject({ extrasChanged: false, kind: 'adjust' })
  })

  it('金额沿用 formatMicrosDecimal 口径（统一 3 位小数）与币种符号', () => {
    expect(formatPriceMicros(4_000_000, 'USD')).toBe('$4.000')
    expect(formatPriceMicros(1_234_567, 'CNY')).toBe('¥1.235')
    expect(formatPriceMicros(null, 'CNY')).toBe('未设置')
    expect(formatPriceMicros(0, 'CNY')).toBe('¥0.000')
  })

  it('失效时间参与比较：当前版本带 expires_at、提交不带时视为变化（后端会新增无失效时间的版本）', () => {
    const expiry = '2099-11-01T00:00:00Z'
    const old = direct({ expires_at: expiry })
    const result = change(old, payload(4, 8))
    expect(result).toMatchObject({ changed: true, kind: 'adjust', toZero: false, changedFields: ['expiresAt'] })
    expect(result.old?.expiresAt).toBe(Date.parse(expiry))
    expect(result.next.expiresAt).toBeNull()
    // 提交里带同样的失效时间则无变化；expires_at 为 null 等价于没有失效时间
    expect(change(old, { ...payload(4, 8), expires_at: expiry }).changed).toBe(false)
    expect(change(direct({ expires_at: null }), payload(4, 8)).changed).toBe(false)
    expect(change(direct({ expires_at: expiry }), { ...payload(4, 8), expires_at: '2099-12-01T00:00:00Z' }).changedFields).toEqual(['expiresAt'])
    expect(snapshotFromPayload(payload(4, 8)).expiresAt).toBeNull()
  })

  it('formatExpiry 按本地时间格式化为 YYYY-MM-DD HH:mm', () => {
    expect(formatExpiry(new Date(2026, 10, 1, 0, 0).getTime())).toBe('2026-11-01 00:00')
    expect(formatExpiry(new Date(2026, 0, 5, 9, 7).getTime())).toBe('2026-01-05 09:07')
    expect(formatExpiry(null)).toBe('无')
  })
})

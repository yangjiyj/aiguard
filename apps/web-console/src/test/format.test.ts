import { describe, it, expect } from 'vitest'
import { compactNumber, formatFull, isCompacted, percentValue, percentText, ratioToPercentText } from '../utils/format'

describe('compactNumber', () => {
  it('< 1 万原样千分位', () => {
    expect(compactNumber(8763)).toBe('8,763')
    expect(compactNumber(0)).toBe('0')
    expect(compactNumber(999)).toBe('999')
    expect(compactNumber(9999)).toBe('9,999')
  })

  it('1 万 ~ 100 万保留 1 位小数', () => {
    expect(compactNumber(12345)).toBe('1.2万')
    expect(compactNumber(924957)).toBe('92.5万')
  })

  it('>= 100 万取整', () => {
    expect(compactNumber(29978834)).toBe('2998万')
    expect(compactNumber(1000000)).toBe('100万')
  })

  it('>= 1 亿保留 2 位小数', () => {
    expect(compactNumber(100000000)).toBe('1.00亿')
    expect(compactNumber(123456789)).toBe('1.23亿')
  })

  it('负数带符号', () => {
    expect(compactNumber(-12345)).toBe('-1.2万')
    expect(compactNumber(-500)).toBe('-500')
  })

  it('容错 null / undefined / NaN', () => {
    expect(compactNumber(null)).toBe('0')
    expect(compactNumber(undefined)).toBe('0')
    expect(compactNumber(NaN)).toBe('0')
  })
})

describe('formatFull', () => {
  it('精确千分位', () => {
    expect(formatFull(29978834)).toBe('29,978,834')
    expect(formatFull(8763)).toBe('8,763')
  })
  it('容错', () => {
    expect(formatFull(null)).toBe('0')
    expect(formatFull(undefined)).toBe('0')
  })
})

describe('isCompacted', () => {
  it('>= 1 万才需要 tooltip', () => {
    expect(isCompacted(9999)).toBe(false)
    expect(isCompacted(10000)).toBe(true)
    expect(isCompacted(null)).toBe(false)
  })
})

describe('percentValue / percentText（入参已是 0~100 的百分数）', () => {
  it('截断浮点长尾，默认保留 1 位', () => {
    // 现网真实案例：应用成功率曾显示 99.55555555555556%
    expect(percentValue(99.55555555555556)).toBe(99.6)
    expect(percentText(99.55555555555556)).toBe('99.6%')
    expect(percentValue(66.66666666666667)).toBe(66.7)
  })

  it('整数与边界值不被改坏', () => {
    expect(percentValue(100)).toBe(100)
    expect(percentValue(0)).toBe(0)
    expect(percentText(100)).toBe('100.0%')
  })

  it('非法值归零，不产生 NaN%', () => {
    expect(percentValue(null)).toBe(0)
    expect(percentValue(undefined)).toBe(0)
    expect(percentValue(Number.NaN)).toBe(0)
    expect(percentText(null)).toBe('0.0%')
  })

  it('可指定小数位', () => {
    expect(percentValue(99.55555555555556, 2)).toBe(99.56)
    expect(percentValue(99.55555555555556, 0)).toBe(100)
  })
})

describe('ratioToPercentText（入参是 0~1 的比率）', () => {
  it('乘 100 后截位', () => {
    expect(ratioToPercentText(0.9955555555)).toBe('99.6%')
    expect(ratioToPercentText(0.8333)).toBe('83.3%')
    expect(ratioToPercentText(1)).toBe('100.0%')
    expect(ratioToPercentText(0)).toBe('0.0%')
  })

  it('非法值归零', () => {
    expect(ratioToPercentText(null)).toBe('0.0%')
    expect(ratioToPercentText(Number.NaN)).toBe('0.0%')
  })

  it('两种口径不可混用：同一个数字走两个函数结果差 100 倍', () => {
    // 后端 stats.go 已乘 100，usage_governance.go 没乘 —— 选错函数就会差 100 倍。
    expect(percentText(83.33)).toBe('83.3%')
    expect(ratioToPercentText(83.33)).toBe('8333.0%')
  })
})

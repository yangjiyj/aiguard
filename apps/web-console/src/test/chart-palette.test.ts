import { readFileSync } from 'node:fs'
import postcss from 'postcss'
import { describe, expect, it } from 'vitest'
import {
  chartColor,
  chartOtherColor,
  chartPalette,
  chartStatusColors,
} from '../utils/chartPalette'

describe('chartPalette', () => {
  it('深浅各 6 色，顺序固定，品牌蓝打头', () => {
    expect(chartPalette(true)).toEqual(['#3987e5', '#d95926', '#199e70', '#9085e9', '#c98500', '#d55181'])
    expect(chartPalette(false)).toEqual(['#2a78d6', '#d4622c', '#17966a', '#6250d6', '#b97f00', '#d4588e'])
  })

  it('同一主题内 6 色互不相同', () => {
    for (const isDark of [true, false]) expect(new Set(chartPalette(isDark)).size).toBe(6)
  })

  it('按下标取色，同一下标结果稳定', () => {
    for (const isDark of [true, false]) {
      chartPalette(isDark).forEach((color, index) => expect(chartColor(isDark, index)).toBe(color))
      expect(chartColor(isDark, 2)).toBe(chartColor(isDark, 2))
    }
  })

  it('第 7 个及以后不循环，也不生成新色，统一用「其他」色', () => {
    for (const isDark of [true, false]) {
      const other = chartOtherColor(isDark)
      expect(chartPalette(isDark)).not.toContain(other)
      for (const index of [6, 7, 12, 100]) expect(chartColor(isDark, index)).toBe(other)
    }
  })

  it('非法下标回落到「其他」色', () => {
    expect(chartColor(true, -1)).toBe(chartOtherColor(true))
    expect(chartColor(false, Number.NaN)).toBe(chartOtherColor(false))
  })

  it('状态色沿用控制台原有的成功/警告/错误色，并与分类色板分开', () => {
    expect(chartStatusColors(true)).toEqual({ ok: '#8bd3b7', warn: '#eac185', high: '#f0a875', danger: '#f0a0a0' })
    expect(chartStatusColors(false)).toEqual({ ok: '#18765e', warn: '#95601b', high: '#c2581d', danger: '#b34444' })
    for (const isDark of [true, false]) {
      for (const color of Object.values(chartStatusColors(isDark))) expect(chartPalette(isDark)).not.toContain(color)
    }
  })
})

// refine.css 里的 --chart-N / --status-* 令牌必须与 chartPalette 一致（页面里的 var(--chart-N) 依赖它）。
describe('refine.css 图表令牌', () => {
  const css = postcss.parse(readFileSync('src/refine.css', 'utf8'))
  const tokens = (isDark: boolean) => {
    const selector = `:root[data-theme='${isDark ? 'dark' : 'light'}']`
    const found: Record<string, string> = {}
    css.walkRules((rule) => {
      if (rule.selector === selector) rule.walkDecls(/^--(chart|status)-/, (decl) => { found[decl.prop] = decl.value.trim().toLowerCase() })
    })
    return found
  }

  it.each([true, false])('isDark=%s 与色板、状态色一致', (isDark) => {
    const found = tokens(isDark)
    chartPalette(isDark).forEach((color, index) => expect(found[`--chart-${index + 1}`]).toBe(color))
    expect(found['--chart-other']).toBe(chartOtherColor(isDark))
    const status = chartStatusColors(isDark)
    expect(found['--status-ok']).toBe(status.ok)
    expect(found['--status-warn']).toBe(status.warn)
    expect(found['--status-high']).toBe(status.high)
    expect(found['--status-danger']).toBe(status.danger)
    expect(found['--chart-7']).toBeUndefined()
  })
})

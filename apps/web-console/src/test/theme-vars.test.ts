import { describe, it, expect, vi, afterEach } from 'vitest'
import { readFileSync } from 'node:fs'
import postcss from 'postcss'
import { createElement } from 'react'
import { render, screen, act } from '@testing-library/react'
import { theme } from 'antd'
import ThemedApp from '../ThemedApp'
import { useThemeStore } from '../stores/theme'

vi.mock('../App', () => ({
  default: () => {
    const { token } = theme.useToken()
    return createElement('output', { 'data-testid': 'resolved-theme' }, JSON.stringify(token))
  },
}))

// CSS 变量在 src/index.css 里定义。曾因误用「不存在的变量名」导致暗色主题下卡片
// background 回退成白底（var(--card-bg) 不存在 → #fff；var(--bg-color) 不存在 → 透明）。
// jsdom 不解析 CSS 变量回退，组件单测查不到样式，所以这里做「源码级护栏」：
// 用 Vite 的 import.meta.glob 把页面/组件源码当字符串读进来，禁止再引用这些拼错的变量名。
// 正确名：--bg-primary（页面底）/ --bg-card（卡片面）/ --bg-elevated（弹层）/ --bg-secondary。
const sources = {
  ...import.meta.glob('../pages/**/*.{ts,tsx}', { query: '?raw', import: 'default', eager: true }),
  ...import.meta.glob('../components/**/*.{ts,tsx}', { query: '?raw', import: 'default', eager: true }),
} as Record<string, string>

const FORBIDDEN = ['--card-bg', '--bg-color']
const globalCss = postcss.parse(readFileSync('src/index.css', 'utf8'))

function cssVariable(isDark: boolean, variable: string): string {
  const selector = `[data-theme=${isDark ? 'dark' : 'light'}]`
  let value: string | undefined
  globalCss.walkRules((rule) => {
    if (rule.selectors.some((item) => item.replace(/\s|['"]/g, '') === selector)) {
      rule.walkDecls(`--${variable}`, (declaration) => { value = declaration.value.trim() })
    }
  })
  if (!value) throw new Error(`Missing CSS variable: ${variable}`)
  return value.replace(/^#([\da-f])([\da-f])([\da-f])$/i, '#$1$1$2$2$3$3')
}

describe('resolved application theme', () => {
  afterEach(() => vi.restoreAllMocks())

  it('keeps explicit light/dark transitions aligned with the resolved root appearance', () => {
    useThemeStore.getState().setMode('light')
    render(createElement(ThemedApp))
    expect(document.documentElement).toHaveAttribute('data-theme', 'light')
    expect(JSON.parse(screen.getByTestId('resolved-theme').textContent || '{}').colorBgContainer).toBe(cssVariable(false, 'bg-card'))
    act(() => useThemeStore.getState().setMode('dark'))
    expect(document.documentElement).toHaveAttribute('data-theme', 'dark')
    expect(JSON.parse(screen.getByTestId('resolved-theme').textContent || '{}').colorBgContainer).toBe(cssVariable(true, 'bg-card'))
  })

  it.each([true, false])('system appearance isDark=%s keeps Antd tokens and CSS surfaces aligned', (isDark) => {
    vi.spyOn(window, 'matchMedia').mockReturnValue({ matches: isDark, addEventListener: vi.fn(), removeEventListener: vi.fn() } as unknown as MediaQueryList)
    useThemeStore.getState().setMode('system')
    render(createElement(ThemedApp))
    expect(document.documentElement).toHaveAttribute('data-theme', isDark ? 'dark' : 'light')
    const token = JSON.parse(screen.getByTestId('resolved-theme').textContent || '{}')
    for (const [name, variable] of Object.entries({
      colorPrimary: 'brand-blue',
      colorSuccess: 'brand-green',
      colorWarning: 'brand-orange',
      colorError: 'brand-red',
      colorBgContainer: 'bg-card',
      colorBgLayout: 'bg-primary',
      colorBgElevated: 'bg-elevated',
      colorText: 'text-primary',
      colorTextSecondary: 'text-secondary',
      colorBorder: 'border-color',
    })) expect(token[name]).toBe(cssVariable(isDark, variable))
    expect(token.fontSize).toBe(14)
    expect(token.borderRadius).toBe(6)
  })
})

describe('theme CSS variables — 暗色主题白底护栏', () => {
  it('扫描到足够多的页面/组件源码', () => {
    expect(Object.keys(sources).length).toBeGreaterThan(10)
  })

  for (const bad of FORBIDDEN) {
    it(`没有任何源码引用不存在的变量 var(${bad})`, () => {
      const hits = Object.entries(sources)
        .filter(([, src]) => src.includes(`var(${bad}`))
        .map(([file]) => file)
      expect(
        hits,
        `var(${bad}) 是不存在的变量名，暗色主题会回退成白底/透明。请改用 --bg-primary / --bg-card / --bg-elevated / --bg-secondary。命中文件:\n${hits.join('\n')}`,
      ).toEqual([])
    })
  }
})

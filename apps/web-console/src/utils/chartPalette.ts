// 控制台统一的图表色板。
// 规则：
// 1. 分类色板固定 6 色、顺序固定，以品牌蓝打头，按实体（模型、供应商、智能体……）取色，不按名次取色。
// 2. 第 7 个及以后的实体不再生成新颜色，统一使用「其他」中性色；调用方应把长尾折叠成一项「其他」。
// 3. 状态色（正常/警告/高危/危险）与分类色板分开，不混用；数值沿用控制台原有的成功/警告/错误色。
// 4. 排行条形图仍用 Charts.tsx 里的单一品牌蓝梯度，避免绿/黄被误读为安全状态。

export const CHART_PALETTE_DARK = ['#3987e5', '#d95926', '#199e70', '#9085e9', '#c98500', '#d55181'] as const
export const CHART_PALETTE_LIGHT = ['#2a78d6', '#d4622c', '#17966a', '#6250d6', '#b97f00', '#d4588e'] as const

export const CHART_OTHER_DARK = '#6b7686'
export const CHART_OTHER_LIGHT = '#8a94a3'

export const CHART_STATUS_DARK = { ok: '#8bd3b7', warn: '#eac185', high: '#f0a875', danger: '#f0a0a0' } as const
export const CHART_STATUS_LIGHT = { ok: '#18765e', warn: '#95601b', high: '#c2581d', danger: '#b34444' } as const

export function chartPalette(isDark: boolean): readonly string[] {
  return isDark ? CHART_PALETTE_DARK : CHART_PALETTE_LIGHT
}

export function chartOtherColor(isDark: boolean): string {
  return isDark ? CHART_OTHER_DARK : CHART_OTHER_LIGHT
}

/** 第 index 个实体的颜色；超出 6 个后一律返回「其他」色，不循环。 */
export function chartColor(isDark: boolean, index: number): string {
  const palette = chartPalette(isDark)
  return Number.isInteger(index) && index >= 0 && index < palette.length ? palette[index] : chartOtherColor(isDark)
}

export function chartStatusColors(isDark: boolean) {
  return isDark ? CHART_STATUS_DARK : CHART_STATUS_LIGHT
}

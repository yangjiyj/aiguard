// 数字展示统一工具。
// 概览卡 / 统计磁贴 / 洞察条等「固定宽度」场景下，大数字（请求数、Token 数）会撑破容器，
// 统一用「万 / 亿」中文单位做紧凑展示；完整值通过 formatFull 放到 tooltip / hint 里。
// 注意：货币金额有独立的 currency store（带符号与精度），不要用本工具压缩。

/**
 * 大数字紧凑展示：万 / 亿 中文单位。
 * - < 1 万：原样千分位（如 8,763）
 * - 1 万 ~ 100 万：保留 1 位小数（如 92.5万）
 * - >= 100 万：取整（如 2998万）
 * - >= 1 亿：保留 2 位小数（如 1.20亿）
 * 用于固定宽度的概览卡 / 统计磁贴，避免数字溢出。
 */
export function compactNumber(value: number | null | undefined): string {
  const n = Number(value)
  if (!Number.isFinite(n) || n === 0) return '0'
  const abs = Math.abs(n)
  const sign = n < 0 ? '-' : ''
  if (abs >= 1_0000_0000) return `${sign}${(abs / 1_0000_0000).toFixed(2)}亿`
  if (abs >= 1_0000) return `${sign}${(abs / 1_0000).toFixed(abs >= 100_0000 ? 0 : 1)}万`
  return `${sign}${Math.round(abs).toLocaleString('zh-CN')}`
}

/**
 * 精确千分位展示，用于 tooltip / hint 里展示完整值。
 */
export function formatFull(value: number | null | undefined): string {
  const n = Number(value)
  if (!Number.isFinite(n)) return '0'
  return Math.round(n).toLocaleString('zh-CN')
}

/**
 * 是否已被紧凑压缩（即 compactNumber 的结果与完整值不同），
 * 用于决定要不要挂 tooltip。< 1 万时无需 tooltip。
 */
export function isCompacted(value: number | null | undefined): boolean {
  const n = Number(value)
  return Number.isFinite(n) && Math.abs(n) >= 1_0000
}

// ---- 百分比 ----
// 后端两种口径并存，务必按数据源选对函数，否则会差 100 倍：
//   - 已乘 100 的百分数：stats.go 的 success_rate（SQL 里写了 100.0 * ...）、cost_percent
//   - 未乘 100 的比率：usage_governance.go 的 success_rate / budget_usage_rate（纯除法）
// 除法结果是浮点，直接渲染会出现 99.55555555555556% 这种长串，必须截位。

/**
 * 百分数（入参已是 0~100）截断到指定小数位，返回数值。
 * 用于 antd <Progress percent> 这类接收数值的组件 —— percent 传浮点会把
 * 全部小数位显示出来。默认保留 1 位。
 */
export function percentValue(value: number | null | undefined, digits = 1): number {
  const n = Number(value)
  if (!Number.isFinite(n)) return 0
  const factor = 10 ** digits
  return Math.round(n * factor) / factor
}

/**
 * 百分数（入参已是 0~100）格式化为带 % 的文本，默认保留 1 位。
 */
export function percentText(value: number | null | undefined, digits = 1): string {
  return `${percentValue(value, digits).toFixed(digits)}%`
}

/**
 * 比率（入参是 0~1）格式化为带 % 的文本，默认保留 1 位。
 * 入参不是 0~1 而是 0~100 时请改用 percentText，否则会多乘 100。
 */
export function ratioToPercentText(value: number | null | undefined, digits = 1): string {
  const n = Number(value)
  if (!Number.isFinite(n)) return `${(0).toFixed(digits)}%`
  return `${(n * 100).toFixed(digits)}%`
}

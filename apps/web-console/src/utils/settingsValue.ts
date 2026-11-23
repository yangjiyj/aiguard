// system_settings 里的值在服务端多存为字符串：布尔是 "true"/"false"，名单是 JSON 字符串数组。

export function settingBool(value: unknown, fallback = false): boolean {
  if (value === undefined || value === null || value === '') return fallback
  return value === true || value === 'true'
}

export function settingList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(String)
  if (typeof value !== 'string' || value.trim() === '') return []
  try {
    const parsed = JSON.parse(value)
    return Array.isArray(parsed) ? parsed.map(String) : []
  } catch {
    return []
  }
}

export function settingChoice<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return allowed.includes(value as T) ? (value as T) : fallback
}

export function settingNumber(value: unknown): number | undefined {
  if (value === undefined || value === null || value === '') return undefined
  const numeric = Number(value)
  return Number.isFinite(numeric) ? numeric : undefined
}

// 只留和基准不同的键。系统设置 GET 会把库里没存的键按环境变量或默认值折算后显示（来源 env/default），
// 保存时只提交用户改动过的键，免得第一次保存就把这些显示值钉进库里。
export function changedEntries(next: Record<string, unknown>, base: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(next).filter(([key, value]) => JSON.stringify(value) !== JSON.stringify(base[key])))
}

// 名单写回时统一成 JSON 字符串数组，去空去重。
export function serializeList(values: unknown): string {
  const list = Array.isArray(values) ? values.map((item) => String(item).trim()).filter(Boolean) : []
  return JSON.stringify(Array.from(new Set(list)))
}

// 系统设置 GET 在 egress_setting_sources 里标出各键生效值的来源（db、env、default、invalid）。只有 invalid
// 要提示：库里存的值无效，实际生效的是部署值，界面显示的不是管理员存进去的那个值。其余来源不加说明。
export const INVALID_SETTING_NOTICE = '配置无效，已用部署值'

export function settingSourceNotice(settings: Record<string, unknown> | undefined, key: string): string | undefined {
  const sources = settings?.egress_setting_sources
  if (!sources || typeof sources !== 'object') return undefined
  return (sources as Record<string, unknown>)[key] === 'invalid' ? INVALID_SETTING_NOTICE : undefined
}

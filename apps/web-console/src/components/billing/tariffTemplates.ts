export type TariffEditorRule = {
  key: string
  model_name: string
  name: string
  band: string
  weekdays: number[]
  special_date?: string
  start_time: string
  end_time: string
  multiplier: number | null
}

export const tariffTemplateOptions = [
  { value: 'workday', label: '工作日峰谷 + 周末优惠' },
  { value: 'night', label: '夜间优惠' },
  { value: 'weekend', label: '周末优惠' },
  { value: 'flat', label: '全天标准' },
  { value: 'custom', label: '自定义' },
]

export const weekdays = [1, 2, 3, 4, 5, 6, 7]
let keySequence = 0
export const newTariffRule = (model: string, overrides: Partial<TariffEditorRule> = {}): TariffEditorRule => ({
  key: `rule-${++keySequence}`, model_name: model, name: '标准时段', band: 'flat',
  weekdays: [...weekdays], start_time: '00:00', end_time: '24:00', multiplier: 1, ...overrides,
})

export const legacyTariffDateMessage = '历史日期方案只读，可停用后新建每周方案。'
export const hasLegacyTariffDates = (plan: any): boolean =>
  (plan?.rules || []).some((rule: any) => rule.special_date !== undefined && rule.special_date !== null && rule.special_date !== '')

export function buildTariffTemplate(template: string, models: string[]): TariffEditorRule[] {
  return [...new Set(models)].flatMap((model) => {
    let rules: TariffEditorRule[]
    switch (template) {
      case 'workday':
        rules = [
          newTariffRule(model, { name: '工作日低谷（凌晨）', band: 'valley', weekdays: [1, 2, 3, 4, 5], end_time: '09:00', multiplier: 0.7 }),
          newTariffRule(model, { name: '工作日高峰', band: 'peak', weekdays: [1, 2, 3, 4, 5], start_time: '09:00', end_time: '18:00', multiplier: 1.2 }),
          newTariffRule(model, { name: '工作日低谷（晚间）', band: 'valley', weekdays: [1, 2, 3, 4, 5], start_time: '18:00', multiplier: 0.7 }),
          newTariffRule(model, { name: '周末优惠', band: 'valley', weekdays: [6, 7], multiplier: 0.8 }),
        ]
        break
      case 'night':
        rules = [newTariffRule(model, { name: '夜间优惠', band: 'valley', end_time: '08:00', multiplier: 0.5 }), newTariffRule(model, { start_time: '08:00' })]
        break
      case 'weekend':
        rules = [newTariffRule(model, { weekdays: [1, 2, 3, 4, 5] }), newTariffRule(model, { name: '周末优惠', band: 'valley', weekdays: [6, 7], multiplier: 0.8 })]
        break
      default: rules = [newTariffRule(model)]
    }
    return rules
  })
}

export const minuteToTime = (minute: number) => `${String(Math.floor(minute / 60)).padStart(2, '0')}:${String(minute % 60).padStart(2, '0')}`
export const timeToMinute = (value: string) => {
  const [hour, minute] = String(value).split(':').map(Number)
  return hour * 60 + minute
}

export function rulesFromPlan(plan: any): TariffEditorRule[] {
  return (plan?.rules || []).map((rule: any) => newTariffRule(rule.model_name || '', {
    name: rule.name, band: rule.band, weekdays: [...(rule.weekdays?.length ? rule.weekdays : weekdays)],
    special_date: rule.special_date?.slice(0, 10), start_time: minuteToTime(rule.start_minute),
    end_time: minuteToTime(rule.end_minute), multiplier: rule.multiplier_ppm / 1_000_000,
  }))
}

export function validateEditorRules(rules: TariffEditorRule[]): string {
  if (!rules.length) return '请至少添加一条时段规则，或选择模型后应用模板'
  const intervals: Array<{ model: string; calendar: string; start: number; end: number; name: string }> = []
  for (const rule of rules) {
    const label = `${rule.model_name || '未选择模型'} / ${rule.name || '未命名时段'}`
    if (!rule.model_name || !rule.name.trim()) return `${label}：请选择模型并填写时段名称`
    if (!/^(?:[01]\d|2[0-3]):[0-5]\d$/.test(rule.start_time) || !/^(?:(?:[01]\d|2[0-3]):[0-5]\d|24:00)$/.test(rule.end_time)) return `${label}：时间格式为 HH:mm，结束时间可填 24:00`
    if (rule.special_date) return legacyTariffDateMessage
    if (!rule.weekdays.length || rule.weekdays.some((day) => day < 1 || day > 7)) return `${label}：请至少选择一天`
    if (rule.multiplier === null || !Number.isFinite(rule.multiplier) || rule.multiplier <= 0 || rule.multiplier > 1000) return `${label}：倍率需大于 0 且不超过 1000`
    const start = timeToMinute(rule.start_time), end = rule.end_time === '00:00' ? 1440 : timeToMinute(rule.end_time)
    if (start === end) return `${label}：开始和结束不能相同，全天请填 00:00–24:00`
    const calendars = rule.weekdays.map((day) => `day:${day}`)
    for (const calendar of calendars) {
      intervals.push({ model: rule.model_name, calendar, start, end: end > start ? end : 1440, name: rule.name })
      if (end < start) {
        const next = `day:${Number(calendar.slice(4)) % 7 + 1}`
        intervals.push({ model: rule.model_name, calendar: next, start: 0, end, name: rule.name })
      }
    }
  }
  for (let i = 0; i < intervals.length; i++) for (let j = i + 1; j < intervals.length; j++) {
    const a = intervals[i], b = intervals[j]
    if (a.model === b.model && a.calendar === b.calendar && a.end > b.start && b.end > a.start) return `${a.model}：「${a.name}」和「${b.name}」时段重叠，请调整时间或星期`
  }
  return ''
}

export function serializeTariffRules(rules: TariffEditorRule[]) {
  const error = validateEditorRules(rules)
  if (error) throw new Error(error)
  return rules.map((rule, index) => ({
    code: `rule-${index + 1}`, name: rule.name.trim(), model_name: rule.model_name, band: rule.band,
    weekdays: rule.weekdays,
    start_minute: timeToMinute(rule.start_time), end_minute: rule.end_time === '00:00' ? 1440 : timeToMinute(rule.end_time),
    multiplier_ppm: Math.round(Number(rule.multiplier) * 1_000_000), priority: rules.length - index,
  }))
}

// Shared copy lets tests use the exact source wording without duplicating CJK.
export const tariffEditorCopy = {
  name: '方案名称', timezone: '计费时区', template: '计费模板', applyModels: '应用到模型',
  selectAll: '全选模型', editModel: '编辑模型', addPeriod: '添加时段',
  copySchedule: '复制当前配置到所选模型', cancel: '取消', saveDraft: '保存草稿',
  saveVersion: '保存为新版本草稿', publish: '保存并发布',
  apply: (count: number) => `应用模板到 ${count} 个模型`,
  ruleName: (index: number) => `时段 ${index} 名称`,
  weekday: (index: number) => `时段 ${index} 星期`,
  start: (index: number) => `时段 ${index} 开始`,
  end: (index: number) => `时段 ${index} 结束`,
  multiplier: (index: number) => `时段 ${index} 倍率`,
  legacyDate: (index: number) => `时段 ${index} 历史日期`,
}

const toSensitiveRuleList = (value: unknown) => {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean)
  return String(value || '').split(/[\n,，]+/).map((item) => item.trim()).filter(Boolean)
}

export type SensitiveRulePayload = {
  name: string
  regex?: string
  category?: string
  severity?: string
  action?: string
  keywords?: string[]
  field_names?: string[]
}

export const buildSensitiveRulePayload = (values: any): SensitiveRulePayload => {
  const matchMode = values.match_mode || 'keyword'
  const payload: SensitiveRulePayload = {
    name: String(values.name || '').trim(),
    keywords: [],
    field_names: [],
    category: values.category || 'customer_sensitive_data',
    severity: values.severity || 'high',
    action: values.action || 'audit',
  }
  if (matchMode === 'keyword') {
    payload.keywords = toSensitiveRuleList(values.keywords)
  } else if (matchMode === 'field_name') {
    payload.field_names = toSensitiveRuleList(values.field_names)
  } else if (matchMode === 'regex') {
    payload.regex = String(values.regex || '').trim()
  }
  return payload
}

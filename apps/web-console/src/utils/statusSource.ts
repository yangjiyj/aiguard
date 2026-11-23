const STATUS_SOURCE_LABELS: Record<string, string> = {
  'system_settings.security_execution_mode': '控制台设置',
  deployment: '部署变量',
  'system_settings.security_audit_only': '系统安全设置',
  safe_default: '默认值',
  settings_unavailable: '读取失败',
  runtime_status_unavailable: '执行热路径状态未上报',
}

const RUNTIME_MODE_LABELS: Record<string, string> = {
  audit_only: '全局仅审计',
  observe: '观察模式',
  per_policy: '按策略执行',
  strict: '严格模式',
  allow: '放行模式',
  audit: '审计模式',
  confirm: '人工确认模式',
  block: '阻断模式',
}

export const getStatusSourceLabel = (source?: string) => {
  const normalized = String(source || '').trim()
  if (!normalized) return '状态来源未识别'
  return STATUS_SOURCE_LABELS[normalized] || '状态来源未识别'
}

export const getRuntimeModeLabel = (mode?: string) => {
  const normalized = String(mode || '').trim()
  return RUNTIME_MODE_LABELS[normalized] || '未识别运行模式'
}

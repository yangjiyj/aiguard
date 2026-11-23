import api from './api'

// 执行模式会定时轮询，单独一个查询键，避免轮询刷新带着别的系统设置表单重置草稿。
// 仍以 'system-settings' 开头，失效 ['system-settings'] 时会一并刷新。
export const SECURITY_EXECUTION_MODE_QUERY_KEY = ['system-settings', 'execution-mode'] as const

export type SecurityExecutionModeValue = 'record' | 'protect'

export interface SecurityExecutionMode {
  configured_mode: SecurityExecutionModeValue
  effective_mode: SecurityExecutionModeValue
  locked: boolean
  source: string
  runtime_verified: boolean
  runtime_status: string
  last_modified_by?: string
  last_modified_at?: string
}

export function normalizeSecurityExecutionMode(settings: unknown): SecurityExecutionMode | undefined {
  const value = (settings as { security_execution_mode?: unknown } | undefined)?.security_execution_mode
  if (!value || typeof value !== 'object') return undefined
  const mode = value as Partial<SecurityExecutionMode>
  if (!['record', 'protect'].includes(mode.configured_mode ?? '') || !['record', 'protect'].includes(mode.effective_mode ?? '')) return undefined
  return mode as SecurityExecutionMode
}

export const securityExecutionModeApi = {
  getSettings: () => api.get<Record<string, unknown>>('/system/settings').then((response) => response.data),
  update: ({ mode, reason }: { mode: SecurityExecutionModeValue; reason: string }) => api.put('/system/settings', {
    security_execution_mode: mode,
    change_reason: reason,
  }),
}

export function securityModeLabel(mode?: SecurityExecutionModeValue): string {
  return mode === 'record' ? '观察留痕' : mode === 'protect' ? '防护阻断' : '待确认'
}

export function securityModeSourceLabel(source?: string): string {
  if (source === 'deployment') return '安装初始配置'
  if (source === 'admin_settings' || source === 'system_setting') return '系统设置'
  if (source === 'safe_default') return '安全默认值'
  return source || '待确认'
}

export function effectiveSecurityAction(configuredAction: string, effectiveMode?: SecurityExecutionModeValue): string {
  if (!effectiveMode) return '实际动作待确认'
  if (effectiveMode === 'record' && ['block', 'confirm', 'mask'].includes(configuredAction)) return '记录/告警放行'
  return configuredAction
}

export function isProtectRunning(mode?: SecurityExecutionMode): boolean {
  return mode?.runtime_verified === true && mode.effective_mode === 'protect'
}

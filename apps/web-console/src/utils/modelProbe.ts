import type { ModelProbeRecord, ProbeProtocol } from '../services/modelOperations'

export const probeProtocolLabels: Record<ProbeProtocol, string> = { chat: 'Chat Completions', responses: 'Responses', messages: 'Claude Messages' }
export const modelOperationError = (error: unknown, fallback: string): string => {
  const value = error as { response?: { status?: number; data?: { error?: { code?: string; message?: string }; message?: string } } }
  if (value?.response?.status === 403) return '当前账号无模型运营权限'
  const code = value?.response?.data?.error?.code
  if (code === 'not_found') return '模型不存在、已停用或不在当前组织，请刷新模型列表后重试'
  if (code === 'invalid_request') return '请求参数无效，请刷新页面后重试'
  if (code === 'cost_confirmation_required') return '请先确认本次验证费用'
  if (code === 'model_operations_conflict') return '模型配置已变化，请刷新后重试'
  return value?.response?.data?.error?.message || value?.response?.data?.message || fallback
}
// 延迟统一以「秒」展示：输入毫秒数值，输出如 "8.39 s"；缺失/非法值如实显示「未知」。
// 全站（模型运营、审计调用明细、SLA、请求诊断等）统一走这一个格式化，禁止再散落 "xxx ms"。
export const formatLatencySeconds = (value?: number | null) => {
  if (value === null || value === undefined || !Number.isFinite(value)) return '未知'
  return `${(value / 1000).toFixed(2)} s`
}
export const probeLatency = formatLatencySeconds
export const probeRecordPassed = (record: ModelProbeRecord) => record.success === true && record.body_validated === true && record.http_status !== null && record.http_status >= 200 && record.http_status < 300

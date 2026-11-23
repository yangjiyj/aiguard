import type { ProtectionAction } from '../services/api'

// 防护动作的统一中文名：防护项、受限文件、例外相关页面都从这里取。
export const ACTION_LABELS: Record<ProtectionAction, string> = {
  record: '仅记录',
  alert_allow: '告警放行',
  confirm: '人工确认',
  block: '阻断',
}

export function actionLabel(action: string): string {
  return ACTION_LABELS[action as ProtectionAction] ?? action
}

// 例外有效期（设计 3c）：创建界面显式选择"永久/到期时间"，NULL=永久（迁移 109）。
export type ExceptionExpiryChoice = '30d' | '90d' | 'never'

export const EXCEPTION_EXPIRY_OPTIONS: { value: ExceptionExpiryChoice; label: string }[] = [
  { value: '30d', label: '30 天后到期' },
  { value: '90d', label: '90 天后到期' },
  { value: 'never', label: '永久生效' },
]

// 后端约定（content_security_config.go）："never" → expires_at=NULL；RFC3339 → 指定到期
export const exceptionExpiryToPayload = (choice: ExceptionExpiryChoice, now = new Date()): string => {
  if (choice === 'never') return 'never'
  const days = choice === '30d' ? 30 : 90
  return new Date(now.getTime() + days * 24 * 60 * 60 * 1000).toISOString()
}

export const formatExceptionExpiry = (expiresAt?: string | null): string => {
  if (!expiresAt) return '永久'
  return new Date(expiresAt).toLocaleString('zh-CN', { hour12: false })
}

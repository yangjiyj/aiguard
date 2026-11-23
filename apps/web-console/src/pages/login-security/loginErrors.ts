import { LOGIN_SECURITY_SETTINGS_TEXT, LOGIN_TEXT, PASSWORD_TEXT } from './text'

// W3 console login security: map backend error codes to UI copy. Unknown codes fall back to a generic message
// so the login page never reveals whether an account exists (the backend already returns one generic 401).

interface ApiErrorBody {
  code?: string
  message?: string
  details?: Record<string, unknown>
}

const errorBody = (error: any): ApiErrorBody => error?.response?.data?.error ?? {}

const numberDetail = (body: ApiErrorBody, key: string, fallback: number): number => {
  const value = body.details?.[key]
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : fallback
}

const retryAfterMinutes = (error: any, body: ApiErrorBody): number => {
  const fromDetails = numberDetail(body, 'retry_after_minutes', 0)
  if (fromDetails > 0) return fromDetails
  const header = Number(error?.response?.headers?.['retry-after'])
  if (Number.isFinite(header) && header > 0) return Math.max(1, Math.ceil(header / 60))
  return 30
}

export const isTotpRequired = (error: any): boolean =>
  error?.response?.status === 401 && errorBody(error).code === 'totp_required'

export function loginErrorMessage(error: any, totpStep: boolean): string {
  const body = errorBody(error)
  const status = error?.response?.status
  if (status === 423 || body.code === 'account_locked') {
    return LOGIN_TEXT.locked(retryAfterMinutes(error, body))
  }
  switch (body.code) {
    case 'invalid_captcha':
      return LOGIN_TEXT.invalidCaptcha
    case 'login_ip_not_allowed':
      return LOGIN_TEXT.ipNotAllowed
    default:
      return totpStep ? LOGIN_TEXT.totpFailure : LOGIN_TEXT.genericFailure
  }
}

// Only same-origin relative paths or http(s) URLs are accepted, so a misconfigured status endpoint
// cannot turn the SSO button into a javascript: link.
export function safeSsoLoginUrl(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.trim() === '') return null
  const value = raw.trim()
  if (value.startsWith('/') && !value.startsWith('//')) return value
  try {
    const url = new URL(value)
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.toString() : null
  } catch {
    return null
  }
}

export function passwordErrorMessage(error: any, fallback: string): string {
  const body = errorBody(error)
  switch (body.code) {
    case 'password_too_short':
      return PASSWORD_TEXT.tooShort(numberDetail(body, 'min_length', 12))
    case 'password_too_few_classes':
      return PASSWORD_TEXT.tooFewClasses(numberDetail(body, 'min_classes', 3))
    case 'password_contains_username':
      return PASSWORD_TEXT.containsUsername
    case 'password_reused':
      return PASSWORD_TEXT.reused(numberDetail(body, 'history_count', 5))
    case 'invalid_password':
      return PASSWORD_TEXT.wrongCurrent
    default:
      return fallback
  }
}

// Mirrors the backend default policy for instant feedback; the backend remains authoritative
// (an administrator may raise the limits, which then surface via passwordErrorMessage).
// Classification order matches handler.passwordCharClasses (unicode upper, lower, decimal digit, other).
export function passwordCharClasses(password: string): number {
  let upper = false
  let lower = false
  let digit = false
  let other = false
  for (const ch of password) {
    if (/\p{Lu}/u.test(ch)) upper = true
    else if (/\p{Ll}/u.test(ch)) lower = true
    else if (/\p{Nd}/u.test(ch)) digit = true
    else other = true
  }
  return [upper, lower, digit, other].filter(Boolean).length
}

export function loginSecuritySaveError(error: any): string {
  return errorBody(error).code === 'allowlist_excludes_current_ip'
    ? LOGIN_SECURITY_SETTINGS_TEXT.excludesCurrentIp
    : LOGIN_SECURITY_SETTINGS_TEXT.invalid
}

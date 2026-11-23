import { cnyStringToMicros } from '../ai-permissions/quotaValues'

// 预算树上直接改组织/部门月预算：后端 PUT /policies/quota 是整条覆盖写，
// 所以必须把已有策略的其他字段（Token、日预算、RPM/TPM/并发、执行模式、时区）原样回写，
// 只替换要改的金额，绝不能因为“只改预算”把限流或执行模式清掉。

type Money = { micros: number | null; blocked: boolean }

// 读出的金额：优先微元字段；只有旧口径元字段时转成微元，0 仍表示“本级不限”。
export function passthroughMoney(data: Record<string, any>, period: 'daily' | 'monthly'): Money {
  if (data[period + '_budget_blocked'] === true) return { micros: null, blocked: true }
  const microsKey = period + '_budget_micros'
  if (Object.prototype.hasOwnProperty.call(data, microsKey)) {
    const value = data[microsKey]
    return { micros: value === null || value === undefined ? null : Number(value), blocked: false }
  }
  const legacy = data[period + '_budget_limit']
  if (legacy === null || legacy === undefined || legacy === '') return { micros: null, blocked: false }
  try {
    return { micros: cnyStringToMicros(String(legacy)), blocked: false }
  } catch {
    return { micros: null, blocked: false }
  }
}

const count = (value: unknown) => (value === null || value === undefined ? null : Number(value))

export function quotaPayloadWithBudget(
  loaded: Record<string, any>,
  scopeType: 'tenant' | 'team' | 'user',
  scopeId: string,
  change: { monthlyMicros?: number | null },
) {
  const data = loaded || {}
  const monthly = passthroughMoney(data, 'monthly')
  const daily = passthroughMoney(data, 'daily')
  const nextMonthly: Money = change.monthlyMicros === undefined ? monthly : { micros: change.monthlyMicros, blocked: false }
  const overage = data.overage_action === 'rate_limit' ? 'rate_limit' : 'notify'
  return {
    scope_type: scopeType,
    scope_id: scopeId,
    project_id: '',
    daily_token_limit: count(data.daily_token_limit),
    daily_token_blocked: data.daily_token_blocked === true,
    monthly_token_limit: count(data.monthly_token_limit),
    monthly_token_blocked: data.monthly_token_blocked === true,
    daily_budget_micros: daily.micros,
    daily_budget_blocked: daily.blocked,
    monthly_budget_micros: nextMonthly.micros,
    monthly_budget_blocked: nextMonthly.blocked,
    rpm_limit: count(data.rpm_limit),
    rpm_blocked: data.rpm_blocked === true,
    tpm_limit: count(data.tpm_limit),
    tpm_blocked: data.tpm_blocked === true,
    concurrency_limit: count(data.concurrency_limit),
    concurrency_blocked: data.concurrency_blocked === true,
    overage_action: overage,
    enforcement_mode: data.enforcement_mode || 'soft',
    quota_timezone: String(data.quota_timezone || 'Asia/Shanghai').trim(),
  }
}

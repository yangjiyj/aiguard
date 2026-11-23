import { describe, expect, it } from 'vitest'
import { quotaPayloadWithBudget, passthroughMoney } from '../components/billing/budgetQuota'
import { parseCsv, toCsv, validateAllowanceRows, ALLOWANCE_CSV_HEADER } from '../components/billing/allowanceCsv'

describe('预算写入：只改金额，不动限流与执行模式', () => {
  const loaded = {
    daily_token_limit: 1000, daily_token_blocked: false, monthly_token_limit: null, monthly_token_blocked: true,
    daily_budget_limit: 3, daily_budget_blocked: false,
    monthly_budget_micros: 200_000_000, monthly_budget_blocked: false,
    rpm_limit: 60, rpm_blocked: false, tpm_limit: 12000, tpm_blocked: false,
    concurrency_limit: null, concurrency_blocked: true,
    overage_action: 'rate_limit', enforcement_mode: 'enforce', quota_timezone: 'UTC',
  }
  it('修改月预算时其余字段原样回写，旧口径日预算转成微元而不是被清空', () => {
    const payload = quotaPayloadWithBudget(loaded, 'team', 't1', { monthlyMicros: 500_000_000 })
    expect(payload).toMatchObject({
      scope_type: 'team', scope_id: 't1', project_id: '',
      monthly_budget_micros: 500_000_000, monthly_budget_blocked: false,
      daily_budget_micros: 3_000_000, daily_budget_blocked: false,
      daily_token_limit: 1000, monthly_token_limit: null, monthly_token_blocked: true,
      rpm_limit: 60, tpm_limit: 12000, concurrency_limit: null, concurrency_blocked: true,
      overage_action: 'rate_limit', enforcement_mode: 'enforce', quota_timezone: 'UTC',
    })
  })
  it('接口给出微元字段时以微元为准（与配额表单同口径）', () => {
    expect(passthroughMoney({ daily_budget_micros: null, daily_budget_limit: 3 }, 'daily')).toEqual({ micros: null, blocked: false })
  })
  it('清除预算写 null；没有已有策略时用默认值', () => {
    const payload = quotaPayloadWithBudget({}, 'tenant', '', { monthlyMicros: null })
    expect(payload).toMatchObject({ monthly_budget_micros: null, monthly_budget_blocked: false, enforcement_mode: 'soft', overage_action: 'notify', quota_timezone: 'Asia/Shanghai', rpm_limit: null })
  })
  it('未知超额动作回落为仅提醒（后端只接受两种）', () => {
    expect(quotaPayloadWithBudget({ overage_action: 'block' }, 'team', 't', {}).overage_action).toBe('notify')
  })
  it('禁止状态原样保留', () => {
    expect(passthroughMoney({ monthly_budget_blocked: true, monthly_budget_micros: null }, 'monthly')).toEqual({ micros: null, blocked: true })
  })
})

describe('员工月额度 CSV', () => {
  const employees = [
    { user_id: 'u1', username: 'alice', department_name: '研发部' },
    { user_id: 'u2', username: '=bob', department_name: '财务部' },
    { user_id: 'u5', username: 'eve' },
    { user_id: 'u6', username: 'frank' },
  ]
  it('导出表头全中文，防公式注入，带 BOM', () => {
    const text = toCsv([ALLOWANCE_CSV_HEADER, ['=bob', '财务部', '100.00']])
    expect(text.startsWith('﻿员工账号,部门,月额度（元）')).toBe(true)
    expect(text).toContain("'=bob")
  })
  it('解析引号、逗号与 BOM', () => {
    expect(parseCsv('﻿a,"b,c","d""e"\r\nx,,z\n')).toEqual([['a', 'b,c', 'd"e'], ['x', '', 'z']])
  })
  it('预览拦住负数、未知员工、非法金额与重复行；空金额表示跟随默认额度', () => {
    const rows = parseCsv([
      '员工账号,部门,月额度（元）',
      'alice,研发部,100.5',
      "'=bob,财务部,",
      'carol,研发部,50',
      'alice,研发部,20',
      'dave,,-5',
      'eve,,abc',
      'frank,,1.234',
    ].join('\n'))
    const preview = validateAllowanceRows(rows, employees)
    expect(preview.headerError).toBe('')
    const byLine = Object.fromEntries(preview.rows.map((row) => [row.line, row]))
    expect(byLine[2]).toMatchObject({ ok: true, userId: 'u1', micros: 100_500_000 })
    expect(byLine[3]).toMatchObject({ ok: true, userId: 'u2', micros: null })
    expect(byLine[4]).toMatchObject({ ok: false, error: '系统中没有这个员工' })
    expect(byLine[5]).toMatchObject({ ok: false, error: '同一员工重复出现' })
    expect(byLine[6]).toMatchObject({ ok: false })
    expect(byLine[6].error).toMatch(/不能为负数|没有这个员工/)
    expect(byLine[7]).toMatchObject({ ok: false, error: '金额格式不对，请填数字' })
    expect(byLine[8]).toMatchObject({ ok: false, error: '金额最多两位小数' })
    expect(preview.validCount).toBe(2)
    expect(preview.errorCount).toBe(5)
  })
  it('已知员工的负数额度单独报“不能为负数”', () => {
    const preview = validateAllowanceRows(parseCsv('员工账号,部门,月额度（元）\nalice,,-1'), employees)
    expect(preview.rows[0]).toMatchObject({ ok: false, error: '月额度不能为负数' })
  })
  it('表头不对直接拒绝', () => {
    expect(validateAllowanceRows(parseCsv('user,amount\nalice,1'), employees).headerError).toMatch(/表头/)
  })
})

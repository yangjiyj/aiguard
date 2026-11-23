import { describe, expect, it } from 'vitest'
import { buildRuleEvidences, hasDirectApiCallLabel } from '../utils/contentAuditEvidence'

// 「直接 API 调用」是请求识别标签：新事件放在 matched_summary.request_labels，存量事件里是一条
// 不计入安全发现的 finding。两种来源都要能在界面上看到「直接调用」，且都不算命中证据。
describe('直接调用识别标签', () => {
  const highRisk = { category: 'illegal_system_command_instructions', severity: 'high', rule_id: 'rule_high_cmd' }

  it('读新事件的 request_labels', () => {
    const events = [{ id: 'e1', matched_summary: { findings: [highRisk], request_labels: ['agent_direct_api_call'] } }]
    expect(hasDirectApiCallLabel(events)).toBe(true)
    expect(buildRuleEvidences(events).map((item) => item.category)).toEqual(['illegal_system_command_instructions'])
  })

  it('兼容存量事件里的观察 finding', () => {
    const legacy = { category: 'agent_direct_api_call', severity: 'low', counts_as_security_finding: false }
    const events = [{ id: 'e2', matched_summary: { findings: [legacy, highRisk] } }]
    expect(hasDirectApiCallLabel(events)).toBe(true)
    expect(buildRuleEvidences(events).map((item) => item.category)).toEqual(['illegal_system_command_instructions'])
  })

  it('没有标签时不显示', () => {
    expect(hasDirectApiCallLabel([{ id: 'e3', matched_summary: { findings: [highRisk] } }])).toBe(false)
    expect(hasDirectApiCallLabel([])).toBe(false)
  })
})

import { describe, expect, it } from 'vitest'
import type { SecurityPolicy } from '../services/securityPoliciesApi'
import {
  classifyPolicyScene,
  describeEffectiveAction,
  describeSemanticEffectiveAction,
  modeCustomerLabel,
  policyHasSemanticJudge,
} from '../pages/security-policy/policyCenterEnterpriseModel'

const policy = (scene: string, categories: string[] = []) => ({
  scene,
  capabilities: categories.map((category) => ({ category })),
}) as Pick<SecurityPolicy, 'scene' | 'capabilities'>

describe('政企策略中心适配层', () => {
  it('集中归类五类安全业务场景并把访问治理和未知类别留给高级维护', () => {
    expect(classifyPolicyScene(policy('data_leak'))).toBe('sensitive-data')
    expect(classifyPolicyScene(policy('data_security'))).toBe('sensitive-data')
    expect(classifyPolicyScene(policy('custom_rules', ['file_archive_scan']))).toBe('file-security')
    expect(classifyPolicyScene(policy('content_safety'))).toBe('content-safety')
    expect(classifyPolicyScene(policy('prompt_injection'))).toBe('prompt-security')
    expect(classifyPolicyScene(policy('agent_detect', ['tool_destructive_intent']))).toBe('agent-tools')
    expect(classifyPolicyScene(policy('model_access'))).toBe('model-access')
    expect(classifyPolicyScene(policy('future_scene'))).toBe('other')
  })

  it('兼容实际 record/protect 与历史 observe/audit/strict 的客户表达', () => {
    expect(modeCustomerLabel('record')).toBe('观察留痕')
    expect(modeCustomerLabel('observe')).toBe('观察留痕')
    expect(modeCustomerLabel('audit')).toBe('告警运营')
    expect(modeCustomerLabel('protect')).toBe('防护阻断')
    expect(modeCustomerLabel('strict')).toBe('防护阻断')
  })

  it.each([
    ['observe + block', { configuredAction: 'block', globalMode: 'observe' }, 'audit', true],
    ['audit + block', { configuredAction: 'block', globalMode: 'audit' }, 'audit', true],
    ['strict + block', { configuredAction: 'block', globalMode: 'strict' }, 'block', false],
    ['strict + confirm', { configuredAction: 'confirm', globalMode: 'strict' }, 'confirm', false],
  ])('%s', (_name, input, effectiveAction, clamped) => {
    expect(describeEffectiveAction(input)).toMatchObject({ effectiveAction, clamped })
  })

  // 2.9.22 删掉了 hardFloor 参数（不再有不读配置的强制拦截），这里只保留审计总开关钳制的断言。
  it('audit-only 把 strict、block 钳制为记录并告警', () => {
    expect(describeEffectiveAction({ configuredAction: 'block', globalMode: 'strict', auditOnly: true })).toMatchObject({
      effectiveAction: 'audit',
      clamped: true,
      source: 'global-ceiling',
    })
    expect(describeEffectiveAction({ configuredAction: 'block', globalMode: 'strict', auditOnly: true }).explanation).not.toMatch(/绝对上限|强制保护规则/)
  })

  it('停用策略不参与执行，后端有效动作优先于前端预期', () => {
    expect(describeEffectiveAction({ configuredAction: 'block', globalMode: 'strict', enabled: false }).effectiveLabel).toBe('已停用')
    expect(describeEffectiveAction({ configuredAction: 'block', globalMode: 'strict', backendEffectiveAction: 'audit' })).toMatchObject({
      effectiveAction: 'audit',
      source: 'runtime',
      clamped: true,
    })
  })

  it('未知枚举保守降级，不显示为已生效', () => {
    const display = describeEffectiveAction({ configuredAction: 'future_action', globalMode: 'future_mode' })
    expect(display.configuredLabel).toContain('未知动作')
    expect(display.effectiveLabel).toBe('待运行时确认')
    expect(display.source).toBe('unknown')
  })
})

describe('智能分析（语义裁判）有效处置', () => {
  it('只有绑定智能分析能力的策略才显示智能分析处置', () => {
    expect(policyHasSemanticJudge({ capabilities: [{ category: 'semantic_jailbreak', semantic_judge: true }] } as Pick<SecurityPolicy, 'capabilities'>)).toBe(true)
    expect(policyHasSemanticJudge({ capabilities: [{ category: 'keyword_roleplay' }] } as Pick<SecurityPolicy, 'capabilities'>)).toBe(false)
  })

  it('配拦截且防护模式：如实显示拦截并提示高置信时拦截、分析不可用时放行', () => {
    const display = describeSemanticEffectiveAction({ semanticAction: 'block', globalMode: 'protect' })
    expect(display).toMatchObject({ blocking: true, label: '智能分析：拦截（高置信时拦截、分析不可用时放行）' })
    expect(display?.explanation).toContain('拦截阈值')
    expect(display?.label).not.toContain('仅告警')
  })

  it('配拦截但非防护模式或审计总开关：显示当前仅记录并告警', () => {
    for (const input of [
      { semanticAction: 'block' as const, globalMode: 'record' },
      { semanticAction: 'block' as const, globalMode: 'audit' },
      { semanticAction: 'block' as const, globalMode: 'protect', auditOnly: true },
    ]) {
      expect(describeSemanticEffectiveAction(input)).toMatchObject({ blocking: false, label: '智能分析：当前仅记录并告警' })
    }
  })

  it('缺省与仅记录不拦截，停用策略不显示', () => {
    expect(describeSemanticEffectiveAction({ globalMode: 'protect' })).toMatchObject({ blocking: false, label: '智能分析：记录并告警' })
    expect(describeSemanticEffectiveAction({ semanticAction: 'observe', globalMode: 'protect' })).toMatchObject({ blocking: false, label: '智能分析：仅记录' })
    expect(describeSemanticEffectiveAction({ semanticAction: 'block', globalMode: 'protect', enabled: false })).toBeUndefined()
  })
})

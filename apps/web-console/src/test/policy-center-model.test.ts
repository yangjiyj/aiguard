import { describe, expect, it } from 'vitest'
import type { SecurityPolicy } from '../services/securityPoliciesApi'
import {
  aggregatePolicyCenterStatus,
  buildSecurityCapabilityCoverage,
  filterCustomerVisiblePolicies,
  hasHealthyRuntimeReceipt,
  POLICY_CENTER_SCENES,
  policiesForScene,
  severityActionMismatch,
} from '../pages/security-policy/policyCenterModel'

const policy = (overrides: Partial<SecurityPolicy> = {}): SecurityPolicy => ({
  id: 'policy-1',
  name: '测试策略',
  description: '',
  scene: 'content_safety',
  severity: 'medium',
  action: 'audit',
  enabled: true,
  source: 'system',
  ownership: 'platform',
  origin: 'preloaded',
  detection_basis: 'capability',
  detection_configured: true,
  detection_ready: true,
  runtime_active: true,
  capabilities: [],
  ...overrides,
})

describe('policyCenterModel', () => {
  it('保留所有预置策略和客户自建策略，未配置项也不得隐藏', () => {
    const visible = filterCustomerVisiblePolicies([
      policy({ id: 'ready-preloaded' }),
      policy({ id: 'management-only', detection_configured: false, detection_ready: false }),
      policy({ id: 'customer-draft', origin: 'organization_created', detection_configured: false, detection_ready: false, enabled: false }),
    ])

    expect(visible.map((item) => item.id)).toEqual(['ready-preloaded', 'management-only', 'customer-draft'])
  })

  it('逐项列出检测能力并标明未绑定项', () => {
    const boundPolicy = policy({
      id: 'bound-policy',
      capabilities: [{
        category: 'phone_cn',
        name: '手机号',
        kind: 'static',
        enabled: true,
        binding_mode: 'any',
        supported_stages: ['input', 'output'],
        allowed_actions: ['audit', 'mask', 'block'],
        mask_capable: true,
      }],
    })
    const coverage = buildSecurityCapabilityCoverage([
      boundPolicy.capabilities[0],
      {
        category: 'debug_secret_template',
        name: 'debug_secret_template',
        kind: 'static',
        enabled: true,
        supported_stages: ['input', 'output'],
        allowed_actions: ['audit', 'block'],
        mask_capable: false,
      },
    ], [boundPolicy])

    expect(coverage).toHaveLength(2)
    expect(coverage[0].policies.map((item) => item.id)).toEqual(['bound-policy'])
    expect(coverage[1]).toMatchObject({
      capability: { category: 'debug_secret_template' },
      policies: [],
    })
  })

  it('按稳定场景键归并 Prompt 注入策略', () => {
    const scene = POLICY_CENTER_SCENES.find((item) => item.key === 'prompt-injection')
    expect(scene).toBeDefined()
    expect(policiesForScene([
      policy({ id: 'injection', scene: 'prompt_injection' }),
      policy({ id: 'leak', scene: 'prompt_leak' }),
      policy({ id: 'content', scene: 'content_safety' }),
    ], scene!)).toHaveLength(2)
  })

  it('只有健康回执才允许进入记录中或保护中', () => {
    expect(hasHealthyRuntimeReceipt(true, 'verified')).toBe(true)
    expect(hasHealthyRuntimeReceipt(false, 'verified')).toBe(false)
    expect(hasHealthyRuntimeReceipt(true, 'applied_with_stale_nodes')).toBe(false)
  })

  it('全局记录模式和保护模式分别返回实际处理动作', () => {
    const policies = [policy({ action: 'block' })]

    expect(aggregatePolicyCenterStatus({
      policies,
      auditOnly: true,
      runtimeVerified: true,
      runtimeStatus: 'verified',
    })).toMatchObject({ key: 'recording', label: '记录中', currentAction: '仅记录' })

    expect(aggregatePolicyCenterStatus({
      policies,
      auditOnly: false,
      runtimeVerified: true,
      runtimeStatus: 'verified',
    })).toMatchObject({ key: 'protecting', label: '保护中', currentAction: '阻止发送' })
  })

  it('没有启用策略或没有回执时返回客户可执行状态', () => {
    expect(aggregatePolicyCenterStatus({
      policies: [policy({ enabled: false })],
      auditOnly: false,
      runtimeVerified: true,
      runtimeStatus: 'verified',
    }).key).toBe('disabled')

    expect(aggregatePolicyCenterStatus({
      policies: [policy()],
      auditOnly: false,
      runtimeVerified: false,
      runtimeStatus: 'degraded',
    })).toMatchObject({ key: 'error', label: '运行异常' })
  })

  it('新版本等待回执时明确说明上一版配置继续运行', () => {
    expect(aggregatePolicyCenterStatus({
      policies: [policy({ action: 'block' })],
      auditOnly: false,
      runtimeVerified: false,
      runtimeStatus: 'pending',
    })).toMatchObject({
      key: 'syncing',
      label: '新配置同步中',
      currentAction: '原配置继续运行',
    })
  })
})

describe('severity and action mismatch', () => {
  it('flags only the two contradictory combinations', () => {
    expect(severityActionMismatch({ severity: 'critical', action: 'audit' })).toBe('严重级别的策略只记录不阻断')
    expect(severityActionMismatch({ severity: 'low', action: 'block' })).toBe('低危级别的策略会阻断请求')
    expect(severityActionMismatch({ severity: 'medium', action: 'block' })).toBe('')
    expect(severityActionMismatch({ severity: 'critical', action: 'block' })).toBe('')
  })
})

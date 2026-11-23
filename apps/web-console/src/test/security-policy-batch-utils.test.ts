import { describe, expect, it } from 'vitest'
import type { SecurityPolicy, SecurityPolicyCapability } from '../services/securityPoliciesApi'
import {
  batchActionAvailability,
  partitionPoliciesForBatchChange,
  partitionPoliciesForBatchAction,
  policySupportsBatchAction,
} from '../utils/securityPolicyBatch'

const capability = (
  category: string,
  allowedActions: SecurityPolicyCapability['allowed_actions'],
  overrides: Partial<SecurityPolicyCapability> = {},
): SecurityPolicyCapability => ({
  category,
  name: category,
  kind: 'static',
  enabled: true,
  supported_stages: ['input'],
  allowed_actions: allowedActions,
  mask_capable: allowedActions.includes('mask'),
  ...overrides,
})

const policy = (overrides: Partial<SecurityPolicy> = {}): SecurityPolicy => ({
  id: 'policy-1',
  name: '测试策略',
  description: '',
  scene: 'data_leak',
  severity: 'high',
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

describe('策略批量动作兼容性', () => {
  it('混合选择时保留动作并统计支持与跳过数量', () => {
    const result = batchActionAvailability([
      policy({ capabilities: [capability('phone_cn', ['audit', 'mask', 'block'])] }),
      policy({
        id: 'policy-2',
        capabilities: [capability('semantic', ['audit'], {
          kind: 'dynamic',
          mask_capable: false,
          semantic_judge: true,
        })],
      }),
    ])

    expect(result.audit).toEqual({ available: true, supportedCount: 2, unsupportedCount: 0 })
    expect(result.mask).toEqual({ available: true, supportedCount: 1, unsupportedCount: 1 })
    expect(result.block).toEqual({ available: true, supportedCount: 1, unsupportedCount: 1 })
  })

  it('只有精确正则识别策略支持批量脱敏', () => {
    expect(policySupportsBatchAction(policy({
      detection_basis: 'matcher',
      capabilities: [],
      matcher: { type: 'regex', config: { regex: '\\d{11}' } },
    }), 'mask')).toBe(true)
    expect(policySupportsBatchAction(policy({
      detection_basis: 'matcher',
      capabilities: [],
      matcher: { type: 'keyword', config: { keywords: ['手机号'] } },
    }), 'mask')).toBe(false)
  })

  it('未配置识别条件时只允许预设审计', () => {
    const draft = policy({
      enabled: false,
      detection_basis: 'none',
      detection_configured: false,
      detection_ready: false,
      runtime_active: false,
      capabilities: [],
    })

    expect(policySupportsBatchAction(draft, 'audit')).toBe(true)
    expect(policySupportsBatchAction(draft, 'block')).toBe(false)
    expect(policySupportsBatchAction(draft, 'mask')).toBe(false)
  })

  it('检测未就绪时允许审计降级但跳过脱敏和阻断', () => {
    const unavailable = policy({
      enabled: true,
      detection_ready: false,
      runtime_active: false,
      capabilities: [capability('phone_cn', ['audit', 'mask', 'block'])],
    })

    expect(policySupportsBatchAction(unavailable, 'audit')).toBe(true)
    expect(policySupportsBatchAction(unavailable, 'mask')).toBe(false)
    expect(policySupportsBatchAction(unavailable, 'block')).toBe(false)
    expect(partitionPoliciesForBatchAction([unavailable], 'audit')).toEqual({
      applicable: [unavailable],
      skipped: [],
    })
  })

  it('联合修改时启用未就绪策略整条跳过并返回明确原因', () => {
    const unavailable = policy({
      enabled: false,
      detection_ready: false,
      runtime_active: false,
      capabilities: [],
    })

    expect(partitionPoliciesForBatchChange([unavailable], {
      action: 'audit',
      enabled: true,
    })).toEqual({
      applicable: [],
      skipped: [{ policy: unavailable, reason: 'detection_not_ready' }],
    })
  })

  it('未配置识别依据的策略不会通过批量动作伪装成已生效', () => {
    const unavailable = policy({
      enabled: false,
      detection_basis: 'none',
      detection_configured: false,
      detection_ready: false,
      runtime_active: false,
      capabilities: [],
    })

    expect(partitionPoliciesForBatchChange([unavailable], {
      action: 'audit',
    })).toEqual({
      applicable: [],
      skipped: [{ policy: unavailable, reason: 'detection_not_ready' }],
    })
  })

  it('停用未就绪策略不增加限制', () => {
    const unavailable = policy({
      enabled: true,
      detection_ready: false,
      runtime_active: false,
      capabilities: [],
    })

    expect(partitionPoliciesForBatchChange([unavailable], {
      enabled: false,
    })).toEqual({
      applicable: [unavailable],
      skipped: [],
    })
  })

  it('全部不兼容时动作不可提交', () => {
    const unavailable = policy({
      detection_basis: 'matcher',
      capabilities: [],
      matcher: { type: 'keyword', config: { keywords: ['手机号'] } },
    })

    expect(batchActionAvailability([unavailable]).mask).toEqual({
      available: false,
      supportedCount: 0,
      unsupportedCount: 1,
    })
  })
})

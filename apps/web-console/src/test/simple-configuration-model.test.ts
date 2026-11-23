import { describe, expect, it, vi } from 'vitest'
import type { SecurityPolicy } from '../services/securityPoliciesApi'
import {
  changedPolicyUpdates,
  saveAgentBehaviorDrafts,
} from '../pages/security-policy/simpleConfigurationModel'

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

describe('simpleConfigurationModel', () => {
  it('只返回管理员实际修改的策略更新', () => {
    expect(changedPolicyUpdates(
      [policy({ id: 'unchanged', action: 'block' }), policy({ id: 'changed' })],
      [
        { id: 'unchanged', action: 'block' },
        { id: 'changed', action: 'block', enabled: true },
      ],
    )).toEqual([{ id: 'changed', action: 'block', enabled: true }])
  })

  it('每次保存前读取最新版本，跳过未改和状态异常的行为', async () => {
    const versions = ['v1', 'v2', 'v3']
    const load = vi.fn(async () => ([
      { key: 'system_command', configured_action: 'record', version: versions.shift() ?? 'v4', health: 'ok' },
      { key: 'sensitive_resource', configured_action: 'alert_allow', version: 'same', health: 'ok' },
      { key: 'network_egress', configured_action: 'record', version: 'unavailable', health: 'error', health_message: '状态异常' },
    ] as never))
    const save = vi.fn(async () => undefined)

    const results = await saveAgentBehaviorDrafts({
      order: ['system_command', 'sensitive_resource', 'network_egress'],
      drafts: {
        system_command: 'block',
        sensitive_resource: 'alert_allow',
        network_egress: 'block',
      },
      load,
      save,
    })

    expect(load).toHaveBeenCalledTimes(3)
    expect(save).toHaveBeenCalledWith('system_command', { action: 'block', version: 'v1' })
    expect(results).toEqual([
      { key: 'system_command', status: 'saved', previousAction: 'record', requestedAction: 'block' },
      { key: 'network_egress', status: 'skipped', previousAction: 'record', requestedAction: 'block', message: '状态异常' },
    ])
  })
})

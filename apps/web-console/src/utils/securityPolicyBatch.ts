import type { SecurityPolicy, SecurityPolicyAction } from '../services/securityPoliciesApi'

export type BatchPolicyAction = Exclude<SecurityPolicyAction, 'allow'>

export type BatchActionAvailability = {
  available: boolean
  supportedCount: number
  unsupportedCount: number
}

export type BatchActionPartition = {
  applicable: SecurityPolicy[]
  skipped: SecurityPolicy[]
}

export type BatchSkipReason = 'detection_not_ready' | 'action_unsupported'

export type BatchPolicyChange = {
  action?: BatchPolicyAction
  enabled?: boolean
}

export type BatchSkippedPolicy = {
  policy: SecurityPolicy
  reason: BatchSkipReason
}

export type BatchChangePartition = {
  applicable: SecurityPolicy[]
  skipped: BatchSkippedPolicy[]
}

function matcherIsRegex(policy: SecurityPolicy): boolean {
  const matcher = policy.matcher
  return matcher?.type === 'regex'
    || matcher?.config?.regex !== undefined
    || matcher?.regex !== undefined
}

export function policySupportsBatchAction(
  policy: SecurityPolicy,
  action: BatchPolicyAction,
): boolean {
  if (action === 'audit') return true
  if (!policy.detection_ready) return false
  if (policy.capabilities.length > 0) {
    return policy.capabilities.every((capability) => (
      capability.enabled
      && capability.allowed_actions.includes(action)
      && (action !== 'mask' || capability.mask_capable)
    ))
  }
  if (action === 'mask') return matcherIsRegex(policy)
  return true
}

export function partitionPoliciesForBatchAction(
  policies: SecurityPolicy[],
  action: BatchPolicyAction,
): BatchActionPartition {
  const applicable: SecurityPolicy[] = []
  const skipped: SecurityPolicy[] = []
  policies.forEach((policy) => {
    if (policySupportsBatchAction(policy, action)) applicable.push(policy)
    else skipped.push(policy)
  })
  return { applicable, skipped }
}

export function partitionPoliciesForBatchChange(
  policies: SecurityPolicy[],
  change: BatchPolicyChange,
): BatchChangePartition {
  const applicable: SecurityPolicy[] = []
  const skipped: BatchSkippedPolicy[] = []

  policies.forEach((policy) => {
    if ((change.enabled === true || Boolean(change.action)) && !policy.detection_ready) {
      skipped.push({ policy, reason: 'detection_not_ready' })
      return
    }
    if (change.action && !policySupportsBatchAction(policy, change.action)) {
      skipped.push({
        policy,
        reason: !policy.detection_ready
          ? 'detection_not_ready'
          : 'action_unsupported',
      })
      return
    }
    applicable.push(policy)
  })

  return { applicable, skipped }
}

export function batchActionAvailability(
  policies: SecurityPolicy[],
): Record<BatchPolicyAction, BatchActionAvailability> {
  return Object.fromEntries((['audit', 'mask', 'block'] as BatchPolicyAction[]).map((action) => {
    const { applicable, skipped } = partitionPoliciesForBatchAction(policies, action)
    const supportedCount = applicable.length
    const unsupportedCount = skipped.length
    return [action, {
      available: supportedCount > 0,
      supportedCount,
      unsupportedCount,
    }]
  })) as Record<BatchPolicyAction, BatchActionAvailability>
}

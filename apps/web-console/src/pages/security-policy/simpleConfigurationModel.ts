import type {
  PolicyCenterAgentBehavior,
  PolicyCenterAgentBehaviorAction,
  SecurityPolicy,
  SecurityPolicyBatchUpdate,
} from '../../services/securityPoliciesApi'

export type SaveItemResult = {
  key: string
  status: 'saved' | 'failed' | 'skipped'
  previousAction: string
  requestedAction: string
  message?: string
}

export function changedPolicyUpdates(
  policies: SecurityPolicy[],
  updates: SecurityPolicyBatchUpdate[],
): SecurityPolicyBatchUpdate[] {
  const policiesByID = new Map(policies.map((policy) => [policy.id, policy]))
  return updates.filter((update) => {
    const policy = policiesByID.get(update.id)
    return Boolean(policy && (
      (update.action !== undefined && update.action !== policy.action)
      || (update.enabled !== undefined && update.enabled !== policy.enabled)
    ))
  })
}

export type SaveAgentBehaviorDraftsInput = {
  order: readonly string[]
  drafts: Partial<Record<string, PolicyCenterAgentBehaviorAction>>
  load: () => Promise<PolicyCenterAgentBehavior[]>
  save: (
    key: string,
    input: { action: PolicyCenterAgentBehaviorAction; version: string },
  ) => Promise<unknown>
}

function agentSaveErrorLabel(error: unknown): string {
  if ((error as { response?: { status?: number } } | undefined)?.response?.status === 409) {
    return '配置已被其他人修改，请确认后重试'
  }
  return '保存失败，原配置继续生效'
}

export async function saveAgentBehaviorDrafts({
  order,
  drafts,
  load,
  save,
}: SaveAgentBehaviorDraftsInput): Promise<SaveItemResult[]> {
  const results: SaveItemResult[] = []
  for (const key of order) {
    const latest = await load()
    const item = latest.find((candidate) => candidate.key === key)
    const requested = drafts[key]
    if (!item || !requested || requested === item.configured_action) continue
    if (item.health === 'error') {
      results.push({
        key,
        status: 'skipped',
        previousAction: item.configured_action,
        requestedAction: requested,
        message: item.health_message || '当前状态异常，暂不可保存',
      })
      continue
    }
    try {
      await save(key, { action: requested, version: item.version })
      results.push({
        key,
        status: 'saved',
        previousAction: item.configured_action,
        requestedAction: requested,
      })
    } catch (error) {
      results.push({
        key,
        status: 'failed',
        previousAction: item.configured_action,
        requestedAction: requested,
        message: agentSaveErrorLabel(error),
      })
    }
  }
  return results
}

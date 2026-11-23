import { useQuery } from '@tanstack/react-query'
import { useEffect } from 'react'
import { Tabs, Tag } from 'antd'
import { useSearchParams } from 'react-router-dom'
import { EnterprisePageHeader } from '../components/EnterpriseUI'
import { useSecurityExecutionMode } from '../hooks/useSecurityExecutionMode'
import { useAuthStore } from '../stores/auth'
import { securityPoliciesApi } from '../services/securityPoliciesApi'
import AgentBehaviorPolicy from './security-policy/AgentBehaviorPolicy'
import SequenceRuleSettings from './agentguard/SequenceRuleSettings'
import AgentOperationProtection from './AgentOperationProtection'
import AgentProtectionCards from './security-policy/AgentProtectionCards'
import { canAccessPath, canManageSecurityPolicy } from '../utils/access'

const AGENT_BEHAVIOR_QUERY_KEY = ['policy-center', 'agent-behaviors'] as const

export default function AgentBehaviorControl() {
  const role = useAuthStore((state) => state.user?.role)
  const [params, setParams] = useSearchParams()
  const canManage = canManageSecurityPolicy(role)
  const advancedAllowed = canAccessPath(role, '/security/agent-operation-protection/advanced')
  const requestedTab = params.get('tab')
  const focusProtection = params.get('protection') || undefined
  const restrictedFileFocused = focusProtection === 'agent.restricted_file'
  const focusBehavior = params.get('behavior') || (restrictedFileFocused ? 'sensitive_resource' : undefined)
  const activeTab = requestedTab === 'advanced' && advancedAllowed ? 'advanced' : 'policies'
  useEffect(() => {
    if (requestedTab !== 'overview') return
    const next = new URLSearchParams(params)
    next.delete('tab')
    setParams(next, { replace: true })
  }, [params, requestedTab, setParams])
  const query = useQuery({
    queryKey: AGENT_BEHAVIOR_QUERY_KEY,
    queryFn: () => securityPoliciesApi.agentBehaviors(),
  })
  const securityModeQuery = useSecurityExecutionMode()

  const loadItems = async () => {
    const response = await securityPoliciesApi.agentBehaviors()
    return response.data.items
  }

  return (
    <div className="enterprise-page security-agent-behavior-page">
      <EnterprisePageHeader
        eyebrow="安全护栏"
        title="智能体行为管控"
      />
      <Tabs activeKey={activeTab} onChange={(tab) => {const next = new URLSearchParams(params);next.set('tab', tab);setParams(next)}} items={[
        {key: 'policies', label: '行为策略', children: <>
      {!canManage && <Tag>只读</Tag>}
      <AgentBehaviorPolicy
        items={query.data?.data?.items ?? []}
        auditOnly={securityModeQuery.mode ? securityModeQuery.mode.effective_mode === 'record' : undefined}
        canManage={canManage}
        focusKey={focusBehavior}
        restrictedFileFocused={restrictedFileFocused}
        loadItems={loadItems}
        onReload={async () => { await query.refetch({ throwOnError: true }) }}
        isLoading={query.isLoading || securityModeQuery.isLoading}
        isError={query.isError || securityModeQuery.isError}
      />
      <AgentProtectionCards canManage={canManage} />
      <SequenceRuleSettings
        item={(query.data?.data?.items ?? []).find((entry) => entry.key === 'network_egress')}
        canManage={canManage && !query.isError && !securityModeQuery.isError}
        onSaved={async () => { await query.refetch({ throwOnError: true }) }}
      />
        </>},
        ...(advancedAllowed ? [{key: 'advanced', label: '高级规则', children: <AgentOperationProtection />}]: []),
      ]} />
    </div>
  )
}

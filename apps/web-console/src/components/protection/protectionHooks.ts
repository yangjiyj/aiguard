import { useEffect, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import {
  agentGuardApi,
  protectionSettingsApi,
  type ProtectionGroup,
  type ProtectionSettingItem,
} from '../../services/api'
import type { AgentExceptionPrefill } from './AgentExceptionModal'

export const PROTECTION_SETTINGS_QUERY_KEY = ['protection-settings'] as const
export const AGENT_EXCEPTIONS_QUERY_KEY = ['agentguard', 'exceptions'] as const

function isProtectionItem(value: unknown): value is ProtectionSettingItem {
  const item = value as ProtectionSettingItem | undefined
  return Boolean(item && typeof item.key === 'string' && typeof item.label === 'string' && Array.isArray(item.actions))
}

export function useProtectionSettings() {
  return useQuery({
    queryKey: PROTECTION_SETTINGS_QUERY_KEY,
    queryFn: async () => {
      const response = await protectionSettingsApi.list()
      const items = (response.data as { items?: unknown } | undefined)?.items
      return Array.isArray(items) ? items.filter(isProtectionItem) : []
    },
  })
}

// 某一组的防护项；按查询结果缓存，刷新出同样内容时不换新数组。
export function useProtectionGroupItems(group: ProtectionGroup) {
  const query = useProtectionSettings()
  const items = useMemo(() => (query.data ?? []).filter((item) => item.group === group), [query.data, group])
  return { query, items }
}

type AgentExceptionRow = { rule_id?: string; enabled?: boolean; expires_at?: string | null }

function exceptionRows(response: unknown): AgentExceptionRow[] {
  const raw = response as { data?: unknown } | undefined
  const data = raw?.data as { data?: unknown } | unknown[] | undefined
  if (Array.isArray(data)) return data as AgentExceptionRow[]
  if (Array.isArray((data as { data?: unknown } | undefined)?.data)) return (data as { data: AgentExceptionRow[] }).data
  return []
}

// 智能体工具例外按关联规则计数；停用的、已过期的不算。
export function useAgentExceptionCounts(): Record<string, number> {
  const query = useQuery({ queryKey: AGENT_EXCEPTIONS_QUERY_KEY, queryFn: agentGuardApi.listExceptions })
  return useMemo(() => {
    const now = Date.now()
    const counts: Record<string, number> = {}
    for (const row of exceptionRows(query.data)) {
      const rule = String(row.rule_id ?? '').trim()
      if (!rule || row.enabled === false) continue
      const expires = row.expires_at ? Date.parse(row.expires_at) : NaN
      if (Number.isFinite(expires) && expires < now) continue
      counts[rule] = (counts[rule] ?? 0) + 1
    }
    return counts
  }, [query.data])
}

// 页面带 ?protection=<键>、?protection_group=<组>，以及拦截记录附带的 rule/target：
// 定位并高亮，加例外时预填。
export function useProtectionFocus() {
  const [params] = useSearchParams()
  const focusKey = params.get('protection') || undefined
  const focusGroup = params.get('protection_group') || undefined
  const rule = params.get('rule') || undefined
  const target = params.get('target') || undefined
  const prefillFor = (itemKey: string): AgentExceptionPrefill => {
    const fromLink = itemKey === focusKey
    return {
      scope_type: 'tenant',
      rule_id: fromLink && rule ? rule : itemKey,
      target_pattern: fromLink ? target ?? '' : '',
    }
  }
  return { focusKey, focusGroup, prefillFor }
}

// 等目标出现后滚过去。
export function useScrollToElement(elementId: string | undefined, ready: boolean) {
  useEffect(() => {
    if (!elementId || !ready) return
    const timer = window.setTimeout(() => {
      document.getElementById(elementId)?.scrollIntoView?.({ block: 'center' })
    }, 0)
    return () => window.clearTimeout(timer)
  }, [elementId, ready])
}

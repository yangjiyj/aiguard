import type { AgentEvent, AgentSession, EnrollmentCreated } from '../../services/agentEndpoint.types'

export const secretVisible = (created: EnrollmentCreated | null) => Boolean(created?.token)
export interface TimelineEntry { pre: AgentEvent; post?: AgentEvent }
export function mergeToolEvents(events: AgentEvent[]): TimelineEntry[] {
  const sorted = [...events].sort((a,b) => Date.parse(a.occurred_at) - Date.parse(b.occurred_at))
  const entries: TimelineEntry[] = []
  const pending = new Map<string,TimelineEntry>()
  for (const event of sorted) {
    const key = `${event.session_id}:${event.tool_use_id}`
    if (event.event_type === 'tool.post' && event.tool_use_id && pending.has(key)) {
      pending.get(key)!.post = event
      pending.delete(key)
    } else {
      const entry = {pre:event}
      entries.push(entry)
      if (event.event_type === 'tool.pre' && event.tool_use_id) pending.set(key,entry)
    }
  }
  return entries
}
const sensitive = new Set(['content','text','prompt','output','result','command','arguments','args','token','authorization','secret','evidence','raw','raw_evidence'])
export function redactRaw(value:unknown,allowed:boolean):unknown {
  if (allowed || value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map(item=>redactRaw(item,false))
  const object = value as Record<string,unknown>
  const out:Record<string,unknown> = {}
  for (const [key,child] of Object.entries(object)) {
    if (sensitive.has(key.toLowerCase())) {
      if (child && typeof child === 'object' && !Array.isArray(child)) {
        out[key]=Object.fromEntries(Object.entries(child).filter(([k])=>k==='hash'||k==='length'||k.endsWith('_hash')||k.endsWith('_length')))
      } else {
        const hash=object[`${key}_hash`]??object.hash
        const length=object[`${key}_length`]??object[`${key}_len`]??object.length
        out[key]=hash||length?{hash:hash??'未提供',length:length??'未提供'}:'内容已脱敏'
      }
    } else out[key]=redactRaw(child,false)
  }
  return out
}
export function firstStoredLocalDecisionEvent(events: AgentEvent[]): AgentEvent | undefined {
  return events.find(event => event.event_type === 'tool.pre' && Object.keys(event.local_decision || {}).length > 0)
    || events.find(event => Object.keys(event.local_decision || {}).length > 0)
}

export function eventRiskLevel(event: AgentEvent): string {
  const risk = event.local_decision?.risk_level
  return typeof risk === 'string' ? risk.trim() : ''
}

export function exactToolPreEvents(
  events: AgentEvent[],
  session: Pick<AgentSession, 'session_id' | 'endpoint_id'> | null | undefined,
  tool: { id?: string | null; session_id?: string | null; endpoint_id?: string | null; tool_call_id?: string | null } | null | undefined,
): AgentEvent[] {
  const sessionID = session?.session_id || ''
  const endpointID = session?.endpoint_id || ''
  const toolLogID = tool?.id || ''
  const toolUseID = tool?.tool_call_id || ''
  if (!sessionID || !endpointID || !toolLogID || !toolUseID
    || tool?.session_id !== sessionID || tool?.endpoint_id !== endpointID) return []
  return events.filter(event => event.event_type === 'tool.pre'
    && event.tool_call_log_id === toolLogID
    && event.endpoint_id === endpointID
    && event.session_id === sessionID
    && event.tool_use_id === toolUseID)
}

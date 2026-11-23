import { apiClient } from './api'
import { useAuthStore } from '../stores/auth'
import { auditQueryIdentity } from '../hooks/useAuditQueryIdentity'
import type { AgentEndpoint, AgentEndpointFilters, AgentSession, AgentSessionDetail, AgentSessionFilters, AgentOverview, AgentAsset, AgentEvent, AgentPolicyBundle, EnrollmentCreated, EnrollmentToken, Page } from './agentEndpoint.types'

const root = '/agent'
const agentQueryScope = () => ['agent', auditQueryIdentity(useAuthStore.getState().user)] as const
export const agentKeys = {
  get scope() { return agentQueryScope() },
  get overview() { return [...agentQueryScope(), 'overview'] as const },
  endpoints: (params: AgentEndpointFilters) => [...agentQueryScope(), 'endpoints', params] as const,
  endpoint: (id: string) => [...agentQueryScope(), 'endpoint', id] as const,
  assets: (endpointId: string, page: number, pageSize = 100) => [...agentQueryScope(), 'assets', endpointId, page, pageSize] as const,
  enrollment: (page: number) => [...agentQueryScope(), 'enrollment', page] as const,
  sessions: (params: AgentSessionFilters) => [...agentQueryScope(), 'sessions', params] as const,
  session: (id: string) => [...agentQueryScope(), 'session', id] as const,
  events: (sessionId: string, page: number) => [...agentQueryScope(), 'events', sessionId, page] as const,
}
export const agentEndpointApi = {
  currentPolicyBundle: async () => (await apiClient.get<AgentPolicyBundle>(`${root}/policy-bundles/current`)).data,
  todayEvents: async (from: string, to: string) => (await apiClient.get<Page<AgentEvent>>(`${root}/events`, { params: { from, to, page: 1, page_size: 1 } })).data,
  overview: async () => (await apiClient.get<AgentOverview>(`${root}/overview`)).data,
  endpoints: async (params: AgentEndpointFilters) => (await apiClient.get<Page<AgentEndpoint>>(`${root}/endpoints`, { params })).data,
  endpoint: async (id: string) => (await apiClient.get<AgentEndpoint>(`${root}/endpoints/${encodeURIComponent(id)}`)).data,
  updateMode: async (id: string, changes: { mode?: string | null; capture_level?: string | null }) => (await apiClient.put<AgentEndpoint>(`${root}/endpoints/${encodeURIComponent(id)}/mode`, changes)).data,
  rotateToken: async (id: string) => (await apiClient.post<{ endpoint_id: string; endpoint_token: string }>(`${root}/endpoints/${encodeURIComponent(id)}/rotate-token`)).data,
  revokeEndpoint: async (id: string) => (await apiClient.post(`${root}/endpoints/${encodeURIComponent(id)}/revoke`)).data,
  assets: async (endpoint_id: string, page = 1, page_size = 100) => (await apiClient.get<Page<AgentAsset>>(`${root}/assets`, { params: { endpoint_id, page, page_size } })).data,
  enrollment: async (page: number) => (await apiClient.get<Page<EnrollmentToken>>(`${root}/enrollment-tokens`, { params: { page, page_size: 20 } })).data,
  createEnrollment: async (body: { name: string; default_mode: string; allowed_products: string[]; max_endpoints: number; expires_at?: string | null }) => (await apiClient.post<EnrollmentCreated>(`${root}/enrollment-tokens`, body)).data,
  revokeEnrollment: async (id: string) => (await apiClient.post(`${root}/enrollment-tokens/${encodeURIComponent(id)}/revoke`)).data,
  sessions: async (params: AgentSessionFilters) => (await apiClient.get<Page<AgentSession>>(`${root}/sessions`, { params })).data,
  session: async (id: string) => (await apiClient.get<AgentSessionDetail>(`${root}/sessions/${encodeURIComponent(id)}`)).data,
  events: async (session_id: string, page: number) => (await apiClient.get<Page<AgentEvent>>(`${root}/events`, { params: { session_id, page, page_size: 50 } })).data,
}

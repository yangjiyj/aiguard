import { apiClient } from './api'

export type ProbeProtocol = 'chat' | 'responses' | 'messages'
export interface ModelOperationFilters {
  provider_id?: string
  model_id?: string
  window_hours?: number
  source?: 'manual' | 'scheduled'
  state?: string
  cursor?: string
  limit?: number
}
export interface ModelOperationTarget {
  model_id: string
  model_name: string
  provider_id: string
  provider_name: string
  upstream_model_id: string
  protocol: ProbeProtocol
  config_digest?: string
  supported?: boolean
}
export interface ModelProbeRecord extends ModelOperationTarget {
  id: string
  source: 'manual' | 'scheduled'
  success: boolean
  http_status: number | null
  body_validated: boolean
  latency_ms: number | null
  error_kind?: string
  error_message?: string
  created_at: string
  config_version?: number
  epoch?: number
  invocation_id?: string
}
export interface ProbeHour {
  hour: string
  samples: number
  successes: number
  availability: number | null
  p50_ms: number | null
  p95_ms: number | null
}
export interface ModelTargetSummary extends ModelOperationTarget {
  state: 'healthy' | 'degraded' | 'stale' | 'unknown'
  samples: number
  successes: number
  availability: number | null
  p50_ms: number | null
  p95_ms: number | null
  last_probe_at: string | null
  last_error?: string
  hourly: ProbeHour[]
}
export interface ModelOperationsConfig {
  version: number
  enabled: boolean
  interval_seconds: number
  concurrency: number
  timeout_seconds: number
  max_targets: number
  max_output_tokens: number
  protocols: ProbeProtocol[]
  failure_threshold: number
  updated_at?: string
  updated_by?: string
  cost_confirmed_at?: string | null
}
export interface ModelOperationAlert extends ModelOperationTarget {
  id: string
  state: 'open' | 'resolved'
  error_kind?: string
  message?: string
  failure_count?: number
  opened_at: string
  last_seen_at?: string
  last_error?: string
  updated_at?: string
  resolved_at?: string | null
  acknowledged_at?: string | null
  acknowledged_by?: string | null
}
export interface ModelQualityItem {
  first_event_p50_ms?: number | null
  first_event_p95_ms?: number | null
  output_tokens_per_sec_p50?: number | null
  security_p50_ms?: number | null
  security_p95_ms?: number | null
  pre_upstream_p50_ms?: number | null
  pre_upstream_p95_ms?: number | null
  rpm?: number | null
  tpm?: number | null
  provider_id: string
  provider_name?: string
  model_id: string
  model_name?: string
  samples?: number
  total?: number
  successes?: number
  success_rate?: number | null
  availability?: number | null
  http_5xx?: number
  http_429?: number
  http_4xx?: number
  cancelled?: number
  p50_ms?: number | null
  p95_ms?: number | null
  avg_ttft_ms?: number | null
  avg_first_event_ms?: number | null
  failures?: number
  auth_failures?: number
  upstream_samples?: number
  upstream_successes?: number
  blocked?: number
  last_request_id?: string
  last_error?: string
}
export interface CursorPage<T> { items: T[]; next_cursor?: string | null }
export interface ModelOperationsOverview {
  targets: ModelTargetSummary[]
  generated_at?: string
  config: ModelOperationsConfig
}
export interface ModelOperationsQuality { items: ModelQualityItem[]; next_cursor?: string | null; counts?: Record<string, number>; generated_at?: string }
export interface ModelProbeJob {
  job_id: string
  state: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'interrupted'
  total: number
  completed: number
  items: ModelProbeRecord[]
  skipped?: Array<ModelOperationTarget & { reason: string }>
  error_code?: string
  created_at?: string
  updated_at?: string
  completed_at?: string | null
}
export interface ModelSLAMetrics {
  requests: number
  eligible_requests: number
  http_successes: number
  platform_failures: number
  client_errors: number
  auth_failures: number
  cancelled: number
  blocked: number
  unknown: number
  availability: number | null
  p50_ms: number | null
  p95_ms: number | null
  first_event_p50_ms: number | null
  first_event_p95_ms: number | null
  first_event_samples: number
  active_minutes: number
  down_minutes: number
  minute_availability: number | null
}
export interface ModelSLAMonth {
  month: string
  timezone: string
  start_at: string
  end_at: string
  generated_at: string
  observed_until: string
  in_progress: boolean
  available: boolean
  totals: ModelSLAMetrics
  models: Array<ModelSLAMetrics & { model_id: string; model_name: string; provider_id: string; provider_name: string }>
  days: Array<ModelSLAMetrics & { day: string }>
  note?: string
}
export interface ModelSLAFilter { month: string; timezone: string; provider_id?: string; model_id?: string }

export interface ProviderErrorBreakdown { http_5xx: number; rate_limited: number; rejected: number; network: number; other: number }
export interface ProviderMonitorPoint { at: string; attempts: number; success_rate: number | null; latency_p95_ms: number | null }
export interface ProviderMonitorItem {
  provider_id: string; provider_name: string; attempts: number; successes: number; success_rate: number | null
  latency_p50_ms: number | null; latency_p95_ms: number | null; ttft_p50_ms: number | null
  errors: ProviderErrorBreakdown; fallback_out: number; fallback_in: number; model_count: number
  models: Array<{ model_id: string; model_name: string; attempts: number; success_rate: number | null }>
  hourly: ProviderMonitorPoint[]
}
export interface ProviderMonitor { items: ProviderMonitorItem[]; totals: { attempts: number; success_rate: number | null; fallbacks: number; ttft_p50_ms: number | null }; window_hours: number; generated_at: string }

export const modelOperationsApi = {
  overview: (params: ModelOperationFilters) => apiClient.get<ModelOperationsOverview>('/model-operations/overview', { params }),
  targets: (params: ModelOperationFilters) => apiClient.get<CursorPage<ModelOperationTarget>>('/model-operations/targets', { params }),
  history: (params: ModelOperationFilters) => apiClient.get<CursorPage<ModelProbeRecord>>('/model-operations/history', { params }),
  quality: (params: ModelOperationFilters) => apiClient.get<ModelOperationsQuality>('/model-operations/quality', { params }),
  providers: (params: ModelOperationFilters) => apiClient.get<ProviderMonitor>('/model-operations/providers', { params }),
  alerts: (params: ModelOperationFilters) => apiClient.get<CursorPage<ModelOperationAlert>>('/model-operations/alerts', { params }),
  config: () => apiClient.get<ModelOperationsConfig>('/model-operations/config'),
  updateConfig: (config: ModelOperationsConfig, confirmCost: boolean) => apiClient.put<ModelOperationsConfig>('/model-operations/config', { version: config.version, enabled: config.enabled, interval_seconds: config.interval_seconds, concurrency: config.concurrency, timeout_seconds: config.timeout_seconds, max_targets: config.max_targets, max_output_tokens: config.max_output_tokens, protocols: config.protocols, failure_threshold: config.failure_threshold, confirm_cost: confirmCost }),
  test: (modelIds: string[], protocols: ProbeProtocol[] | undefined, idempotencyKey: string, expectedConfigVersion: number) => apiClient.post<ModelProbeJob>('/model-operations/test', { model_ids: modelIds, ...(protocols?.length ? { protocols } : {}), confirm_cost: true, idempotency_key: idempotencyKey, expected_config_version: expectedConfigVersion }),
  job: (id: string) => apiClient.get<ModelProbeJob>(`/model-operations/jobs/${encodeURIComponent(id)}`),
  cancelJob: (id: string) => apiClient.post<ModelProbeJob>(`/model-operations/jobs/${encodeURIComponent(id)}/cancel`),
  ackAlert: (id: string) => apiClient.post<ModelOperationAlert>(`/model-operations/alerts/${encodeURIComponent(id)}/ack`),
  sla: (params: ModelSLAFilter) => apiClient.get<{ data: ModelSLAMonth }>('/model-operations/sla', { params }),
  exportSla: (params: ModelSLAFilter) => apiClient.get<Blob>('/model-operations/sla/export', { params, responseType: 'blob' }),
}

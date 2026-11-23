export interface Page<T> { items: T[]; page: number; page_size: number; total: number }
export interface AgentOverview { endpoints_total: number; endpoints_active: number; endpoints_stale: number; endpoints_revoked: number; sessions_active: number; events_24h: number; assets_present: number }
export interface AgentEndpoint {
  id: string; machine_id: string; hostname: string; os: string; os_version: string; arch: string; os_user: string;
  product: string; agent_version: string; adapter_name: string; adapter_version: string; hookd_version: string;
  capabilities: string[]; token_prefix: string; mode: string | null; capture_level: string; status: string;
  last_heartbeat_at: string | null; last_event_at: string | null; last_policy_version: number; last_config_version: number;
  health: Record<string, number | string>; created_at: string; updated_at: string;
  /** health.control_boundary projected by the control plane; null when hookd has not reported it. */
  control_boundary?: ControlBoundaryReport | null;
}
export interface ControlBoundaryPath { trigger: string; behavior: string; timeout_ms?: number; log?: string; source: string }
export interface ControlBoundaryReport {
  schema: string; hookd_version?: string; config_version?: number;
  require_trusted_agent_authorization?: boolean; strict_approval?: boolean; approval_required_actions?: string[];
  decide_fail_mode?: string; decide_timeout_ms?: number;
  hosts?: Record<string, { pre_tool_gate?: boolean; paths?: ControlBoundaryPath[] }>;
  uncontrolled?: string[]; config_error?: string;
}
export interface EnrollmentToken { id: string; name: string; token_prefix: string; default_mode: string; allowed_products: string[]; max_endpoints: number; enabled: boolean; expires_at: string | null; revoked_at: string | null; last_used_at: string | null; created_by: string; created_at: string }
export interface EnrollmentCreated extends EnrollmentToken { token: string }
export interface AgentSession { id: string; session_id: string; endpoint_id: string | null; source: string; parent_session_id: string | null; product: string | null; model: string | null; project_label: string | null; cwd_hash: string | null; permission_mode: string | null; status: string; risk_score: number; started_at: string | null; ended_at: string | null; last_request_at: string | null; turn_count: number; event_count: number; tool_call_count: number; blocked_count: number; would_block_count: number; gateway_request_count: number }
export interface AgentTurn { id: string; prompt_id: string; seq: number; started_at: string | null; ended_at: string | null; stop_reason: string; prompt_hash: string; prompt_preview?: string; assistant_preview?: string; tool_call_count: number; blocked_count: number }
export interface AgentEvent { id: string; endpoint_id: string; session_id: string; prompt_id: string; tool_use_id: string; event_type: string; occurred_at: string; received_at: string; tool_name: string; tool_type: string; mcp_server: string; payload: Record<string, unknown>; local_decision: Record<string, unknown>; server_decision: Record<string, unknown>; tool_call_log_id?: string; severity: string }
export interface AgentAsset { id: string; endpoint_id: string; asset_type: string; name: string; version?: string; source?: string; hash?: string; present: boolean; scan_status?: string; scan_decision?: string; first_seen?: string; last_seen?: string }
export interface AgentToolCall { id: string; request_id: string; tool_name: string; tool_type: string; risk_level: string; args_summary: Record<string, unknown>; status: string; created_at: string }
export interface AgentAlert { id: string; event_id: string | null; channel: string | null; delivery_status: string | null; severity: string; alert_type: string; decision: string; payload_summary: Record<string, unknown>; created_at: string }
export interface AgentSessionDetail { overview: AgentSession; turns: AgentTurn[]; events: AgentEvent[]; tool_call_logs: AgentToolCall[]; alerts: AgentAlert[] }
export interface AgentEndpointFilters { product?: string; status?: string; os?: string; mode?: string; stale?: boolean; q?: string; page?: number; page_size?: number }
export interface AgentSessionFilters { endpoint_id?: string; product?: string; status?: string; from?: string; to?: string; min_risk?: number; q?: string; page?: number; page_size?: number }

export interface AgentPolicyBundle { id: string; version: number; checksum: string; created_at: string; created_by: string }

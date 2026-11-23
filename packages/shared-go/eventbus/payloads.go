package eventbus

import "time"

// RequestLogSnapshot carries enough request context for asynchronous evidence
// writers to create the parent request log before inserting child evidence rows.
type RequestLogSnapshot struct {
	AgentInstanceID      string    `json:"agent_instance_id,omitempty"`
	AgentIdentityHeaders string    `json:"agent_identity_headers,omitempty"`
	UserAgent            string    `json:"user_agent,omitempty"`
	AgentDetectionSource string    `json:"agent_detection_source,omitempty"`
	RequestID            string    `json:"request_id"`
	TenantID             string    `json:"tenant_id"`
	ProjectID            string    `json:"project_id"`
	UserID               string    `json:"user_id,omitempty"`
	ClientID             string    `json:"client_id,omitempty"`
	EnvironmentScope     string    `json:"environment_scope,omitempty"`
	ProviderID           string    `json:"provider_id,omitempty"`
	ModelID              string    `json:"model_id,omitempty"`
	SessionID            string    `json:"session_id,omitempty"`
	AgentType            string    `json:"agent_type,omitempty"`
	EndpointType         string    `json:"endpoint_type,omitempty"`
	TraceID              string    `json:"trace_id,omitempty"`
	LSEEvalRunID         string    `json:"lse_eval_run_id,omitempty"`
	LSETaskID            string    `json:"lse_task_id,omitempty"`
	LSESampleID          string    `json:"lse_sample_id,omitempty"`
	LSETargetID          string    `json:"lse_target_id,omitempty"`
	SourceIP             string    `json:"source_ip,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
}

// AuditContentLogPayload is the durable outbox payload for content_logs writes.
type AuditContentLogPayload struct {
	RequestLog   RequestLogSnapshot `json:"request_log"`
	LogID        string             `json:"log_id"`
	Role         string             `json:"role"`
	MessageIndex *int               `json:"message_index,omitempty"`
	Content      string             `json:"content"`
	Tokens       int                `json:"tokens"`
	CreatedAt    time.Time          `json:"created_at"`
}

// AuditSecurityEventPayload is the durable outbox payload for security_events writes.
type AuditSecurityEventPayload struct {
	RequestLog        RequestLogSnapshot `json:"request_log"`
	EventID           string             `json:"event_id"`
	EventType         string             `json:"event_type"`
	Severity          string             `json:"severity"`
	EffectiveSeverity string             `json:"effective_severity,omitempty"`
	ClassKey          string             `json:"class_key,omitempty"`
	RuleID            string             `json:"rule_id,omitempty"`
	ActionTaken       string             `json:"action_taken"`
	MatchedSummary    map[string]any     `json:"matched_summary"`
	EvidenceRef       string             `json:"evidence_ref,omitempty"`
	// ConversationKey 会话归组键（gateway A 路 aiconvo 计算；契约第 6 条）。
	// sink 落 security_events.conversation_key；principal_key 由 sink 从 RequestLog 快照物化。
	ConversationKey string    `json:"conversation_key,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

func (s RequestLogSnapshot) NormalizeCreatedAt(now time.Time) RequestLogSnapshot {
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	return s
}

func (p AuditContentLogPayload) NormalizeCreatedAt(now time.Time) AuditContentLogPayload {
	p.RequestLog = p.RequestLog.NormalizeCreatedAt(now)
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	return p
}

func (p AuditSecurityEventPayload) NormalizeCreatedAt(now time.Time) AuditSecurityEventPayload {
	p.RequestLog = p.RequestLog.NormalizeCreatedAt(now)
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	return p
}

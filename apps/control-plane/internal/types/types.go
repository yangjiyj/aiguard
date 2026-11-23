package types

import "time"

// Auth types
type LoginRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	CaptchaID   string `json:"captcha_id"`
	CaptchaCode string `json:"captcha_code"`
}

type LoginResponse struct {
	Token                  string   `json:"token"`
	User                   UserInfo `json:"user"`
	Expires                string   `json:"expires"`
	PasswordChangeRequired bool     `json:"password_change_required"`
}

type UserInfo struct {
	PossibleDuplicateUserIDs   []string   `json:"possible_duplicate_user_ids,omitempty"`
	ID                         string     `json:"id"`
	Username                   string     `json:"username"`
	Email                      string     `json:"email,omitempty"`
	Phone                      string     `json:"phone,omitempty"`
	Role                       string     `json:"role"`
	Status                     string     `json:"status"`
	PasswordChangeRequired     bool       `json:"password_change_required,omitempty"`
	TenantID                   string     `json:"tenant_id,omitempty"`
	CreatedAt                  string     `json:"created_at,omitempty"`
	DepartmentID               string     `json:"department_id,omitempty"`
	DepartmentName             string     `json:"department_name,omitempty"`
	DepartmentAssignmentMode   string     `json:"department_assignment_mode,omitempty"`
	DepartmentAssignmentSource string     `json:"department_assignment_source,omitempty"`
	DepartmentAssignmentRuleID string     `json:"department_assignment_rule_id,omitempty"`
	DepartmentResolvedAt       *time.Time `json:"department_resolved_at,omitempty"`
	// Extended fields for list view (spec §7.2)
	TeamsCSV      string `json:"teams_csv,omitempty"`
	TeamsJSON     string `json:"teams_json,omitempty"`
	ProjectsCount int64  `json:"projects_count,omitempty"`
	GrantsCount   int64  `json:"grants_count,omitempty"`
	LastLoginAt   string `json:"last_login_at,omitempty"`
}

type CreateUserRequest struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	Email        string `json:"email,omitempty"`
	Phone        string `json:"phone,omitempty"`
	Role         string `json:"role"`
	TenantID     string `json:"tenant_id,omitempty"`
	DepartmentID string `json:"department_id,omitempty"`
}

type UpdateUserRequest struct {
	Username     string  `json:"username,omitempty"`
	Email        string  `json:"email,omitempty"`
	Phone        string  `json:"phone,omitempty"`
	Role         string  `json:"role,omitempty"`
	Status       string  `json:"status,omitempty"`
	DepartmentID *string `json:"department_id,omitempty"`
}

type ResetPasswordRequest struct {
	Password string `json:"password"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type UserListResponse struct {
	Data  []UserInfo `json:"data"`
	Total int        `json:"total"`
}

// Tenant types
type TenantInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Edition   string `json:"edition"` // cloud or enterprise
	Status    string `json:"status"`
	Industry  string `json:"industry"` // generic/medical_imaging/finance，驱动行业预置数据安全规则包挂载
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type TenantListResponse struct {
	Data  []TenantInfo `json:"data"`
	Total int          `json:"total"`
}

type CreateTenantRequest struct {
	Name    string `json:"name"`
	Edition string `json:"edition"`
}

type UpdateTenantRequest struct {
	Name     string `json:"name,omitempty"`
	Edition  string `json:"edition,omitempty"`
	Status   string `json:"status,omitempty"`
	Industry string `json:"industry,omitempty"` // 经 normalizeIndustry 白名单校验后落库
}

// Project types
type ProjectInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	TenantID    string `json:"tenant_id"`
	Code        string `json:"code,omitempty"`
	Environment string `json:"environment,omitempty"`
	TeamID      string `json:"team_id,omitempty"`
	Status      string `json:"status"`
	// 控制台应用抽屉按这几项回填“模型白名单 / 额度 / 所属部门”；少了它们，抽屉永远是空的，
	// 而“保存模型”会把真实配置整个覆盖成空。
	ModelWhitelist []string       `json:"model_whitelist,omitempty"`
	QuotaLimits    map[string]any `json:"quota_limits,omitempty"`
	CreatedAt      string         `json:"created_at,omitempty"`
	UpdatedAt      string         `json:"updated_at,omitempty"`
}

type ProjectListResponse struct {
	Data  []ProjectInfo `json:"data"`
	Total int           `json:"total"`
}

type CreateProjectRequest struct {
	Name        string `json:"name"`
	TenantID    string `json:"tenant_id,omitempty"`
	Code        string `json:"code,omitempty"`
	Environment string `json:"environment,omitempty"`
}

type UpdateProjectRequest struct {
	Name        string `json:"name,omitempty"`
	Code        string `json:"code,omitempty"`
	Environment string `json:"environment,omitempty"`
	Status      string `json:"status,omitempty"`
}

// Key types
type KeyInfo struct {
	ID        string   `json:"id"`
	ProjectID string   `json:"project_id"`
	UserID    string   `json:"user_id"`
	Name      string   `json:"name,omitempty"`
	KeyPrefix string   `json:"key_prefix"`
	Scopes    []string `json:"scopes,omitempty"`
	FullKey   string   `json:"full_key,omitempty"` // 仅创建时返回
	Status    string   `json:"status"`
	CreatedAt string   `json:"created_at"`
	ExpiresAt string   `json:"expires_at,omitempty"`
	// TrafficClass 为管理员设置的流量类别（""/evaluation/coding），告警页车道依赖它。
	TrafficClass string `json:"traffic_class"`
}

type KeyListResponse struct {
	Data  []KeyInfo `json:"data"`
	Total int       `json:"total"`
}

type CreateKeyRequest struct {
	ProjectID string   `json:"project_id"`
	UserID    string   `json:"user_id"`
	Name      string   `json:"name"`
	ExpiresAt string   `json:"expires_at"` // RFC3339，可选，必须是未来时间
	Scopes    []string `json:"scopes,omitempty"`
}

// UpdateKeyRequest 仅允许改备注/名称（PATCH /admin/v1/keys/{id}）。
type UpdateKeyRequest struct {
	Name string `json:"name"`
}

// Provider types
type ProviderInfo struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	ProviderType        string `json:"provider_type"` // openai, anthropic, azure, bedrock
	BaseURL             string `json:"base_url"`
	AuthMode            string `json:"auth_mode"`
	HasCredential       bool   `json:"has_credential"`
	CredentialUpdatedAt string `json:"credential_updated_at,omitempty"`
	Status              string `json:"status"`
	CreatedAt           string `json:"created_at,omitempty"`
	UpdatedAt           string `json:"updated_at,omitempty"`
}

type ProviderListResponse struct {
	Data  []ProviderInfo `json:"data"`
	Total int            `json:"total"`
}

type ProviderCredentialInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	RotatedAt string `json:"rotated_at,omitempty"`
	CreatedAt string `json:"created_at"`
}

type ProviderCredentialHistoryResponse struct {
	Data  []ProviderCredentialInfo `json:"data"`
	Total int                      `json:"total"`
}

type CreateProviderRequest struct {
	Name         string `json:"name"`
	ProviderType string `json:"provider_type"`
	BaseURL      string `json:"base_url"`
	APIKey       string `json:"api_key,omitempty"`
	AuthMode     string `json:"auth_mode,omitempty"`
	ModelID      string `json:"model_id,omitempty"`
}

type UpdateProviderRequest struct {
	Name    string `json:"name,omitempty"`
	BaseURL string `json:"base_url,omitempty"`
	APIKey  string `json:"api_key,omitempty"`
	Status  string `json:"status,omitempty"`
}

// Model types
type ModelInfo struct {
	ID                 string                 `json:"id"`
	ProviderID         string                 `json:"provider_id"`
	ModelName          string                 `json:"model_name"`
	ModelLabel         string                 `json:"model_label,omitempty"`
	UpstreamModelID    string                 `json:"upstream_model_id,omitempty"`
	FallbackProviderID string                 `json:"fallback_provider_id,omitempty"`
	ProxyConfig        map[string]interface{} `json:"proxy_config,omitempty"`
	Capabilities       map[string]interface{} `json:"capabilities,omitempty"`
	Status             string                 `json:"status"`
	CreatedAt          string                 `json:"created_at,omitempty"`
	Callable           bool                   `json:"callable"`
	AvailabilityState  string                 `json:"availability_state"`
	InventoryState     string                 `json:"inventory_state"`
	CallableEndpoints  []string               `json:"callable_endpoints"`
	HealthState        string                 `json:"health_state"`
	ProofState         string                 `json:"proof_state"`
	Advice             string                 `json:"advice"`
}

type ModelListResponse struct {
	Data  []ModelInfo `json:"data"`
	Total int         `json:"total"`
}

type UpdateModelRoutingRequest struct {
	FallbackProviderID string `json:"fallback_provider_id"`
}

type UpdateModelProxyConfigRequest struct {
	ProxyConfig map[string]interface{} `json:"proxy_config"`
}

type CreateModelRequest struct {
	ProviderID      string   `json:"provider_id"`
	ModelName       string   `json:"model_name"`
	ModelLabel      string   `json:"model_label,omitempty"`
	UpstreamModelID string   `json:"upstream_model_id,omitempty"`
	Protocols       []string `json:"protocols,omitempty"`
	Status          string   `json:"status,omitempty"`
}

// Model sync types
type SyncModelsRequest struct {
	ProviderID string `json:"provider_id"`
	// CatalogModelIDs 非空时只同步勾选的目录模型；为空时保持既有全量同步语义。
	CatalogModelIDs []string `json:"catalog_model_ids,omitempty"`
}

type SyncModelsResponse struct {
	ProviderID         string `json:"provider_id"`
	TotalSeen          int    `json:"total_seen"`
	Created            int    `json:"created"`
	Updated            int    `json:"updated"`
	Deactivated        int    `json:"deactivated"`
	Skipped            int    `json:"skipped"`
	Verified           int    `json:"verified"`
	VerificationFailed int    `json:"verification_failed"`
	// SelectionApplied 为 true 时表示本次是勾选同步：只处理勾选项，
	// 且不会停用任何未勾选的现有模型。
	SelectionApplied bool `json:"selection_applied,omitempty"`
	// SelectedMatched 是勾选项里在上游目录中真实命中的数量。
	SelectedMatched int `json:"selected_matched,omitempty"`
	// NotFoundModelIDs 是勾选项里上游已不存在的标识，按字典序返回。
	NotFoundModelIDs []string `json:"not_found_model_ids,omitempty"`
}

type ProviderCatalogModel struct {
	ID          string `json:"id"`
	Object      string `json:"object"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Policy types
type ModelPolicyInfo struct {
	ID        string   `json:"id"`
	TenantID  string   `json:"tenant_id"`
	ProjectID string   `json:"project_id"`
	AllowList []string `json:"allow_list"`
	DenyList  []string `json:"deny_list"`
}

type ModelPolicyRequest struct {
	TenantID  string   `json:"tenant_id"`
	ProjectID string   `json:"project_id"`
	AllowList []string `json:"allow_list"`
	DenyList  []string `json:"deny_list"`
}

type QuotaPolicyInfo struct {
	ID                   string  `json:"id"`
	TenantID             string  `json:"tenant_id"`
	ProjectID            string  `json:"project_id"`
	ScopeType            string  `json:"scope_type,omitempty"`
	ScopeID              string  `json:"scope_id,omitempty"` // key scope 使用 internal_keys.id
	DailyTokenLimit      *int64  `json:"daily_token_limit"`
	MonthlyTokenLimit    *int64  `json:"monthly_token_limit"`
	DailyTokenBlocked    bool    `json:"daily_token_blocked"`
	MonthlyTokenBlocked  bool    `json:"monthly_token_blocked"`
	DailyBudgetLimit     float64 `json:"daily_budget_limit,omitempty"`
	MonthlyBudgetLimit   float64 `json:"monthly_budget_limit,omitempty"`
	DailyBudgetMicros    *int64  `json:"daily_budget_micros"`
	MonthlyBudgetMicros  *int64  `json:"monthly_budget_micros"`
	DailyBudgetBlocked   bool    `json:"daily_budget_blocked"`
	MonthlyBudgetBlocked bool    `json:"monthly_budget_blocked"`
	BudgetAmountBasis    string  `json:"budget_amount_basis"`
	RPMLimit             *int    `json:"rpm_limit"`
	RPMBlocked           bool    `json:"rpm_blocked"`
	TPMLimit             *int64  `json:"tpm_limit"`
	TPMBlocked           bool    `json:"tpm_blocked"`
	ConcurrencyLimit     *int    `json:"concurrency_limit"`
	ConcurrencyBlocked   bool    `json:"concurrency_blocked"`
	OverageAction        string  `json:"overage_action,omitempty"`
	EnforcementMode      string  `json:"enforcement_mode,omitempty"`
	QuotaTimezone        string  `json:"quota_timezone"`
}

type QuotaPolicyRequest struct {
	TenantID             string  `json:"tenant_id"`
	ProjectID            string  `json:"project_id"`
	ScopeType            string  `json:"scope_type,omitempty"`
	ScopeID              string  `json:"scope_id,omitempty"` // key scope 使用 internal_keys.id
	DailyTokenLimit      *int64  `json:"daily_token_limit"`
	MonthlyTokenLimit    *int64  `json:"monthly_token_limit"`
	DailyTokenBlocked    bool    `json:"daily_token_blocked"`
	MonthlyTokenBlocked  bool    `json:"monthly_token_blocked"`
	DailyBudgetLimit     float64 `json:"daily_budget_limit,omitempty"`
	MonthlyBudgetLimit   float64 `json:"monthly_budget_limit,omitempty"`
	DailyBudgetMicros    *int64  `json:"daily_budget_micros"`
	MonthlyBudgetMicros  *int64  `json:"monthly_budget_micros"`
	DailyBudgetBlocked   bool    `json:"daily_budget_blocked"`
	MonthlyBudgetBlocked bool    `json:"monthly_budget_blocked"`
	RPMLimit             *int    `json:"rpm_limit"`
	RPMBlocked           bool    `json:"rpm_blocked"`
	TPMLimit             *int64  `json:"tpm_limit"`
	TPMBlocked           bool    `json:"tpm_blocked"`
	ConcurrencyLimit     *int    `json:"concurrency_limit"`
	ConcurrencyBlocked   bool    `json:"concurrency_blocked"`
	OverageAction        string  `json:"overage_action,omitempty"`
	EnforcementMode      string  `json:"enforcement_mode,omitempty"`
	QuotaTimezone        string  `json:"quota_timezone,omitempty"`
}

// Security types
type RuleSetInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Published bool   `json:"published"`
}

type RuleSetListResponse struct {
	Data  []RuleSetInfo `json:"data"`
	Total int           `json:"total"`
}

type CreateRuleSetRequest struct {
	Name string `json:"name"`
}

// Rule types
type RuleInfo struct {
	ID              string                 `json:"id"`
	RuleSetID       string                 `json:"rule_set_id"`
	RuleType        string                 `json:"rule_type"` // prompt_injection, content_safety, agent_detect, data_leak
	Name            string                 `json:"name"`
	Priority        int                    `json:"priority"`
	Severity        string                 `json:"severity"` // low, medium, high, critical
	ScopeJSON       map[string]interface{} `json:"scope_json,omitempty"`
	MatchConfigJSON map[string]interface{} `json:"match_config_json,omitempty"`
	Action          string                 `json:"action"` // allow, audit, mask, block, reply
	Enabled         bool                   `json:"enabled"`
	Description     string                 `json:"description,omitempty"`
	CreatedAt       string                 `json:"created_at,omitempty"`
}

type RuleListResponse struct {
	Data  []RuleInfo `json:"data"`
	Total int        `json:"total"`
}

type CreateRuleRequest struct {
	RuleSetID       string                 `json:"rule_set_id"`
	RuleType        string                 `json:"rule_type"`
	Name            string                 `json:"name"`
	Priority        int                    `json:"priority,omitempty"`
	Severity        string                 `json:"severity,omitempty"`
	ScopeJSON       map[string]interface{} `json:"scope_json,omitempty"`
	MatchConfigJSON map[string]interface{} `json:"match_config_json,omitempty"`
	Action          string                 `json:"action,omitempty"`
}

type UpdateRuleRequest struct {
	Name     *string `json:"name,omitempty"`
	Priority *int    `json:"priority,omitempty"`
	Severity *string `json:"severity,omitempty"`
	Action   *string `json:"action,omitempty"`
	Enabled  *bool   `json:"enabled,omitempty"`
}

// BatchUpdateDetectorRequest is the request for batch updating all rules of a type
type BatchUpdateDetectorRequest struct {
	RuleType     string  `json:"rule_type"`
	Enabled      *bool   `json:"enabled,omitempty"`
	Action       *string `json:"action,omitempty"`
	ReplyMessage *string `json:"reply_message,omitempty"`
}

type SecurityTestRequest struct {
	Text       string `json:"text"`
	ProjectID  string `json:"project_id"`
	Model      string `json:"model"`
	ClientType string `json:"client_type,omitempty"`
}

// SecurityTestResponse matches the security-engine /test/ endpoint response
type SecurityTestResponse struct {
	Findings      []SecurityFinding `json:"findings"`
	Action        string            `json:"action"`
	MaskedPreview string            `json:"masked_preview,omitempty"`
	LatencyMs     int               `json:"latency_ms"`
}

// SecurityFinding matches the security-engine SecurityFinding model
type SecurityFinding struct {
	Type               string  `json:"type"` // pii, secret, code_config
	Category           string  `json:"category"`
	Severity           string  `json:"severity"` // low, medium, high, critical
	MatchedTextPreview string  `json:"matched_text_preview"`
	RuleID             string  `json:"rule_id"`
	Confidence         float64 `json:"confidence,omitempty"`
}

// Audit types
type AuditRequestInfo struct {
	RequestID         string                 `json:"request_id"`
	SessionID         string                 `json:"session_id,omitempty"`
	ConversationID    string                 `json:"conversation_id,omitempty"`
	ModelID           string                 `json:"model_id,omitempty"`
	Model             string                 `json:"model"`
	Status            string                 `json:"status"`
	InputAuditResult  map[string]interface{} `json:"input_audit_result,omitempty"`
	OutputAuditResult map[string]interface{} `json:"output_audit_result,omitempty"`
	CreatedAt         string                 `json:"created_at"`
	// Related counts for audit display
	ContentCount       int `json:"content_count"`
	ToolCallCount      int `json:"tool_call_count"`
	SecurityEventCount int `json:"security_event_count"`
}

type AuditRequestListResponse struct {
	Data  []AuditRequestInfo `json:"data"`
	Total int                `json:"total"`
}

type SecurityEventInfo struct {
	AgentInstanceID string                 `json:"agent_instance_id"`
	ID              string                 `json:"id"`
	RequestID       string                 `json:"request_id"`
	EventType       string                 `json:"event_type"`
	Severity        string                 `json:"severity"`
	RuleID          string                 `json:"rule_id,omitempty"`
	RuleName        string                 `json:"rule_name,omitempty"`
	RuleType        string                 `json:"rule_type,omitempty"`
	ActionTaken     string                 `json:"action_taken"`
	MatchedSummary  map[string]interface{} `json:"matched_summary,omitempty"`
	EvidenceRef     string                 `json:"evidence_ref,omitempty"`
	CreatedAt       string                 `json:"created_at"`
}

type SecurityEventListResponse struct {
	Data  []SecurityEventInfo `json:"data"`
	Total int                 `json:"total"`
}

type AuditDispositionInfo struct {
	ID           string `json:"id"`
	SubjectType  string `json:"subject_type"`
	SubjectID    string `json:"subject_id"`
	Status       string `json:"status"`
	Note         string `json:"note,omitempty"`
	OperatorID   string `json:"operator_id,omitempty"`
	OperatorName string `json:"operator_name,omitempty"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type AuditDispositionListResponse struct {
	Data  []AuditDispositionInfo `json:"data"`
	Total int                    `json:"total"`
}

type UpsertAuditDispositionRequest struct {
	CaseSeenThrough string `json:"case_seen_through,omitempty"`
	SubjectType     string `json:"subject_type"`
	SubjectID       string `json:"subject_id"`
	Status          string `json:"status"`
	Note            string `json:"note,omitempty"`
	// Action 为可选的处置真实动作（revoke_key/ban_user/block_session），为空表示仅定性不处置。
	Action       string `json:"action,omitempty"`
	ActionTarget string `json:"action_target,omitempty"`
}

type ForwardProxyAccessInfo struct {
	RequestID            string   `json:"request_id"`
	TenantID             string   `json:"tenant_id,omitempty"`
	UserID               string   `json:"user_id,omitempty"`
	Username             string   `json:"username,omitempty"`
	CreatedAt            string   `json:"created_at"`
	SourceIP             string   `json:"source_ip,omitempty"`
	TargetHost           string   `json:"target_host"`
	TargetPath           string   `json:"target_path,omitempty"`
	Method               string   `json:"method,omitempty"`
	Provider             string   `json:"provider,omitempty"`
	ProviderCN           string   `json:"provider_cn,omitempty"`
	Product              string   `json:"product,omitempty"`
	ProductCN            string   `json:"product_cn,omitempty"`
	AccessType           string   `json:"access_type"`
	EndpointKind         string   `json:"endpoint_kind,omitempty"`
	PathTemplate         string   `json:"path_template,omitempty"`
	Status               string   `json:"status"`
	StatusCode           int      `json:"status_code"`
	ResponseBytes        int64    `json:"response_bytes"`
	RequestBytes         int64    `json:"request_bytes"`
	TunnelDurationMS     int64    `json:"tunnel_duration_ms"`
	TLSInspected         bool     `json:"tls_inspected"`
	RetentionLevel       string   `json:"retention_level"`
	ContentRetained      bool     `json:"content_retained"`
	RiskState            string   `json:"risk_state"`
	RiskReasons          []string `json:"risk_reasons,omitempty"`
	ActionTaken          string   `json:"action_taken"`
	SecurityEventCount   int      `json:"security_event_count"`
	ActionableAlertCount int      `json:"actionable_alert_count"`
	DispositionStatus    string   `json:"disposition_status"`
	AccessDirection      string   `json:"access_direction"`
	AgentType            string   `json:"agent_type,omitempty"`
	AgentLabel           string   `json:"agent_label,omitempty"`
	ClientID             string   `json:"client_id,omitempty"`
	ClientName           string   `json:"client_name,omitempty"`
	IdentityKind         string   `json:"identity_kind"`
	KeyOwner             string   `json:"key_owner,omitempty"`
	// MemberCount 为会话内物理请求数，TurnCount 为按 section_id 去重后的用户对话轮次；
	// MemberRequestIDs 包含会话内全部物理请求 ID，供详情合并和单请求下钻。
	MemberCount      int      `json:"member_count,omitempty"`
	TurnCount        int      `json:"turn_count,omitempty"`
	MemberRequestIDs []string `json:"member_request_ids,omitempty"`
}

type EvidenceRunInfo struct {
	RunID                    string   `json:"run_id"`
	Kind                     string   `json:"kind"`
	TaskClass                string   `json:"task_class,omitempty"`
	CorrelationSource        string   `json:"correlation_source"`
	CorrelationConfidence    string   `json:"correlation_confidence"`
	RepresentativeRequestID  string   `json:"representative_request_id"`
	MemberRequestIDs         []string `json:"member_request_ids"`
	Title                    string   `json:"title"`
	StartedAt                string   `json:"started_at"`
	EndedAt                  string   `json:"ended_at"`
	DurationMs               int64    `json:"duration_ms"`
	AgentType                string   `json:"agent_type,omitempty"`
	AgentLabel               string   `json:"agent_label,omitempty"`
	AgentRuntime             string   `json:"agent_runtime,omitempty"`
	AgentDetectionSource     string   `json:"agent_detection_source,omitempty"`
	AgentDetectionConfidence float64  `json:"agent_detection_confidence,omitempty"`
	Username                 string   `json:"username,omitempty"`
	ClientName               string   `json:"client_name,omitempty"`
	SourceIP                 string   `json:"source_ip,omitempty"`
	Models                   []string `json:"models"`
	AccessDirections         []string `json:"access_directions"`
	RequestCount             int      `json:"request_count"`
	EvidenceStatus           string   `json:"evidence_status"`
	RiskState                string   `json:"risk_state"`
}

type EvidenceRunListResponse struct {
	Data       []EvidenceRunInfo `json:"data"`
	Total      int               `json:"total"`
	TotalKnown bool              `json:"total_known"`
	HasMore    bool              `json:"has_more"`
}

type EvidenceTimelineEventInfo struct {
	ID        string `json:"id"`
	RequestID string `json:"request_id,omitempty"`
	Type      string `json:"type"`
	Title     string `json:"title"`
	Detail    string `json:"detail,omitempty"`
	Status    string `json:"status,omitempty"`
	EventKind string `json:"event_kind,omitempty"`
	FactLabel string `json:"fact_label,omitempty"`
	Timestamp string `json:"timestamp"`
	Count     int    `json:"count,omitempty"`
}

type ForwardProxyAccessDimensionInfo struct {
	Name      string `json:"name"`
	Count     int    `json:"count"`
	RiskCount int    `json:"risk_count"`
}

type ForwardProxyAccessAgentDimensionInfo struct {
	Name      string `json:"name"`
	Label     string `json:"label"`
	Count     int    `json:"count"`
	RiskCount int    `json:"risk_count"`
}

type ForwardProxyEvidenceQualityInfo struct {
	CompleteCount     int `json:"complete_count"`
	RequestOnlyCount  int `json:"request_only_count"`
	ResponseOnlyCount int `json:"response_only_count"`
	MetadataOnlyCount int `json:"metadata_only_count"`
}

type ForwardProxyAccessTimelinePointInfo struct {
	Bucket       string `json:"bucket"`
	TotalCount   int    `json:"total_count"`
	NormalCount  int    `json:"normal_count"`
	RiskCount    int    `json:"risk_count"`
	BlockedCount int    `json:"blocked_count"`
}

type ForwardProxyRiskCategoryInfo struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type ForwardProxyAccessSummaryInfo struct {
	Total                  int                                    `json:"total"`
	NormalCount            int                                    `json:"normal_count"`
	RiskCount              int                                    `json:"risk_count"`
	BlockedCount           int                                    `json:"blocked_count"`
	LLMCount               int                                    `json:"llm_count"`
	AIIdeCount             int                                    `json:"ai_ide_count"`
	NormalPublicCount      int                                    `json:"normal_public_count"`
	RetainedContentCount   int                                    `json:"retained_content_count"`
	UndetectedCount        int                                    `json:"undetected_count"`
	ForwardCount           int                                    `json:"forward_count"`
	ReverseCount           int                                    `json:"reverse_count"`
	DeviceCount            int                                    `json:"device_count"`
	AgentRequestCount      int                                    `json:"agent_request_count"`
	IdentifiedAgentCount   int                                    `json:"identified_agent_count"`
	UnidentifiedAgentCount int                                    `json:"unidentified_agent_count"`
	UniqueModelCount       int                                    `json:"unique_model_count"`
	EvidenceQuality        ForwardProxyEvidenceQualityInfo        `json:"evidence_quality"`
	TopProviders           []ForwardProxyAccessDimensionInfo      `json:"top_providers"`
	TopTargets             []ForwardProxyAccessDimensionInfo      `json:"top_targets"`
	TopAgents              []ForwardProxyAccessAgentDimensionInfo `json:"top_agents"`
	Timeline               []ForwardProxyAccessTimelinePointInfo  `json:"timeline"`
	TopRiskCategories      []ForwardProxyRiskCategoryInfo         `json:"top_risk_categories"`
	DataFreshUntil         string                                 `json:"data_fresh_until,omitempty"`
}

type ForwardProxyAccessListResponse struct {
	Data         []ForwardProxyAccessInfo      `json:"data"`
	Total        int                           `json:"total"`
	HasMore      bool                          `json:"has_more"`
	TotalKnown   bool                          `json:"total_known"`
	Summary      ForwardProxyAccessSummaryInfo `json:"summary"`
	SummaryError string                        `json:"summary_error,omitempty"`
}

type AccessRetentionMessageInfo struct {
	ID        string `json:"id"`
	RequestID string `json:"request_id"`
	Sequence  int    `json:"sequence"`
	Role      string `json:"role"`
	Kind      string `json:"kind"`
	Content   string `json:"content"`
	CreatedAt string `json:"created_at,omitempty"`
}

type AccessRetentionToolInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	RequestID string `json:"request_id"`
}

type AccessRetentionTurnInfo struct {
	Tools      []AccessRetentionToolInfo   `json:"tools,omitempty"`
	ID         string                      `json:"id"`
	Index      int                         `json:"index"`
	UserInput  string                      `json:"user_input"`
	Answer     *AccessRetentionMessageInfo `json:"answer,omitempty"`
	RequestIDs []string                    `json:"request_ids"`
	// BlockedInputEvidenceRequestIDs 是 RequestIDs 中在原文留证表里有“输入方向、已阻断”记录的请求编号（保持原顺序）；仅对有权查看原文留证的角色返回。
	BlockedInputEvidenceRequestIDs []string `json:"blocked_input_evidence_request_ids,omitempty"`
	RequestCount                   int      `json:"request_count"`
	ProcessCount                   int      `json:"process_count"`
	Status                         string   `json:"status"`
	FinalitySource                 string   `json:"finality_source"`
	CorrelationSource              string   `json:"correlation_source"`
	EvidenceStatus                 string   `json:"evidence_status"`
	StartedAt                      string   `json:"started_at,omitempty"`
	LastObservedAt                 string   `json:"last_observed_at,omitempty"`
	ObservedDurationMS             int64    `json:"observed_duration_ms"`
}

type AccessRetentionSearchHit struct {
	RequestID    string `json:"request_id"`
	TurnID       string `json:"turn_id,omitempty"`
	Kind         string `json:"kind"`
	Role         string `json:"role"`
	Snippet      string `json:"snippet"`
	MessageIndex *int   `json:"message_index,omitempty"`
}

type AccessRetentionContentInfo struct {
	SearchHits          []AccessRetentionSearchHit `json:"search_hits,omitempty"`
	SearchHitsTruncated bool                       `json:"search_hits_truncated,omitempty"`
	TurnViewVersion     int                        `json:"turn_view_version,omitempty"`
	Turns               []AccessRetentionTurnInfo  `json:"turns,omitempty"`
	RequestID           string                     `json:"request_id"`
	// Deprecated raw compatibility fields remain internal-only. Customer responses
	// use the typed projections below and must never serialize these values.
	RequestContent  string                        `json:"-"`
	ResponseContent string                        `json:"-"`
	FileMetadata    []map[string]interface{}      `json:"-"`
	RetentionUntil  string                        `json:"retention_until,omitempty"`
	UserInput       string                        `json:"user_input"`
	ModelOutput     string                        `json:"model_output"`
	Artifacts       []AccessRetentionArtifactInfo `json:"artifacts"`
	EvidenceStatus  string                        `json:"evidence_status"`
	Messages        []AccessRetentionMessageInfo  `json:"messages"`
}

// AccessRetentionArtifactInfo excludes storage keys, reference IDs, URLs and bytes.
type AccessRetentionArtifactInfo struct {
	ID              string `json:"id"`
	RequestID       string `json:"request_id"`
	Direction       string `json:"direction"`
	Kind            string `json:"kind"`
	DisplayName     string `json:"display_name"`
	MediaType       string `json:"media_type"`
	ByteSize        int64  `json:"byte_size"`
	SHA256          string `json:"sha256"`
	RetentionStatus string `json:"retention_status"`
	FailureCode     string `json:"failure_code,omitempty"`
	HasPreview      bool   `json:"has_preview"`
	ReferenceCount  int    `json:"reference_count"`
	// Internal ordering and isolation metadata. These values never cross the API.
	EnvironmentScope     string    `json:"-"`
	LinkEnvironmentScope string    `json:"-"`
	RequestCreatedAt     time.Time `json:"-"`
	LinkCreatedAt        time.Time `json:"-"`
	Ordinal              int       `json:"-"`
}

// ContentLogInfo represents a single content log entry for API response
type ContentLogInfo struct {
	ID        string `json:"id"`
	RequestID string `json:"request_id"`
	Role      string `json:"role"` // user, assistant, system
	Content   string `json:"content"`
	Tokens    int    `json:"tokens"`
	CreatedAt string `json:"created_at"`
}

// ToolCallLogInfo represents a single tool call log entry for API response.
// EventKind=definition_exposed 仅表示网关观察到客户端提交工具定义，不证明定义已送达模型。
type ToolCallLogInfo struct {
	ID                    string  `json:"id"`
	RequestID             string  `json:"request_id"`
	ToolName              string  `json:"tool_name"`
	ToolType              string  `json:"tool_type"`  // file, network, database, mcp, system
	RiskLevel             string  `json:"risk_level"` // low, medium, high, critical
	MatchedPolicyID       string  `json:"matched_policy_id,omitempty"`
	MatchedPolicyName     string  `json:"matched_policy_name,omitempty"`
	MatchedAction         string  `json:"matched_action,omitempty"`
	MatchReason           string  `json:"match_reason,omitempty"`
	Status                string  `json:"status"` // success, failed, blocked
	EventKind             string  `json:"event_kind"`
	ExecutionObserved     bool    `json:"execution_observed"`
	ResultObserved        bool    `json:"result_observed"`
	ToolCallID            string  `json:"tool_call_id,omitempty"`
	AssetID               string  `json:"asset_id,omitempty"`
	SkillInvocationID     string  `json:"skill_invocation_id,omitempty"`
	MCPServerID           string  `json:"mcp_server_id,omitempty"`
	MCPToolID             string  `json:"mcp_tool_id,omitempty"`
	DefinitionHash        string  `json:"definition_hash,omitempty"`
	AttributionMode       string  `json:"attribution_mode,omitempty"`
	AttributionConfidence float64 `json:"attribution_confidence,omitempty"`
	CreatedAt             string  `json:"created_at"`
}

// AuditEvidenceInfo is a manager-readable evidence item derived from raw audit records.
type AuditEvidenceInfo struct {
	Label    string `json:"label"`
	Value    string `json:"value"`
	Severity string `json:"severity,omitempty"`
}

// AuditToolSummaryInfo summarizes agent tool behavior without exposing raw tool output by default.
type AuditToolSummaryInfo struct {
	Total              int      `json:"total"`
	UniqueTools        int      `json:"unique_tools"`
	HighRisk           int      `json:"high_risk"`
	DefinitionExposed  int      `json:"definition_exposed"`
	InvocationProposed int      `json:"invocation_proposed"`
	ExecutionForwarded int      `json:"execution_forwarded"`
	ResultObserved     int      `json:"result_observed"`
	Types              []string `json:"types"`
	TopTools           []string `json:"top_tools"`
	Summary            string   `json:"summary"`
}

// AuditDecisionInfo separates an observed signal from a proven attempt or impact.
type AuditDecisionInfo struct {
	Stage          string `json:"stage"`
	SemanticStatus string `json:"semantic_status"`
	WhatHappened   string `json:"what_happened"`
	WhyRisky       string `json:"why_risky"`
	Impact         string `json:"impact"`
	NextAction     string `json:"next_action"`
}

// AuditSummaryInfo is a management-oriented summary for one request.
type AuditSummaryInfo struct {
	Title              string                 `json:"title"`
	Intent             string                 `json:"intent"`
	Outcome            string                 `json:"outcome"`
	BusinessSummary    string                 `json:"business_summary"`
	RiskLevel          string                 `json:"risk_level"`
	RiskScore          int                    `json:"risk_score"`
	RiskReasons        []string               `json:"risk_reasons"`
	RecommendedAction  string                 `json:"recommended_action"`
	Tags               []string               `json:"tags"`
	PrimaryUserMessage string                 `json:"primary_user_message"`
	AssistantSummary   string                 `json:"assistant_summary"`
	SystemPromptCount  int                    `json:"system_prompt_count"`
	RawContentCount    int                    `json:"raw_content_count"`
	HiddenNoiseCount   int                    `json:"hidden_noise_count"`
	Evidence           []AuditEvidenceInfo    `json:"evidence"`
	Tools              AuditToolSummaryInfo   `json:"tools"`
	Decision           AuditDecisionInfo      `json:"decision"`
	GeneratedBy        string                 `json:"generated_by"`
	Extra              map[string]interface{} `json:"extra,omitempty"`
}

type AuditContentEvidenceInfo struct {
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code"`
	Summary    string `json:"summary"`
	CanView    bool   `json:"can_view"`
}

type AuditDetectionIssueInfo struct {
	Component  string `json:"component"`
	ReasonCode string `json:"reason_code"`
	Summary    string `json:"summary"`
	NextAction string `json:"next_action"`
}

// AuditRequestDetailResponse is the response for the request detail endpoint
type AuditRequestDetailResponse struct {
	RequestID           string                    `json:"request_id"`
	AuditSummary        AuditSummaryInfo          `json:"audit_summary"`
	SecurityEvents      []SecurityEventInfo       `json:"security_events"`
	ContentLogs         []ContentLogInfo          `json:"content_logs"`
	ToolCallLogs        []ToolCallLogInfo         `json:"tool_call_logs"`
	ContentEvidence     AuditContentEvidenceInfo  `json:"content_evidence"`
	DetectionIssues     []AuditDetectionIssueInfo `json:"detection_issues"`
	ContentAuditEnabled bool                      `json:"content_audit_enabled"`
	ToolAuditEnabled    bool                      `json:"tool_audit_enabled"`
}

// Usage types
type UsageSummary struct {
	TenantID       string  `json:"tenant_id"`
	Requests       int     `json:"requests"`
	InputTokens    int     `json:"input_tokens"`
	OutputTokens   int     `json:"output_tokens"`
	TotalCost      float64 `json:"total_cost"`
	DataFreshUntil string  `json:"data_fresh_until,omitempty"`
}

type ProjectUsage struct {
	ProjectID       string  `json:"project_id"`
	Name            string  `json:"name,omitempty"`
	Requests        int     `json:"requests"`
	InputTokens     int     `json:"input_tokens"`
	OutputTokens    int     `json:"output_tokens"`
	TotalTokens     int     `json:"total_tokens,omitempty"`
	TotalCost       float64 `json:"total_cost"`
	SuccessRate     float64 `json:"success_rate,omitempty"`
	BudgetUsageRate float64 `json:"budget_usage_rate,omitempty"`
}

type CostCoverageInfo struct {
	TotalRequests        int     `json:"total_requests"`
	PricedRequests       int     `json:"priced_requests"`
	UnpricedRequests     int     `json:"unpriced_requests"`
	CoverageRate         float64 `json:"coverage_rate"`
	UnpricedModelCount   int     `json:"unpriced_model_count"`
	CostTrustedStartDate string  `json:"cost_trusted_start_date"`
}

type CostDimensionRow struct {
	ID               string  `json:"id"`
	Name             string  `json:"name"`
	ProviderName     string  `json:"provider_name,omitempty"`
	ProviderType     string  `json:"provider_type,omitempty"`
	ModelID          string  `json:"model_id,omitempty"`
	ProjectID        string  `json:"project_id,omitempty"`
	ProjectName      string  `json:"project_name,omitempty"`
	UserID           string  `json:"user_id,omitempty"`
	Username         string  `json:"username,omitempty"`
	KeyPrefix        string  `json:"key_prefix,omitempty"`
	Requests         int     `json:"requests"`
	InputTokens      int64   `json:"input_tokens"`
	OutputTokens     int64   `json:"output_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	TotalCost        float64 `json:"total_cost"`
	CostPercent      float64 `json:"cost_percent"`
	AverageCost      float64 `json:"average_cost"`
	SuccessRate      float64 `json:"success_rate"`
	BudgetUsageRate  float64 `json:"budget_usage_rate,omitempty"`
	AverageLatencyMs float64 `json:"average_latency_ms,omitempty"`
	ModelCount       int     `json:"model_count,omitempty"`
	LastCalledAt     string  `json:"last_called_at,omitempty"`
	AbnormalGrowth   bool    `json:"abnormal_growth,omitempty"`
}

type CostRecommendation struct {
	ID           string  `json:"id"`
	Severity     string  `json:"severity"`
	Problem      string  `json:"problem"`
	Impact       string  `json:"impact"`
	ImpactCost   float64 `json:"impact_cost,omitempty"`
	ImpactTokens int64   `json:"impact_tokens,omitempty"`
	ProjectID    string  `json:"project_id,omitempty"`
	UserID       string  `json:"user_id,omitempty"`
	ModelID      string  `json:"model_id,omitempty"`
	Suggestion   string  `json:"suggestion"`
}

// Agent Session types
type AgentSessionInfo struct {
	SessionID    string `json:"session_id"`
	AgentType    string `json:"agent_type"`
	WorkspaceID  string `json:"workspace_id"`
	RiskScore    int    `json:"risk_score"`
	RequestCount int    `json:"request_count"`
	FirstRequest string `json:"first_request"`
	LastRequest  string `json:"last_request"`
}

type AgentSessionListResponse struct {
	Data  []AgentSessionInfo `json:"data"`
	Total int                `json:"total"`
}

// Error types
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
	Details   any    `json:"details,omitempty"`
}

// Project-user association types
type ProjectUserListResponse struct {
	Data  []ProjectUserInfo `json:"data"`
	Total int               `json:"total"`
}

type ProjectUserInfo struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Email     string `json:"email,omitempty"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at,omitempty"`
}

type BindUserRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role,omitempty"` // owner, developer, viewer (defaults to developer)
}

// UpdateModelConfigRequest for updating project model config
type UpdateModelConfigRequest struct {
	ModelWhitelist string `json:"model_whitelist"` // JSON array of allowed model IDs
	QuotaLimits    string `json:"quota_limits"`    // JSON object for quota limits
}

// System & Audit types
type AuditOperationInfo struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	ActionType   string                 `json:"action_type"`
	ActionDetail map[string]interface{} `json:"action_detail,omitempty"`
	TargetType   string                 `json:"target_type,omitempty"`
	TargetID     string                 `json:"target_id,omitempty"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	CreatedAt    string                 `json:"created_at"`
}

type AuditOperationListResponse struct {
	Data  []AuditOperationInfo `json:"data"`
	Total int                  `json:"total"`
}

type ModelEvalStatusItem struct {
	ModelID      string `json:"model_id"`
	Status       string `json:"status"`
	HasHighRisk  bool   `json:"has_high_risk"`
	ReportURL    string `json:"report_url,omitempty"`
	LatestEvalAt string `json:"latest_eval_at,omitempty"`
}

type ModelEvalStatusResponse struct {
	Data []ModelEvalStatusItem `json:"data"`
}

type UpdateModelCapabilitiesRequest struct {
	Capabilities           map[string]interface{} `json:"capabilities"`
	OverrideReason         string                 `json:"override_reason,omitempty"`
	ClearProtocolOverrides []string               `json:"clear_protocol_overrides,omitempty"`
}

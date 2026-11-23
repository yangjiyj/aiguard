package governor

import (
	"context"
	"fmt"
	"time"
)

type ActionType string

const (
	ActionNone         ActionType = "none"
	ActionAlert        ActionType = "alert"
	ActionRateLimit    ActionType = "rate_limit"
	ActionPauseKey     ActionType = "pause_key"
	ActionDowngradeMod ActionType = "downgrade_model"
)

type Decision struct {
	Action          ActionType
	TriggeredScope  string
	TriggeredMetric string
	ScopeID         string
	DowngradeTo     string
	Reason          string
	AlertOnly       bool
	// BudgetCutoff 为 true 表示这是“预算断流”开启后的 fail-closed 拒绝（额度状态无法确认）。
	BudgetCutoff bool
	// Estimated / Actual 只在“预留超出”类通知里有值：准入时冻结的估算量与结算时的实际量
	// （token 或金额微单位，由 TriggeredMetric 区分）。其他事件恒为 0。
	Estimated int64
	Actual    int64
}

type Snapshot struct {
	TenantID, TeamID, ProjectID, UserID string
	MonthTokens, DayTokens              int64
	MonthCostMicros, DayCostMicros      int64
	Rpm, Concurrency                    int64
}

type ScopeRef struct {
	// UserModelAccessEnforced is supplied only by the mandatory key-owner gate.
	UserModelAccessEnforced             bool
	TenantID, TeamID, ProjectID, UserID string
	KeyID                               string
	ModelID                             string // for model whitelist check
	ModelName                           string // final logical model after any legacy model-layer decision
}

type AdmissionRequest struct {
	Ref                   ScopeRef
	RequestID             string
	IdempotencyKey        string
	EstimatedTokens       int64
	EstimatedCostMicros   int64
	CostEstimateAvailable bool
	// CostEstimateMissingPrice distinguishes "model has no price" (D6: refuse
	// with model_price_missing) from a billing outage (runtime fault).
	CostEstimateMissingPrice bool
	// CostCurrency 是估算金额的计价币种（只用于提示文案，不参与比较或换算）。
	CostCurrency string
}

type AdmissionScope struct {
	Scope                  string `json:"scope"`
	ID                     string `json:"id"`
	EnforcementMode        string `json:"enforcement_mode"`
	RPMLimit               int64  `json:"rpm_limit"`
	RPMBlocked             bool   `json:"rpm_blocked"`
	TPMLimit               int64  `json:"tpm_limit"`
	TPMConfigured          bool   `json:"tpm_configured"`
	TPMBlocked             bool   `json:"tpm_blocked"`
	ConcurrencyLimit       int64  `json:"concurrency_limit"`
	ConcurrencyBlocked     bool   `json:"concurrency_blocked"`
	DailyTokenLimit        int64  `json:"daily_token_limit"`
	DailyTokenBlocked      bool   `json:"daily_token_blocked"`
	MonthlyTokenLimit      int64  `json:"monthly_token_limit"`
	MonthlyTokenBlocked    bool   `json:"monthly_token_blocked"`
	DailyCostLimitMicros   int64  `json:"daily_cost_limit_micros"`
	DailyCostBlocked       bool   `json:"daily_cost_blocked"`
	MonthlyCostLimitMicros int64  `json:"monthly_cost_limit_micros"`
	MonthlyCostBlocked     bool   `json:"monthly_cost_blocked"`
	QuotaTimezone          string `json:"quota_timezone"`
	DayBucket              string `json:"day_bucket"`
	MonthBucket            string `json:"month_bucket"`
	OverageAction          string `json:"overage_action"`
}

type AdmissionObservation struct {
	Metric     string `json:"metric"`
	Scope      string `json:"scope"`
	Limit      int64  `json:"limit"`
	Used       int64  `json:"used"`
	Reserved   int64  `json:"reserved"`
	Requested  int64  `json:"requested"`
	RetryAfter int64  `json:"retry_after"`
}

type AdmissionLease struct {
	TenantID              string                 `json:"tenant_id"`
	RequestID             string                 `json:"request_id"`
	LeaseID               string                 `json:"lease_id"`
	EstimatedTokens       int64                  `json:"estimated_tokens"`
	EstimatedCostMicros   int64                  `json:"estimated_cost_micros"`
	CostEstimateAvailable bool                   `json:"cost_estimate_available"`
	MinuteBucket          int64                  `json:"minute_bucket"`
	DayBucket             string                 `json:"day_bucket"`
	MonthBucket           string                 `json:"month_bucket"`
	ExpiresAt             time.Time              `json:"expires_at"`
	LeaseTTLMillis        int64                  `json:"lease_ttl_ms,omitempty"`
	State                 string                 `json:"state"`
	Fingerprint           string                 `json:"fingerprint"`
	Scopes                []AdmissionScope       `json:"scopes"`
	Observations          []AdmissionObservation `json:"observations,omitempty"`
}

type AdmissionLimitError struct {
	Metric           string
	Scope            string
	ScopeID          string
	Limit            int64
	Used             int64
	Reserved         int64
	Requested        int64
	RetryAfter       int64
	RequestID        string
	ConfiguredAction string
	// BudgetCutoff 表示“预算断流”总开关在本次准入时处于开启状态：金额类超限按断流处理。
	BudgetCutoff bool
	// ScopeName 是作用域的展示名（例如部门名称），可能为空。
	ScopeName string
	// ResetAt 是该额度周期的下一次重置时间（带策略时区），零值表示未知。
	ResetAt time.Time
	// Currency 是本次请求计价币种，仅决定提示里的金额符号；空值按历史口径显示 ¥。
	Currency string
}

func (e *AdmissionLimitError) Error() string {
	return fmt.Sprintf("quota admission rejected: metric=%s scope=%s limit=%d used=%d reserved=%d requested=%d", e.Metric, e.Scope, e.Limit, e.Used, e.Reserved, e.Requested)
}

type AdmissionRuntimeError struct {
	Metric    string
	RequestID string
	Err       error
	// BudgetCutoff 表示断流开关开启时因计费/限额运行时不可用而拒绝（fail-closed）。
	BudgetCutoff bool
}

func (e *AdmissionRuntimeError) Error() string {
	if e.Err == nil {
		return "quota admission runtime fault"
	}
	return "quota admission runtime fault: " + e.Err.Error()
}

func (e *AdmissionRuntimeError) Unwrap() error { return e.Err }

// ModelPriceMissingMessage is the operator-facing reason shown when a model
// without a configured price is refused (D6).
const ModelPriceMissingMessage = "该模型未配置价格，请联系管理员"

// ModelPriceMissingCutoffMessage 是预算断流开启后，未定价模型被拒绝时的提示。
const ModelPriceMissingCutoffMessage = "该模型未配置价格，已暂停使用，请联系管理员"

// BillingUnavailableCutoffMessage 是断流开启后计费/限额运行时不可用（fail-closed）的提示。
const BillingUnavailableCutoffMessage = "计费服务暂不可用，请稍后重试"

type AdmissionIdempotencyError struct {
	RequestID string
	State     string
	Reason    string
}

func (e *AdmissionIdempotencyError) Error() string {
	return fmt.Sprintf("quota admission idempotency conflict: request_id=%s state=%s reason=%s", e.RequestID, e.State, e.Reason)
}

type AdmissionOverrunError struct {
	RequestID       string
	EstimatedTokens int64
	ActualTokens    int64
}

type AdmissionCostOverrunError struct {
	RequestID       string
	EstimatedMicros int64
	ActualMicros    int64
}

func (e *AdmissionCostOverrunError) Error() string {
	return fmt.Sprintf("quota cost reservation overrun: request_id=%s estimated_micros=%d actual_micros=%d", e.RequestID, e.EstimatedMicros, e.ActualMicros)
}

func (e *AdmissionOverrunError) Error() string {
	return fmt.Sprintf("quota token reservation overrun: request_id=%s estimated=%d actual=%d", e.RequestID, e.EstimatedTokens, e.ActualTokens)
}

type EffectiveQuotaInput struct {
	MonthlyTokenLimit, DailyTokenLimit       int64
	MonthlyBudgetMicros, DailyBudgetMicros   int64
	RPMLimit, TPMLimit, ConcurrencyLimit     int64
	RPMBlocked, TPMConfigured, TPMBlocked    bool
	ConcurrencyBlocked                       bool
	DailyTokenBlocked, MonthlyTokenBlocked   bool
	DailyBudgetBlocked, MonthlyBudgetBlocked bool
	QuotaTimezone                            string
	OverageAction                            string
	DowngradeTo                              string
	TriggeredScope                           string
}

// ScopedQuota keeps one policy's limits paired with the exact usage bucket
// that must be checked. Limits from one scope must never be compared with a
// different scope's usage.
type ScopedQuota struct {
	Scope           string
	ID              string
	EnforcementMode string
	Limits          EffectiveQuotaInput
	// Name 是作用域的展示名（部门名称等），仅用于拒绝提示，不参与准入指纹。
	Name string
}

func (q ScopedQuota) Key() string {
	return q.Scope + ":" + q.ID
}

// ModelChecker provides team model whitelist lookups for the governor.
type ModelChecker interface {
	// IsModelAllowedForTeam returns true if the model is allowed for the team.
	// Returns true (fail-open) when teamID is empty or on DB errors.
	IsModelAllowedForTeam(ctx context.Context, teamID, modelID string) (bool, error)
}

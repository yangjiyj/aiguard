package modelops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/providercompat"
)

var (
	ErrConflict         = errors.New("model operations config version conflict")
	ErrCostConfirmation = errors.New("probe cost confirmation required")
	ErrUnavailable      = errors.New("model operations target unavailable")
	ErrLeaseLost        = errors.New("model operations lease lost")
	ErrIdentityChanged  = errors.New("model operations target identity changed")
	ErrInvalid          = errors.New("invalid model operations request")
)

type Config struct {
	Version          int64      `json:"version"`
	Enabled          bool       `json:"enabled"`
	IntervalSeconds  int        `json:"interval_seconds"`
	Concurrency      int        `json:"concurrency"`
	TimeoutSeconds   int        `json:"timeout_seconds"`
	MaxTargets       int        `json:"max_targets"`
	MaxOutputTokens  int        `json:"max_output_tokens"`
	Protocols        []string   `json:"protocols"`
	FailureThreshold int        `json:"failure_threshold"`
	UpdatedAt        time.Time  `json:"updated_at"`
	UpdatedBy        string     `json:"updated_by"`
	CostConfirmedAt  *time.Time `json:"cost_confirmed_at"`
	CostConfirmedBy  string     `json:"cost_confirmed_by"`
}

func DefaultConfig() Config {
	return Config{Version: 1, IntervalSeconds: 300, Concurrency: 2, TimeoutSeconds: 15, MaxTargets: 50, MaxOutputTokens: 128, Protocols: []string{"chat", "responses", "messages"}, FailureThreshold: 3}
}

func ValidateProtocols(protocols []string) error {
	if len(protocols) == 0 || len(protocols) > 3 {
		return fmt.Errorf("%w: select 1 to 3 protocols", ErrInvalid)
	}
	seen := map[string]bool{}
	for _, p := range protocols {
		if (p != "chat" && p != "responses" && p != "messages") || seen[p] {
			return fmt.Errorf("%w: invalid or duplicate protocol", ErrInvalid)
		}
		seen[p] = true
	}
	return nil
}

func (c Config) Validate() error {
	if c.IntervalSeconds < 60 || c.IntervalSeconds > 86400 || c.Concurrency < 1 || c.Concurrency > 5 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 60 || c.MaxTargets < 1 || c.MaxTargets > 100 || c.MaxOutputTokens < 1 || c.MaxOutputTokens > 1024 || c.FailureThreshold < 1 || c.FailureThreshold > 10 {
		return fmt.Errorf("%w: configuration outside supported limits", ErrInvalid)
	}
	return ValidateProtocols(c.Protocols)
}

type Target struct {
	ModelID           string `json:"model_id"`
	ModelName         string `json:"model_name"`
	ProviderID        string `json:"provider_id"`
	ProviderName      string `json:"provider_name"`
	UpstreamModelID   string `json:"upstream_model_id"`
	Protocol          string `json:"protocol"`
	ConfigDigest      string `json:"config_digest"`
	IdentityDigest    string `json:"-"`
	CredentialID      string `json:"-"`
	ModelStatus       string `json:"model_status,omitempty"`
	ManualProbe       bool   `json:"-"`
	ProviderStatus    string `json:"-"`
	MaxOutputTokens   int    `json:"-"`
	TimeoutSeconds    int    `json:"-"`
	PreferredProtocol string `json:"-"`
	ConfigVersion     int64  `json:"-"`
	ProviderType      string `json:"-"`
	Supported         bool   `json:"supported"`
}

func (t Target) Key() string { return t.ModelID + "/" + t.ProviderID + "/" + t.Protocol }
func ProtocolSupported(providerType, protocol string) bool {
	typ := strings.ToLower(strings.TrimSpace(providerType))
	if typ == "gemini" || typ == "vertex" || typ == "bedrock" {
		return protocol == "chat"
	}
	return (providercompat.OpenAICompatible(providerType) && (protocol == "chat" || protocol == "responses" || protocol == "messages")) || (strings.EqualFold(strings.TrimSpace(providerType), "anthropic") && protocol == "messages")
}

// The digest binds the exact deployment and credential bytes without persisting secrets.
func DigestTargetIdentity(providerType, baseURL, authMode, credentialID, ciphertext, modelID, providerID, modelName, upstreamModelID, modelStatus, providerStatus string) string {
	h := sha256.Sum256([]byte(ciphertext))
	b, _ := json.Marshal([]string{providerType, baseURL, authMode, credentialID, hex.EncodeToString(h[:]), modelID, providerID, modelName, upstreamModelID, modelStatus, providerStatus})
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func TargetIdentityDigest(p *repository.Provider, c *repository.ProviderCredential, m *repository.Model) string {
	if p == nil || c == nil || m == nil {
		return ""
	}
	return DigestTargetIdentity(p.ProviderType, p.BaseURL, p.AuthMode, c.ID, c.SecretCiphertext, m.ID, m.ProviderID, m.ModelName, m.UpstreamModelID, m.Status, p.Status)
}

type Outcome struct {
	Success       bool   `json:"success"`
	HTTPStatus    int    `json:"http_status"`
	BodyValidated bool   `json:"body_validated"`
	LatencyMS     int64  `json:"latency_ms"`
	ErrorKind     string `json:"error_kind"`
}

func (o Outcome) sanitized() Outcome {
	allowed := map[string]bool{"": true, "unauthorized": true, "not_deployed": true, "rate_limited": true, "upstream_error": true, "timeout": true, "cancelled": true, "invalid_request": true, "invalid_body": true, "transport_error": true, "config_changed": true, "unavailable": true, "unsupported": true}
	if !allowed[o.ErrorKind] {
		o.ErrorKind = "upstream_error"
	}
	if o.HTTPStatus < 0 || o.HTTPStatus > 599 {
		o.HTTPStatus = 0
	}
	if o.LatencyMS < 0 {
		o.LatencyMS = 0
	}
	if o.Success && (!o.BodyValidated || o.HTTPStatus < 200 || o.HTTPStatus >= 300 || o.ErrorKind != "") {
		o.Success = false
		o.ErrorKind = "invalid_body"
	}
	if !o.Success && o.ErrorKind == "" {
		o.ErrorKind = "upstream_error"
	}
	return o
}

type ProbeRecord struct {
	ID string `json:"id"`
	Target
	Outcome
	Source        string    `json:"source"`
	Actor         string    `json:"actor"`
	CreatedAt     time.Time `json:"created_at"`
	ConfigVersion int64     `json:"config_version"`
	Epoch         int64     `json:"epoch"`
	InvocationID  string    `json:"invocation_id"`
}
type HistoryFilter struct {
	ModelID, ProviderID, Protocol, Source, Cursor, InvocationID string
	Limit, WindowHours                                          int
}
type HistoryPage struct {
	Items      []ProbeRecord `json:"items"`
	NextCursor string        `json:"next_cursor"`
}
type HourlyPoint struct {
	Hour         time.Time `json:"hour"`
	Samples      int64     `json:"samples"`
	Successes    int64     `json:"successes"`
	Availability *float64  `json:"availability"`
	P50MS        *float64  `json:"p50_ms"`
	P95MS        *float64  `json:"p95_ms"`
}
type TargetSummary struct {
	Target
	State        string        `json:"state"`
	Samples      int64         `json:"samples"`
	Successes    int64         `json:"successes"`
	Availability *float64      `json:"availability"`
	P50MS        *float64      `json:"p50_ms"`
	P95MS        *float64      `json:"p95_ms"`
	LastProbeAt  *time.Time    `json:"last_probe_at"`
	LastError    string        `json:"last_error"`
	Hourly       []HourlyPoint `json:"hourly"`
}
type Overview struct {
	Config      Config          `json:"config"`
	Targets     []TargetSummary `json:"targets"`
	GeneratedAt time.Time       `json:"generated_at"`
}
type QualityItem struct {
	FirstEventP50MS       *float64   `json:"first_event_p50_ms"`
	FirstEventP95MS       *float64   `json:"first_event_p95_ms"`
	OutputTokensPerSecP50 *float64   `json:"output_tokens_per_sec_p50"`
	SecurityP50MS         *float64   `json:"security_p50_ms"`
	SecurityP95MS         *float64   `json:"security_p95_ms"`
	PreUpstreamP50MS      *float64   `json:"pre_upstream_p50_ms"`
	PreUpstreamP95MS      *float64   `json:"pre_upstream_p95_ms"`
	RPM                   *float64   `json:"rpm"`
	TPM                   *float64   `json:"tpm"`
	ModelID               string     `json:"model_id"`
	ModelName             string     `json:"model_name"`
	ProviderID            string     `json:"provider_id"`
	ProviderName          string     `json:"provider_name"`
	Samples               int64      `json:"samples"`
	Successes             int64      `json:"successes"`
	Failures              int64      `json:"failures"`
	AuthFailures          int64      `json:"auth_failures"`
	Availability          *float64   `json:"availability"`
	P50MS                 *float64   `json:"p50_ms"`
	P95MS                 *float64   `json:"p95_ms"`
	LastRequestAt         *time.Time `json:"last_request_at"`
	HTTP5xx               int64      `json:"http_5xx"`
	HTTP429               int64      `json:"http_429"`
	HTTP4xx               int64      `json:"http_4xx"`
	Cancelled             int64      `json:"cancelled"`
	AvgFirstEventMS       *float64   `json:"avg_first_event_ms"`
	LastRequestID         string     `json:"last_request_id"`
	UpstreamSamples       int64      `json:"upstream_samples"`
	UpstreamSuccesses     int64      `json:"upstream_successes"`
	Blocked               int64      `json:"blocked"`
}
type ReadFilter struct {
	WindowHours         int
	ProviderID, ModelID string
}

func (f ReadFilter) validated() (ReadFilter, error) {
	if f.WindowHours == 0 {
		f.WindowHours = 24
	}
	if f.WindowHours != 6 && f.WindowHours != 24 && f.WindowHours != 72 && f.WindowHours != 168 {
		return f, ErrInvalid
	}
	return f, nil
}

type Quality struct {
	Note        string        `json:"note"`
	Items       []QualityItem `json:"items"`
	GeneratedAt time.Time     `json:"generated_at"`
}
type Alert struct {
	ID string `json:"id"`
	Target
	State          string     `json:"state"`
	FailureCount   int        `json:"failure_count"`
	LastError      string     `json:"last_error"`
	OpenedAt       time.Time  `json:"opened_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	ResolvedAt     *time.Time `json:"resolved_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at"`
	AcknowledgedBy string     `json:"acknowledged_by"`
}
type AlertFilter struct {
	State, Cursor, ProviderID, ModelID string
	Limit                              int
}
type AlertPage struct {
	Items      []Alert `json:"items"`
	NextCursor string  `json:"next_cursor"`
}
type TestRequest struct {
	ModelIDs              []string `json:"model_ids"`
	Protocols             []string `json:"protocols"`
	ConfirmCost           bool     `json:"confirm_cost"`
	ExpectedConfigVersion int64    `json:"expected_config_version"`
}
type SkippedTarget struct {
	Target
	Reason string `json:"reason"`
}
type TestResult struct {
	Items   []ProbeRecord   `json:"items"`
	Skipped []SkippedTarget `json:"skipped"`
}

type Executor interface {
	Execute(context.Context, string, Target) Outcome
}
type ExecutorFunc func(context.Context, string, Target) Outcome

func (f ExecutorFunc) Execute(ctx context.Context, tenant string, t Target) Outcome {
	return f(ctx, tenant, t)
}

type invocationKey struct{}

func WithInvocation(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, invocationKey{}, id)
}
func invocationID(ctx context.Context) string {
	id, _ := ctx.Value(invocationKey{}).(string)
	return id
}

type jobOwnerKey struct{}

func WithJobOwner(ctx context.Context, id, token string) context.Context {
	return context.WithValue(WithInvocation(ctx, id), jobOwnerKey{}, token)
}
func jobOwner(ctx context.Context) string {
	token, _ := ctx.Value(jobOwnerKey{}).(string)
	return token
}

type targetIdentitiesKey struct{}

func WithTargetIdentities(ctx context.Context, identities map[string]string) context.Context {
	copyMap := make(map[string]string, len(identities))
	for k, v := range identities {
		copyMap[k] = v
	}
	return context.WithValue(ctx, targetIdentitiesKey{}, copyMap)
}
func targetIdentities(ctx context.Context) map[string]string {
	m, _ := ctx.Value(targetIdentitiesKey{}).(map[string]string)
	return m
}

type Lease struct {
	TenantID, Token, Owner, Cursor string
	Epoch                          int64
	Config                         Config
	ExpiresAt                      time.Time
}
type Store interface {
	GetConfig(context.Context, string) (Config, error)
	UpdateConfig(context.Context, string, string, int64, Config, bool) (Config, error)
	ListTargets(context.Context, string, []string) ([]Target, error)
	ListManualTargets(context.Context, string, []string) ([]Target, error)
	ListEnabledTenants(context.Context) ([]string, error)
	AcquireLease(context.Context, string, string) (*Lease, error)
	RenewLease(context.Context, *Lease) error
	ReleaseLease(context.Context, *Lease, string) error
	ClaimTarget(context.Context, *Lease, Target) (bool, error)
	BeginScheduledDispatch(context.Context, *Lease, Target) error
	Complete(context.Context, *Lease, Target, Outcome) (ProbeRecord, error)
	RecordManual(context.Context, string, string, Target, Outcome) (ProbeRecord, error)
	BeginManualTarget(context.Context, string, string, Target) (bool, error)
	GetOverview(context.Context, string, ReadFilter) (Overview, error)
	ListHistory(context.Context, string, HistoryFilter) (HistoryPage, error)
	GetQuality(context.Context, string, ReadFilter) (Quality, error)
	GetProviderMonitor(context.Context, string, ReadFilter) (ProviderMonitor, error)
	GetModelPerformance(context.Context, string, int) (ModelPerformanceReport, error)
	ListAlerts(context.Context, string, AlertFilter) (AlertPage, error)
	AcknowledgeAlert(context.Context, string, string, string) (Alert, error)
}

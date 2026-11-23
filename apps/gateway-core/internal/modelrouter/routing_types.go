package modelrouter

import (
	"context"
	"encoding/json"
	"math"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/yangjiyj/aiguard/packages/shared-go/modelrouting"
)

// RoutingPolicy represents a routing policy record from the routing_policies table.
type RoutingPolicy struct {
	ID        string
	ScopeType string
	ScopeRef  string
	Layer     string
	Strategy  string
	Config    map[string]any
	Enabled   bool
}

// V2RoutingPolicy is the typed provider-layer policy used by model routing v2.
// Legacy rows remain represented by RoutingPolicy and PolicyCache.GetPolicy.
type V2RoutingPolicy struct {
	Scope         modelrouting.Scope
	ModelName     string
	ConfigVersion int64
	Config        modelrouting.Config
}

type RoutePlan struct {
	Primary   ModelRecord
	Fallbacks []ModelRecord
	Decision  *RoutingDecision
	// RouteIdentities is an in-memory provider ID to safe audit identity map.
	// Map keys are never serialized or returned by the control-plane API.
	RouteIdentities map[string]RouteIdentity `json:"-"`
}

type RouteKey struct {
	TenantID   string
	ModelName  string
	ProviderID string
}

type AttemptResult struct {
	Success       bool
	Retryable     bool
	HealthNeutral bool
	StatusCode    int
	Latency       time.Duration
	TTFT          time.Duration
	OccurredAt    time.Time
}

type Engine interface {
	HasV2Policy(ctx context.Context, tenantID, modelRef string) (bool, error)
	Plan(ctx context.Context, env RequestEnvelope) (RoutePlan, bool, error)
	// AllowAttempt atomically claims a half-open probe immediately before an
	// upstream call. A claimed attempt must always be followed by RecordAttempt.
	AllowAttempt(key RouteKey) bool
	RecordAttempt(key RouteKey, result AttemptResult)
}

// FallbackAlertRecorder is an optional Engine capability used by the request
// executor after a backup route actually succeeds.
type FallbackAlertRecorder interface {
	RecordFallback(ctx context.Context, key RouteKey)
}

// AttemptClaimReleaser releases a half-open probe claim when an adapter proves
// ineligible before making an upstream request.
type AttemptClaimReleaser interface {
	ReleaseAttempt(key RouteKey)
}

// ModelDecision is the output of the model selection layer.
type ModelDecision struct {
	TargetModel string         `json:"target_model"`
	Strategy    string         `json:"strategy"`
	Reason      map[string]any `json:"factors,omitempty"`
}

// ProviderDecision is the output of the provider selection layer.
type ProviderDecision struct {
	ProviderID    string         `json:"selected_provider"`
	Strategy      string         `json:"strategy"`
	FallbackChain []string       `json:"fallback_chain,omitempty"`
	Reason        map[string]any `json:"factors,omitempty"`
}

// RouteIdentity is deliberately customer-readable. It must never contain a
// provider, credential, policy, or tenant database identifier.
type RouteIdentity struct {
	ProviderName string `json:"provider_name,omitempty"`
	RouteRef     string `json:"route_ref,omitempty"`
}

type RouteCandidateDecision struct {
	ProviderName     string             `json:"provider_name,omitempty"`
	RouteRef         string             `json:"route_ref,omitempty"`
	SampleState      string             `json:"sample_state,omitempty"`
	NormalizedScores map[string]float64 `json:"normalized_scores,omitempty"`
	DimensionState   map[string]string  `json:"dimension_state,omitempty"`
	ExclusionReason  string             `json:"exclusion_reason,omitempty"`
}

type RouteAttemptDecision struct {
	Route              RouteIdentity `json:"route"`
	Result             string        `json:"result"`
	StatusCodeCategory string        `json:"status_code_category,omitempty"`
	LatencyMS          int64         `json:"latency_ms"`
	FailureCategory    string        `json:"failure_category,omitempty"`
}

type ModelRouteDecisionV2 struct {
	SchemaVersion  int                      `json:"schema_version"`
	RequestedModel string                   `json:"requested_model"`
	PolicySource   string                   `json:"policy_source,omitempty"`
	PolicyVersion  int64                    `json:"policy_version,omitempty"`
	Strategy       string                   `json:"strategy,omitempty"`
	Candidates     []RouteCandidateDecision `json:"candidates,omitempty"`
	PlannedRoute   RouteIdentity            `json:"planned_route"`
	ActualRoute    RouteIdentity            `json:"actual_route"`
	Attempts       []RouteAttemptDecision   `json:"attempts,omitempty"`
	FallbackUsed   bool                     `json:"fallback_used"`
	FallbackReason string                   `json:"fallback_reason,omitempty"`
}

// RoutingDecision aggregates both layers plus governor overrides.
// It is persisted as routing_decision_json in request_logs.
type RoutingDecision struct {
	ModelLayer       *ModelDecision        `json:"model_layer,omitempty"`
	GovernorOverride map[string]any        `json:"governor_override,omitempty"`
	ProviderLayer    *ProviderDecision     `json:"provider_layer,omitempty"`
	FallbackRetries  int                   `json:"fallback_retries"`
	ModelRouteV2     *ModelRouteDecisionV2 `json:"model_route_v2,omitempty"`
	IngressProtocol  string                `json:"ingress_protocol,omitempty"`
	UpstreamProtocol string                `json:"upstream_protocol,omitempty"`
	RequestFeatures  []string              `json:"request_features,omitempty"`
	// ClientModel 是客户端请求里写的原始模型名（失败请求或别名解析时记录）。
	ClientModel string `json:"client_model,omitempty"`
	// ModelResolution：suffix_alias（补全了供应商前缀）/ not_found / ambiguous / inactive。
	ModelResolution string   `json:"model_resolution,omitempty"`
	ModelCandidates []string `json:"model_candidates,omitempty"`
	// RejectReason：请求被拒的具体原因，如 feature_contract:cache_tokens、key_allowlist。
	RejectReason string `json:"reject_reason,omitempty"`
}

// SanitizeRoutingDecision returns a detached copy safe for audit persistence.
// Typed v2 fields only admit an allow-list. Legacy extensible maps are scrubbed
// recursively so old callers cannot accidentally persist request content or
// credentials. URL values retain only scheme/host/path.
func SanitizeRoutingDecision(in *RoutingDecision) *RoutingDecision {
	if in == nil {
		return nil
	}
	out := *in
	out.IngressProtocol = sanitizeDecisionString(in.IngressProtocol)
	out.UpstreamProtocol = sanitizeDecisionString(in.UpstreamProtocol)
	out.ClientModel = sanitizeDecisionString(in.ClientModel)
	out.ModelResolution = sanitizeDecisionString(in.ModelResolution)
	out.RejectReason = sanitizeDecisionString(in.RejectReason)
	if len(in.ModelCandidates) > 0 {
		out.ModelCandidates = make([]string, len(in.ModelCandidates))
		for i, name := range in.ModelCandidates {
			out.ModelCandidates[i] = sanitizeDecisionString(name)
		}
	}
	out.RequestFeatures = make([]string, len(in.RequestFeatures))
	for i, feature := range in.RequestFeatures {
		out.RequestFeatures[i] = sanitizeDecisionString(feature)
	}
	out.GovernorOverride = sanitizeDecisionMap(in.GovernorOverride)
	if in.ModelLayer != nil {
		v := *in.ModelLayer
		v.TargetModel = sanitizeDecisionString(v.TargetModel)
		v.Strategy = sanitizeDecisionString(v.Strategy)
		v.Reason = sanitizeDecisionMap(in.ModelLayer.Reason)
		out.ModelLayer = &v
	}
	if in.ProviderLayer != nil {
		v := *in.ProviderLayer
		v.ProviderID = sanitizeDecisionString(v.ProviderID)
		v.Strategy = sanitizeDecisionString(v.Strategy)
		v.FallbackChain = make([]string, len(in.ProviderLayer.FallbackChain))
		for i, item := range in.ProviderLayer.FallbackChain {
			v.FallbackChain[i] = sanitizeDecisionString(item)
		}
		v.Reason = sanitizeDecisionMap(in.ProviderLayer.Reason)
		out.ProviderLayer = &v
	}
	if in.ModelRouteV2 != nil {
		v := *in.ModelRouteV2
		v.RequestedModel = sanitizeDecisionString(v.RequestedModel)
		v.PolicySource = sanitizeDecisionString(v.PolicySource)
		v.Strategy = sanitizeDecisionString(v.Strategy)
		v.FallbackReason = sanitizeDecisionString(v.FallbackReason)
		v.PlannedRoute = sanitizeRouteIdentity(v.PlannedRoute)
		v.ActualRoute = sanitizeRouteIdentity(v.ActualRoute)
		v.Candidates = make([]RouteCandidateDecision, len(in.ModelRouteV2.Candidates))
		for i, candidate := range in.ModelRouteV2.Candidates {
			candidate.ProviderName = sanitizeDecisionString(candidate.ProviderName)
			candidate.RouteRef = sanitizeDecisionString(candidate.RouteRef)
			candidate.SampleState = sanitizeDecisionString(candidate.SampleState)
			candidate.ExclusionReason = sanitizeDecisionString(candidate.ExclusionReason)
			candidate.DimensionState = sanitizeStringMap(candidate.DimensionState)
			candidate.NormalizedScores = sanitizeScoreMap(candidate.NormalizedScores)
			v.Candidates[i] = candidate
		}
		v.Attempts = make([]RouteAttemptDecision, len(in.ModelRouteV2.Attempts))
		for i, attempt := range in.ModelRouteV2.Attempts {
			attempt.Route = sanitizeRouteIdentity(attempt.Route)
			attempt.Result = sanitizeDecisionString(attempt.Result)
			attempt.StatusCodeCategory = sanitizeDecisionString(attempt.StatusCodeCategory)
			attempt.FailureCategory = sanitizeDecisionString(attempt.FailureCategory)
			v.Attempts[i] = attempt
		}
		out.ModelRouteV2 = &v
	}
	return &out
}

var decisionURLPattern = regexp.MustCompile(`(?i)https?://[^\s]+`)
var decisionAssignmentPattern = regexp.MustCompile(`(?i)\b(?:authorization|api[-_ ]?key|secret|credential(?:_id)?)\s*[:=]\s*(?:bearer\s+)?[^\s,;]+`)
var decisionBearerPattern = regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._~+/=-]+`)
var decisionSKPattern = regexp.MustCompile(`(?i)\bsk-[a-z0-9_-]{4,}`)

func sanitizeDecisionString(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	value = decisionURLPattern.ReplaceAllStringFunc(value, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			return "[REDACTED_URL]"
		}
		u.RawQuery = ""
		u.Fragment = ""
		u.User = nil
		return u.String()
	})
	value = decisionAssignmentPattern.ReplaceAllString(value, "[REDACTED]")
	value = decisionBearerPattern.ReplaceAllString(value, "Bearer [REDACTED]")
	value = decisionSKPattern.ReplaceAllString(value, "[REDACTED]")
	runes := []rune(value)
	if len(runes) > 256 {
		value = string(runes[:256])
	}
	return value
}
func sanitizeRouteIdentity(v RouteIdentity) RouteIdentity {
	v.ProviderName = sanitizeDecisionString(v.ProviderName)
	v.RouteRef = sanitizeDecisionString(v.RouteRef)
	return v
}
func sanitizeStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[sanitizeDecisionString(k)] = sanitizeDecisionString(v)
	}
	return out
}
func sanitizeScoreMap(in map[string]float64) map[string]float64 {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]float64, len(in))
	for k, v := range in {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		out[sanitizeDecisionString(k)] = v
	}
	return out
}

func sanitizeDecisionMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		if forbiddenDecisionKey(key) {
			continue
		}
		if clean, ok := sanitizeDecisionValue(value); ok {
			out[sanitizeDecisionString(key)] = clean
		}
	}
	return out
}

func forbiddenDecisionKey(key string) bool {
	n := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
	for _, token := range []string{"prompt", "response", "body", "content", "authorization", "api_key", "apikey", "secret", "credential", "purchase_price", "actual_cost", "token_price"} {
		if strings.Contains(n, token) {
			return true
		}
	}
	return false
}

func sanitizeDecisionValue(value any) (any, bool) {
	switch typed := value.(type) {
	case nil:
		return nil, true
	case string:
		return sanitizeDecisionString(typed), true
	case bool:
		return typed, true
	case int:
		return typed, true
	case int8:
		return typed, true
	case int16:
		return typed, true
	case int32:
		return typed, true
	case int64:
		return typed, true
	case uint:
		return typed, true
	case uint8:
		return typed, true
	case uint16:
		return typed, true
	case uint32:
		return typed, true
	case uint64:
		return typed, true
	case float32:
		if math.IsNaN(float64(typed)) || math.IsInf(float64(typed), 0) {
			return nil, false
		}
		return typed, true
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return nil, false
		}
		return typed, true
	case json.Number:
		number, err := typed.Float64()
		if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, false
		}
		return typed, true
	case map[string]any:
		return sanitizeDecisionMap(typed), true
	case map[string]string:
		return sanitizeStringMap(typed), true
	case []string:
		out := make([]string, len(typed))
		for i, item := range typed {
			out[i] = sanitizeDecisionString(item)
		}
		return out, true
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			if clean, ok := sanitizeDecisionValue(item); ok {
				out = append(out, clean)
			}
		}
		return out, true
	default:
		return nil, false
	}
}

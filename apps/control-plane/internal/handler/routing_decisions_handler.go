package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type routingDecisionV2View struct {
	SchemaVersion  int                    `json:"schema_version"`
	RequestedModel string                 `json:"requested_model"`
	PolicySource   string                 `json:"policy_source,omitempty"`
	PolicyVersion  int64                  `json:"policy_version,omitempty"`
	Strategy       string                 `json:"strategy,omitempty"`
	Candidates     []routingCandidateView `json:"candidates,omitempty"`
	PlannedRoute   routingRouteView       `json:"planned_route"`
	ActualRoute    routingRouteView       `json:"actual_route"`
	Attempts       []routingAttemptView   `json:"attempts,omitempty"`
	FallbackUsed   bool                   `json:"fallback_used"`
	FallbackReason string                 `json:"fallback_reason,omitempty"`
}

type routingRouteView struct {
	ProviderName string `json:"provider_name,omitempty"`
	RouteRef     string `json:"route_ref,omitempty"`
}
type routingCandidateView struct {
	ProviderName     string             `json:"provider_name,omitempty"`
	RouteRef         string             `json:"route_ref,omitempty"`
	SampleState      string             `json:"sample_state,omitempty"`
	NormalizedScores map[string]float64 `json:"normalized_scores,omitempty"`
	DimensionState   map[string]string  `json:"dimension_state,omitempty"`
	ExclusionReason  string             `json:"exclusion_reason,omitempty"`
}
type routingAttemptView struct {
	Route              routingRouteView `json:"route"`
	Result             string           `json:"result"`
	StatusCodeCategory string           `json:"status_code_category,omitempty"`
	LatencyMS          int64            `json:"latency_ms"`
	FailureCategory    string           `json:"failure_category,omitempty"`
}

type RoutingDecisionListItem struct {
	RequestID          string           `json:"request_id"`
	ModelName          string           `json:"model_name"`
	EndpointType       string           `json:"endpoint_type"`
	Result             string           `json:"result"`
	StatusCodeCategory string           `json:"status_code_category,omitempty"`
	LatencyMS          *int             `json:"latency_ms"`
	CreatedAt          time.Time        `json:"created_at"`
	PlannedRoute       routingRouteView `json:"planned_route,omitempty"`
	ActualRoute        routingRouteView `json:"actual_route,omitempty"`
	FallbackUsed       bool             `json:"fallback_used"`
	FallbackReason     string           `json:"fallback_reason,omitempty"`
	ExplanationStatus  string           `json:"explanation_status"`
}

type RoutingDecisionDetail struct {
	RoutingDecisionListItem
	PolicySource  string                 `json:"policy_source,omitempty"`
	PolicyVersion int64                  `json:"policy_version,omitempty"`
	Strategy      string                 `json:"strategy,omitempty"`
	Candidates    []routingCandidateView `json:"candidates,omitempty"`
	Attempts      []routingAttemptView   `json:"attempts,omitempty"`
}

type RoutingDecisionListResponse struct {
	Data  []RoutingDecisionListItem `json:"data"`
	Total int                       `json:"total"`
}

func ListRoutingDecisions(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		filter, ok := parseRoutingDecisionFilter(w, r)
		if !ok {
			return
		}
		limit, offset := parseIntParam(r.URL.Query().Get("limit"), 100), parseIntParam(r.URL.Query().Get("offset"), 0)
		decisions, total, err := deps.RequestLogRepo.ListRoutingDecisionsFiltered(r.Context(), user.TenantID, filter, limit, offset)
		if err != nil {
			log.Printf("ListRoutingDecisions error: tenant=%s, err=%v", user.TenantID, err)
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list routing decisions")
			return
		}
		items := make([]RoutingDecisionListItem, 0, len(decisions))
		for _, d := range decisions {
			items = append(items, routingDecisionListItem(d))
		}
		writeRoutingDecisionJSON(w, RoutingDecisionListResponse{Data: items, Total: total})
	}
}

func GetRoutingDecision(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		requestID := chi.URLParam(r, "request_id")
		if requestID == "" {
			writeError(w, "invalid_request", "request_id is required")
			return
		}
		d, err := deps.RequestLogRepo.GetRoutingDecision(r.Context(), user.TenantID, requestID)
		if err != nil {
			log.Printf("GetRoutingDecision error: tenant=%s, err=%v", user.TenantID, err)
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get routing decision")
			return
		}
		if d == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "routing decision not found")
			return
		}
		v2 := decodeRoutingDecisionV2(d.RoutingDecisionJSON)
		detail := RoutingDecisionDetail{RoutingDecisionListItem: routingDecisionListItem(d)}
		if v2 != nil {
			detail.PolicySource = v2.PolicySource
			detail.PolicyVersion = v2.PolicyVersion
			detail.Strategy = v2.Strategy
			detail.Candidates = v2.Candidates
			detail.Attempts = v2.Attempts
		}
		writeRoutingDecisionJSON(w, detail)
	}
}

func parseRoutingDecisionFilter(w http.ResponseWriter, r *http.Request) (repository.RoutingDecisionFilter, bool) {
	q := r.URL.Query()
	f := repository.RoutingDecisionFilter{Model: q.Get("model"), Provider: q.Get("provider"), Result: q.Get("result")}
	if value := q.Get("from"); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			writeError(w, "invalid_request", "from/to must be RFC3339")
			return f, false
		}
		f.From = parsed
	}
	if value := q.Get("to"); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			writeError(w, "invalid_request", "from/to must be RFC3339")
			return f, false
		}
		f.To = parsed
	}
	if value := q.Get("fallback"); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			writeError(w, "invalid_request", "fallback must be true or false")
			return f, false
		}
		f.Fallback = &parsed
	}
	return f, true
}

func routingDecisionListItem(d *repository.RoutingDecision) RoutingDecisionListItem {
	item := RoutingDecisionListItem{RequestID: d.RequestID, ModelName: d.ModelName, EndpointType: d.EndpointType, Result: d.RequestStatus, LatencyMS: d.LatencyMS, CreatedAt: d.CreatedAt, ExplanationStatus: d.DecisionParseStatus}
	if d.StatusCode > 0 {
		item.StatusCodeCategory = strconv.Itoa(d.StatusCode/100) + "xx"
	}
	if item.ExplanationStatus == "unparseable" {
		return item
	}
	if v2 := decodeRoutingDecisionV2(d.RoutingDecisionJSON); v2 != nil {
		item.ExplanationStatus = "parsed"
		item.ModelName = v2.RequestedModel
		item.PlannedRoute = v2.PlannedRoute
		item.ActualRoute = v2.ActualRoute
		item.FallbackUsed = v2.FallbackUsed
		item.FallbackReason = v2.FallbackReason
	} else if _, hasV2 := d.RoutingDecisionJSON["model_route_v2"]; hasV2 {
		item.ExplanationStatus = "unparseable"
	} else {
		item.ExplanationStatus = "legacy"
	}
	return item
}

func decodeRoutingDecisionV2(raw map[string]any) *routingDecisionV2View {
	value, ok := raw["model_route_v2"]
	if !ok {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var v routingDecisionV2View
	if json.Unmarshal(encoded, &v) != nil || v.SchemaVersion != 2 {
		return nil
	}
	sanitizeRoutingDecisionV2View(&v)
	return &v
}

var routingAuditURLPattern = regexp.MustCompile(`(?i)https?://[^\s]+`)
var routingAuditAssignmentPattern = regexp.MustCompile(`(?i)\b(?:authorization|api[-_ ]?key|secret|credential(?:_id)?)\s*[:=]\s*(?:bearer\s+)?[^\s,;]+`)
var routingAuditBearerPattern = regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._~+/=-]+`)
var routingAuditSKPattern = regexp.MustCompile(`(?i)\bsk-[a-z0-9_-]{4,}`)

func sanitizeRoutingAuditString(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	value = routingAuditURLPattern.ReplaceAllStringFunc(value, func(raw string) string {
		parsed, err := url.Parse(raw)
		if err != nil {
			return "[REDACTED_URL]"
		}
		parsed.RawQuery = ""
		parsed.Fragment = ""
		parsed.User = nil
		return parsed.String()
	})
	value = routingAuditAssignmentPattern.ReplaceAllString(value, "[REDACTED]")
	value = routingAuditBearerPattern.ReplaceAllString(value, "Bearer [REDACTED]")
	value = routingAuditSKPattern.ReplaceAllString(value, "[REDACTED]")
	runes := []rune(value)
	if len(runes) > 256 {
		value = string(runes[:256])
	}
	return value
}
func sanitizeRoutingRouteView(v routingRouteView) routingRouteView {
	v.ProviderName = sanitizeRoutingAuditString(v.ProviderName)
	v.RouteRef = sanitizeRoutingAuditString(v.RouteRef)
	return v
}
func sanitizeRoutingDecisionV2View(v *routingDecisionV2View) {
	v.RequestedModel = sanitizeRoutingAuditString(v.RequestedModel)
	v.PolicySource = sanitizeRoutingAuditString(v.PolicySource)
	v.Strategy = sanitizeRoutingAuditString(v.Strategy)
	v.FallbackReason = sanitizeRoutingAuditString(v.FallbackReason)
	v.PlannedRoute = sanitizeRoutingRouteView(v.PlannedRoute)
	v.ActualRoute = sanitizeRoutingRouteView(v.ActualRoute)
	for i := range v.Candidates {
		c := &v.Candidates[i]
		c.ProviderName = sanitizeRoutingAuditString(c.ProviderName)
		c.RouteRef = sanitizeRoutingAuditString(c.RouteRef)
		c.SampleState = sanitizeRoutingAuditString(c.SampleState)
		c.ExclusionReason = sanitizeRoutingAuditString(c.ExclusionReason)
		cleanStates := make(map[string]string, len(c.DimensionState))
		for k, value := range c.DimensionState {
			cleanStates[sanitizeRoutingAuditString(k)] = sanitizeRoutingAuditString(value)
		}
		c.DimensionState = cleanStates
		cleanScores := make(map[string]float64, len(c.NormalizedScores))
		for k, value := range c.NormalizedScores {
			cleanScores[sanitizeRoutingAuditString(k)] = value
		}
		c.NormalizedScores = cleanScores
	}
	for i := range v.Attempts {
		a := &v.Attempts[i]
		a.Route = sanitizeRoutingRouteView(a.Route)
		a.Result = sanitizeRoutingAuditString(a.Result)
		a.StatusCodeCategory = sanitizeRoutingAuditString(a.StatusCodeCategory)
		a.FailureCategory = sanitizeRoutingAuditString(a.FailureCategory)
	}
}
func writeRoutingDecisionJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

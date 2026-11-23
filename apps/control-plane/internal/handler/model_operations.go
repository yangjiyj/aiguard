package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/modelops"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

type ModelOperationsService interface {
	Config(context.Context, string) (modelops.Config, error)
	UpdateConfig(context.Context, string, string, int64, modelops.Config, bool) (modelops.Config, error)
	Targets(context.Context, string) ([]modelops.Target, error)
	Overview(context.Context, string) (modelops.Overview, error)
	OverviewFiltered(context.Context, string, modelops.ReadFilter) (modelops.Overview, error)
	History(context.Context, string, modelops.HistoryFilter) (modelops.HistoryPage, error)
	Quality(context.Context, string) (modelops.Quality, error)
	QualityFiltered(context.Context, string, modelops.ReadFilter) (modelops.Quality, error)
	ProviderMonitor(context.Context, string, modelops.ReadFilter) (modelops.ProviderMonitor, error)
	Alerts(context.Context, string, modelops.AlertFilter) (modelops.AlertPage, error)
	Test(context.Context, string, string, modelops.TestRequest) (modelops.TestResult, error)
	AcknowledgeAlert(context.Context, string, string, string) (modelops.Alert, error)
}

type ModelOperationsHandler struct {
	deps    *Dependencies
	service ModelOperationsService
}

func NewModelOperationsHandler(deps *Dependencies, service ModelOperationsService) *ModelOperationsHandler {
	return &ModelOperationsHandler{deps: deps, service: service}
}

func (h *ModelOperationsHandler) authorize(w http.ResponseWriter, r *http.Request, action string) (*repository.User, bool) {
	user := auth.GetUser(r.Context())
	if user == nil || user.TenantID == "" {
		writeUnauthorized(w, "authentication required")
		return nil, false
	}
	if h == nil || h.deps == nil || h.deps.PermissionChecker == nil {
		writeErrorWithStatus(w, http.StatusForbidden, "permission_check_failed", "permission check failed")
		return nil, false
	}
	allowed, err := h.deps.PermissionChecker.HasPermission(r.Context(), user.ID, user.TenantID, "tenant", user.TenantID, "models", action)
	if err != nil || !allowed {
		writeErrorWithStatus(w, http.StatusForbidden, "permission_denied", "permission denied")
		return nil, false
	}
	if h.service == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "model_operations_unavailable", "model operations are unavailable")
		return nil, false
	}
	return user, true
}

func (h *ModelOperationsHandler) read(w http.ResponseWriter, r *http.Request, get func(context.Context, string) (interface{}, error)) {
	user, ok := h.authorize(w, r, "read")
	if !ok || !modelOperationsQuery(w, r) {
		return
	}
	value, err := get(r.Context(), user.TenantID)
	modelOperationsResponse(w, value, err)
}

func (h *ModelOperationsHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	h.read(w, r, func(ctx context.Context, tenant string) (interface{}, error) { return h.service.Config(ctx, tenant) })
}

func (h *ModelOperationsHandler) RequireReadQuery(next http.HandlerFunc, allowed ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := h.authorize(w, r, "read"); !ok {
			return
		}
		if !modelOperationsQuery(w, r, allowed...) {
			return
		}
		next(w, r)
	}
}
func (h *ModelOperationsHandler) GetOverview(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authorize(w, r, "read")
	if !ok {
		return
	}
	filter, ok := modelOperationsReadFilter(w, r)
	if !ok {
		return
	}
	value, err := h.service.OverviewFiltered(r.Context(), user.TenantID, filter)
	modelOperationsResponse(w, value, err)
}
func (h *ModelOperationsHandler) GetQuality(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authorize(w, r, "read")
	if !ok {
		return
	}
	filter, ok := modelOperationsReadFilter(w, r)
	if !ok {
		return
	}
	value, err := h.service.QualityFiltered(r.Context(), user.TenantID, filter)
	modelOperationsResponse(w, value, err)
}
func (h *ModelOperationsHandler) GetProviders(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authorize(w, r, "read")
	if !ok {
		return
	}
	filter, ok := modelOperationsReadFilter(w, r)
	if !ok {
		return
	}
	value, err := h.service.ProviderMonitor(r.Context(), user.TenantID, filter)
	modelOperationsResponse(w, value, err)
}
func (h *ModelOperationsHandler) GetTargets(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authorize(w, r, "read")
	if !ok || !modelOperationsQuery(w, r, "provider_id", "model_id") {
		return
	}
	q := r.URL.Query()
	providerID, modelID := q.Get("provider_id"), q.Get("model_id")
	if (providerID != "" && !modelOperationsID(providerID)) || (modelID != "" && !modelOperationsID(modelID)) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid model or provider filter")
		return
	}
	items, err := h.service.Targets(r.Context(), user.TenantID)
	if err != nil {
		modelOperationsResponse(w, nil, err)
		return
	}
	filtered := []modelops.Target{}
	for _, item := range items {
		if (providerID == "" || item.ProviderID == providerID) && (modelID == "" || item.ModelID == modelID) {
			filtered = append(filtered, item)
		}
	}
	modelOperationsResponse(w, struct {
		Items []modelops.Target `json:"items"`
	}{Items: filtered}, nil)
}

func (h *ModelOperationsHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authorize(w, r, "read")
	if !ok || !modelOperationsQuery(w, r, "model_id", "provider_id", "protocol", "source", "cursor", "limit", "window_hours") {
		return
	}
	q := r.URL.Query()
	limit, ok := modelOperationsLimit(w, q.Get("limit"))
	if !ok {
		return
	}
	hours, ok := modelOperationsWindow(w, q.Get("window_hours"))
	if !ok {
		return
	}
	filter := modelops.HistoryFilter{ModelID: q.Get("model_id"), ProviderID: q.Get("provider_id"), Protocol: q.Get("protocol"), Source: q.Get("source"), Cursor: q.Get("cursor"), Limit: limit, WindowHours: hours}
	if (filter.ModelID != "" && !modelOperationsID(filter.ModelID)) || (filter.ProviderID != "" && !modelOperationsID(filter.ProviderID)) || (filter.Protocol != "" && modelops.ValidateProtocols([]string{filter.Protocol}) != nil) || (filter.Source != "" && filter.Source != "manual" && filter.Source != "scheduled") || len(filter.Cursor) > 1024 {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid history filter")
		return
	}
	value, err := h.service.History(r.Context(), user.TenantID, filter)
	modelOperationsResponse(w, value, err)
}

func (h *ModelOperationsHandler) GetAlerts(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authorize(w, r, "read")
	if !ok || !modelOperationsQuery(w, r, "state", "cursor", "limit", "provider_id", "model_id") {
		return
	}
	q := r.URL.Query()
	limit, ok := modelOperationsLimit(w, q.Get("limit"))
	if !ok {
		return
	}
	filter := modelops.AlertFilter{State: q.Get("state"), Cursor: q.Get("cursor"), Limit: limit, ModelID: q.Get("model_id"), ProviderID: q.Get("provider_id")}
	if (filter.State != "" && filter.State != "open" && filter.State != "resolved") || len(filter.Cursor) > 1024 || (filter.ModelID != "" && !modelOperationsID(filter.ModelID)) || (filter.ProviderID != "" && !modelOperationsID(filter.ProviderID)) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid alert filter")
		return
	}
	value, err := h.service.Alerts(r.Context(), user.TenantID, filter)
	modelOperationsResponse(w, value, err)
}

type modelOperationsConfigRequest struct {
	Version          int64    `json:"version"`
	Enabled          bool     `json:"enabled"`
	IntervalSeconds  int      `json:"interval_seconds"`
	Concurrency      int      `json:"concurrency"`
	TimeoutSeconds   int      `json:"timeout_seconds"`
	MaxTargets       int      `json:"max_targets"`
	MaxOutputTokens  int      `json:"max_output_tokens"`
	Protocols        []string `json:"protocols"`
	FailureThreshold int      `json:"failure_threshold"`
	ConfirmCost      bool     `json:"confirm_cost"`
}

func (h *ModelOperationsHandler) PutConfig(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authorize(w, r, "write")
	if !ok || !modelOperationsQuery(w, r) {
		return
	}
	var req modelOperationsConfigRequest
	if !decodeModelOperationsBody(w, r, &req) {
		return
	}
	cfg := modelops.Config{Enabled: req.Enabled, IntervalSeconds: req.IntervalSeconds, Concurrency: req.Concurrency, TimeoutSeconds: req.TimeoutSeconds, MaxTargets: req.MaxTargets, MaxOutputTokens: req.MaxOutputTokens, Protocols: req.Protocols, FailureThreshold: req.FailureThreshold}
	if req.Version < 1 || cfg.Validate() != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid probe configuration")
		return
	}
	value, err := h.service.UpdateConfig(r.Context(), user.TenantID, user.ID, req.Version, cfg, req.ConfirmCost)
	if err == nil {
		logAudit(r, h.deps, "update_model_operations_config", map[string]interface{}{"version": value.Version, "enabled": value.Enabled, "confirm_cost": req.ConfirmCost}, "model_operations", user.TenantID)
	}
	modelOperationsResponse(w, value, err)
}

func (h *ModelOperationsHandler) AcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authorize(w, r, "write")
	if !ok || !modelOperationsQuery(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	if !modelOperationsID(id) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid alert ID")
		return
	}
	// No input is needed; refusing unexpected content prevents silently ignored
	// actor or tenant fields from appearing to influence acknowledgement.
	if r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, 2))
		if err != nil || len(body) > 0 {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "acknowledgement body must be empty")
			return
		}
	}
	value, err := h.service.AcknowledgeAlert(r.Context(), user.TenantID, id, user.ID)
	if err == nil {
		logAudit(r, h.deps, "acknowledge_model_operations_alert", map[string]interface{}{"alert_id": id}, "model_operations_alert", id)
	}
	modelOperationsResponse(w, value, err)
}

func modelOperationsID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func decodeModelOperationsBody(w http.ResponseWriter, r *http.Request, value interface{}) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeErrorWithStatus(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return false
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "request body must contain one JSON object")
		return false
	}
	return true
}

func modelOperationsQuery(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	keys := map[string]bool{}
	for _, key := range allowed {
		keys[key] = true
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	for key, values := range q {
		if !keys[key] || len(values) != 1 {
			err = errors.New("unknown or duplicate query")
		}
	}
	if err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid query parameters")
		return false
	}
	return true
}

func modelOperationsLimit(w http.ResponseWriter, raw string) (int, bool) {
	if raw == "" {
		return 50, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 100 {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 100")
		return 0, false
	}
	return n, true
}

func modelOperationsWindow(w http.ResponseWriter, raw string) (int, bool) {
	if raw == "" {
		return 24, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || (n != 6 && n != 24 && n != 72 && n != 168) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "window_hours must be 6, 24, 72 or 168")
		return 0, false
	}
	return n, true
}

func modelOperationsReadFilter(w http.ResponseWriter, r *http.Request) (modelops.ReadFilter, bool) {
	if !modelOperationsQuery(w, r, "window_hours", "provider_id", "model_id") {
		return modelops.ReadFilter{}, false
	}
	q := r.URL.Query()
	hours, ok := modelOperationsWindow(w, q.Get("window_hours"))
	filter := modelops.ReadFilter{WindowHours: hours, ProviderID: q.Get("provider_id"), ModelID: q.Get("model_id")}
	if !ok {
		return filter, false
	}
	if (filter.ModelID != "" && !modelOperationsID(filter.ModelID)) || (filter.ProviderID != "" && !modelOperationsID(filter.ProviderID)) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid model or provider filter")
		return filter, false
	}
	return filter, true
}

func modelOperationsResponse(w http.ResponseWriter, value interface{}, err error) {
	if err != nil {
		switch {
		case errors.Is(err, modelops.ErrInvalid):
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid model operations request")
		case errors.Is(err, modelops.ErrCostConfirmation):
			writeErrorWithStatus(w, http.StatusBadRequest, "cost_confirmation_required", "probe cost confirmation is required")
		case errors.Is(err, modelops.ErrConflict), errors.Is(err, modelops.ErrIdentityChanged), errors.Is(err, modelops.ErrLeaseLost):
			writeErrorWithStatus(w, http.StatusConflict, "model_operations_conflict", "configuration changed; reload before retrying")
		case errors.Is(err, modelops.ErrUnavailable):
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "model operations target not found or not owned")
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			writeErrorWithStatus(w, http.StatusRequestTimeout, "cancelled", "model operations request was cancelled")
		default:
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "model_operations_unavailable", "model operations are unavailable")
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

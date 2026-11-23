package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type AgentAdminRepo interface {
	Overview(context.Context, string) (*repository.AgentOverview, error)
	ListEndpoints(context.Context, string, repository.AgentEndpointFilter) (*repository.AgentEndpointPage, error)
	GetEndpoint(context.Context, string, string) (*repository.AgentAdminEndpoint, error)
	UpdateEndpointMode(context.Context, string, string, repository.AgentEndpointModeUpdate) (*repository.AgentAdminEndpoint, error)
	RevokeEndpoint(context.Context, string, string) (bool, error)
	RotateEndpointToken(context.Context, string, string) (string, bool, error)
	ListEnrollmentTokens(context.Context, string, repository.AgentEnrollmentTokenFilter) (*repository.AgentEnrollmentTokenPage, error)
	CreateEnrollmentToken(context.Context, string, repository.AgentEnrollmentTokenCreate) (*repository.AgentEnrollmentTokenCreated, error)
	RevokeEnrollmentToken(context.Context, string, string) (bool, error)
	ListSessions(context.Context, string, repository.AgentSessionFilter) (*repository.AgentSessionPage, error)
	GetSessionDetail(context.Context, string, string) (*repository.AgentSessionDetail, error)
	ListEvents(context.Context, string, repository.AgentEventFilter) (*repository.AgentEventPage, error)
	ListAssets(context.Context, string, repository.AgentAssetFilter) (*repository.AgentAssetPage, error)
	ListPolicyBundles(context.Context, string, int, int) (*repository.AgentPolicyBundlePage, error)
	CurrentPolicyBundle(context.Context, string) (*repository.AgentPolicyBundle, error)
}

type AgentAdminAPI struct {
	Repo AgentAdminRepo
	Deps *Dependencies
}

func NewAgentAdminAPI(repo AgentAdminRepo, deps *Dependencies) *AgentAdminAPI {
	return &AgentAdminAPI{Repo: repo, Deps: deps}
}

func agentAdminUser(w http.ResponseWriter, r *http.Request) (*repository.User, bool) {
	user, ok := authenticatedContentEvidenceUser(w, r)
	if !ok {
		return nil, false
	}
	return user, true
}

func writeAgentAdminJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeAgentAdminSecretJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store,max-age=0")
	w.Header().Set("Pragma", "no-cache")
	writeAgentAdminJSON(w, status, value)
}

func agentAdminPage(r *http.Request) (int, int, bool) {
	page, pageSize := 1, 50
	if raw := strings.TrimSpace(r.URL.Query().Get("page")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			return 0, 0, false
		}
		page = value
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("page_size")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 200 {
			return 0, 0, false
		}
		pageSize = value
	}
	return page, pageSize, true
}

func agentAdminPageOrError(w http.ResponseWriter, r *http.Request) (int, int, bool) {
	page, pageSize, ok := agentAdminPage(r)
	if !ok {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "page must be at least 1 and page_size must be between 1 and 200")
	}
	return page, pageSize, ok
}

func optionalBool(raw string) (*bool, bool) {
	if strings.TrimSpace(raw) == "" {
		return nil, true
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, false
	}
	return &value, true
}

func optionalInt(raw string) (*int, bool) {
	if strings.TrimSpace(raw) == "" {
		return nil, true
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return nil, false
	}
	return &value, true
}

func optionalTime(raw string) (*time.Time, bool) {
	if strings.TrimSpace(raw) == "" {
		return nil, true
	}
	value, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, false
	}
	value = value.UTC()
	return &value, true
}

func validAgentMode(mode string) bool {
	return mode == "monitor" || mode == "would_block" || mode == "block"
}

func validAgentCaptureLevel(level string) bool {
	return level == "metadata" || level == "summary" || level == "full"
}

func (h *AgentAdminAPI) Overview(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	value, err := h.Repo.Overview(r.Context(), user.TenantID)
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get agent overview")
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, value)
}

func (h *AgentAdminAPI) ListEndpoints(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	stale, valid := optionalBool(r.URL.Query().Get("stale"))
	if !valid {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "stale must be boolean")
		return
	}
	page, size, validPage := agentAdminPageOrError(w, r)
	if !validPage {
		return
	}
	q := r.URL.Query()
	value, err := h.Repo.ListEndpoints(r.Context(), user.TenantID, repository.AgentEndpointFilter{Product: strings.TrimSpace(q.Get("product")), Status: strings.TrimSpace(q.Get("status")), OS: strings.TrimSpace(q.Get("os")), Mode: strings.TrimSpace(q.Get("mode")), Query: strings.TrimSpace(q.Get("q")), Stale: stale, Page: page, PageSize: size})
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list agent endpoints")
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, value)
}

func (h *AgentAdminAPI) GetEndpoint(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	value, err := h.Repo.GetEndpoint(r.Context(), user.TenantID, chi.URLParam(r, "id"))
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get agent endpoint")
		return
	}
	if value == nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "agent endpoint not found")
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, value)
}

func (h *AgentAdminAPI) UpdateEndpointMode(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON")
		return
	}
	update := repository.AgentEndpointModeUpdate{}
	if value, exists := raw["mode"]; exists {
		update.ModeSet = true
		if string(value) != "null" {
			var mode string
			if json.Unmarshal(value, &mode) != nil || !validAgentMode(mode) {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid mode")
				return
			}
			update.Mode = &mode
		}
	}
	if value, exists := raw["capture_level"]; exists {
		update.CaptureLevelSet = true
		if string(value) != "null" {
			var level string
			if json.Unmarshal(value, &level) != nil || !validAgentCaptureLevel(level) {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid capture_level")
				return
			}
			update.CaptureLevel = &level
		}
	}
	if !update.ModeSet && !update.CaptureLevelSet {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "mode or capture_level is required")
		return
	}
	id := chi.URLParam(r, "id")
	value, err := h.Repo.UpdateEndpointMode(r.Context(), user.TenantID, id, update)
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to update agent endpoint")
		return
	}
	if value == nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "agent endpoint not found")
		return
	}
	logAudit(r, h.Deps, "agent.endpoint.mode.update", map[string]interface{}{"endpoint_id": id, "mode_changed": update.ModeSet, "capture_level_changed": update.CaptureLevelSet}, "agent_endpoint", id)
	writeAgentAdminJSON(w, http.StatusOK, value)
}

func (h *AgentAdminAPI) RevokeEndpoint(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	found, err := h.Repo.RevokeEndpoint(r.Context(), user.TenantID, id)
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to revoke agent endpoint")
		return
	}
	if !found {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "agent endpoint not found")
		return
	}
	logAudit(r, h.Deps, "agent.endpoint.revoke", map[string]interface{}{"endpoint_id": id}, "agent_endpoint", id)
	writeAgentAdminJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

func (h *AgentAdminAPI) RotateEndpointToken(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	token, found, err := h.Repo.RotateEndpointToken(r.Context(), user.TenantID, id)
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to rotate endpoint token")
		return
	}
	if !found {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "agent endpoint not found")
		return
	}
	logAudit(r, h.Deps, "agent.endpoint.token.rotate", map[string]interface{}{"endpoint_id": id}, "agent_endpoint", id)
	writeAgentAdminSecretJSON(w, http.StatusOK, map[string]string{"endpoint_id": id, "endpoint_token": token})
}

func (h *AgentAdminAPI) ListEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	page, size, validPage := agentAdminPageOrError(w, r)
	if !validPage {
		return
	}
	enabled, valid := optionalBool(r.URL.Query().Get("enabled"))
	if !valid {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "enabled must be boolean")
		return
	}
	value, err := h.Repo.ListEnrollmentTokens(r.Context(), user.TenantID, repository.AgentEnrollmentTokenFilter{Enabled: enabled, Page: page, PageSize: size})
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list enrollment tokens")
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, value)
}

func (h *AgentAdminAPI) CreateEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	var input struct {
		Name            string     `json:"name"`
		DefaultMode     string     `json:"default_mode"`
		AllowedProducts []string   `json:"allowed_products"`
		MaxEndpoints    int        `json:"max_endpoints"`
		ExpiresAt       *time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || input.MaxEndpoints < 0 {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "name is required and max_endpoints cannot be negative")
		return
	}
	if input.DefaultMode == "" {
		input.DefaultMode = "monitor"
	}
	if !validAgentMode(input.DefaultMode) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid default_mode")
		return
	}
	value, err := h.Repo.CreateEnrollmentToken(r.Context(), user.TenantID, repository.AgentEnrollmentTokenCreate{Name: input.Name, DefaultMode: input.DefaultMode, AllowedProducts: input.AllowedProducts, MaxEndpoints: input.MaxEndpoints, ExpiresAt: input.ExpiresAt, CreatedBy: user.ID})
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to create enrollment token")
		return
	}
	logAudit(r, h.Deps, "agent.enrollment_token.create", map[string]interface{}{"enrollment_id": value.ID, "name": value.Name}, "agent_enrollment_token", value.ID)
	writeAgentAdminSecretJSON(w, http.StatusCreated, value)
}

func (h *AgentAdminAPI) RevokeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	found, err := h.Repo.RevokeEnrollmentToken(r.Context(), user.TenantID, id)
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to revoke enrollment token")
		return
	}
	if !found {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "enrollment token not found")
		return
	}
	logAudit(r, h.Deps, "agent.enrollment_token.revoke", map[string]interface{}{"enrollment_id": id}, "agent_enrollment_token", id)
	writeAgentAdminJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

func (h *AgentAdminAPI) ListSessions(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	from, validFrom := optionalTime(r.URL.Query().Get("from"))
	to, validTo := optionalTime(r.URL.Query().Get("to"))
	minRisk, validRisk := optionalInt(r.URL.Query().Get("min_risk"))
	if !validFrom || !validTo || !validRisk || (from != nil && to != nil && from.After(*to)) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid session filters")
		return
	}
	page, size, validPage := agentAdminPageOrError(w, r)
	if !validPage {
		return
	}
	q := r.URL.Query()
	value, err := h.Repo.ListSessions(r.Context(), user.TenantID, repository.AgentSessionFilter{EndpointID: strings.TrimSpace(q.Get("endpoint_id")), Product: strings.TrimSpace(q.Get("product")), Status: strings.TrimSpace(q.Get("status")), Query: strings.TrimSpace(q.Get("q")), From: from, To: to, MinRisk: minRisk, Page: page, PageSize: size})
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list agent sessions")
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, value)
}

var agentAdminSensitiveContentKeys = map[string]struct{}{
	"content": {}, "text": {}, "prompt": {}, "output": {}, "result": {},
	"command": {}, "arguments": {}, "args": {}, "token": {}, "authorization": {},
	"secret": {}, "evidence": {}, "raw": {}, "raw_evidence": {},
}

func retainAgentAdminEvidenceKey(key string) bool {
	lower := strings.ToLower(key)
	return lower == "hash" || lower == "length" || strings.HasSuffix(lower, "_hash") || strings.HasSuffix(lower, "_length")
}

func redactSensitiveContentValue(value any) (any, bool) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	out := map[string]any{}
	for key, child := range object {
		if retainAgentAdminEvidenceKey(key) {
			out[key] = redactContentTree(child)
		}
	}
	return out, true
}

func redactContentTree(value any) any {
	switch current := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, child := range current {
			lower := strings.ToLower(key)
			if _, sensitive := agentAdminSensitiveContentKeys[lower]; sensitive && !retainAgentAdminEvidenceKey(key) {
				if retained, ok := redactSensitiveContentValue(child); ok {
					out[key] = retained
				}
				continue
			}
			out[key] = redactContentTree(child)
		}
		return out
	case []any:
		out := make([]any, len(current))
		for i := range current {
			out[i] = redactContentTree(current[i])
		}
		return out
	default:
		return current
	}
}

func redactRawContent(raw json.RawMessage) json.RawMessage {
	var value any
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil {
		return json.RawMessage(`{}`)
	}
	redacted, err := json.Marshal(redactContentTree(value))
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return redacted
}

func downgradeAgentSessionContent(detail *repository.AgentSessionDetail) {
	for i := range detail.Turns {
		detail.Turns[i].PromptPreview = ""
		detail.Turns[i].AssistantPreview = ""
	}
	for i := range detail.Events {
		detail.Events[i].Payload = redactRawContent(detail.Events[i].Payload)
		detail.Events[i].LocalDecision = redactRawContent(detail.Events[i].LocalDecision)
		detail.Events[i].ServerDecision = redactRawContent(detail.Events[i].ServerDecision)
	}
	for i := range detail.ToolCallLogs {
		detail.ToolCallLogs[i].ArgsSummary = redactRawContent(detail.ToolCallLogs[i].ArgsSummary)
	}
	for i := range detail.Alerts {
		detail.Alerts[i].PayloadSummary = redactRawContent(detail.Alerts[i].PayloadSummary)
	}
}

func (h *AgentAdminAPI) GetSession(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	value, err := h.Repo.GetSessionDetail(r.Context(), user.TenantID, chi.URLParam(r, "id"))
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get agent session")
		return
	}
	if value == nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "agent session not found")
		return
	}
	if !canReadFullTenantContentEvidence(user) {
		downgradeAgentSessionContent(value)
	}
	writeAgentAdminJSON(w, http.StatusOK, value)
}

func (h *AgentAdminAPI) ListEvents(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	from, validFrom := optionalTime(r.URL.Query().Get("from"))
	to, validTo := optionalTime(r.URL.Query().Get("to"))
	if !validFrom || !validTo || (from != nil && to != nil && from.After(*to)) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid event time range")
		return
	}
	page, size, validPage := agentAdminPageOrError(w, r)
	if !validPage {
		return
	}
	q := r.URL.Query()
	value, err := h.Repo.ListEvents(r.Context(), user.TenantID, repository.AgentEventFilter{SessionID: strings.TrimSpace(q.Get("session_id")), EndpointID: strings.TrimSpace(q.Get("endpoint_id")), EventType: strings.TrimSpace(q.Get("event_type")), From: from, To: to, Page: page, PageSize: size})
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list agent events")
		return
	}
	if !canReadFullTenantContentEvidence(user) {
		for i := range value.Items {
			value.Items[i].Payload = redactRawContent(value.Items[i].Payload)
			value.Items[i].LocalDecision = redactRawContent(value.Items[i].LocalDecision)
			value.Items[i].ServerDecision = redactRawContent(value.Items[i].ServerDecision)
		}
	}
	writeAgentAdminJSON(w, http.StatusOK, value)
}

func (h *AgentAdminAPI) ListAssets(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	present, valid := optionalBool(r.URL.Query().Get("present"))
	if !valid {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "present must be boolean")
		return
	}
	page, size, validPage := agentAdminPageOrError(w, r)
	if !validPage {
		return
	}
	q := r.URL.Query()
	value, err := h.Repo.ListAssets(r.Context(), user.TenantID, repository.AgentAssetFilter{EndpointID: strings.TrimSpace(q.Get("endpoint_id")), AssetType: strings.TrimSpace(q.Get("asset_type")), Present: present, Page: page, PageSize: size})
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list agent assets")
		return
	}
	if !canReadFullTenantContentEvidence(user) {
		for i := range value.Items {
			value.Items[i].Evidence = redactRawContent(value.Items[i].Evidence)
		}
	}
	writeAgentAdminJSON(w, http.StatusOK, value)
}

func (h *AgentAdminAPI) ListPolicyBundles(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	page, size, validPage := agentAdminPageOrError(w, r)
	if !validPage {
		return
	}
	value, err := h.Repo.ListPolicyBundles(r.Context(), user.TenantID, page, size)
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list policy bundles")
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, value)
}

func (h *AgentAdminAPI) CurrentPolicyBundle(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	value, err := h.Repo.CurrentPolicyBundle(r.Context(), user.TenantID)
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get current policy bundle")
		return
	}
	if value == nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "policy bundle not found")
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, value)
}

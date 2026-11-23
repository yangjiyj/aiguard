package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/go-chi/chi/v5"
)

// MockAgentSessionRepository for testing
type MockAgentSessionRepository struct {
	Sessions    map[string]*repository.AgentSession
	TenantIDMap map[string]string // session_id -> tenant_id mapping
	ListError   error
	GetError    error
	GotTenantID string
}

func (m *MockAgentSessionRepository) List(ctx context.Context, tenantID string, limit, offset int) ([]repository.AgentSession, int, error) {
	m.GotTenantID = tenantID
	if m.ListError != nil {
		return nil, 0, m.ListError
	}

	// Extract sessions for the tenant into a slice
	sessions := []repository.AgentSession{}
	for _, s := range m.Sessions {
		if tenantID == "" || s.TenantID == tenantID {
			sessions = append(sessions, *s)
		}
	}
	total := len(sessions)

	// Sort by LastRequestAt DESC (matching production behavior)
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].LastRequestAt.After(sessions[j].LastRequestAt)
	})

	// Apply pagination
	if offset > len(sessions) {
		return []repository.AgentSession{}, total, nil
	}
	end := offset + limit
	if end > len(sessions) {
		end = len(sessions)
	}
	return sessions[offset:end], total, nil
}

func (m *MockAgentSessionRepository) GetBySessionID(ctx context.Context, tenantID string, sessionID string) (*repository.AgentSession, error) {
	if m.GetError != nil {
		return nil, m.GetError
	}

	session, ok := m.Sessions[sessionID]
	if !ok || session.TenantID != tenantID {
		return nil, nil
	}
	return session, nil
}

func TestListAgentSessionsUnauthorized(t *testing.T) {
	deps := &Dependencies{
		AgentSessionRepo: &MockAgentSessionRepository{},
	}

	handler := ListAgentSessions(deps)

	httpReq := httptest.NewRequest("GET", "/admin/v1/agent-sessions", nil)
	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for unauthenticated request, got %d", w.Code)
	}
}

func TestListAgentSessionsSuccess(t *testing.T) {
	mockRepo := &MockAgentSessionRepository{
		Sessions: map[string]*repository.AgentSession{
			"sess_001": {
				ID:             "id_001",
				TenantID:       "tenant_456",
				SessionID:      "sess_001",
				AgentType:      "claude",
				WorkspaceID:    "ws_123",
				RequestCount:   10,
				RiskScore:      25,
				FirstRequestAt: time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
				LastRequestAt:  time.Date(2024, 1, 2, 15, 30, 0, 0, time.UTC),
			},
			"sess_002": {
				ID:             "id_002",
				TenantID:       "tenant_456",
				SessionID:      "sess_002",
				AgentType:      "cursor",
				WorkspaceID:    "",
				RequestCount:   5,
				RiskScore:      80,
				FirstRequestAt: time.Date(2024, 1, 3, 8, 0, 0, 0, time.UTC),
				LastRequestAt:  time.Date(2024, 1, 3, 12, 0, 0, 0, time.UTC),
			},
		},
	}

	deps := &Dependencies{
		AgentSessionRepo: mockRepo,
	}

	handler := ListAgentSessions(deps)

	httpReq := httptest.NewRequest("GET", "/admin/v1/agent-sessions", nil)
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp types.AgentSessionListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Total != 2 {
		t.Errorf("Expected total=2, got %d", resp.Total)
	}
	if len(resp.Data) != 2 {
		t.Errorf("Expected 2 sessions in data, got %d", len(resp.Data))
	}
}

func TestListAgentSessionsTenantIsolation(t *testing.T) {
	mockRepo := &MockAgentSessionRepository{
		Sessions: map[string]*repository.AgentSession{
			"sess_001": {
				ID:             "id_001",
				TenantID:       "tenant_456",
				SessionID:      "sess_001",
				AgentType:      "claude",
				RequestCount:   10,
				RiskScore:      25,
				FirstRequestAt: time.Now(),
				LastRequestAt:  time.Now(),
			},
			"sess_002": {
				ID:             "id_002",
				TenantID:       "tenant_other", // Different tenant
				SessionID:      "sess_002",
				AgentType:      "cursor",
				RequestCount:   50,
				RiskScore:      90,
				FirstRequestAt: time.Now(),
				LastRequestAt:  time.Now(),
			},
		},
	}

	deps := &Dependencies{
		AgentSessionRepo: mockRepo,
	}

	handler := ListAgentSessions(deps)

	// Request as tenant_456
	httpReq := httptest.NewRequest("GET", "/admin/v1/agent-sessions", nil)
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp types.AgentSessionListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Should only see tenant_456's sessions
	if resp.Total != 1 {
		t.Errorf("Expected total=1 (only own tenant), got %d", resp.Total)
	}
	if len(resp.Data) != 1 {
		t.Errorf("Expected 1 session in data, got %d", len(resp.Data))
	}
	if len(resp.Data) > 0 && resp.Data[0].SessionID != "sess_001" {
		t.Errorf("Expected session_id='sess_001', got '%s'", resp.Data[0].SessionID)
	}
}

func TestListAgentSessionsEmptyList(t *testing.T) {
	mockRepo := &MockAgentSessionRepository{
		Sessions: map[string]*repository.AgentSession{}, // Empty
	}

	deps := &Dependencies{
		AgentSessionRepo: mockRepo,
	}

	handler := ListAgentSessions(deps)

	httpReq := httptest.NewRequest("GET", "/admin/v1/agent-sessions", nil)
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for empty list, got %d", w.Code)
	}

	var resp types.AgentSessionListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Total != 0 {
		t.Errorf("Expected total=0 for empty, got %d", resp.Total)
	}
	if len(resp.Data) != 0 {
		t.Errorf("Expected empty data array, got %d items", len(resp.Data))
	}
}

func TestGetAgentSessionSuccess(t *testing.T) {
	mockRepo := &MockAgentSessionRepository{
		Sessions: map[string]*repository.AgentSession{
			"sess_001": {
				ID:             "id_001",
				TenantID:       "tenant_456",
				SessionID:      "sess_001",
				AgentType:      "claude",
				WorkspaceID:    "ws_123",
				RequestCount:   10,
				RiskScore:      25,
				FirstRequestAt: time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
				LastRequestAt:  time.Date(2024, 1, 2, 15, 30, 0, 0, time.UTC),
			},
		},
	}

	deps := &Dependencies{
		AgentSessionRepo: mockRepo,
	}

	handler := GetAgentSession(deps)

	// Chi router context setup for URL param
	r := chi.NewRouter()
	r.Get("/admin/v1/agent-sessions/{session_id}", handler)

	httpReq := httptest.NewRequest("GET", "/admin/v1/agent-sessions/sess_001", nil)
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp types.AgentSessionInfo
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.SessionID != "sess_001" {
		t.Errorf("Expected session_id='sess_001', got '%s'", resp.SessionID)
	}
	if resp.AgentType != "claude" {
		t.Errorf("Expected agent_type='claude', got '%s'", resp.AgentType)
	}
	if resp.WorkspaceID != "ws_123" {
		t.Errorf("Expected workspace_id='ws_123', got '%s'", resp.WorkspaceID)
	}
	if resp.RiskScore != 25 {
		t.Errorf("Expected risk_score=25, got %d", resp.RiskScore)
	}
}

func TestGetAgentSessionNotFound(t *testing.T) {
	mockRepo := &MockAgentSessionRepository{
		Sessions: map[string]*repository.AgentSession{}, // No sessions
	}

	deps := &Dependencies{
		AgentSessionRepo: mockRepo,
	}

	handler := GetAgentSession(deps)

	r := chi.NewRouter()
	r.Get("/admin/v1/agent-sessions/{session_id}", handler)

	httpReq := httptest.NewRequest("GET", "/admin/v1/agent-sessions/sess_nonexistent", nil)
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httpReq)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for not found, got %d", w.Code)
	}

	// Assert error.code in response body
	var resp types.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}
	if resp.Error.Code != "not_found" {
		t.Errorf("Expected error.code='not_found', got '%s'", resp.Error.Code)
	}
}

func TestGetAgentSessionCrossTenant(t *testing.T) {
	mockRepo := &MockAgentSessionRepository{
		Sessions: map[string]*repository.AgentSession{
			"sess_001": {
				ID:             "id_001",
				TenantID:       "tenant_other", // Different tenant
				SessionID:      "sess_001",
				AgentType:      "claude",
				RequestCount:   10,
				RiskScore:      25,
				FirstRequestAt: time.Now(),
				LastRequestAt:  time.Now(),
			},
		},
	}

	deps := &Dependencies{
		AgentSessionRepo: mockRepo,
	}

	handler := GetAgentSession(deps)

	r := chi.NewRouter()
	r.Get("/admin/v1/agent-sessions/{session_id}", handler)

	// Request as tenant_456, but session belongs to tenant_other
	httpReq := httptest.NewRequest("GET", "/admin/v1/agent-sessions/sess_001", nil)
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httpReq)

	// Should return 404 (not found in caller's tenant scope), not 403
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for cross-tenant session, got %d", w.Code)
	}

	// Assert error.code in response body
	var resp types.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}
	if resp.Error.Code != "not_found" {
		t.Errorf("Expected error.code='not_found', got '%s'", resp.Error.Code)
	}
}

func TestGetAgentSessionUnauthorized(t *testing.T) {
	deps := &Dependencies{
		AgentSessionRepo: &MockAgentSessionRepository{},
	}

	handler := GetAgentSession(deps)

	r := chi.NewRouter()
	r.Get("/admin/v1/agent-sessions/{session_id}", handler)

	httpReq := httptest.NewRequest("GET", "/admin/v1/agent-sessions/sess_001", nil)
	// No user context

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httpReq)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for unauthenticated request, got %d", w.Code)
	}
}

func TestListAgentSessionsPagination(t *testing.T) {
	// Create 5 sessions with distinct LastRequestAt times (ordered newest to oldest)
	// sess_005 is newest (Jan 5), sess_001 is oldest (Jan 1)
	mockRepo := &MockAgentSessionRepository{
		Sessions: map[string]*repository.AgentSession{
			"sess_001": {
				ID:             "id_001",
				TenantID:       "tenant_456",
				SessionID:      "sess_001",
				AgentType:      "claude",
				RequestCount:   1,
				RiskScore:      10,
				FirstRequestAt: time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
				LastRequestAt:  time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC), // oldest
			},
			"sess_002": {
				ID:             "id_002",
				TenantID:       "tenant_456",
				SessionID:      "sess_002",
				AgentType:      "cursor",
				RequestCount:   2,
				RiskScore:      20,
				FirstRequestAt: time.Date(2024, 1, 2, 10, 0, 0, 0, time.UTC),
				LastRequestAt:  time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC), // 4th newest
			},
			"sess_003": {
				ID:             "id_003",
				TenantID:       "tenant_456",
				SessionID:      "sess_003",
				AgentType:      "copilot",
				RequestCount:   3,
				RiskScore:      30,
				FirstRequestAt: time.Date(2024, 1, 3, 10, 0, 0, 0, time.UTC),
				LastRequestAt:  time.Date(2024, 1, 3, 12, 0, 0, 0, time.UTC), // 3rd newest
			},
			"sess_004": {
				ID:             "id_004",
				TenantID:       "tenant_456",
				SessionID:      "sess_004",
				AgentType:      "aider",
				RequestCount:   4,
				RiskScore:      40,
				FirstRequestAt: time.Date(2024, 1, 4, 10, 0, 0, 0, time.UTC),
				LastRequestAt:  time.Date(2024, 1, 4, 12, 0, 0, 0, time.UTC), // 2nd newest
			},
			"sess_005": {
				ID:             "id_005",
				TenantID:       "tenant_456",
				SessionID:      "sess_005",
				AgentType:      "cline",
				RequestCount:   5,
				RiskScore:      50,
				FirstRequestAt: time.Date(2024, 1, 5, 10, 0, 0, 0, time.UTC),
				LastRequestAt:  time.Date(2024, 1, 5, 12, 0, 0, 0, time.UTC), // newest
			},
		},
	}

	deps := &Dependencies{
		AgentSessionRepo: mockRepo,
	}

	handler := ListAgentSessions(deps)

	// Request with limit=2, offset=1
	// After sorting by LastRequestAt DESC: [sess_005, sess_004, sess_003, sess_002, sess_001]
	// With offset=1, we skip sess_005 (newest), and get sess_004 and sess_003 (2nd and 3rd newest)
	httpReq := httptest.NewRequest("GET", "/admin/v1/agent-sessions?limit=2&offset=1", nil)
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp types.AgentSessionListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Total should still be 5 (all sessions for tenant)
	if resp.Total != 5 {
		t.Errorf("Expected total=5, got %d", resp.Total)
	}

	// Data should only have 2 items (due to limit)
	if len(resp.Data) != 2 {
		t.Errorf("Expected 2 sessions in data (limit=2), got %d", len(resp.Data))
	}

	// Assert specific session_ids returned (2nd and 3rd newest after DESC sort)
	if resp.Data[0].SessionID != "sess_004" {
		t.Errorf("Expected first session_id='sess_004' (2nd newest), got '%s'", resp.Data[0].SessionID)
	}
	if resp.Data[1].SessionID != "sess_003" {
		t.Errorf("Expected second session_id='sess_003' (3rd newest), got '%s'", resp.Data[1].SessionID)
	}
}

func TestListAgentSessionsPaginationOffsetExceedsTotal(t *testing.T) {
	mockRepo := &MockAgentSessionRepository{
		Sessions: map[string]*repository.AgentSession{
			"sess_001": {
				ID:             "id_001",
				TenantID:       "tenant_456",
				SessionID:      "sess_001",
				AgentType:      "claude",
				RequestCount:   1,
				RiskScore:      10,
				FirstRequestAt: time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
				LastRequestAt:  time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			},
		},
	}

	deps := &Dependencies{
		AgentSessionRepo: mockRepo,
	}

	handler := ListAgentSessions(deps)

	// Request with offset=100 (exceeds total)
	httpReq := httptest.NewRequest("GET", "/admin/v1/agent-sessions?limit=10&offset=100", nil)
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp types.AgentSessionListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Total should be 1
	if resp.Total != 1 {
		t.Errorf("Expected total=1, got %d", resp.Total)
	}

	// But data should be empty (offset exceeds available data)
	if len(resp.Data) != 0 {
		t.Errorf("Expected 0 sessions in data (offset exceeds total), got %d", len(resp.Data))
	}
}

func TestListAgentSessionsRepositoryError(t *testing.T) {
	mockRepo := &MockAgentSessionRepository{
		ListError: context.DeadlineExceeded, // Simulate repository error
	}

	deps := &Dependencies{
		AgentSessionRepo: mockRepo,
	}

	handler := ListAgentSessions(deps)

	httpReq := httptest.NewRequest("GET", "/admin/v1/agent-sessions", nil)
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for internal error, got %d", w.Code)
	}

	var resp types.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}
	if resp.Error.Code != "internal_error" {
		t.Errorf("Expected error.code='internal_error', got '%s'", resp.Error.Code)
	}
}

func TestListAgentSessionsPlatformAdminCanSelectTenant(t *testing.T) {
	mockRepo := &MockAgentSessionRepository{Sessions: map[string]*repository.AgentSession{}}
	deps := &Dependencies{
		AgentSessionRepo: mockRepo,
		TenantLookup:     &fakeAgentOperationTenantLookup{tenantIDs: map[string]bool{"tenant-b": true}},
	}
	request := httptest.NewRequest("GET", "/admin/v1/agent-sessions?tenant_scope=tenant&tenant_id=tenant-b", nil)
	request = request.WithContext(context.WithValue(request.Context(), auth.UserKey, &repository.User{
		ID: "platform", TenantID: "tenant-a", Role: "platform_admin",
	}))
	recorder := httptest.NewRecorder()
	ListAgentSessions(deps).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || mockRepo.GotTenantID != "tenant-b" {
		t.Fatalf("status=%d target=%q body=%s", recorder.Code, mockRepo.GotTenantID, recorder.Body.String())
	}
}

func TestListAgentSessionsPlatformAdminCanListAllTenants(t *testing.T) {
	mockRepo := &MockAgentSessionRepository{Sessions: map[string]*repository.AgentSession{
		"a": {TenantID: "tenant-a", SessionID: "a", AgentType: "codex"},
		"b": {TenantID: "tenant-b", SessionID: "b", AgentType: "cursor"},
	}}
	deps := &Dependencies{AgentSessionRepo: mockRepo}
	request := httptest.NewRequest("GET", "/admin/v1/agent-sessions?tenant_scope=all", nil)
	request = request.WithContext(context.WithValue(request.Context(), auth.UserKey, &repository.User{
		ID: "platform", TenantID: "tenant-a", Role: "platform_admin",
	}))
	recorder := httptest.NewRecorder()
	ListAgentSessions(deps).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || mockRepo.GotTenantID != "" {
		t.Fatalf("status=%d target=%q body=%s", recorder.Code, mockRepo.GotTenantID, recorder.Body.String())
	}
	var response types.AgentSessionListResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Total != 2 {
		t.Fatalf("total=%d body=%s", response.Total, recorder.Body.String())
	}
}

func TestListAgentSessionsRejectsNonPlatformCrossTenantTarget(t *testing.T) {
	mockRepo := &MockAgentSessionRepository{Sessions: map[string]*repository.AgentSession{}}
	deps := &Dependencies{AgentSessionRepo: mockRepo}
	request := httptest.NewRequest("GET", "/admin/v1/agent-sessions?tenant_scope=tenant&tenant_id=tenant-b", nil)
	request = request.WithContext(context.WithValue(request.Context(), auth.UserKey, &repository.User{
		ID: "user-a", TenantID: "tenant-a", Role: "tenant_admin",
	}))
	recorder := httptest.NewRecorder()
	ListAgentSessions(deps).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || mockRepo.GotTenantID != "" {
		t.Fatalf("status=%d target=%q body=%s", recorder.Code, mockRepo.GotTenantID, recorder.Body.String())
	}
}

func TestGetAgentSessionRepositoryError(t *testing.T) {
	mockRepo := &MockAgentSessionRepository{
		GetError: context.DeadlineExceeded, // Simulate repository error
	}

	deps := &Dependencies{
		AgentSessionRepo: mockRepo,
	}

	handler := GetAgentSession(deps)

	r := chi.NewRouter()
	r.Get("/admin/v1/agent-sessions/{session_id}", handler)

	httpReq := httptest.NewRequest("GET", "/admin/v1/agent-sessions/sess_001", nil)
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for internal error, got %d", w.Code)
	}

	var resp types.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}
	if resp.Error.Code != "internal_error" {
		t.Errorf("Expected error.code='internal_error', got '%s'", resp.Error.Code)
	}
}

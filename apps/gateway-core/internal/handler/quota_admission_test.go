package handler

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/principal"
)

type lifecycleQuotaAdmission struct {
	heartbeatStarted chan struct{}
	heartbeatResult  chan error
	heartbeatActive  atomic.Bool
	finalizeOverlap  atomic.Bool
	settled          chan struct{}
}

func (a *lifecycleQuotaAdmission) Admit(context.Context, governor.AdmissionRequest) (*governor.AdmissionLease, error) {
	return &governor.AdmissionLease{
		TenantID: "tenant-a", RequestID: "request-a", LeaseID: "lease-a",
		State: "acquired", ExpiresAt: time.Now().Add(time.Millisecond),
	}, nil
}

func (a *lifecycleQuotaAdmission) Heartbeat(ctx context.Context, lease *governor.AdmissionLease) error {
	a.heartbeatActive.Store(true)
	defer a.heartbeatActive.Store(false)
	lease.ExpiresAt = time.Now().Add(time.Minute)
	select {
	case a.heartbeatStarted <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-a.heartbeatResult:
		return err
	}
}

func (a *lifecycleQuotaAdmission) Settle(_ context.Context, lease *governor.AdmissionLease, _, _ int64, _ bool) error {
	if a.heartbeatActive.Load() {
		a.finalizeOverlap.Store(true)
	}
	_ = lease.ExpiresAt
	close(a.settled)
	return nil
}

func (a *lifecycleQuotaAdmission) Release(context.Context, *governor.AdmissionLease, int64, int64) error {
	return nil
}

func TestAttachQuotaAdmissionStopsHeartbeatBeforeFinalize(t *testing.T) {
	admission := &lifecycleQuotaAdmission{
		heartbeatStarted: make(chan struct{}, 1), heartbeatResult: make(chan error), settled: make(chan struct{}),
	}
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", RequestID: "request-a"}
	if err := attachQuotaAdmission(context.Background(), admission, envelope, 10, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-admission.heartbeatStarted:
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not start")
	}

	if err := envelope.QuotaFinalize(context.Background(), 8, 0, false, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-admission.settled:
	default:
		t.Fatal("settle was not called")
	}
	if admission.finalizeOverlap.Load() {
		t.Fatal("finalize overlapped an in-flight heartbeat")
	}
}

func TestAttachQuotaAdmissionHeartbeatRecordsAfterRequestCancellation(t *testing.T) {
	admission := &lifecycleQuotaAdmission{
		heartbeatStarted: make(chan struct{}, 1), heartbeatResult: make(chan error, 1), settled: make(chan struct{}),
	}
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	recorded := make(chan error, 1)
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", RequestID: "request-a"}
	if err := attachQuotaAdmission(requestCtx, admission, envelope, 10, func(recordCtx context.Context, decision governor.Decision) {
		if decision.TriggeredMetric == "runtime_fault" {
			recorded <- recordCtx.Err()
		}
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-admission.heartbeatStarted:
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not start")
	}
	cancelRequest()
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-admission.heartbeatStarted:
			case <-time.After(time.Second):
				t.Fatal("heartbeat retry did not run")
			}
		}
		admission.heartbeatResult <- errors.New("redis unavailable")
	}

	select {
	case err := <-recorded:
		if err != nil {
			t.Fatalf("heartbeat recorder reused canceled request context: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("heartbeat fault was not recorded")
	}
	envelope.QuotaHeartbeatStop()
}

func TestAttachQuotaAdmissionRetriesTransientHeartbeatAndKeepsRunning(t *testing.T) {
	admission := &lifecycleQuotaAdmission{
		heartbeatStarted: make(chan struct{}, 1), heartbeatResult: make(chan error), settled: make(chan struct{}),
	}
	var recorded atomic.Int64
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", RequestID: "request-a"}
	if err := attachQuotaAdmission(context.Background(), admission, envelope, 10, func(_ context.Context, decision governor.Decision) {
		if decision.TriggeredMetric == "runtime_fault" {
			recorded.Add(1)
		}
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-admission.heartbeatStarted:
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not start")
	}
	admission.heartbeatResult <- errors.New("transient Redis disconnect")
	select {
	case <-admission.heartbeatStarted:
	case <-time.After(time.Second):
		t.Fatal("heartbeat was not retried")
	}
	admission.heartbeatResult <- nil
	select {
	case <-admission.heartbeatStarted:
	case <-time.After(time.Second):
		t.Fatal("heartbeat loop stopped after recovery")
	}
	if got := recorded.Load(); got != 0 {
		t.Fatalf("transient heartbeat emitted persistent-fault alerts: %d", got)
	}
	if err := envelope.QuotaFinalize(context.Background(), 8, 0, false, true); err != nil {
		t.Fatalf("settlement after heartbeat recovery failed: %v", err)
	}
	select {
	case <-admission.settled:
	default:
		t.Fatal("Redis recovery did not reach settlement")
	}
}

func TestRealAuditWriterQuotaFallbackDistinguishesMissingAndExplicitZeroUsage(t *testing.T) {
	tests := []struct {
		name       string
		status     string
		body       []byte
		wantTokens int64
		wantSettle bool
		wantSource string
	}{
		{name: "successful omitted usage", status: "success", body: []byte(`{"id":"response"}`), wantTokens: 17, wantSettle: true, wantSource: "estimated_reservation"},
		{name: "incomplete omitted usage", status: "incomplete", body: []byte(`{"id":"response"}`), wantTokens: 17, wantSettle: true, wantSource: "estimated_incomplete"},
		{name: "client canceled omitted usage", status: "client_canceled", body: nil, wantTokens: 17, wantSettle: true, wantSource: "estimated_incomplete"},
		{name: "provider timeout omitted usage", status: "provider_timeout", body: nil, wantTokens: 17, wantSettle: true, wantSource: "estimated_incomplete"},
		{name: "stream aborted partial usage", status: "stream_aborted", body: []byte(`{"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`), wantTokens: 5, wantSettle: true, wantSource: "upstream"},
		{name: "stream aborted omitted usage", status: "stream_aborted", body: nil, wantTokens: 17, wantSettle: true, wantSource: "estimated_incomplete"},
		{name: "successful explicit zero", status: "success", body: []byte(`{"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}`), wantSettle: true, wantSource: "upstream"},
		{name: "successful conflicting usage", status: "success", body: []byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":3}}`), wantTokens: 17, wantSettle: true, wantSource: "estimated_reservation_invalid_usage"},
		{name: "successful inflated total", status: "success", body: []byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":30}}`), wantTokens: 30, wantSettle: true, wantSource: "upstream_total_adjusted"},
		{name: "anthropic cache usage", status: "success", body: []byte(`{"usage":{"input_tokens":15,"cache_read_input_tokens":60,"cache_creation_input_tokens":25,"output_tokens":30}}`), wantTokens: 130, wantSettle: true, wantSource: "upstream"},
		{name: "anthropic components exceed total", status: "success", body: []byte(`{"usage":{"input_tokens":15,"cache_read_input_tokens":60,"cache_creation_input_tokens":25,"output_tokens":30,"total_tokens":90}}`), wantTokens: 17, wantSettle: true, wantSource: "estimated_reservation_invalid_usage"},
		{name: "security reply", status: "security_replied", body: []byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`), wantSettle: false, wantSource: "synthetic_no_upstream"},
		{name: "failed omitted usage", status: "provider_unavailable", body: nil, wantSettle: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotTokens int64
			var gotSettle bool
			envelope := &modelrouter.RequestEnvelope{
				RequestID: "request-a", TenantID: "tenant-a", ProjectID: "project-a",
				QuotaAdmissionManaged: true, QuotaEstimatedTokens: 17,
				QuotaFinalize: func(_ context.Context, actualTokens, _ int64, _ bool, settle bool) error {
					gotTokens, gotSettle = actualTokens, settle
					return nil
				},
			}
			writer := &RealAuditWriter{db: &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}}
			writer.FinalizeRequestLog(context.Background(), envelope, tc.body, tc.status, 200, 1, nil)
			if gotTokens != tc.wantTokens || gotSettle != tc.wantSettle || envelope.QuotaUsageSource != tc.wantSource {
				t.Fatalf("tokens=%d settle=%v source=%q", gotTokens, gotSettle, envelope.QuotaUsageSource)
			}
		})
	}
}

type rejectingEntrypointQuotaAdmission struct {
	requests chan governor.AdmissionRequest
}

type quotaTerminalCall struct {
	actual     int64
	cost       int64
	costActual bool
	settle     bool
}

type recordingEntrypointQuotaAdmission struct {
	mu       sync.Mutex
	requests []governor.AdmissionRequest
	terminal []quotaTerminalCall
}

func (a *recordingEntrypointQuotaAdmission) Admit(_ context.Context, request governor.AdmissionRequest) (*governor.AdmissionLease, error) {
	a.mu.Lock()
	a.requests = append(a.requests, request)
	a.mu.Unlock()
	return &governor.AdmissionLease{
		TenantID: request.Ref.TenantID, RequestID: request.RequestID, LeaseID: request.RequestID,
		EstimatedTokens: request.EstimatedTokens, EstimatedCostMicros: request.EstimatedCostMicros,
		CostEstimateAvailable: request.CostEstimateAvailable, State: "acquired",
		ExpiresAt: time.Now().Add(time.Hour), LeaseTTLMillis: time.Hour.Milliseconds(),
	}, nil
}

func (*recordingEntrypointQuotaAdmission) Heartbeat(context.Context, *governor.AdmissionLease) error {
	return nil
}

func (a *recordingEntrypointQuotaAdmission) Settle(_ context.Context, _ *governor.AdmissionLease, actual, cost int64, costActual bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.terminal = append(a.terminal, quotaTerminalCall{actual: actual, cost: cost, costActual: costActual, settle: true})
	return nil
}

func (a *recordingEntrypointQuotaAdmission) Release(_ context.Context, _ *governor.AdmissionLease, actual, cost int64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.terminal = append(a.terminal, quotaTerminalCall{actual: actual, cost: cost})
	return nil
}

func (a *recordingEntrypointQuotaAdmission) terminalCalls() []quotaTerminalCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]quotaTerminalCall(nil), a.terminal...)
}

func buildQuotaEntrypointHandler(
	name string,
	admission QuotaAdmission,
	audit AuditWriter,
	caller *MockProviderCaller,
	billing BillingPreflight,
) http.Handler {
	cfg := &config.Config{}
	resolver := &MockModelResolver{}
	limiter := &MockRateLimitChecker{}
	security := &MockSecurityChecker{}
	factory := &MockProviderAdapterFactory{MockProviderCaller: caller}
	switch name {
	case "chat":
		h := NewChatCompletionsHandler(cfg, resolver, limiter, security, audit, factory, nil, nil)
		h.SetQuotaAdmission(admission)
		h.SetBillingPreflight(billing)
		return h.Handler()
	case "messages":
		h := NewMessagesHandler(cfg, resolver, limiter, security, audit, factory, nil, nil)
		h.SetQuotaAdmission(admission)
		h.SetBillingPreflight(billing)
		return h.Handler()
	case "responses":
		h := NewResponsesHandler(cfg, resolver, limiter, security, audit, factory, nil, nil)
		h.SetQuotaAdmission(admission)
		h.SetBillingPreflight(billing)
		return h.Handler()
	case "embeddings":
		h := NewEmbeddingsHandler(cfg, resolver, limiter, security, audit, factory)
		h.SetQuotaAdmission(admission)
		h.SetBillingPreflight(billing)
		return h.Handler()
	case "images":
		h := NewImagesHandler(cfg, resolver, limiter, security, audit, factory, nil)
		h.SetQuotaAdmission(admission)
		h.SetBillingPreflight(billing)
		return h.Handler()
	default:
		panic("unknown quota entrypoint: " + name)
	}
}

func quotaEntrypointCases() []struct {
	name string
	path string
	body string
} {
	return []struct {
		name string
		path string
		body string
	}{
		{name: "chat", path: "/v1/chat/completions", body: `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`},
		{name: "messages", path: "/v1/messages", body: `{"model":"gpt-4","max_tokens":16,"messages":[{"role":"user","content":"hello"}]}`},
		{name: "responses", path: "/v1/responses", body: `{"model":"gpt-4","input":"hello"}`},
		{name: "embeddings", path: "/v1/embeddings", body: `{"model":"gpt-4","input":"hello"}`},
		{name: "images", path: "/v1/images/generations", body: `{"model":"gpt-4","prompt":"hello"}`},
	}
}

func TestAtomicQuotaAdmissionFiveEntrypointTerminalLifecycle(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	scenarios := []struct {
		name        string
		providerErr error
		wantStatus  int
		wantSettle  bool
	}{
		{name: "success", wantStatus: http.StatusOK, wantSettle: true},
		{name: "provider_failure", providerErr: errors.New("provider disconnected"), wantStatus: http.StatusBadGateway},
		{name: "client_canceled", providerErr: context.Canceled, wantStatus: http.StatusRequestTimeout, wantSettle: true},
		{name: "deadline_exceeded", providerErr: context.DeadlineExceeded, wantStatus: http.StatusGatewayTimeout, wantSettle: true},
	}
	for _, entrypoint := range quotaEntrypointCases() {
		for _, scenario := range scenarios {
			t.Run(entrypoint.name+"/"+scenario.name, func(t *testing.T) {
				admission := &recordingEntrypointQuotaAdmission{}
				audit := &RealAuditWriter{db: &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}}
				caller := &MockProviderCaller{CallError: scenario.providerErr}
				if entrypoint.name == "images" && scenario.providerErr == nil {
					caller.CallResponse = []byte(testImageResponse)
				}
				h := buildQuotaEntrypointHandler(entrypoint.name, admission, audit, caller, nil)
				req := httptest.NewRequest(http.MethodPost, entrypoint.path, bytes.NewBufferString(entrypoint.body))
				req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
				response := httptest.NewRecorder()
				h.ServeHTTP(response, req)
				if response.Code != scenario.wantStatus {
					t.Fatalf("status=%d want=%d body=%s", response.Code, scenario.wantStatus, response.Body.String())
				}
				calls := admission.terminalCalls()
				if len(calls) != 1 || calls[0].settle != scenario.wantSettle {
					t.Fatalf("terminal calls=%+v, want one settle=%v", calls, scenario.wantSettle)
				}
				if (scenario.name == "client_canceled" || scenario.name == "deadline_exceeded") && calls[0].actual < 1 {
					t.Fatalf("incomplete request settled at zero: %+v", calls[0])
				}
				if scenario.name == "provider_failure" && calls[0].actual != 0 {
					t.Fatalf("provider failure charged without usage: %+v", calls[0])
				}
			})
		}
	}
}

type quotaQuoteBilling struct{ amount int64 }

func (q quotaQuoteBilling) Reserve(_ context.Context, envelope *modelrouter.RequestEnvelope, _ *ChatCompletionRequest) error {
	envelope.QuotaEstimatedCostMicros = q.amount
	envelope.QuotaCostEstimateAvailable = true
	return nil
}

func (q quotaQuoteBilling) ReserveUsage(_ context.Context, envelope *modelrouter.RequestEnvelope, _ BillingUsage) error {
	envelope.QuotaEstimatedCostMicros = q.amount
	envelope.QuotaCostEstimateAvailable = true
	return nil
}

func TestBillingQuotePrecedesAtomicAdmissionAcrossFiveEntrypoints(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	for _, entrypoint := range quotaEntrypointCases() {
		t.Run(entrypoint.name, func(t *testing.T) {
			admission := &recordingEntrypointQuotaAdmission{}
			audit := &RealAuditWriter{db: &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}}
			caller := &MockProviderCaller{}
			if entrypoint.name == "images" {
				caller.CallResponse = []byte(testImageResponse)
			}
			handler := buildQuotaEntrypointHandler(entrypoint.name, admission, audit, caller, quotaQuoteBilling{amount: 25})
			request := httptest.NewRequest(http.MethodPost, entrypoint.path, bytes.NewBufferString(entrypoint.body))
			request = request.WithContext(setAuthInfo(request.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			admission.mu.Lock()
			requests := append([]governor.AdmissionRequest(nil), admission.requests...)
			admission.mu.Unlock()
			if len(requests) != 1 || !requests[0].CostEstimateAvailable || requests[0].EstimatedCostMicros != 25 {
				t.Fatalf("admission requests=%+v", requests)
			}
			calls := admission.terminalCalls()
			if len(calls) != 1 || !calls[0].settle || calls[0].cost != 25 || calls[0].costActual {
				t.Fatalf("terminal calls=%+v", calls)
			}
		})
	}
}

func TestBillingReservationIsReleasedWhenAtomicAdmissionRejectsAcrossFiveEntrypoints(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	for _, entrypoint := range quotaEntrypointCases() {
		t.Run(entrypoint.name, func(t *testing.T) {
			var mu sync.Mutex
			var reserveCalls, releaseCalls int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch r.URL.Path {
				case "/internal/v1/billing/reservations":
					reserveCalls++
					_, _ = w.Write([]byte(`{"reserved":true,"reserved_micros":25}`))
				case "/internal/v1/billing/releases":
					releaseCalls++
					_, _ = w.Write([]byte(`{}`))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			client := NewBillingClient(server.URL, "internal-secret", "default")
			admission := &rejectingEntrypointQuotaAdmission{requests: make(chan governor.AdmissionRequest, 1)}
			inner := &RealAuditWriter{db: &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}}
			audit := NewBillingAuditWriter(inner, client)
			caller := &MockProviderCaller{}
			h := buildQuotaEntrypointHandler(entrypoint.name, admission, audit, caller, client)
			request := httptest.NewRequest(http.MethodPost, entrypoint.path, bytes.NewBufferString(entrypoint.body))
			request = request.WithContext(setAuthInfo(request.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			if response.Code != http.StatusTooManyRequests {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			mu.Lock()
			gotReserve, gotRelease := reserveCalls, releaseCalls
			mu.Unlock()
			if gotReserve != 1 || gotRelease != 1 {
				t.Fatalf("billing reserve=%d release=%d, want 1/1", gotReserve, gotRelease)
			}
		})
	}
}

func (a *rejectingEntrypointQuotaAdmission) Admit(_ context.Context, request governor.AdmissionRequest) (*governor.AdmissionLease, error) {
	a.requests <- request
	return nil, &governor.AdmissionLimitError{
		Metric: "rpm", Scope: "tenant", Limit: 1, Used: 1, Requested: 1, RequestID: request.RequestID,
	}
}

func (*rejectingEntrypointQuotaAdmission) Heartbeat(context.Context, *governor.AdmissionLease) error {
	return nil
}
func (*rejectingEntrypointQuotaAdmission) Settle(context.Context, *governor.AdmissionLease, int64, int64, bool) error {
	return nil
}
func (*rejectingEntrypointQuotaAdmission) Release(context.Context, *governor.AdmissionLease, int64, int64) error {
	return nil
}

func TestAtomicQuotaAdmissionCoversAllFiveModelEntrypointsAndBypassesLegacyLimiter(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	admission := &rejectingEntrypointQuotaAdmission{requests: make(chan governor.AdmissionRequest, 5)}
	resolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{
		RPMLimit: 1, ConcurrencyLimit: 1, DailyTokenLimit: 1, MonthlyTokenLimit: 1, EnforcementMode: "enforce",
	}}
	limiter := &MockRateLimitChecker{}
	security := &MockSecurityChecker{}
	audit := &MockAuditWriter{}
	factory := &MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{}}
	cfg := &config.Config{}

	chat := NewChatCompletionsHandler(cfg, resolver, limiter, security, audit, factory, nil, nil)
	messages := NewMessagesHandler(cfg, resolver, limiter, security, audit, factory, nil, nil)
	responses := NewResponsesHandler(cfg, resolver, limiter, security, audit, factory, nil, nil)
	embeddings := NewEmbeddingsHandler(cfg, resolver, limiter, security, audit, factory)
	images := NewImagesHandler(cfg, resolver, limiter, security, audit, factory, nil)
	chat.SetQuotaAdmission(admission)
	messages.SetQuotaAdmission(admission)
	responses.SetQuotaAdmission(admission)
	embeddings.SetQuotaAdmission(admission)
	images.SetQuotaAdmission(admission)

	tests := []struct {
		endpoint string
		body     string
		handler  http.Handler
	}{
		{endpoint: "chat", body: `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`, handler: chat.Handler()},
		{endpoint: "messages", body: `{"model":"gpt-4","max_tokens":16,"messages":[{"role":"user","content":"hello"}]}`, handler: messages.Handler()},
		{endpoint: "responses", body: `{"model":"gpt-4","input":"hello"}`, handler: responses.Handler()},
		{endpoint: "embeddings", body: `{"model":"gpt-4","input":"hello"}`, handler: embeddings.Handler()},
		{endpoint: "images", body: `{"model":"gpt-4","prompt":"hello"}`, handler: images.Handler()},
	}
	for _, tc := range tests {
		t.Run(tc.endpoint, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/"+tc.endpoint, bytes.NewBufferString(tc.body))
			req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
			response := httptest.NewRecorder()
			tc.handler.ServeHTTP(response, req)
			if response.Code != http.StatusTooManyRequests {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			select {
			case request := <-admission.requests:
				if request.Ref.TenantID != "tenant-a" || request.Ref.ProjectID != "project-a" || request.Ref.KeyID != "key-a" || request.Ref.ModelName != "gpt-4" || request.EstimatedTokens < 1 {
					t.Fatalf("invalid admission request: %+v", request)
				}
			case <-time.After(time.Second):
				t.Fatal("atomic admission was not called; legacy limiter likely intercepted the request")
			}
		})
	}
	if len(limiter.ReleaseConcurrencyCalls) != 0 {
		t.Fatalf("legacy concurrency lease was acquired: %v", limiter.ReleaseConcurrencyCalls)
	}
}

func TestQuotaAdmissionUsesOnlyTrustedActorForUserScope(t *testing.T) {
	admission := &rejectingEntrypointQuotaAdmission{requests: make(chan governor.AdmissionRequest, 2)}
	trusted := &modelrouter.RequestEnvelope{
		RequestID: "trusted", TenantID: "tenant-a", ProjectID: "project-a", ClientID: "key-a", UserID: "key-owner",
		Principal: &principal.Context{SchemaVersion: 1, TenantID: "tenant-a", ActorUserID: "actor-a", KeyOwnerUserID: "key-owner", TrustLevel: principal.TrustAuthenticated},
	}
	_ = attachQuotaAdmission(context.Background(), admission, trusted, 1, nil)
	if request := <-admission.requests; request.Ref.UserID != "actor-a" {
		t.Fatalf("trusted actor user scope=%q", request.Ref.UserID)
	}

	keyOnly := &modelrouter.RequestEnvelope{
		RequestID: "key-only", TenantID: "tenant-a", ProjectID: "project-a", ClientID: "key-a", UserID: "key-owner",
		Principal: &principal.Context{SchemaVersion: 1, TenantID: "tenant-a", KeyOwnerUserID: "key-owner", TrustLevel: principal.TrustKeyBound},
	}
	_ = attachQuotaAdmission(context.Background(), admission, keyOnly, 1, nil)
	if request := <-admission.requests; request.Ref.UserID != "" {
		t.Fatalf("key owner fabricated user scope=%q", request.Ref.UserID)
	}
}

func TestWriteQuotaAdmissionIdempotencyConflictIsNotRuntimeFault(t *testing.T) {
	response := httptest.NewRecorder()
	writeQuotaAdmissionError(response, &governor.AdmissionIdempotencyError{RequestID: "request-a", State: "acquired"}, "request-a")
	if response.Code != http.StatusConflict || bytes.Contains(response.Body.Bytes(), []byte("runtime_fault")) || !bytes.Contains(response.Body.Bytes(), []byte(`"metric":"idempotency"`)) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRecordQuotaAdmissionIdempotencyConflictIsNotRuntimeFault(t *testing.T) {
	var recorded governor.Decision
	recordQuotaAdmissionError(context.Background(), func(_ context.Context, decision governor.Decision) {
		recorded = decision
	}, &governor.AdmissionIdempotencyError{RequestID: "request-a", State: "acquired"})
	if recorded.TriggeredMetric != "idempotency_conflict" || !recorded.AlertOnly {
		t.Fatalf("recorded decision=%+v", recorded)
	}
}

type fixedGovernorDecision struct{ decision governor.Decision }

func (g fixedGovernorDecision) Decide(context.Context, governor.ScopeRef) governor.Decision {
	return g.decision
}

func (g fixedGovernorDecision) DecideNonRealtime(context.Context, governor.ScopeRef) governor.Decision {
	return g.decision
}

func TestUnsupportedGovernorDowngradeIsSafelyRateLimitedWithoutRerouting(t *testing.T) {
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", ModelID: "original-id", Model: "original-model"}
	response := httptest.NewRecorder()
	blocked := applyGovernorDecision(
		context.Background(), response, envelope, "request-a",
		fixedGovernorDecision{decision: governor.Decision{Action: governor.ActionDowngradeMod, DowngradeTo: "other-model"}},
		true, false, nil,
	)
	if !blocked || response.Code != http.StatusTooManyRequests || envelope.ModelID != "original-id" || envelope.Model != "original-model" {
		t.Fatalf("unsupported downgrade was not safely rate-limited: blocked=%v status=%d envelope=%+v", blocked, response.Code, envelope)
	}
	if response.Header().Get("X-UAG-Downgraded") != "" {
		t.Fatal("unsupported downgrade claimed to have rerouted the request")
	}
}

func TestEstimatedChatAdmissionTokensSaturatesBeforeIntegerOverflow(t *testing.T) {
	request := &ChatCompletionRequest{
		Messages:  []Message{{Role: "user", Content: jsonQuote("hello")}},
		MaxTokens: int(^uint(0) >> 1),
	}
	if got := estimatedChatAdmissionTokens(request); got != maxExactTokenCount {
		t.Fatalf("estimate=%d, want saturation at %d", got, maxExactTokenCount)
	}
}

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/modelops"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func modelOperationsJobsPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("MODEL_OPS_TEST_DSN")
	if dsn == "" {
		t.Skip("MODEL_OPS_TEST_DSN must point to an isolated fixture")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "modelops_jobs_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	admin.Close()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err = pool.Exec(ctx, `CREATE TABLE tenants(id TEXT PRIMARY KEY); INSERT INTO tenants VALUES('tenant-1'),('tenant-2')`); err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("MODEL_OPS_MIGRATION")
	if path == "" {
		path = filepath.Join("..", "..", "..", "..", "deploy", "migrations", "943_model_operations.sql")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(b)); err != nil {
		t.Fatal(err)
	}
	t.Logf("isolated retained schema=%s", schema)
	return pool
}

func modelOperationsValidJobRequest() modelOperationsJobRequest {
	return modelOperationsJobRequest{ModelIDs: []string{"model-1"}, Protocols: []string{"messages"}, ConfirmCost: true, ExpectedConfigVersion: 1, IdempotencyKey: "request-key-1", FrozenIdentities: map[string]string{"model-1": "identity"}}
}

func TestModelOperationsJobsPostgresReplayConfigCASAndConcurrentAdmission(t *testing.T) {
	pool := modelOperationsJobsPG(t)
	s := NewPostgresModelOperationsJobStore(pool)
	ctx := context.Background()
	req := modelOperationsValidJobRequest()
	var wg sync.WaitGroup
	jobs := make(chan ModelOperationsJob, 8)
	errs := make(chan error, 8)
	var created atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j, new, err := s.Create(ctx, "tenant-1", "actor", req)
			if err != nil {
				errs <- err
				return
			}
			if new {
				created.Add(1)
			}
			jobs <- j
		}()
	}
	wg.Wait()
	close(jobs)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var first ModelOperationsJob
	for j := range jobs {
		if first.ID == "" {
			first = j
		}
		if j.ID != first.ID {
			t.Fatalf("replay created distinct job %s != %s", j.ID, first.ID)
		}
	}
	if created.Load() != 1 {
		t.Fatalf("created=%d", created.Load())
	}
	changed := req
	changed.ModelIDs = []string{"model-2"}
	if _, _, err := s.Replay(ctx, "tenant-1", "actor", changed); !errors.Is(err, errModelOperationsJobReplay) {
		t.Fatalf("changed request accepted: %v", err)
	}
	other := req
	other.IdempotencyKey = "another-key"
	if _, _, err := s.Create(ctx, "tenant-1", "other-actor", other); err == nil {
		t.Fatal("second active writer admitted")
	} else {
		var active modelOperationsActiveJobError
		if !errors.As(err, &active) || active.ID != first.ID {
			t.Fatalf("active conflict=%v", err)
		}
	}
	if _, err := s.Get(ctx, "tenant-2", first.ID); !errors.Is(err, modelops.ErrUnavailable) {
		t.Fatalf("cross tenant get=%v", err)
	}
	if _, err := s.Cancel(ctx, "tenant-2", first.ID); !errors.Is(err, modelops.ErrUnavailable) {
		t.Fatalf("cross tenant cancel=%v", err)
	}
	if _, err := s.Cancel(ctx, "tenant-1", first.ID); err != nil {
		t.Fatal(err)
	}
	stale := req
	stale.IdempotencyKey = "stale-version"
	stale.ExpectedConfigVersion = 2
	if _, _, err := s.Create(ctx, "tenant-1", "actor", stale); !errors.Is(err, modelops.ErrConflict) {
		t.Fatalf("stale cost version accepted: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE model_ops_configs SET version=2 WHERE tenant_id='tenant-1'`); err != nil {
		t.Fatal(err)
	}
	old, exists, err := s.Replay(ctx, "tenant-1", "actor", req)
	if err != nil || !exists || old.ID != first.ID {
		t.Fatalf("exact replay after config update failed: %v", err)
	}
}

func TestModelOperationsJobsPostgresCancellationLeaseLossAndTerminalPersistence(t *testing.T) {
	pool := modelOperationsJobsPG(t)
	s := NewPostgresModelOperationsJobStore(pool)
	ctx := context.Background()
	req := modelOperationsValidJobRequest()
	j, _, err := s.Create(ctx, "tenant-1", "actor", req)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Start(ctx, j); err != nil {
		t.Fatal(err)
	}
	if err = s.Start(ctx, j); !errors.Is(err, modelops.ErrLeaseLost) {
		t.Fatalf("second start=%v", err)
	}
	foreign := j
	foreign.token = "foreign"
	if err = s.Heartbeat(ctx, foreign); !errors.Is(err, modelops.ErrLeaseLost) {
		t.Fatalf("foreign heartbeat=%v", err)
	}
	if _, err = s.Cancel(ctx, "tenant-1", j.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.Heartbeat(ctx, j); !errors.Is(err, modelops.ErrLeaseLost) {
		t.Fatalf("cancelled heartbeat=%v", err)
	}
	if err = s.Finish(ctx, j, "completed", "", modelops.TestResult{}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "tenant-1", j.ID)
	if err != nil || got.State != "cancelled" {
		t.Fatalf("cancel final=%+v err=%v", got, err)
	}
	req.IdempotencyKey = "expired-worker"
	j, _, err = s.Create(ctx, "tenant-1", "actor", req)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Start(ctx, j); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE model_operations_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, j.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.Finish(ctx, j, "completed", "", modelops.TestResult{}); !errors.Is(err, modelops.ErrLeaseLost) {
		t.Fatalf("expired finish accepted: %v", err)
	}
	got, err = s.Get(ctx, "tenant-1", j.ID)
	if err != nil || got.State != "interrupted" || got.ErrorCode != "worker_interrupted" {
		t.Fatalf("expired final=%+v err=%v", got, err)
	}
	if err = s.Start(ctx, j); !errors.Is(err, modelops.ErrLeaseLost) {
		t.Fatalf("interrupted job replayed: %v", err)
	}
	req.IdempotencyKey = "terminal-failure"
	req.ModelIDs = []string{"model-1", "model-2"}
	req.TargetCount = 2
	j, _, err = s.Create(ctx, "tenant-1", "actor", req)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Start(ctx, j); err != nil {
		t.Fatal(err)
	}
	if err = s.Finish(ctx, j, "illegal-state", "", modelops.TestResult{}); err == nil {
		t.Fatal("faulted terminal write reported success")
	}
	got, err = s.Get(ctx, "tenant-1", j.ID)
	if err != nil || got.State != "running" {
		t.Fatalf("faulted terminal changed state=%s err=%v", got.State, err)
	}
	value := modelops.TestResult{Items: []modelops.ProbeRecord{{InvocationID: j.ID, Target: modelops.Target{ModelID: "model-1", ProviderID: "provider-1", Protocol: "messages"}, Outcome: modelops.Outcome{HTTPStatus: 401, ErrorKind: "unauthorized"}}}, Skipped: []modelops.SkippedTarget{{Target: modelops.Target{ModelID: "model-2", ProviderID: "provider-1", Protocol: "messages"}, Reason: "provider_auth_failed"}}}
	if err = s.Finish(ctx, j, "completed", "", value); err != nil {
		t.Fatal(err)
	}
	got, err = s.Get(ctx, "tenant-1", j.ID)
	if err != nil || got.State != "completed" || got.Total != 2 || got.Completed != 1 || len(got.Skipped) != 1 || got.Skipped[0].Reason != "provider_auth_failed" || got.Items[0].InvocationID != j.ID {
		t.Fatalf("full typed result lost: %+v err=%v", got, err)
	}
}

type modelOperationsAsyncService struct {
	modelOperationsServiceStub
	started   chan struct{}
	cancelled chan struct{}
	count     atomic.Int32
	targets   []modelops.Target
}

func (s *modelOperationsAsyncService) Targets(_ context.Context, _ string) ([]modelops.Target, error) {
	if s.targets != nil {
		return s.targets, nil
	}
	return []modelops.Target{{ModelID: "model-1", ProviderID: "provider-1", Protocol: "chat", IdentityDigest: "identity"}}, nil
}
func (s *modelOperationsAsyncService) Config(_ context.Context, _ string) (modelops.Config, error) {
	return modelops.DefaultConfig(), nil
}
func (s *modelOperationsAsyncService) History(_ context.Context, _ string, _ modelops.HistoryFilter) (modelops.HistoryPage, error) {
	return modelops.HistoryPage{Items: []modelops.ProbeRecord{}}, nil
}
func (s *modelOperationsAsyncService) Test(ctx context.Context, _, _ string, req modelops.TestRequest) (modelops.TestResult, error) {
	s.count.Add(1)
	close(s.started)
	<-ctx.Done()
	close(s.cancelled)
	return modelops.TestResult{}, ctx.Err()
}

func TestModelOperationsJobsHTTPPersistentAsyncReplayCancelAndTenantIsolation(t *testing.T) {
	pool := modelOperationsJobsPG(t)
	s := &modelOperationsAsyncService{started: make(chan struct{}), cancelled: make(chan struct{})}
	lifecycle, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := NewModelOperationsJobsHandler(&Dependencies{PermissionChecker: newModelBatchDeletePermissionAuthorizer()}, s, NewPostgresModelOperationsJobStore(pool), lifecycle)
	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := r.Header.Get("X-Fixture-Tenant")
			if tenant == "" {
				tenant = "tenant-1"
			}
			r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{ID: "actor", TenantID: tenant}))
			next.ServeHTTP(w, r)
		})
	})
	router.Post("/admin/v1/model-operations/test", h.Submit)
	router.Get("/admin/v1/model-operations/jobs/{id}", h.Get)
	router.Post("/admin/v1/model-operations/jobs/{id}/cancel", h.Cancel)
	server := httptest.NewServer(router)
	defer server.Close()
	body := `{"model_ids":["model-1"],"protocols":["messages"],"confirm_cost":true,"expected_config_version":1,"idempotency_key":"request-key-1"}`
	submit := func(payload string) (int, ModelOperationsJob) {
		t.Helper()
		resp, err := http.Post(server.URL+"/admin/v1/model-operations/test", "application/json", strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var job ModelOperationsJob
		if err = json.NewDecoder(resp.Body).Decode(&job); err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, job
	}
	code, j := submit(body)
	if code != 202 || j.ID == "" || j.Total != 1 {
		t.Fatalf("code=%d job=%+v", code, j)
	}
	select {
	case <-s.started:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not start")
	}
	code, replay := submit(body)
	if code != 202 || replay.ID != j.ID || s.count.Load() != 1 {
		t.Fatalf("replay started new billable invocation: %d %+v count=%d", code, replay, s.count.Load())
	}
	request, err := http.NewRequest("GET", server.URL+"/admin/v1/model-operations/jobs/"+j.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Fixture-Tenant", "tenant-2")
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("foreign tenant read=%d", resp.StatusCode)
	}
	resp, err = http.Post(server.URL+"/admin/v1/model-operations/jobs/"+j.ID+"/cancel", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("cancel=%d", resp.StatusCode)
	}
	select {
	case <-s.cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not stop active executor context")
	}
	waitCtx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	h.Wait(waitCtx)
	got, err := NewPostgresModelOperationsJobStore(pool).Get(context.Background(), "tenant-1", j.ID)
	if err != nil || got.State != "cancelled" {
		t.Fatalf("persisted final=%+v err=%v", got, err)
	}
}

func TestModelOperationsJobsRejectsInputsBeforeCreatingWork(t *testing.T) {
	valid := `{"model_ids":["model-1"],"confirm_cost":true,"expected_config_version":1,"idempotency_key":"fixture-key"}`
	for _, tc := range []struct {
		name, body       string
		user, permission bool
		want             int
	}{
		{"unauthenticated", valid, false, true, 401},
		{"without_write_permission", valid, true, false, 403},
		{"unconfirmed_cost", strings.Replace(valid, `"confirm_cost":true`, `"confirm_cost":false`, 1), true, true, 400},
		{"missing_expected_config", strings.Replace(valid, `,"expected_config_version":1`, "", 1), true, true, 400},
		{"missing_idempotency", strings.Replace(valid, `,"idempotency_key":"fixture-key"`, "", 1), true, true, 400},
		{"client_injected_identity", strings.TrimSuffix(valid, "}") + `,"frozen_identities":{"model-1":"attacker"}}`, true, true, 400},
		{"client_injected_url", strings.TrimSuffix(valid, "}") + `,"base_url":"http://127.0.0.1"}`, true, true, 400},
		{"client_injected_secret", strings.TrimSuffix(valid, "}") + `,"api_key":"attacker"}`, true, true, 400},
		{"empty_models", strings.Replace(valid, `["model-1"]`, `[]`, 1), true, true, 400},
		{"duplicate_model", strings.Replace(valid, `["model-1"]`, `["model-1","model-1"]`, 1), true, true, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewModelOperationsJobsHandler(&Dependencies{PermissionChecker: &modelBatchDeletePermissionAuthorizer{allowed: tc.permission}}, &modelOperationsServiceStub{}, nil, context.Background())
			var user *repository.User
			if tc.user {
				user = &repository.User{ID: "actor", TenantID: "tenant"}
			}
			w := httptest.NewRecorder()
			h.Submit(w, modelOperationsRequest("POST", "/admin/v1/model-operations/test", tc.body, user))
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestModelOperationsJobsActualPlanCountsNativeProtocolsAndPreservesQueuedCancellation(t *testing.T) {
	pool := modelOperationsJobsPG(t)
	s := &modelOperationsAsyncService{started: make(chan struct{}), cancelled: make(chan struct{}), targets: []modelops.Target{{ModelID: "native-1", ProviderID: "provider-1", ProviderType: "anthropic", Protocol: "messages", IdentityDigest: "native-identity"}, {ModelID: "generic-1", ProviderID: "provider-2", ProviderType: "custom", Protocol: "chat", IdentityDigest: "generic-identity"}}}
	lifecycle, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewPostgresModelOperationsJobStore(pool)
	h := NewModelOperationsJobsHandler(&Dependencies{PermissionChecker: newModelBatchDeletePermissionAuthorizer()}, s, store, lifecycle)
	body := `{"model_ids":["native-1","generic-1"],"protocols":["chat","responses","messages"],"confirm_cost":true,"expected_config_version":1,"idempotency_key":"planned-targets"}`
	w := httptest.NewRecorder()
	h.Submit(w, modelOperationsRequest("POST", "/admin/v1/model-operations/test", body, &repository.User{ID: "actor", TenantID: "tenant-1"}))
	var j ModelOperationsJob
	if err := json.Unmarshal(w.Body.Bytes(), &j); err != nil {
		t.Fatal(err)
	}
	if w.Code != 202 || j.Total != 4 {
		t.Fatalf("native+generic actual total code=%d job=%+v", w.Code, j)
	}
	j, err := store.Get(context.Background(), "tenant-1", j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(j.request.PlannedTargets) != 4 || j.request.PlannedTargets[0].Protocol != "messages" || len(j.request.FrozenIdentities) != 2 {
		t.Fatalf("frozen actual plan=%+v", j.request.PlannedTargets)
	}
	if _, err = store.Cancel(context.Background(), "tenant-1", j.ID); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	stop := h.cancels[j.ID]
	h.mu.Unlock()
	if stop != nil {
		stop()
	}
	cancel()
	waitCtx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	h.Wait(waitCtx)
	// A queued task has certainly sent no request; persist exact planned skips.
	req := modelOperationsValidJobRequest()
	req.IdempotencyKey = "queued-cancel"
	req.TargetCount = 1
	req.PlannedTargets = []modelops.Target{{ModelID: "model-1", ProviderID: "provider-1", Protocol: "messages"}}
	queued, _, err := store.Create(context.Background(), "tenant-2", "actor", req)
	if err != nil {
		t.Fatal(err)
	}
	queued, err = store.Cancel(context.Background(), "tenant-2", queued.ID)
	if err != nil || queued.State != "cancelled" || len(queued.Skipped) != 1 || queued.Skipped[0].Reason != "cancelled" || queued.Completed != 0 {
		t.Fatalf("queued cancellation plan=%+v err=%v", queued, err)
	}
	if err = store.Start(context.Background(), queued); !errors.Is(err, modelops.ErrLeaseLost) {
		t.Fatalf("cancelled queued task started: %v", err)
	}
}

func TestModelOperationsJobsInterruptedProgressUsesOnlyThisInvocationAndFrozenPlan(t *testing.T) {
	s := &modelOperationsServiceStub{}
	h := NewModelOperationsJobsHandler(&Dependencies{PermissionChecker: newModelBatchDeletePermissionAuthorizer()}, s, nil, context.Background())
	plan := []modelops.Target{{ModelID: "model-1", ProviderID: "provider-1", Protocol: "chat"}, {ModelID: "model-2", ProviderID: "provider-1", Protocol: "messages"}}
	j := ModelOperationsJob{ID: "job-specific", State: "interrupted", Total: 2, request: modelOperationsJobRequest{PlannedTargets: plan}, Items: []modelops.ProbeRecord{{InvocationID: "job-specific", Target: plan[0]}}}
	value, err := h.progress(context.Background(), "tenant-1", j)
	if err != nil || s.history.InvocationID != "job-specific" || s.tenant != "tenant-1" || value.Completed != 1 || len(value.Skipped) != 1 || value.Skipped[0].Key() != plan[1].Key() || value.Skipped[0].Reason != "unknown_after_interruption" {
		t.Fatalf("job progress=%+v history=%+v err=%v", value, s.history, err)
	}
}

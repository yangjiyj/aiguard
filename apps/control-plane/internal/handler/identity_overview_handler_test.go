package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identityruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
)

// overviewDirectoryRuntimeStub 是总览探活用的目录运行态替身。
// statusErr 控制 Status 调用是否模拟运行态不可达。
type overviewDirectoryRuntimeStub struct {
	status      *directoryruntime.RuntimeStatus
	statusErr   error
	statusCalls int
}

func (s *overviewDirectoryRuntimeStub) Publish(context.Context, directoryruntime.DirectoryConfig) (directoryruntime.Publication, error) {
	return directoryruntime.Publication{}, nil
}
func (s *overviewDirectoryRuntimeStub) FullSync(context.Context) error { return nil }
func (s *overviewDirectoryRuntimeStub) Status(context.Context) (directoryruntime.RuntimeStatus, error) {
	s.statusCalls++
	if s.status != nil {
		return *s.status, s.statusErr
	}
	return directoryruntime.RuntimeStatus{Exists: true, Enabled: true}, s.statusErr
}

func buildOverviewDeps(t *testing.T, pool *pgxpool.Pool, runtime *fakeIdentityRuntime, dirRuntime DirectoryRuntime) *Dependencies {
	t.Helper()
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	deps.DirectorySourceRepo = repository.NewDirectorySourceRepository(pool)
	deps.DirectorySyncPreviewRepo = repository.NewDirectorySyncPreviewRepository(pool)
	deps.UserRepo = repository.NewUserRepository(pool)
	if dirRuntime != nil {
		deps.DirectoryRuntime = dirRuntime
	}
	return deps
}

func TestIdentityOverviewEmptyReturnsUnconfiguredStates(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	dirRuntime := &overviewDirectoryRuntimeStub{statusErr: errors.New("runtime unreachable")}
	deps := buildOverviewDeps(t, pool, &fakeIdentityRuntime{}, dirRuntime)

	req := withOrgUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/identity/overview", nil), tenantID, userID)
	rr := httptest.NewRecorder()
	GetIdentityOverview(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp identityOverviewResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rr.Body.String())
	}
	if resp.Login.State != "unconfigured" || resp.Directory.State != "unconfigured" {
		t.Fatalf("expected both unconfigured, got login=%s directory=%s", resp.Login.State, resp.Directory.State)
	}
	if resp.ReconciliationRequired != 0 {
		t.Fatalf("expected zero reconciliation, got %d", resp.ReconciliationRequired)
	}
	// 空态尚无可运行配置，不应探活或给出运行态故障建议。
	if resp.Login.RuntimeHealthy {
		t.Fatalf("login must not be healthy without published source")
	}
	if dirRuntime.statusCalls != 0 {
		t.Fatalf("unconfigured directory must not probe runtime, got %d calls", dirRuntime.statusCalls)
	}
	if resp.Directory.RuntimeMessage != "" {
		t.Fatalf("unconfigured directory must not report runtime advice, got %q", resp.Directory.RuntimeMessage)
	}
}

func TestIdentityOverviewTestedDirectoryDoesNotProbeRuntime(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	dirRuntime := &overviewDirectoryRuntimeStub{statusErr: errors.New("runtime unreachable")}
	deps := buildOverviewDeps(t, pool, &fakeIdentityRuntime{}, dirRuntime)
	seedTestedDirectorySource(t, deps, tenantID)

	req := withOrgUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/identity/overview", nil), tenantID, userID)
	rr := httptest.NewRecorder()
	GetIdentityOverview(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp identityOverviewResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rr.Body.String())
	}
	if resp.Directory.State != "tested" {
		t.Fatalf("expected tested directory, got %+v", resp.Directory)
	}
	if dirRuntime.statusCalls != 0 {
		t.Fatalf("tested directory must not probe runtime, got %d calls", dirRuntime.statusCalls)
	}
	if resp.Directory.RuntimeMessage != "" {
		t.Fatalf("tested directory must not report runtime advice, got %q", resp.Directory.RuntimeMessage)
	}
}

func TestIdentityOverviewReportsActiveLoginWithRuntimeHealthy(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{status: identityruntime.RuntimeStatus{
		Exists: true, Enabled: true, Digest: handlerTestDigest,
	}}
	deps := buildOverviewDeps(t, pool, runtime, &overviewDirectoryRuntimeStub{})
	seedActiveIdentitySource(t, deps, tenantID, userID)

	req := withOrgUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/identity/overview", nil), tenantID, userID)
	rr := httptest.NewRecorder()
	GetIdentityOverview(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp identityOverviewResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Login.State != "active" || !resp.Login.RuntimeHealthy {
		t.Fatalf("expected active+healthy login, got %+v", resp.Login)
	}
	if resp.Login.LastPublishedAt == "" || resp.Login.LastTestedAt == "" {
		t.Fatalf("expected timestamps, got %+v", resp.Login)
	}
}

func TestIdentityOverviewLoginRuntimeDownStillReturns200(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{statusErr: errors.New("runtime unreachable")}
	deps := buildOverviewDeps(t, pool, runtime, &overviewDirectoryRuntimeStub{})
	seedActiveIdentitySource(t, deps, tenantID, userID)

	req := withOrgUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/identity/overview", nil), tenantID, userID)
	rr := httptest.NewRecorder()
	GetIdentityOverview(deps)(rr, req)

	// 硬要求：运行态不可达时 200 + runtime_healthy=false + 客户可执行建议，不得 500。
	if rr.Code != http.StatusOK {
		t.Fatalf("runtime down must still return 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp identityOverviewResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Login.RuntimeHealthy {
		t.Fatalf("login runtime must be unhealthy when Status err, body=%s", rr.Body.String())
	}
	if !strings.Contains(resp.Login.RuntimeMessage, "本地管理员登录不受影响") {
		t.Fatalf("expected actionable advice, got %q", resp.Login.RuntimeMessage)
	}
}

func TestIdentityOverviewDirectoryRuntimeDownStillReturns200(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	dirRuntime := &overviewDirectoryRuntimeStub{statusErr: errors.New("runtime unreachable")}
	deps := buildOverviewDeps(t, pool, &fakeIdentityRuntime{}, dirRuntime)
	source := seedTestedDirectorySource(t, deps, tenantID)
	if err := deps.DirectorySourceRepo.Activate(context.Background(), tenantID, source.ID, source.Version); err != nil {
		t.Fatal(err)
	}

	req := withOrgUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/identity/overview", nil), tenantID, userID)
	rr := httptest.NewRecorder()
	GetIdentityOverview(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("runtime down must still return 200, got %d", rr.Code)
	}
	var resp identityOverviewResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Directory.State != "active" {
		t.Fatalf("expected active directory, got %+v", resp.Directory)
	}
	if dirRuntime.statusCalls != 1 {
		t.Fatalf("active directory must probe runtime once, got %d calls", dirRuntime.statusCalls)
	}
	if resp.Directory.RuntimeHealthy {
		t.Fatalf("directory runtime must be unhealthy when Status err")
	}
	if !strings.Contains(resp.Directory.RuntimeMessage, "目录同步服务暂不可用") {
		t.Fatalf("expected actionable advice, got %q", resp.Directory.RuntimeMessage)
	}
}

func TestIdentityOverviewActiveDirectoryClassifiesRuntimeStatus(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildOverviewDeps(t, pool, &fakeIdentityRuntime{}, nil)
	source := seedTestedDirectorySource(t, deps, tenantID)
	if err := deps.DirectorySourceRepo.Activate(context.Background(), tenantID, source.ID, source.Version); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		status      directoryruntime.RuntimeStatus
		wantState   string
		wantMessage string
	}{
		{
			name:        "missing component is unavailable",
			status:      directoryruntime.RuntimeStatus{Exists: false},
			wantState:   "active",
			wantMessage: "目录同步服务暂不可用",
		},
		{
			name:        "disabled component is unavailable",
			status:      directoryruntime.RuntimeStatus{Exists: true, Enabled: false},
			wantState:   "active",
			wantMessage: "目录同步服务暂不可用",
		},
		{
			name:        "drifted component requires reconciliation",
			status:      directoryruntime.RuntimeStatus{Exists: true, Drifted: true},
			wantState:   "abnormal",
			wantMessage: "重新对账",
		},
		{
			name:        "missing component takes precedence over stale drift flag",
			status:      directoryruntime.RuntimeStatus{Drifted: true},
			wantState:   "active",
			wantMessage: "目录同步服务暂不可用",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := tt.status
			deps.DirectoryRuntime = &overviewDirectoryRuntimeStub{status: &status}
			req := withOrgUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/identity/overview", nil), tenantID, userID)
			rr := httptest.NewRecorder()
			GetIdentityOverview(deps)(rr, req)

			var resp identityOverviewResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v body=%s", err, rr.Body.String())
			}
			if resp.Directory.State != tt.wantState || resp.Directory.RuntimeHealthy {
				t.Fatalf("unexpected directory runtime classification: %+v", resp.Directory)
			}
			if !strings.Contains(resp.Directory.RuntimeMessage, tt.wantMessage) {
				t.Fatalf("message=%q want substring %q", resp.Directory.RuntimeMessage, tt.wantMessage)
			}
		})
	}
}

func TestIdentityOverviewReconciliationCountFromUsersTable(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildOverviewDeps(t, pool, &fakeIdentityRuntime{}, &overviewDirectoryRuntimeStub{})

	// 播两个 reconciliation_required 用户 + 一个 active 用户。
	for i, suffix := range []string{"a", "b"} {
		uid := userID + "-recon-" + suffix
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			uid, tenantID, uid, uid+"@test.com", "x", "developer", "reconciliation_required"); err != nil {
			t.Fatalf("seed recon user %d: %v", i, err)
		}
	}

	req := withOrgUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/identity/overview", nil), tenantID, userID)
	rr := httptest.NewRecorder()
	GetIdentityOverview(deps)(rr, req)

	var resp identityOverviewResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.ReconciliationRequired != 2 {
		t.Fatalf("expected 2 reconciliation_required users, got %d", resp.ReconciliationRequired)
	}
}

func TestIdentityOverviewDirectoryReconciliationIsAbnormalAndCounted(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildOverviewDeps(t, pool, &fakeIdentityRuntime{}, &overviewDirectoryRuntimeStub{})
	source := seedTestedDirectorySource(t, deps, tenantID)
	if err := deps.DirectorySourceRepo.MarkRuntimeReconciliationRequired(
		context.Background(),
		tenantID,
		source.ID,
		repository.DirectoryReconciliationReasonPostSyncFailed,
	); err != nil {
		t.Fatal(err)
	}

	req := withOrgUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/identity/overview", nil), tenantID, userID)
	rr := httptest.NewRecorder()
	GetIdentityOverview(deps)(rr, req)

	var resp identityOverviewResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Directory.State != "abnormal" ||
		!strings.Contains(resp.Directory.RuntimeMessage, "重新对账") ||
		resp.ReconciliationRequired != 1 {
		t.Fatalf("unexpected directory reconciliation overview: %+v body=%s", resp, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), repository.DirectoryReconciliationReasonPostSyncFailed) {
		t.Fatalf("overview leaked internal reconciliation reason: %s", rr.Body.String())
	}
}

func TestIdentityOverviewDoesNotLeakSecretsOrInternals(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{status: identityruntime.RuntimeStatus{
		Exists: true, Enabled: true, Digest: handlerTestDigest,
	}}
	deps := buildOverviewDeps(t, pool, runtime, &overviewDirectoryRuntimeStub{})
	active := seedActiveIdentitySource(t, deps, tenantID, userID)

	// 即使配置草稿里含 secret/Bind Password，总览也只返回状态/计数/时间。
	_ = active

	req := withOrgUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/identity/overview", nil), tenantID, userID)
	rr := httptest.NewRecorder()
	GetIdentityOverview(deps)(rr, req)

	body := rr.Body.String()
	// 客户端密钥、Bind DN 密码、内部 runtime 实现术语、管理 URL 不得出现。
	for _, forbidden := range []string{"source-secret", "client_secret", "bind_password", "ClientSecret"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("overview leaked secret %q: %s", forbidden, body)
		}
	}
	if regexp.MustCompile("(?i)keycloak|master realm|client mapper|admin/realms").MatchString(body) {
		t.Fatalf("overview leaked runtime implementation detail: %s", body)
	}
}

func TestIdentityOverviewRejectsMissingUser(t *testing.T) {
	pool, _, _ := setupOrgHandlerPool(t)
	deps := buildOverviewDeps(t, pool, &fakeIdentityRuntime{}, &overviewDirectoryRuntimeStub{})

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/identity/overview", nil)
	rr := httptest.NewRecorder()
	GetIdentityOverview(deps)(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing user must be 401, got %d", rr.Code)
	}
}

func TestIdentityOverviewLiveLoginDriftElevatesActiveDatabaseState(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{status: identityruntime.RuntimeStatus{
		Exists: true, Enabled: true, Drifted: true, Digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}}
	deps := buildOverviewDeps(t, pool, runtime, &overviewDirectoryRuntimeStub{})
	active := seedActiveIdentitySource(t, deps, tenantID, userID)
	if active.PublishStatus != "active" {
		t.Fatalf("test precondition: database publish status=%q want active", active.PublishStatus)
	}

	req := withOrgUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/identity/overview", nil), tenantID, userID)
	rr := httptest.NewRecorder()
	GetIdentityOverview(deps)(rr, req)

	var resp identityOverviewResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Login.State != "abnormal" || resp.Login.RuntimeHealthy {
		t.Fatalf("drifted login must be abnormal+unhealthy, got %+v", resp.Login)
	}
}

func TestIdentityOverviewLoginDatabaseAbnormalKeepsActionableAdvice(t *testing.T) {
	tests := []struct {
		name          string
		publishStatus string
		runtime       *fakeIdentityRuntime
		wantMessage   string
	}{
		{
			name:          "drift advice survives runtime error",
			publishStatus: "drifted",
			runtime:       &fakeIdentityRuntime{statusErr: errors.New("runtime unreachable")},
			wantMessage:   "修复",
		},
		{
			name:          "publish error has retry advice when runtime is healthy",
			publishStatus: "error",
			runtime: &fakeIdentityRuntime{status: identityruntime.RuntimeStatus{
				Exists: true, Enabled: true, Digest: handlerTestDigest,
			}},
			wantMessage: "发布失败",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, tenantID, userID := setupOrgHandlerPool(t)
			deps := buildOverviewDeps(t, pool, tt.runtime, &overviewDirectoryRuntimeStub{})
			active := seedActiveIdentitySource(t, deps, tenantID, userID)
			if err := deps.IdentitySourceRepo.MarkRuntimeStatus(
				context.Background(), tenantID, active.ID, tt.publishStatus,
			); err != nil {
				t.Fatal(err)
			}

			req := withOrgUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/identity/overview", nil), tenantID, userID)
			rr := httptest.NewRecorder()
			GetIdentityOverview(deps)(rr, req)

			var resp identityOverviewResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v body=%s", err, rr.Body.String())
			}
			if resp.Login.State != "abnormal" {
				t.Fatalf("database %s must stay abnormal, got %+v", tt.publishStatus, resp.Login)
			}
			if !strings.Contains(resp.Login.RuntimeMessage, tt.wantMessage) {
				t.Fatalf("message=%q want substring %q", resp.Login.RuntimeMessage, tt.wantMessage)
			}
		})
	}
}

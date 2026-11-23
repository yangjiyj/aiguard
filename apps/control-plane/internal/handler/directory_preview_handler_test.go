package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryruntime"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryldap"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// fakeDirectoryLister 实现 DirectoryTester，只用于预览读取。
type fakeDirectoryLister struct {
	users []directoryldap.DirectoryUser
	err   error
	last  directoryldap.SyncRequest
}

func (f *fakeDirectoryLister) ListUsers(_ context.Context, req directoryldap.SyncRequest) ([]directoryldap.DirectoryUser, error) {
	f.last = req
	return f.users, f.err
}
func (n *noopDirectoryRuntime) Disable(context.Context) (directoryruntime.RuntimeSnapshot, error) {
	return directoryruntime.RuntimeSnapshot{}, nil
}

func (n *noopDirectoryRuntime) Restore(context.Context, directoryruntime.RuntimeSnapshot) error {
	return nil
}

func (f *fakeDirectoryLister) TestConnection(context.Context, directoryldap.TestRequest) (directoryldap.TestResult, error) {
	return directoryldap.TestResult{Connected: true, Bound: true, RootDSE: true}, nil
}

// noopDirectoryRuntime 满足 DirectoryRuntime，预览/激活路径不应触达它。
type noopDirectoryRuntime struct{ calls int }

func (n *noopDirectoryRuntime) Publish(context.Context, directoryruntime.DirectoryConfig) (directoryruntime.Publication, error) {
	n.calls++
	return directoryruntime.Publication{}, nil
}
func (n *noopDirectoryRuntime) FullSync(context.Context) error {
	n.calls++
	return nil
}

// setupDirectoryPreviewFixture 建租户 + 已测试的目录草稿（status=tested），返回 pool/tenant/source。
func setupDirectoryPreviewFixture(t *testing.T) (*pgxpool.Pool, string, string, *repository.DirectorySource) {
	t.Helper()
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	repo := repository.NewDirectorySourceRepository(pool)
	source := &repository.DirectorySource{
		TenantID: tenantID, Kind: repository.DirectoryKindLDAP,
		DisplayName: "preview ldap", ConnectionURL: "ldaps://ldap-sim.jjdguard.test:636",
		BindDN: "cn=reader,dc=jjdguard,dc=test", BindPasswordEnc: "encstub",
		BaseDN: "dc=jjdguard,dc=test", UsersDN: "ou=People,dc=jjdguard,dc=test",
		StableIDAttribute: "entryUUID", UsernameAttribute: "uid", EmailAttribute: "mail", NameAttribute: "displayName",
		Version: 1,
	}
	if err := repo.UpsertDraft(context.Background(), source); err != nil {
		t.Fatalf("upsert draft: %v", err)
	}
	if err := repo.UpdateTestResult(context.Background(), tenantID, source.ID, source.Version, &repository.TestResult{Success: true}); err != nil {
		t.Fatalf("mark tested: %v", err)
	}
	draft, err := repo.GetDraft(context.Background(), tenantID)
	if err != nil || draft == nil {
		t.Fatalf("reload tested draft: %v", err)
	}
	_ = userID
	return pool, tenantID, source.ID, draft
}

// setupDirectoryPreviewFixtureWithKind 建指定 kind（ldap/ad）的已测试目录草稿。
func setupDirectoryPreviewFixtureWithKind(t *testing.T, kind repository.DirectoryKind) (*pgxpool.Pool, string, string, *repository.DirectorySource) {
	t.Helper()
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	repo := repository.NewDirectorySourceRepository(pool)
	displayName := "preview ldap"
	stableAttr, usernameAttr := "entryUUID", "uid"
	if kind == repository.DirectoryKindActiveDirectory {
		displayName, stableAttr, usernameAttr = "preview ad", "objectGUID", "sAMAccountName"
	}
	source := &repository.DirectorySource{
		TenantID: tenantID, Kind: kind,
		DisplayName: displayName, ConnectionURL: "ldaps://ldap-sim.jjdguard.test:636",
		BindDN: "cn=reader,dc=jjdguard,dc=test", BindPasswordEnc: "encstub",
		BaseDN: "dc=jjdguard,dc=test", UsersDN: "ou=People,dc=jjdguard,dc=test",
		StableIDAttribute: stableAttr, UsernameAttribute: usernameAttr, EmailAttribute: "mail", NameAttribute: "displayName",
		Version: 1,
	}
	if err := repo.UpsertDraft(context.Background(), source); err != nil {
		t.Fatalf("upsert draft: %v", err)
	}
	if err := repo.UpdateTestResult(context.Background(), tenantID, source.ID, source.Version, &repository.TestResult{Success: true}); err != nil {
		t.Fatalf("mark tested: %v", err)
	}
	draft, err := repo.GetDraft(context.Background(), tenantID)
	if err != nil || draft == nil {
		t.Fatalf("reload tested draft: %v", err)
	}
	_ = userID
	return pool, tenantID, source.ID, draft
}

// ensureDepartment inserts a non-system department and returns its id.
func ensureDepartment(t *testing.T, pool *pgxpool.Pool, tenantID, name string) string {
	t.Helper()
	id := "team_" + name + "_" + tenantID[len(tenantID)-6:]
	_, err := pool.Exec(context.Background(), `
		INSERT INTO teams (id, tenant_id, name, path)
		VALUES ($1, $2, $3, $4)
	`, id, tenantID, name, "/"+id)
	if err != nil {
		t.Fatalf("insert department: %v", err)
	}
	return id
}

// seedDepartmentMapping inserts an identity_department_mappings rule.
func seedDepartmentMapping(t *testing.T, pool *pgxpool.Pool, tenantID, sourceKind, sourceID, matchType, matchValue, departmentID string, priority int) {
	t.Helper()
	id := "idm_" + matchType + "_" + departmentID + "_" + tenantID[len(tenantID)-6:]
	_, err := pool.Exec(context.Background(), `
		INSERT INTO identity_department_mappings (id, tenant_id, source_kind, source_id, match_type, match_value, target_department_id, priority, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE)
	`, id, tenantID, sourceKind, sourceID, matchType, matchValue, departmentID, priority)
	if err != nil {
		t.Fatalf("insert dept mapping: %v", err)
	}
}

// seedPreviewEntryWithGroup 直接写一条带组信息的 preview entry，用于端到端测试
// 激活路径的部门冲突解析（绕过 LDAP 拉取限制）。
func seedPreviewEntryWithGroup(t *testing.T, pool *pgxpool.Pool, tenantID, previewID, externalSubject, username, matchType, matchValue string) {
	t.Helper()
	hash := sha256.Sum256([]byte(externalSubject + username))
	_, err := pool.Exec(context.Background(), `
		INSERT INTO directory_sync_preview_entries (
			id, tenant_id, preview_id, external_subject, content_digest, action,
			username, display_name, department_match_type, department_match_value, resolution_status
		) VALUES ($1, $2, $3, $4, $5, 'create', $6, '', $7, $8, 'pending')
	`, "dspe_test_"+externalSubject[:8], tenantID, previewID, externalSubject,
		hex.EncodeToString(hash[:]), username, matchType, matchValue)
	if err != nil {
		t.Fatalf("seed preview entry: %v", err)
	}
}

func directoryPreviewDeps(pool *pgxpool.Pool, lister *fakeDirectoryLister) *Dependencies {
	return &Dependencies{
		DirectorySourceRepo:      repository.NewDirectorySourceRepository(pool),
		DirectorySyncPreviewRepo: repository.NewDirectorySyncPreviewRepository(pool),
		DirectoryTester:          lister,
		DirectoryRuntime:         &noopDirectoryRuntime{},
		IdentityBindingService:   identitybinding.NewService(repository.NewUserIdentityLinkRepository(pool)),
		UserRepo:                 repository.NewUserRepository(pool),
		SystemRepo:               &orgTestSystemRepo{},
		DirectoryTargetPolicy: func() directoryldap.TargetPolicy {
			policy, _ := testApprovedDirectoryPolicy()
			return policy
		}(),
	}
}

type bindAndResolveErrorService struct {
	IdentityBindingService
	err        error
	resolution identitybinding.Resolution
}

func (service *bindAndResolveErrorService) BindAndResolve(
	context.Context,
	identitybinding.ExternalIdentity,
) (identitybinding.Resolution, error) {
	if service.err != nil {
		return identitybinding.Resolution{}, service.err
	}
	return service.resolution, nil
}

func newPreviewRequest(method, path, tenantID, userID, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	}
	r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{
		ID: userID, TenantID: tenantID, Role: "platform_admin", Status: "active",
	}))
	return r
}

func parseJSONBody(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response %q: %v", rr.Body.String(), err)
	}
	return out
}

func TestPreviewAndIncrementalRejectTargetOutsideApprovedPolicy(t *testing.T) {
	for _, operation := range []struct {
		name string
		run  func(context.Context, *Dependencies, string, string) error
	}{
		{
			name: "preview",
			run: func(_ context.Context, deps *Dependencies, tenantID, _ string) error {
				response := httptest.NewRecorder()
				PreviewDirectorySource(deps)(response, newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}"))
				if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_request") {
					return fmt.Errorf("status=%d body=%s", response.Code, response.Body.String())
				}
				return nil
			},
		},
		{
			name: "incremental",
			run: func(ctx context.Context, deps *Dependencies, tenantID, sourceID string) error {
				_, err := IncrementalDirectorySync(ctx, deps, tenantID, sourceID, "u1", "")
				if !errors.Is(err, directoryldap.ErrTargetNotAllowed) {
					return fmt.Errorf("error=%v", err)
				}
				return nil
			},
		},
	} {
		t.Run(operation.name, func(t *testing.T) {
			pool, tenantID, sourceID, _ := setupDirectoryPreviewFixture(t)
			if _, err := pool.Exec(context.Background(), `UPDATE directory_sources SET connection_url='ldaps://unapproved.example.test:636' WHERE tenant_id=$1`, tenantID); err != nil {
				t.Fatalf("replace source target: %v", err)
			}
			lister := &fakeDirectoryLister{}
			deps := directoryPreviewDeps(pool, lister)
			if err := operation.run(context.Background(), deps, tenantID, sourceID); err != nil {
				t.Fatal(err)
			}
			if lister.last.ConnectionURL != "" {
				t.Fatalf("unapproved target reached LDAP client: %q", lister.last.ConnectionURL)
			}
		})
	}
}
func TestActivateDirectoryPreviewPublishesRuntimeAndRunsFullSync(t *testing.T) {
	pool, tenantID, _, _ := setupDirectoryPreviewFixture(t)
	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{
		{ObjectID: "runtime-stable-1", DN: "cn=runtime", Username: "runtime-user"},
	}}
	deps := directoryPreviewDeps(pool, lister)
	runtime := &lifecycleDirectoryRuntime{snapshot: directoryruntime.RuntimeSnapshot{Exists: true}}
	deps.DirectoryRuntime = runtime

	previewResponse := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(previewResponse, newPreviewRequest(
		http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}",
	))
	if previewResponse.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", previewResponse.Code, previewResponse.Body.String())
	}
	previewID := parseJSONBody(t, previewResponse)["data"].(map[string]any)["preview_id"].(string)

	request := newPreviewRequest(
		http.MethodPost,
		"/admin/v1/directory/sources/previews/"+previewID+"/activate",
		tenantID,
		"u1",
		`{"confirm":true}`,
	)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", previewID)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
	response := httptest.NewRecorder()
	ActivateDirectoryPreview(deps).ServeHTTP(response, request)

	if response.Code != http.StatusOK || runtime.publishCalls != 1 || runtime.fullSyncCalls != 1 {
		t.Fatalf("status=%d publish=%d sync=%d body=%s", response.Code, runtime.publishCalls, runtime.fullSyncCalls, response.Body.String())
	}
}

func TestActivateDirectoryPreviewRequiresExplicitConfirmation(t *testing.T) {
	request := newPreviewRequest(
		http.MethodPost,
		"/admin/v1/directory/sources/previews/dsp_test/activate",
		"tenant-a",
		"u1",
		"{}",
	)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", "dsp_test")
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
	response := httptest.NewRecorder()

	ActivateDirectoryPreview(&Dependencies{}).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "confirmation_required") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

// 空 body 是现场真实症状：前端不带 body 时 json.Decode 返回 io.EOF。
// 语义上「没有 body」= 「没有确认」，必须回 confirmation_required，
// 而不是让实施人员去追一个误导性的「请求格式错误」。
func TestActivateDirectoryPreviewEmptyBodyRequiresConfirmation(t *testing.T) {
	request := newPreviewRequest(
		http.MethodPost,
		"/admin/v1/directory/sources/previews/dsp_test/activate",
		"tenant-a",
		"u1",
		"",
	)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", "dsp_test")
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
	response := httptest.NewRecorder()

	ActivateDirectoryPreview(&Dependencies{}).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), "confirmation_required") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

// 真正格式错误（非法 JSON）仍必须是 invalid_request，不能被上面的放宽吞掉。
func TestActivateDirectoryPreviewMalformedBodyStaysInvalidRequest(t *testing.T) {
	request := newPreviewRequest(
		http.MethodPost,
		"/admin/v1/directory/sources/previews/dsp_test/activate",
		"tenant-a",
		"u1",
		"{not-json",
	)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", "dsp_test")
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
	response := httptest.NewRecorder()

	ActivateDirectoryPreview(&Dependencies{}).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), "invalid_request") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPreviewAndIncrementalRejectInvalidFiltersBeforeLDAP(t *testing.T) {
	for _, filter := range []string{"(invalid"} {
		pool, tenantID, sourceID, _ := setupDirectoryPreviewFixture(t)
		if _, err := pool.Exec(context.Background(), "UPDATE directory_sources SET user_filter=$1 WHERE tenant_id=$2", filter, tenantID); err != nil {
			t.Fatal(err)
		}
		lister := &fakeDirectoryLister{}
		deps := directoryPreviewDeps(pool, lister)
		response := httptest.NewRecorder()
		PreviewDirectorySource(deps)(response, newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}"))
		if response.Code != http.StatusBadRequest || lister.last.ConnectionURL != "" {
			t.Fatalf("preview status=%d ldap=%q", response.Code, lister.last.ConnectionURL)
		}
		if _, err := IncrementalDirectorySync(context.Background(), deps, tenantID, sourceID, "u1", ""); !errors.Is(err, directoryldap.ErrInvalidUserFilter) || lister.last.ConnectionURL != "" {
			t.Fatalf("incremental err=%v ldap=%q", err, lister.last.ConnectionURL)
		}
	}
}

// 断言1：未通过连接测试的草稿不能预览（409 not_tested）。
func TestDirectoryPreviewRejectsUntestedDraft(t *testing.T) {
	pool, tenantID, _, _ := setupDirectoryPreviewFixture(t)
	// 故意把 status 改回 draft 模拟未通过测试
	if _, err := pool.Exec(context.Background(), `UPDATE directory_sources SET status='draft' WHERE tenant_id=$1`, tenantID); err != nil {
		t.Fatalf("reset status: %v", err)
	}
	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{{ObjectID: "s1", DN: "cn=a", Username: "a", Email: "a@x.test"}}}
	deps := directoryPreviewDeps(pool, lister)

	rr := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(rr, newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}"))

	if rr.Code != http.StatusConflict {
		t.Fatalf("status=%d want 409; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "not_tested") {
		t.Fatalf("expected not_tested code, got %s", rr.Body.String())
	}
}

// 断言2：预览只写 preview 表，不写 users / identity_links / team_members。
func TestDirectoryPreviewWritesOnlyPreviewTables(t *testing.T) {
	pool, tenantID, _, _ := setupDirectoryPreviewFixture(t)
	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{
		{ObjectID: "stable-1", DN: "cn=alice", Username: "alice", Email: "alice@x.test", Name: "Alice"},
		{ObjectID: "stable-2", DN: "cn=bob", Username: "bob", Email: "bob@x.test", Name: "Bob"},
	}}
	deps := directoryPreviewDeps(pool, lister)

	rr := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(rr, newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}"))
	if rr.Code != http.StatusOK {
		t.Fatalf("preview status=%d want 200; body=%s", rr.Code, rr.Body.String())
	}
	body := parseJSONBody(t, rr)
	data, ok := body["data"].(map[string]any)
	if !ok {
		t.Fatalf("missing data: %v", body)
	}
	if scanned, _ := data["scanned"].(float64); scanned != 2 {
		t.Fatalf("scanned=%v want 2", data["scanned"])
	}
	previewID, _ := data["preview_id"].(string)
	if previewID == "" {
		t.Fatalf("missing preview_id: %v", data)
	}
	if strings.Contains(rr.Body.String(), "alice@x.test") || strings.Contains(rr.Body.String(), "bob@x.test") {
		t.Fatalf("preview response leaked PII (email): %s", rr.Body.String())
	}

	ctx := context.Background()
	// users 表不应有任何目录账号
	var userCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE tenant_id=$1 AND username IN ('alice','bob')`, tenantID).Scan(&userCount); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if userCount != 0 {
		t.Fatalf("preview wrote %d user rows, want 0", userCount)
	}
	// user_identity_links 不应有目录账号
	var linkCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_identity_links WHERE tenant_id=$1 AND source_type IN ('ldap','ad')`, tenantID).Scan(&linkCount); err != nil {
		t.Fatalf("count links: %v", err)
	}
	if linkCount != 0 {
		t.Fatalf("preview wrote %d identity links, want 0", linkCount)
	}
	// team_members 不应因预览新增目录账号投影（fixture 的 admin 用户已有 team_member，
	// 由迁移 137 触发器自动分配到未分配部门，与预览无关；这里只断言目录账号 alice/bob
	// 不应出现 team_members）。
	var tmCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM team_members tm
		JOIN users u ON u.id=tm.user_id
		WHERE u.tenant_id=$1 AND u.username IN ('alice','bob')`, tenantID).Scan(&tmCount); err != nil {
		t.Fatalf("count team_members: %v", err)
	}
	if tmCount != 0 {
		t.Fatalf("preview wrote %d team_members for directory users, want 0", tmCount)
	}
	// directory_user_links 也不应有
	var dulCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM directory_user_links WHERE tenant_id=$1`, tenantID).Scan(&dulCount); err != nil {
		t.Fatalf("count directory_user_links: %v", err)
	}
	if dulCount != 0 {
		t.Fatalf("preview wrote %d directory_user_links, want 0", dulCount)
	}
	// 但 preview entries 必须有 2 条且只含脱敏字段
	var entryCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM directory_sync_preview_entries WHERE tenant_id=$1 AND preview_id=$2`, tenantID, previewID).Scan(&entryCount); err != nil {
		t.Fatalf("count preview entries: %v", err)
	}
	if entryCount != 2 {
		t.Fatalf("preview entries=%d want 2", entryCount)
	}
	// entries 表绝不能有 password 列值泄露
	var pwLeak int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM directory_sync_preview_entries WHERE tenant_id=$1 AND preview_id=$2 AND (content_digest IS NULL OR content_digest='')`, tenantID, previewID).Scan(&pwLeak); err != nil {
		t.Fatalf("check digest: %v", err)
	}
	if pwLeak != 0 {
		t.Fatalf("preview entries missing content_digest")
	}
}

// 断言3：激活必须引用同租户、未过期、配置版本未漂移的成功预览。
func TestDirectoryActivationRejectsExpiredPreview(t *testing.T) {
	pool, tenantID, _, _ := setupDirectoryPreviewFixture(t)
	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{{ObjectID: "s1", DN: "cn=a", Username: "alice", Email: "alice@x.test"}}}
	deps := directoryPreviewDeps(pool, lister)

	rr := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(rr, newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}"))
	previewID, _ := parseJSONBody(t, rr)["data"].(map[string]any)["preview_id"].(string)

	// 把 expires_at 改到过去模拟过期
	if _, err := pool.Exec(context.Background(), `UPDATE directory_sync_previews SET expires_at=now()-interval '1 hour' WHERE id=$1`, previewID); err != nil {
		t.Fatalf("expire preview: %v", err)
	}

	req := newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/previews/"+previewID+"/activate", tenantID, "u1", "{\x22confirm\x22:true}")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", previewID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	actRR := httptest.NewRecorder()
	ActivateDirectoryPreview(deps).ServeHTTP(actRR, req)
	if actRR.Code != http.StatusConflict {
		t.Fatalf("activate expired status=%d want 409; body=%s", actRR.Code, actRR.Body.String())
	}
}

// 断言3b：跨租户激活被拒（404 not_found）。
func TestDirectoryActivationRejectsCrossTenantPreview(t *testing.T) {
	pool, tenantID, _, _ := setupDirectoryPreviewFixture(t)
	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{{ObjectID: "s1", DN: "cn=a", Username: "alice", Email: "alice@x.test"}}}
	deps := directoryPreviewDeps(pool, lister)

	rr := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(rr, newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}"))
	previewID, _ := parseJSONBody(t, rr)["data"].(map[string]any)["preview_id"].(string)

	// 用另一个 tenant 的用户身份激活
	req := newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/previews/"+previewID+"/activate", "tenant_other", "u2", "{\x22confirm\x22:true}")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", previewID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	actRR := httptest.NewRecorder()
	ActivateDirectoryPreview(deps).ServeHTTP(actRR, req)
	if actRR.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant activate status=%d want 404; body=%s", actRR.Code, actRR.Body.String())
	}
}

// 断言4：二次激活同一 preview 幂等（返回相同 run，不重复创建用户）。
func TestDirectoryActivationIsIdempotent(t *testing.T) {
	pool, tenantID, _, _ := setupDirectoryPreviewFixture(t)
	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{{ObjectID: "stable-1", DN: "cn=alice", Username: "alice", Email: "alice@x.test"}}}
	deps := directoryPreviewDeps(pool, lister)

	rr := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(rr, newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}"))
	previewID, _ := parseJSONBody(t, rr)["data"].(map[string]any)["preview_id"].(string)

	activate := func() map[string]any {
		req := newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/previews/"+previewID+"/activate", tenantID, "u1", "{\x22confirm\x22:true}")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", previewID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()
		ActivateDirectoryPreview(deps).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("activate status=%d want 200; body=%s", rec.Code, rec.Body.String())
		}
		return parseJSONBody(t, rec)
	}

	first := activate()
	second := activate()
	firstData := first["data"].(map[string]any)
	secondData := second["data"].(map[string]any)
	if firstData["run_id"] != secondData["run_id"] {
		t.Fatalf("idempotent activate returned different run_id: %v vs %v", firstData["run_id"], secondData["run_id"])
	}
	// 只创建了一个用户
	var userCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE tenant_id=$1 AND username='alice'`, tenantID).Scan(&userCount); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if userCount != 1 {
		t.Fatalf("after 2 activations user count=%d want 1", userCount)
	}
}

// 断言5+6+7+8：完整激活流程——创建用户、稳定 ID 增量更新、冲突进未分配、不覆盖本地身份。
func TestDirectoryActivationRestoresPreviouslyBoundUserWhenItReappears(t *testing.T) {
	pool, tenantID, sourceID, _ := setupDirectoryPreviewFixture(t)
	ctx := context.Background()
	userID := "user_directory_restore"
	externalID := "stable-directory-restore"
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		VALUES ($1, $2, 'restored-alice', 'restored@x.test', 'x', 'developer', 'disabled')
	`, userID, tenantID); err != nil {
		t.Fatalf("insert disabled directory user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_identity_links
			(id, tenant_id, user_id, issuer, source_id, source_type, external_subject)
		VALUES ('uil-directory-restore', $1, $2, $3, $3, 'ldap', $4)
	`, tenantID, userID, sourceID, externalID); err != nil {
		t.Fatalf("insert directory identity link: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO directory_user_links
			(id, tenant_id, directory_source_id, external_object_id, source_dn, user_id)
		VALUES ('dul-directory-restore', $1, $2, $3, 'cn=restored-alice', $4)
	`, tenantID, sourceID, externalID, userID); err != nil {
		t.Fatalf("insert directory user link: %v", err)
	}

	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{{
		ObjectID: externalID, DN: "cn=restored-alice", Username: "restored-alice",
		Email: "restored@x.test", Name: "Restored Alice",
	}}}
	deps := directoryPreviewDeps(pool, lister)
	previewResponse := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(previewResponse, newPreviewRequest(
		http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}",
	))
	previewID := parseJSONBody(t, previewResponse)["data"].(map[string]any)["preview_id"].(string)
	request := newPreviewRequest(
		http.MethodPost, "/admin/v1/directory/sources/previews/"+previewID+"/activate",
		tenantID, "u1", "{\x22confirm\x22:true}",
	)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", previewID)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
	response := httptest.NewRecorder()
	ActivateDirectoryPreview(deps).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("activate status=%d want 200 body=%s", response.Code, response.Body.String())
	}
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM users WHERE tenant_id=$1 AND id=$2`, tenantID, userID).Scan(&status); err != nil {
		t.Fatalf("query restored user status: %v", err)
	}
	if status != "active" {
		t.Fatalf("reappeared directory user status=%s want active", status)
	}
	data := parseJSONBody(t, response)["data"].(map[string]any)
	if data["restored"] != float64(1) {
		t.Fatalf("restored=%v want 1", data["restored"])
	}
}

func TestDirectoryActivationFullFlow(t *testing.T) {
	pool, tenantID, sourceID, _ := setupDirectoryPreviewFixture(t)
	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{
		{ObjectID: "stable-create", DN: "cn=newdir", Username: "newdir", Email: "newdir@x.test", Name: "New Dir"},
	}}
	deps := directoryPreviewDeps(pool, lister)

	// 预先建本地用户行（user_identity_links.user_id 外键依赖 users）
	localUserID := "user_local_keep"
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO users (id, tenant_id, username, email, password_hash, role, status, department_assignment_source)
		VALUES ($1, $2, 'localkeep', 'localkeep@x.test', 'x', 'developer', 'active', 'local')
	`, localUserID, tenantID); err != nil {
		t.Fatalf("insert local user: %v", err)
	}
	// 把 stable-create 这个 subject 绑到本地用户（模拟 stable identity link 已被 local 占用）
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO user_identity_links (id, tenant_id, user_id, issuer, source_id, source_type, external_subject)
		VALUES ('uil-local-keep', $1, $2, 'local-issuer', 'local-source', 'local', 'stable-create')
	`, tenantID, localUserID); err != nil {
		t.Fatalf("insert local identity link: %v", err)
	}

	rr := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(rr, newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}"))
	previewID, _ := parseJSONBody(t, rr)["data"].(map[string]any)["preview_id"].(string)

	req := newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/previews/"+previewID+"/activate", tenantID, "u1", "{\x22confirm\x22:true}")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", previewID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	actRR := httptest.NewRecorder()
	ActivateDirectoryPreview(deps).ServeHTTP(actRR, req)
	if actRR.Code != http.StatusOK {
		t.Fatalf("activate status=%d want 200; body=%s", actRR.Code, actRR.Body.String())
	}
	_ = sourceID

	// local 的 stable identity link 必须保留不变（不被目录覆盖成 ldap）。
	// 目录同步可以为同一 external_subject 建立独立的 ldap link（不同 issuer/source_type
	// 的 stable key），但绝不能改写已存在的 local link。
	var localLinkCount int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM user_identity_links
		WHERE tenant_id=$1 AND external_subject='stable-create' AND source_type='local'`, tenantID).Scan(&localLinkCount); err != nil {
		t.Fatalf("query local link: %v", err)
	}
	if localLinkCount != 1 {
		t.Fatalf("local stable identity link was overwritten or removed: local_link_count=%d want 1", localLinkCount)
	}
	// local user 行必须仍然存在且仍绑在 local user 上
	var boundLocalUserID string
	if err := pool.QueryRow(context.Background(), `
		SELECT user_id FROM user_identity_links
		WHERE tenant_id=$1 AND external_subject='stable-create' AND source_type='local'`, tenantID).Scan(&boundLocalUserID); err != nil {
		t.Fatalf("query local user id: %v", err)
	}
	if boundLocalUserID != "user_local_keep" {
		t.Fatalf("local link user_id=%s want user_local_keep (overwritten)", boundLocalUserID)
	}
}

// 断言：同步历史读取。
func TestDirectorySyncHistoryListing(t *testing.T) {
	pool, tenantID, _, _ := setupDirectoryPreviewFixture(t)
	deps := directoryPreviewDeps(pool, &fakeDirectoryLister{})

	// 直接插一条 sync_run 模拟历史
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO directory_sync_runs (id, tenant_id, directory_source_id, source_version, run_kind, status, scanned_count, created_count)
		SELECT 'run-hist-1', tenant_id, id, 1, 'full', 'succeeded', 5, 2 FROM directory_sources WHERE tenant_id=$1 ORDER BY tenant_id LIMIT 1
	`, tenantID); err != nil {
		t.Fatalf("insert run: %v", err)
	}

	rr := httptest.NewRecorder()
	ListDirectorySyncRuns(deps).ServeHTTP(rr, newPreviewRequest(http.MethodGet, "/admin/v1/directory/sync-runs", tenantID, "u1", ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("list runs status=%d want 200; body=%s", rr.Code, rr.Body.String())
	}
	body := parseJSONBody(t, rr)
	data, _ := body["data"].([]any)
	if len(data) == 0 {
		t.Fatalf("expected at least one run, got %v", body)
	}
}

func TestDirectorySyncRunDetail(t *testing.T) {
	pool, tenantID, _, _ := setupDirectoryPreviewFixture(t)
	deps := directoryPreviewDeps(pool, &fakeDirectoryLister{})

	if _, err := pool.Exec(context.Background(), `
		INSERT INTO directory_sync_runs (id, tenant_id, directory_source_id, source_version, run_kind, status, scanned_count)
		SELECT 'run-detail-1', tenant_id, id, 1, 'full', 'succeeded', 3 FROM directory_sources WHERE tenant_id=$1 ORDER BY tenant_id LIMIT 1
	`, tenantID); err != nil {
		t.Fatalf("insert run: %v", err)
	}

	req := newPreviewRequest(http.MethodGet, "/admin/v1/directory/sync-runs/run-detail-1", tenantID, "u1", "")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "run-detail-1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	GetDirectorySyncRun(deps).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("get run status=%d want 200; body=%s", rr.Code, rr.Body.String())
	}
	body := parseJSONBody(t, rr)
	data, _ := body["data"].(map[string]any)
	if data["id"] != "run-detail-1" {
		t.Fatalf("run detail id=%v want run-detail-1", data["id"])
	}
}

// 断言：GET preview 详情。
func TestDirectoryPreviewDetail(t *testing.T) {
	pool, tenantID, _, _ := setupDirectoryPreviewFixture(t)
	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{{ObjectID: "s1", DN: "cn=a", Username: "alice", Email: "alice@x.test"}}}
	deps := directoryPreviewDeps(pool, lister)

	rr := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(rr, newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}"))
	previewID, _ := parseJSONBody(t, rr)["data"].(map[string]any)["preview_id"].(string)

	req := newPreviewRequest(http.MethodGet, "/admin/v1/directory/sources/previews/"+previewID, tenantID, "u1", "")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", previewID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	detailRR := httptest.NewRecorder()
	GetDirectoryPreview(deps).ServeHTTP(detailRR, req)
	if detailRR.Code != http.StatusOK {
		t.Fatalf("get preview status=%d want 200; body=%s", detailRR.Code, detailRR.Body.String())
	}
	// 详情响应不得泄露 email
	if strings.Contains(detailRR.Body.String(), "alice@x.test") {
		t.Fatalf("preview detail leaked email: %s", detailRR.Body.String())
	}
}

// === 缺口 3：AD 目录激活后 user_identity_links.source_type='ad' ===
func TestDirectoryActivationADSource(t *testing.T) {
	pool, tenantID, sourceID, _ := setupDirectoryPreviewFixtureWithKind(t, repository.DirectoryKindActiveDirectory)
	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{
		{ObjectID: "ad-stable-1", DN: "cn=aduser", Username: "aduser", Email: "aduser@x.test", Name: "AD User"},
	}}
	deps := directoryPreviewDeps(pool, lister)

	rr := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(rr, newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}"))
	if rr.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", rr.Code, rr.Body.String())
	}
	previewID, _ := parseJSONBody(t, rr)["data"].(map[string]any)["preview_id"].(string)

	req := newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/previews/"+previewID+"/activate", tenantID, "u1", "{\x22confirm\x22:true}")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", previewID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	actRR := httptest.NewRecorder()
	ActivateDirectoryPreview(deps).ServeHTTP(actRR, req)
	if actRR.Code != http.StatusOK {
		t.Fatalf("activate status=%d body=%s", actRR.Code, actRR.Body.String())
	}

	// AD 目录激活后，stable identity link 的 source_type 必须是 'ad'（不是 ldap）
	var linkType string
	if err := pool.QueryRow(context.Background(), `
		SELECT source_type FROM user_identity_links
		WHERE tenant_id=$1 AND external_subject='ad-stable-1' AND source_id=$2
	`, tenantID, sourceID).Scan(&linkType); err != nil {
		t.Fatalf("query ad link: %v", err)
	}
	if linkType != "ad" {
		t.Fatalf("AD directory activation produced source_type=%s, want 'ad'", linkType)
	}
}

// === 缺口 2 断言5：全量激活禁用已消失账号但不删审计历史 ===
func TestDirectoryActivationDisablesMissing(t *testing.T) {
	pool, tenantID, sourceID, _ := setupDirectoryPreviewFixture(t)
	ctx := context.Background()

	// 预先建一个"上次同步遗留"的目录账号（user + directory_user_links + user_identity_links）
	legacyUserID := "user_legacy_disappear"
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		VALUES ($1, $2, 'legacyuser', 'legacy@x.test', 'x', 'developer', 'active')
	`, legacyUserID, tenantID); err != nil {
		t.Fatalf("insert legacy user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO directory_user_links (id, tenant_id, directory_source_id, external_object_id, source_dn, user_id)
		VALUES ('dul_legacy', $1, $2, 'legacy-ext-id', 'cn=legacy', $3)
	`, tenantID, sourceID, legacyUserID); err != nil {
		t.Fatalf("insert legacy link: %v", err)
	}

	// 本次预览/激活的目录列表里没有 legacy-ext-id（账号已消失）
	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{
		{ObjectID: "still-here", DN: "cn=present", Username: "presentuser", Email: "present@x.test"},
	}}
	deps := directoryPreviewDeps(pool, lister)

	rr := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(rr, newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}"))
	previewID, _ := parseJSONBody(t, rr)["data"].(map[string]any)["preview_id"].(string)

	req := newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/previews/"+previewID+"/activate", tenantID, "u1", "{\x22confirm\x22:true}")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", previewID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	actRR := httptest.NewRecorder()
	ActivateDirectoryPreview(deps).ServeHTTP(actRR, req)
	if actRR.Code != http.StatusOK {
		t.Fatalf("activate status=%d body=%s", actRR.Code, actRR.Body.String())
	}
	body := parseJSONBody(t, actRR)
	data := body["data"].(map[string]any)
	if disabled, _ := data["disabled"].(float64); disabled != 1 {
		t.Fatalf("disabled count=%v want 1", data["disabled"])
	}

	// user 行必须仍存在（不删），且 status=disabled
	var userStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM users WHERE id=$1`, legacyUserID).Scan(&userStatus); err != nil {
		t.Fatalf("query legacy user: %v", err)
	}
	if userStatus != "disabled" {
		t.Fatalf("legacy user status=%s want disabled", userStatus)
	}
	// directory_user_links 审计历史必须保留（不删）
	var linkCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM directory_user_links WHERE tenant_id=$1 AND external_object_id='legacy-ext-id'`, tenantID).Scan(&linkCount); err != nil {
		t.Fatalf("count legacy link: %v", err)
	}
	if linkCount != 1 {
		t.Fatalf("legacy directory_user_links count=%d want 1 (audit history preserved)", linkCount)
	}
}

func testDirectoryActivationBindError(t *testing.T, bindErr error, wantSuccess bool) {
	t.Helper()
	pool, tenantID, sourceID, _ := setupDirectoryPreviewFixture(t)
	ctx := context.Background()
	userID := "user_still_present"
	externalID := "still-present-external-id"
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		VALUES ($1, $2, 'still-present', 'still-present@example.test', 'x', 'developer', 'active')
	`, userID, tenantID); err != nil {
		t.Fatalf("insert existing directory user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO directory_user_links (
			id, tenant_id, directory_source_id, external_object_id, source_dn, user_id
		) VALUES ('dul_still_present', $1, $2, $3, 'cn=still-present', $4)
	`, tenantID, sourceID, externalID, userID); err != nil {
		t.Fatalf("insert existing directory link: %v", err)
	}

	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{{
		ObjectID: externalID,
		DN:       "cn=still-present",
		Username: "still-present",
		Email:    "still-present@example.test",
	}}}
	deps := directoryPreviewDeps(pool, lister)
	bindingService := &bindAndResolveErrorService{
		IdentityBindingService: deps.IdentityBindingService,
		err:                    bindErr,
		resolution:             identitybinding.Resolution{UserID: userID, Mode: identitybinding.ModeAutomatic},
	}
	deps.IdentityBindingService = bindingService

	previewResponse := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(previewResponse, newPreviewRequest(
		http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}",
	))
	if previewResponse.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", previewResponse.Code, previewResponse.Body.String())
	}
	previewID := parseJSONBody(t, previewResponse)["data"].(map[string]any)["preview_id"].(string)
	request := newPreviewRequest(
		http.MethodPost,
		"/admin/v1/directory/sources/previews/"+previewID+"/activate",
		tenantID,
		"u1",
		"{\x22confirm\x22:true}",
	)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", previewID)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
	response := httptest.NewRecorder()
	ActivateDirectoryPreview(deps).ServeHTTP(response, request)

	if wantSuccess {
		if response.Code != http.StatusOK {
			t.Fatalf("per-entry error must not fail activation: status=%d body=%s", response.Code, response.Body.String())
		}
		data := parseJSONBody(t, response)["data"].(map[string]any)
		if conflict, _ := data["conflict"].(float64); conflict != 1 {
			t.Fatalf("conflict count=%v want 1", data["conflict"])
		}
	} else {
		if response.Code == http.StatusOK {
			t.Fatalf("unclassified bind error unexpectedly activated: %s", response.Body.String())
		}
		var status, errorCode string
		if err := pool.QueryRow(ctx, `
			SELECT status, error_code FROM directory_sync_runs
			WHERE tenant_id=$1 AND directory_source_id=$2
			ORDER BY started_at DESC LIMIT 1
		`, tenantID, sourceID).Scan(&status, &errorCode); err != nil {
			t.Fatalf("query failed sync run: %v", err)
		}
		if status != "failed" || errorCode != "activation_link_failed" {
			t.Fatalf("sync run status=%s error_code=%s", status, errorCode)
		}

		var activatedRunID string
		if err := pool.QueryRow(ctx, `
			SELECT COALESCE(activated_run_id, '') FROM directory_sync_previews
			WHERE tenant_id=$1 AND id=$2
		`, tenantID, previewID).Scan(&activatedRunID); err != nil {
			t.Fatalf("query preview activation claim: %v", err)
		}
		if activatedRunID != "" {
			t.Fatalf("failed activation leaked preview claim: activated_run_id=%s", activatedRunID)
		}

		bindingService.err = nil
		retryRequest := newPreviewRequest(
			http.MethodPost,
			"/admin/v1/directory/sources/previews/"+previewID+"/activate",
			tenantID, "u1", "{\x22confirm\x22:true}",
		)
		retryRouteContext := chi.NewRouteContext()
		retryRouteContext.URLParams.Add("id", previewID)
		retryRequest = retryRequest.WithContext(context.WithValue(retryRequest.Context(), chi.RouteCtxKey, retryRouteContext))
		retryResponse := httptest.NewRecorder()
		ActivateDirectoryPreview(deps).ServeHTTP(retryResponse, retryRequest)
		if retryResponse.Code != http.StatusOK {
			t.Fatalf("retry after bind recovery: status=%d body=%s", retryResponse.Code, retryResponse.Body.String())
		}
		var runningCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM directory_sync_runs WHERE tenant_id=$1 AND status='running'`, tenantID).Scan(&runningCount); err != nil {
			t.Fatalf("count running sync runs: %v", err)
		}
		if runningCount != 0 {
			t.Fatalf("retry left %d running sync runs", runningCount)
		}
	}

	var userStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM users WHERE id=$1`, userID).Scan(&userStatus); err != nil {
		t.Fatalf("query existing directory user: %v", err)
	}
	if userStatus != "active" {
		t.Fatalf("directory user still present in preview was disabled after bind error: status=%s", userStatus)
	}
}

func TestDirectoryActivationKeepsSeenUserOnInvalidIdentity(t *testing.T) {
	testDirectoryActivationBindError(t, identitybinding.ErrInvalidIdentity, true)
}

func TestDirectoryActivationFailsOnUnclassifiedBindError(t *testing.T) {
	testDirectoryActivationBindError(t, errors.New("injected storage failure"), false)
}

// === 缺口 2 断言7：外部组多部门冲突进入未分配并报告冲突计数 ===
func TestDirectoryActivationConflictCount(t *testing.T) {
	pool, tenantID, sourceID, _ := setupDirectoryPreviewFixture(t)
	ctx := context.Background()

	// seed 两个非系统部门 + 两条同优先级、匹配不同组但都指向不同部门的规则
	// 账号同时属于 cn=g1 和 cn=g2（entry 的 department_match_value 存逗号分隔多值），
	// 两条规则同优先级 100 分别把 g1→deptA、g2→deptB，触发 BindAndResolve 的多部门冲突。
	deptA := ensureDepartment(t, pool, tenantID, "deptA")
	deptB := ensureDepartment(t, pool, tenantID, "deptB")
	seedDepartmentMapping(t, pool, tenantID, "ldap", sourceID, "member_of", "cn=g1", deptA, 100)
	seedDepartmentMapping(t, pool, tenantID, "ldap", sourceID, "member_of", "cn=g2", deptB, 100)

	// 预览（先建空 preview），然后直接 seed 一条带组信息的 entry
	// （directoryldap 不拉组，这里绕过：预览阶段不填组，激活靠 entry 的 department_match_*）
	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{
		{ObjectID: "conflict-user", DN: "cn=conflictuser", Username: "conflictuser", Email: "c@x.test"},
	}}
	deps := directoryPreviewDeps(pool, lister)

	rr := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(rr, newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}"))
	previewID, _ := parseJSONBody(t, rr)["data"].(map[string]any)["preview_id"].(string)

	// 覆盖预览 entry：注入组信息（账号同时属于 cn=g1 和 cn=g2，逗号分隔多值，
	// 激活路径会拆分并填入 ExternalIdentity.MemberOf）
	if _, err := pool.Exec(ctx, `
		UPDATE directory_sync_preview_entries
		SET department_match_type='member_of', department_match_value='cn=g1,cn=g2'
		WHERE tenant_id=$1 AND preview_id=$2 AND external_subject='conflict-user'
	`, tenantID, previewID); err != nil {
		t.Fatalf("update entry with group: %v", err)
	}

	req := newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/previews/"+previewID+"/activate", tenantID, "u1", "{\x22confirm\x22:true}")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", previewID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	actRR := httptest.NewRecorder()
	ActivateDirectoryPreview(deps).ServeHTTP(actRR, req)
	if actRR.Code != http.StatusOK {
		t.Fatalf("activate status=%d body=%s", actRR.Code, actRR.Body.String())
	}
	body := parseJSONBody(t, actRR)
	data := body["data"].(map[string]any)
	if conflict, _ := data["conflict"].(float64); conflict < 1 {
		t.Fatalf("conflict count=%v want >=1", data["conflict"])
	}
	if unassigned, _ := data["unassigned"].(float64); unassigned < 1 {
		t.Fatalf("unassigned count=%v want >=1", data["unassigned"])
	}

	// 用户必须落到"未分配部门"（system_key='unassigned'）
	var deptSystemKey string
	if err := pool.QueryRow(ctx, `
		SELECT t.system_key FROM users u JOIN teams t ON t.id=u.department_id
		WHERE u.tenant_id=$1 AND u.username='conflictuser'
	`, tenantID).Scan(&deptSystemKey); err != nil {
		t.Fatalf("query conflict user dept: %v", err)
	}
	if deptSystemKey != "unassigned" {
		t.Fatalf("conflict user landed in dept system_key=%s, want 'unassigned'", deptSystemKey)
	}
}

// === 缺口 1：Incremental 按稳定 ID 增量更新 ===
func TestDirectoryIncrementalSync(t *testing.T) {
	pool, tenantID, sourceID, _ := setupDirectoryPreviewFixture(t)
	ctx := context.Background()

	// 先跑一次全量激活，seed 初始绑定集合（两个账号）
	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{
		{ObjectID: "stable-inc-1", DN: "cn=u1", Username: "incuser1", Email: "u1@x.test"},
		{ObjectID: "stable-inc-2", DN: "cn=u2", Username: "incuser2", Email: "u2@x.test"},
	}}
	deps := directoryPreviewDeps(pool, lister)

	rr := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(rr, newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}"))
	previewID, _ := parseJSONBody(t, rr)["data"].(map[string]any)["preview_id"].(string)
	req := newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/previews/"+previewID+"/activate", tenantID, "u1", "{\x22confirm\x22:true}")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", previewID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	actRR := httptest.NewRecorder()
	ActivateDirectoryPreview(deps).ServeHTTP(actRR, req)
	if actRR.Code != http.StatusOK {
		t.Fatalf("initial full activate status=%d body=%s", actRR.Code, actRR.Body.String())
	}

	// 记录上次 run_id 作为 cursor
	var lastRunID string
	if err := pool.QueryRow(ctx, `SELECT activated_run_id FROM directory_sync_previews WHERE id=$1`, previewID).Scan(&lastRunID); err != nil {
		t.Fatalf("query last run id: %v", err)
	}

	// 增量：目录现在多了一个新账号 stable-inc-3，inc-1/inc-2 还在（不变）
	lister.users = append(lister.users, directoryldap.DirectoryUser{
		ObjectID: "stable-inc-3", DN: "cn=u3", Username: "incuser3", Email: "u3@x.test",
	})

	// 调 IncrementalDirectorySync（服务层方法，cursor=lastRunID）
	result, err := IncrementalDirectorySync(ctx, deps, tenantID, sourceID, "u1", lastRunID)
	if err != nil {
		t.Fatalf("incremental sync: %v", err)
	}
	if result.RunID == "" {
		t.Fatalf("incremental run_id empty")
	}
	// run_kind 必须是 'changed'
	var runKind string
	if err := pool.QueryRow(ctx, `SELECT run_kind FROM directory_sync_runs WHERE id=$1`, result.RunID).Scan(&runKind); err != nil {
		t.Fatalf("query run kind: %v", err)
	}
	if runKind != "changed" {
		t.Fatalf("incremental run_kind=%s want 'changed'", runKind)
	}
	// 只应创建 1 个新用户（inc-3），inc-1/inc-2 不重复创建
	var userCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE tenant_id=$1 AND username LIKE 'incuser%'`, tenantID).Scan(&userCount); err != nil {
		t.Fatalf("count inc users: %v", err)
	}
	if userCount != 3 {
		t.Fatalf("after incremental, inc user count=%d want 3", userCount)
	}
	if result.Counts.Created < 1 {
		t.Fatalf("incremental created=%d want >=1 (new account inc-3)", result.Counts.Created)
	}
	// 增量不应禁用任何账号（inc-1/inc-2 还在；增量语义=只处理变化，不禁用消失）
	if result.Counts.Disabled != 0 {
		t.Fatalf("incremental disabled=%d want 0 (incremental does not disable)", result.Counts.Disabled)
	}
}

// === I-1: 激活路径事务原子性（汇总写失败必须回滚）===
// failingFinalizePreviewRepo 包装真实 repo，在 FinalizeSyncRunTx 第 N 次调用时返错，
// 模拟汇总写中途失败，断言 MarkDirectoryUserDisabledTx 的副作用被回滚。
type failingFinalizePreviewRepo struct {
	*repository.DirectorySyncPreviewRepository
	finalizeFailAfter int           // 触发失败的调用计数阈值
	finalizeCalls     int           // 已调用次数
	failCh            chan struct{} // 测试用：记录失败是否被触发
}

func (f *failingFinalizePreviewRepo) FinalizeSyncRunTx(ctx context.Context, tx pgx.Tx, tenantID, runID, status string, counts repository.PreviewCounts, errorCode string) error {
	f.finalizeCalls++
	if f.finalizeCalls >= f.finalizeFailAfter {
		if f.failCh != nil {
			select {
			case f.failCh <- struct{}{}:
			default:
			}
		}
		return errors.New("injected finalize failure")
	}
	return f.DirectorySyncPreviewRepository.FinalizeSyncRunTx(ctx, tx, tenantID, runID, status, counts, errorCode)
}

type missingUserBindingService struct {
	IdentityBindingService
}

func (service missingUserBindingService) BindAndResolve(
	context.Context,
	identitybinding.ExternalIdentity,
) (identitybinding.Resolution, error) {
	return identitybinding.Resolution{
		UserID:  "missing-directory-user",
		Mode:    identitybinding.ModeAutomatic,
		Changed: true,
	}, nil
}

func TestDirectoryActivationDomainFailureReleasesClaim(t *testing.T) {
	pool, tenantID, _, _ := setupDirectoryPreviewFixture(t)
	ctx := context.Background()
	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{
		{ObjectID: "domain-failure", DN: "cn=domain-failure", Username: "domain-failure"},
	}}
	deps := directoryPreviewDeps(pool, lister)
	deps.IdentityBindingService = missingUserBindingService{
		IdentityBindingService: deps.IdentityBindingService,
	}

	previewResponse := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(previewResponse, newPreviewRequest(
		http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}",
	))
	previewID := parseJSONBody(t, previewResponse)["data"].(map[string]any)["preview_id"].(string)
	request := newPreviewRequest(
		http.MethodPost,
		"/admin/v1/directory/sources/previews/"+previewID+"/activate",
		tenantID,
		"u1",
		"{\x22confirm\x22:true}",
	)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", previewID)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
	response := httptest.NewRecorder()
	ActivateDirectoryPreview(deps).ServeHTTP(response, request)
	if response.Code == http.StatusOK {
		t.Fatalf("domain failure unexpectedly activated: %s", response.Body.String())
	}
	claim, err := deps.DirectorySourceRepo.ClaimActivation(ctx, tenantID)
	if err != nil {
		t.Fatalf("activation claim leaked after domain failure: %v", err)
	}
	if err := claim.Release(ctx); err != nil {
		t.Fatalf("release verification claim: %v", err)
	}
}

func TestDirectoryActivationAtomicRollbackOnFinalizeFailure(t *testing.T) {
	pool, tenantID, sourceID, _ := setupDirectoryPreviewFixture(t)
	ctx := context.Background()

	// 预先建一个"待禁用"的遗留目录账号（激活时会因消失被 MarkDirectoryUserDisabled）
	legacyUserID := "user_atomic_rollback"
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		VALUES ($1, $2, 'atomiclegacy', 'al@x.test', 'x', 'developer', 'active')
	`, legacyUserID, tenantID); err != nil {
		t.Fatalf("insert legacy user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO directory_user_links (id, tenant_id, directory_source_id, external_object_id, source_dn, user_id)
		VALUES ('dul_atomic', $1, $2, 'legacy-atomic', 'cn=al', $3)
	`, tenantID, sourceID, legacyUserID); err != nil {
		t.Fatalf("insert legacy link: %v", err)
	}

	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{
		{ObjectID: "new-atomic", DN: "cn=new", Username: "newatomic", Email: "n@x.test"},
	}}
	deps := directoryPreviewDeps(pool, lister)
	// 用 wrapper 包装真实 repo，让 FinalizeSyncRunTx 在 succeeded 状态那次（第2次，第1次是 claimAndCreateRun 里没有，实际上是 finalize 里的1次）失败
	wrapped := &failingFinalizePreviewRepo{
		DirectorySyncPreviewRepository: deps.DirectorySyncPreviewRepo.(*repository.DirectorySyncPreviewRepository),
		finalizeFailAfter:              1,
	}
	deps.DirectorySyncPreviewRepo = wrapped

	rr := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(rr, newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}"))
	previewID, _ := parseJSONBody(t, rr)["data"].(map[string]any)["preview_id"].(string)

	req := newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/previews/"+previewID+"/activate", tenantID, "u1", "{\x22confirm\x22:true}")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", previewID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	actRR := httptest.NewRecorder()
	ActivateDirectoryPreview(deps).ServeHTTP(actRR, req)
	if actRR.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on injected failure, got %d body=%s", actRR.Code, actRR.Body.String())
	}

	// 关键断言：事务回滚——legacy user 的 status 必须仍是 active（不是 disabled）
	var userStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM users WHERE id=$1`, legacyUserID).Scan(&userStatus); err != nil {
		t.Fatalf("query legacy user: %v", err)
	}
	if userStatus != "active" {
		t.Fatalf("事务未回滚：legacy user status=%s, want active（disabled 副作用应被回滚）", userStatus)
	}
	// preview 仍应是 succeeded（可重试），不是 activated 或 running
	var previewStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM directory_sync_previews WHERE id=$1`, previewID).Scan(&previewStatus); err != nil {
		t.Fatalf("query preview: %v", err)
	}
	if previewStatus != "succeeded" {
		t.Fatalf("preview status=%s, want succeeded（失败应可重试）", previewStatus)
	}
	// 不应留 running 状态的 sync_run 残行
	var runningCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM directory_sync_runs WHERE tenant_id=$1 AND status='running'`, tenantID).Scan(&runningCount); err != nil {
		t.Fatalf("count running runs: %v", err)
	}
	if runningCount != 0 {
		t.Fatalf("事务未回滚：留下 %d 条 running 残行", runningCount)
	}
	source, err := deps.DirectorySourceRepo.GetByID(ctx, tenantID, sourceID)
	if err != nil || source == nil ||
		!source.RuntimeReconciliationRequired ||
		source.RuntimeReconciliationReason != repository.DirectoryReconciliationReasonPostSyncFailed {
		t.Fatalf("post-sync DB failure reconciliation source=%#v err=%v", source, err)
	}
	claim, err := deps.DirectorySourceRepo.ClaimActivation(ctx, tenantID)
	if err != nil {
		t.Fatalf("activation claim leaked after finalize failure: %v", err)
	}
	if err := claim.Release(ctx); err != nil {
		t.Fatalf("release verification claim: %v", err)
	}
}

// === I-2: 并发激活只能有一个 run 执行写 ===
func TestDirectoryActivationConcurrentSingleRun(t *testing.T) {
	pool, tenantID, sourceID, _ := setupDirectoryPreviewFixture(t)
	ctx := context.Background()
	_ = sourceID

	lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{
		{ObjectID: "concurrent-stable", DN: "cn=cc", Username: "ccuser", Email: "cc@x.test"},
	}}
	deps := directoryPreviewDeps(pool, lister)

	rr := httptest.NewRecorder()
	PreviewDirectorySource(deps).ServeHTTP(rr, newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}"))
	previewID, _ := parseJSONBody(t, rr)["data"].(map[string]any)["preview_id"].(string)

	makeActivateReq := func() *http.Request {
		req := newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/previews/"+previewID+"/activate", tenantID, "u1", "{\x22confirm\x22:true}")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", previewID)
		return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	}

	const concurrency = 8
	var wg sync.WaitGroup
	responses := make([]*httptest.ResponseRecorder, concurrency)
	wg.Add(concurrency)
	start := make(chan struct{})
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			<-start
			ActivateDirectoryPreview(deps).ServeHTTP(rec, makeActivateReq())
			responses[idx] = rec
		}(i)
	}
	close(start)
	wg.Wait()

	// 赢家和锁释放后的幂等请求返回同一 run；锁竞争者稳定返回 409 且不进 runtime。
	runIDs := make(map[string]int)
	conflicts := 0
	for i, rec := range responses {
		switch rec.Code {
		case http.StatusOK:
			body := parseJSONBody(t, rec)
			data := body["data"].(map[string]any)
			runIDs[data["run_id"].(string)]++
		case http.StatusConflict:
			if !strings.Contains(rec.Body.String(), "directory_activation_in_progress") {
				t.Fatalf("goroutine %d unstable conflict body=%s", i, rec.Body.String())
			}
			conflicts++
		default:
			t.Fatalf("goroutine %d status=%d body=%s", i, rec.Code, rec.Body.String())
		}
	}
	if len(runIDs) != 1 {
		t.Fatalf("并发激活产生 %d 个不同 run_id，期望 1（CAS 应保证唯一赢家）: %v", len(runIDs), runIDs)
	}
	if conflicts == 0 {
		t.Log("all concurrent requests ran after claim release and returned idempotently")
	}
	// 只创建一个目录用户
	var userCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE tenant_id=$1 AND username='ccuser'`, tenantID).Scan(&userCount); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if userCount != 1 {
		t.Fatalf("并发激活后用户数=%d, want 1（双写未防止）", userCount)
	}
	// 只有一个 succeeded 的 sync_run
	var succeededRuns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM directory_sync_runs WHERE tenant_id=$1 AND status='succeeded'`, tenantID).Scan(&succeededRuns); err != nil {
		t.Fatalf("count succeeded runs: %v", err)
	}
	if succeededRuns != 1 {
		t.Fatalf("succeeded sync_runs=%d, want 1（CAS 应保证唯一赢家执行写）", succeededRuns)
	}
}

func (n *noopDirectoryRuntime) Status(context.Context) (directoryruntime.RuntimeStatus, error) {
	n.calls++
	return directoryruntime.RuntimeStatus{}, nil
}

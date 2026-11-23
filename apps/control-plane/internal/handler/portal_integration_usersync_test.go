package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	entlicense "github.com/yangjiyj/aiguard/apps/control-plane/internal/license"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/org"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// ---------- 纯逻辑校验（无需 DB） ----------

// 任务7：契约要求 issuer/source_type/external_subject/username 任一缺失返回 400。
// 字段来源是已验证 OIDC token 的 iss/sub/groups/preferred_username/email——缺任一说明
// 上游身份不完整，一律拒绝，绝不落到默认值让门户拿到错误授权。
func TestEnsurePortalUserRequiresTenantHeader(t *testing.T) {
	w := httptest.NewRecorder()
	EnsurePortalUser(&Dependencies{})(w, userSyncReq(http.MethodPost, "/x", "", `{"issuer":"iss","source_type":"oidc","external_subject":"s","username":"u"}`))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "tenant") {
		t.Fatalf("want 400 tenant_required, got %d %s", w.Code, w.Body.String())
	}
}

func TestEnsurePortalUserRequiresIssuer(t *testing.T) {
	w := httptest.NewRecorder()
	EnsurePortalUser(&Dependencies{})(w, userSyncReq(http.MethodPost, "/x", "tenant_default", `{"issuer":"","source_type":"oidc","external_subject":"s","username":"u"}`))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "issuer") {
		t.Fatalf("want 400 issuer required, got %d %s", w.Code, w.Body.String())
	}
}

func TestEnsurePortalUserRequiresSourceType(t *testing.T) {
	w := httptest.NewRecorder()
	EnsurePortalUser(&Dependencies{})(w, userSyncReq(http.MethodPost, "/x", "tenant_default", `{"issuer":"iss","source_type":"","external_subject":"s","username":"u"}`))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "source_type") {
		t.Fatalf("want 400 source_type required, got %d %s", w.Code, w.Body.String())
	}
}

func TestEnsurePortalUserRequiresSubject(t *testing.T) {
	w := httptest.NewRecorder()
	EnsurePortalUser(&Dependencies{})(w, userSyncReq(http.MethodPost, "/x", "tenant_default", `{"issuer":"iss","source_type":"oidc","external_subject":"  ","username":"u"}`))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "external_subject") {
		t.Fatalf("want 400 external_subject required, got %d %s", w.Code, w.Body.String())
	}
}

func TestEnsurePortalUserRequiresUsername(t *testing.T) {
	w := httptest.NewRecorder()
	EnsurePortalUser(&Dependencies{})(w, userSyncReq(http.MethodPost, "/x", "tenant_default", `{"issuer":"iss","source_type":"oidc","external_subject":"s","username":""}`))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "username") {
		t.Fatalf("want 400 username required, got %d %s", w.Code, w.Body.String())
	}
}

type portalIdentitySourceLookupStub struct {
	source *repository.IdentitySource
	err    error
}

func (s portalIdentitySourceLookupStub) GetActive(context.Context, string) (*repository.IdentitySource, error) {
	return s.source, s.err
}

type portalIdentityBindingCapture struct {
	identity identitybinding.ExternalIdentity
}

func (s *portalIdentityBindingCapture) BindAndResolve(_ context.Context, identity identitybinding.ExternalIdentity) (identitybinding.Resolution, error) {
	s.identity = identity
	return identitybinding.Resolution{
		UserID: "user-1", DepartmentID: "team-1", Mode: identitybinding.ModeAutomatic,
		ChatAllowed: true, Changed: true, DepartmentVersion: 1,
	}, nil
}

func (s *portalIdentityBindingCapture) AssignManually(context.Context, string, string, string, string) error {
	return nil
}

func (s *portalIdentityBindingCapture) AssignManyManually(context.Context, string, []string, string, string, string) error {
	return nil
}

func (s *portalIdentityBindingCapture) SetAutomatic(context.Context, string, string, string) error {
	return nil
}

func (s *portalIdentityBindingCapture) Unassign(context.Context, string, string, string) error {
	return nil
}

func TestEnsurePortalUserResolvesActiveSourceIDForRuntimeIssuer(t *testing.T) {
	binding := &portalIdentityBindingCapture{}
	deps := &Dependencies{
		UserRepo:               &repository.UserRepository{},
		IdentityBindingService: binding,
		IdentityRuntimeConfig:  IdentityRuntimeConfig{IssuerURL: "https://sso.corp.test"},
		IdentitySourceLookup: portalIdentitySourceLookupStub{
			source: &repository.IdentitySource{ID: "ids_sso_1", IssuerURL: "https://sso.corp.test"},
		},
	}

	w := httptest.NewRecorder()
	EnsurePortalUser(deps)(w, userSyncReq(http.MethodPost, "/x", "tenant-a", `{"issuer":"https://sso.corp.test","source_type":"oidc","external_subject":"subject-1","username":"employee","email":"employee@corp.test","departments":["SEC-E2E"]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("ensure: status=%d body=%s", w.Code, w.Body.String())
	}
	if binding.identity.SourceID != "ids_sso_1" {
		t.Fatalf("source id = %q, want ids_sso_1", binding.identity.SourceID)
	}
	if len(binding.identity.Departments) != 1 || binding.identity.Departments[0] != "SEC-E2E" {
		t.Fatalf("departments = %#v, want [SEC-E2E]", binding.identity.Departments)
	}
}

func TestEnsurePortalUserRuntimeIssuerAllowsNoActiveEnterpriseSource(t *testing.T) {
	binding := &portalIdentityBindingCapture{}
	deps := &Dependencies{
		UserRepo:               &repository.UserRepository{},
		IdentityBindingService: binding,
		IdentityRuntimeConfig:  IdentityRuntimeConfig{IssuerURL: "https://sso.corp.test"},
		IdentitySourceLookup:   portalIdentitySourceLookupStub{},
	}

	w := httptest.NewRecorder()
	EnsurePortalUser(deps)(w, userSyncReq(http.MethodPost, "/x", "tenant-a", `{"issuer":"https://sso.corp.test","source_type":"oidc","external_subject":"ldap-subject-1","username":"alice","email":"alice@corp.test"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("ensure LDAP-only runtime identity: status=%d body=%s", w.Code, w.Body.String())
	}
	if binding.identity.SourceID != "" {
		t.Fatalf("source id = %q, want empty without an active enterprise source", binding.identity.SourceID)
	}
	if binding.identity.Issuer != "https://sso.corp.test" || binding.identity.ExternalSubject != "ldap-subject-1" {
		t.Fatalf("runtime identity was not preserved: %#v", binding.identity)
	}
}

func TestEnsurePortalUserLegacyPortalProxyDefaultsRuntimeIdentity(t *testing.T) {
	binding := &portalIdentityBindingCapture{}
	deps := &Dependencies{
		UserRepo:               &repository.UserRepository{},
		IdentityBindingService: binding,
		IdentityRuntimeConfig:  IdentityRuntimeConfig{IssuerURL: "https://sso.corp.test"},
	}

	w := httptest.NewRecorder()
	EnsurePortalUser(deps)(w, userSyncReq(http.MethodPost, "/x", "tenant-a", `{"external_subject":"subject-legacy","email":"employee@corp.test"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("ensure: status=%d body=%s", w.Code, w.Body.String())
	}
	if binding.identity.Issuer != "https://sso.corp.test" || binding.identity.SourceType != "oidc" {
		t.Fatalf("legacy identity runtime fields = %#v", binding.identity)
	}
	if binding.identity.Username != "employee@corp.test" || binding.identity.ExternalSubject != "subject-legacy" {
		t.Fatalf("legacy identity user fields = %#v", binding.identity)
	}
}

type portalFailingAuditSystemRepo struct {
	orgTestSystemRepo
	err error
}

func (r *portalFailingAuditSystemRepo) CreateAuditOperation(context.Context, *repository.AuditOperation) error {
	return r.err
}

func TestPortalLogAuditDoesNotLogRawStorageError(t *testing.T) {
	var output bytes.Buffer
	oldWriter := log.Writer()
	oldFlags := log.Flags()
	oldPrefix := log.Prefix()
	log.SetOutput(&output)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
	})

	deps := &Dependencies{SystemRepo: &portalFailingAuditSystemRepo{
		err: errors.New("database write failed dsn=secret"),
	}}
	r := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/users", nil)
	portalLogAudit(r, deps, "tenant-a", "portal_test", map[string]interface{}{
		"user_id": "user-a",
	}, "user", "user-a")

	got := output.String()
	if strings.Contains(got, "dsn=secret") {
		t.Fatalf("audit failure log leaked raw storage error: %q", got)
	}
	if !strings.Contains(got, "component=portal_integration stage=audit_write error_code=audit_write_failed") {
		t.Fatalf("audit failure log missing bounded diagnostic fields: %q", got)
	}
}

func TestEnsureTeamMemberRequiresTenantHeader(t *testing.T) {
	w := httptest.NewRecorder()
	EnsureTeamMember(&Dependencies{})(w, userSyncReq(http.MethodPost, "/x", "", `{"user_id":"u"}`))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "tenant") {
		t.Fatalf("want 400 tenant_required, got %d %s", w.Code, w.Body.String())
	}
}

// ---------- DB 集成流（无测试库则跳过） ----------

func setupUserSyncPool(t *testing.T) (*pgxpool.Pool, string, string) {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// 任务7：identitybinding.Service 依赖迁移137（user_identity_links +
	// identity_department_mappings + teams.system_key='unassigned'）。测试库缺迁移则跳过，
	// 而不是把 ErrNotFound 误判成 handler bug。
	var migrationReady bool
	if err := pool.QueryRow(ctx, `
		SELECT to_regclass('public.user_identity_links') IS NOT NULL
	`).Scan(&migrationReady); err != nil || !migrationReady {
		pool.Close()
		t.Skip("enterprise identity migration 137 is not applied")
	}
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantA := "tus_a_" + sfx
	tenantB := "tus_b_" + sfx
	for _, tid := range []string{tenantA, tenantB} {
		if _, err = pool.Exec(ctx,
			`INSERT INTO tenants (id, name, edition, status) VALUES ($1, $2, $3, $4)`,
			tid, tid, "enterprise", "active"); err != nil {
			t.Fatalf("insert tenant %s: %v", tid, err)
		}
	}
	t.Cleanup(func() {
		cctx := context.Background()
		for _, tid := range []string{tenantA, tenantB} {
			_, _ = pool.Exec(cctx, `DELETE FROM internal_keys WHERE tenant_id=$1`, tid)
			_, _ = pool.Exec(cctx, `DELETE FROM model_policies WHERE tenant_id=$1`, tid)
			_, _ = pool.Exec(cctx, `DELETE FROM project_users WHERE project_id IN (SELECT id FROM projects WHERE tenant_id = $1)`, tid)
			_, _ = pool.Exec(cctx, `DELETE FROM projects WHERE tenant_id = $1`, tid)
			_, _ = pool.Exec(cctx, `DELETE FROM team_members WHERE team_id IN (SELECT id FROM teams WHERE tenant_id = $1)`, tid)
			_, _ = pool.Exec(cctx, `DELETE FROM teams WHERE tenant_id = $1`, tid)
			_, _ = pool.Exec(cctx, `DELETE FROM users WHERE tenant_id = $1`, tid)
			_, _ = pool.Exec(cctx, `DELETE FROM tenants WHERE id = $1`, tid)
		}
		pool.Close()
	})
	return pool, tenantA, tenantB
}

func buildUserSyncDeps(pool *pgxpool.Pool) *Dependencies {
	teamRepo := repository.NewTeamRepository(pool)
	teamMemberRepo := repository.NewTeamMemberRepository(pool)
	quotaRepo := repository.NewQuotaPolicyRepository(pool)
	return &Dependencies{
		UserRepo:               repository.NewUserRepository(pool),
		TeamRepo:               teamRepo,
		TeamMemberRepo:         teamMemberRepo,
		IdentityBindingService: identitybinding.NewService(repository.NewUserIdentityLinkRepository(pool)),
		TeamModelRepo:          repository.NewTeamModelRepository(pool),
		ProjectRepo:            repository.NewProjectRepository(pool),
		ProjectUserRepo:        repository.NewProjectUserRepository(pool),
		OrgService:             org.NewService(teamRepo, teamMemberRepo, quotaRepo),
		SystemRepo:             &orgTestSystemRepo{},
	}
}

func userSyncReq(method, path, tenantID, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if tenantID != "" {
		r.Header.Set(portalIntegrationTenantHeader, tenantID)
	}
	return r
}

// portalEnsureBody 拼装新契约 EnsurePortalUser body（issuer+source_type=oidc+subject+username+email）。
// 测试中所有门户身份默认 source_type=oidc，issuer 固定为测试 OIDC 站点，groups 可选。
func portalEnsureBody(subject, email string, groups []string) string {
	g, _ := json.Marshal(groups)
	if string(g) == "null" {
		g = []byte("[]")
	}
	return fmt.Sprintf(`{"issuer":"https://sso.corp.test","source_type":"oidc","external_subject":%q,"username":%q,"email":%q,"groups":%s}`,
		subject, email, email, string(g))
}

type ensureUserResp struct {
	UserID            string `json:"user_id"`
	DepartmentID      string `json:"department_id"`
	ProjectID         string `json:"project_id"`
	DepartmentVersion int64  `json:"department_version"`
	ChatAllowed       bool   `json:"chat_allowed"`
	Resolution        string `json:"resolution"`
	Created           bool   `json:"created"`
}

// 任务7-场景1：稳定键 = tenant+issuer+source_type+subject。同 email 不同 subject
// 必须各自独立绑定，绝不因 email 相同就合并成同一 user——否则邮件碰撞会导致越权借用账号。
func TestEnsurePortalUserSameEmailDifferentSubjectsNotMerged(t *testing.T) {
	pool, tenantA, _ := setupUserSyncPool(t)
	deps := buildUserSyncDeps(pool)
	email := "shared-" + fmt.Sprintf("%d", time.Now().UnixNano()) + "@corp.test"
	subA := "oidc-sub-a-" + email
	subB := "oidc-sub-b-" + email

	w := httptest.NewRecorder()
	EnsurePortalUser(deps)(w, userSyncReq(http.MethodPost, "/x", tenantA, portalEnsureBody(subA, email, nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("subA ensure: %d %s", w.Code, w.Body.String())
	}
	var r1 ensureUserResp
	_ = json.Unmarshal(w.Body.Bytes(), &r1)
	if r1.UserID == "" || !r1.Created {
		t.Fatalf("subA should create a new binding, got %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	var secondClaims map[string]any
	_ = json.Unmarshal([]byte(portalEnsureBody(subB, email, nil)), &secondClaims)
	secondClaims["username"] = "distinct-" + subB
	secondBody, _ := json.Marshal(secondClaims)
	EnsurePortalUser(deps)(w, userSyncReq(http.MethodPost, "/x", tenantA, string(secondBody)))
	if w.Code != http.StatusOK {
		t.Fatalf("subB ensure: %d %s", w.Code, w.Body.String())
	}
	var r2 ensureUserResp
	_ = json.Unmarshal(w.Body.Bytes(), &r2)
	if r2.UserID == "" || !r2.Created {
		t.Fatalf("subB should create a new binding, got %s", w.Body.String())
	}
	if r1.UserID == r2.UserID {
		t.Fatalf("same email different subjects must NOT merge into one user, both returned %s", r1.UserID)
	}

	// 落库校验：两个不同的 user_identity_links，分别绑定到各自 subject，互不污染。
	var linkCount int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM user_identity_links WHERE tenant_id=$1 AND external_subject IN ($2,$3)
	`, tenantA, subA, subB).Scan(&linkCount); err != nil {
		t.Fatal(err)
	}
	if linkCount != 2 {
		t.Fatalf("expected 2 distinct identity links, got %d", linkCount)
	}
}

// 任务7-场景2：同稳定键并发 → BindAndResolve 事务内 CreateLinkOrGet 兜底，
// 只创建一个绑定，全部 8 个并发请求拿到同一 user_id，DB 只落一行 user_identity_links。
func TestEnsurePortalUserConcurrentSingleBinding(t *testing.T) {
	pool, tenantA, _ := setupUserSyncPool(t)
	deps := buildUserSyncDeps(pool)
	subject := "race-sub-" + fmt.Sprintf("%d", time.Now().UnixNano())

	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := map[string]int{}
	codes := map[int]int{}
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// 每个请求带不同 email/username，使合并只能来自稳定键而非 username 索引。
			body := portalEnsureBody(subject, fmt.Sprintf("race%d@corp.test", i), nil)
			<-start
			w := httptest.NewRecorder()
			EnsurePortalUser(deps)(w, userSyncReq(http.MethodPost, "/x", tenantA, body))
			mu.Lock()
			codes[w.Code]++
			if w.Code == http.StatusOK {
				var rr ensureUserResp
				_ = json.Unmarshal(w.Body.Bytes(), &rr)
				ids[rr.UserID]++
			}
			mu.Unlock()
		}(i)
	}
	close(start)
	wg.Wait()

	if codes[http.StatusOK] != n {
		t.Fatalf("expected all %d requests OK (no 5xx), got codes=%v", n, codes)
	}
	if len(ids) != 1 {
		t.Fatalf("expected exactly one user_id across concurrent ensures, got %v", ids)
	}
	var linkCount int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM user_identity_links
		WHERE tenant_id=$1 AND issuer='https://sso.corp.test'
		  AND source_type='oidc' AND external_subject=$2
	`, tenantA, subject).Scan(&linkCount); err != nil {
		t.Fatal(err)
	}
	if linkCount != 1 {
		t.Fatalf("expected exactly one identity link row in DB, got %d", linkCount)
	}
}

// 无匹配部门映射时仍保留 unassigned 治理状态，但若 JJDGuard 已有 Chat 默认
// 部门/应用，首次登录应自动绑定该应用并返回 project_id，Chat 不再需要另配权限。
func TestEnsurePortalUserUnassignedGetsChatAllowed(t *testing.T) {
	pool, tenantA, _ := setupUserSyncPool(t)
	deps := buildUserSyncDeps(pool)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	chatTeamID := "chat-team-" + suffix
	chatProjectID := "chat-project-" + suffix
	mustExec(t, pool, `INSERT INTO teams (id,tenant_id,name,path,is_system,system_key,model_access_mode) VALUES ($1,$2,'Chat 默认部门','/'||$1::varchar,TRUE,'chat_default','all_active')`, chatTeamID, tenantA)
	mustExec(t, pool, `INSERT INTO projects (id,tenant_id,name,code,status,team_id,system_key) VALUES ($1,$2,'企业 AI 对话项目','chat','active',$3,'chat_default')`, chatProjectID, tenantA, chatTeamID)
	subject := "unassigned-sub-" + suffix
	email := "unassigned@corp.test"

	w := httptest.NewRecorder()
	EnsurePortalUser(deps)(w, userSyncReq(http.MethodPost, "/x", tenantA, portalEnsureBody(subject, email, nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("ensure: %d %s", w.Code, w.Body.String())
	}
	var r ensureUserResp
	_ = json.Unmarshal(w.Body.Bytes(), &r)
	if r.UserID == "" {
		t.Fatalf("expected user_id, got %s", w.Body.String())
	}
	if r.Resolution != identitybinding.ModeUnassigned {
		t.Fatalf("expected resolution=unassigned, got %q (full %s)", r.Resolution, w.Body.String())
	}
	if !r.ChatAllowed || r.ProjectID != chatProjectID {
		t.Fatalf("unassigned user must receive JJDGuard Chat project authorization, got %s", w.Body.String())
	}
	var projectBindingCount int
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM project_users WHERE project_id=$1 AND user_id=$2`, chatProjectID, r.UserID).Scan(&projectBindingCount); err != nil || projectBindingCount != 1 {
		t.Fatalf("Chat project binding count=%d err=%v", projectBindingCount, err)
	}

	// 落库：治理归属仍指向 tenant 的未分配部门，assignment_mode='unassigned'。
	var deptSystemKey, mode string
	if err := pool.QueryRow(context.Background(), `
		SELECT t.system_key, u.department_assignment_mode
		FROM users u JOIN teams t ON t.id=u.department_id
		WHERE u.tenant_id=$1 AND u.id=$2
	`, tenantA, r.UserID).Scan(&deptSystemKey, &mode); err != nil {
		t.Fatal(err)
	}
	if deptSystemKey != "unassigned" || mode != identitybinding.ModeUnassigned {
		t.Fatalf("expected unassigned department, got system_key=%s mode=%s", deptSystemKey, mode)
	}
}

// 任务7-场景4：应急管理用户（AssignmentMode=emergency）chat_allowed=false，
// 不能登录 Chat。预置一个应急模式的用户 + 其身份链接，EnsurePortalUser 委托
// BindAndResolve 命中应急分支返回 ChatAllowed=false。
func TestEnsurePortalUserEmergencyReturnsChatDisallowed(t *testing.T) {
	pool, tenantA, _ := setupUserSyncPool(t)
	deps := buildUserSyncDeps(pool)
	ctx := context.Background()
	subject := "emergency-sub-" + fmt.Sprintf("%d", time.Now().UnixNano())
	issuer := "https://sso.corp.test"

	// 预置：未分配部门 + 一个应急模式用户 + 对应身份链接。
	var unassignedID string
	if err := pool.QueryRow(ctx, `SELECT id FROM teams WHERE tenant_id=$1 AND system_key='unassigned'`, tenantA).Scan(&unassignedID); err != nil {
		t.Fatal(err)
	}
	emergencyUserID := "user-emergency-" + subject
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id,tenant_id,username,email,role,status,department_id,
		                  department_assignment_mode,department_assignment_source)
		VALUES ($1,$2,$3,$4,'developer','active',$5,'emergency','admin')
	`, emergencyUserID, tenantA, subject, subject+"@corp.test", unassignedID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_identity_links (id,tenant_id,user_id,issuer,source_type,external_subject)
		VALUES ($1,$2,$3,$4,'oidc',$5)
	`, "uil-emergency-"+subject, tenantA, emergencyUserID, issuer, subject); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	EnsurePortalUser(deps)(w, userSyncReq(http.MethodPost, "/x", tenantA,
		fmt.Sprintf(`{"issuer":%q,"source_type":"oidc","external_subject":%q,"username":%q,"email":%q}`,
			issuer, subject, subject, subject+"@corp.test")))
	if w.Code != http.StatusOK {
		t.Fatalf("ensure emergency: %d %s", w.Code, w.Body.String())
	}
	var r ensureUserResp
	_ = json.Unmarshal(w.Body.Bytes(), &r)
	if r.UserID != emergencyUserID {
		t.Fatalf("expected to resolve to emergency user %s, got %s", emergencyUserID, r.UserID)
	}
	if r.Resolution != identitybinding.ModeEmergency {
		t.Fatalf("expected resolution=emergency, got %q", r.Resolution)
	}
	if r.ChatAllowed {
		t.Fatalf("emergency admin must have chat_allowed=false, got %s", w.Body.String())
	}
}

// 任务7-场景5：部门移动后旧 team 权限立即失效。
// BindAndResolve 在事务内更新 user.department_id 并触发 team_members 触发器/失效缓存；
// 用户被解析到部门A（手工指派）后再被解析到部门B，旧 team_members 投影必须立即移除，
// 不能残留旧部门权限导致越权访问旧部门模型。
func TestEnsurePortalUserDepartmentMoveInvalidatesOldTeamMembership(t *testing.T) {
	pool, tenantA, _ := setupUserSyncPool(t)
	deps := buildUserSyncDeps(pool)
	ctx := context.Background()
	subject := "move-sub-" + fmt.Sprintf("%d", time.Now().UnixNano())
	email := "move@corp.test"

	// 第一次：解析为未分配部门。
	w := httptest.NewRecorder()
	EnsurePortalUser(deps)(w, userSyncReq(http.MethodPost, "/x", tenantA, portalEnsureBody(subject, email, nil)))
	var r1 ensureUserResp
	_ = json.Unmarshal(w.Body.Bytes(), &r1)
	var firstPersistedVersion int64
	if err := pool.QueryRow(ctx, `SELECT department_version FROM users WHERE id=$1`, r1.UserID).Scan(&firstPersistedVersion); err != nil {
		t.Fatal(err)
	}
	if r1.DepartmentVersion <= 0 || r1.DepartmentVersion != firstPersistedVersion {
		t.Fatalf("first ensure must return persisted positive revision: response=%d database=%d", r1.DepartmentVersion, firstPersistedVersion)
	}
	if r1.UserID == "" {
		t.Fatalf("first ensure no user: %s", w.Body.String())
	}
	// 未分配用户的 team_members 投影指向未分配部门（system_key='unassigned'），
	// 而不是任何业务 team——这是迁移137 projection 设计：所有非应急用户都投影到
	// 自己的 department_id（含未分配），保证 team_members 始终是 users.department_id 的镜像。
	var memberTeamID string
	if err := pool.QueryRow(ctx, `
		SELECT team_id FROM team_members WHERE user_id=$1`,
		r1.UserID).Scan(&memberTeamID); err != nil {
		t.Fatal(err)
	}
	var memberTeamSystemKey string
	if err := pool.QueryRow(ctx, `SELECT system_key FROM teams WHERE id=$1`, memberTeamID).Scan(&memberTeamSystemKey); err != nil {
		t.Fatal(err)
	}
	if memberTeamSystemKey != "unassigned" {
		t.Fatalf("unassigned user should project to unassigned department, got team system_key=%s", memberTeamSystemKey)
	}

	// 人工把用户移到一个业务 team（模拟 IAM 部门移动到 teamA）。
	// 建 teamA + 挂成员（走 EnsureTeamMember 触发 team_members 投影）。
	w = httptest.NewRecorder()
	CreatePortalTeam(deps)(w, userSyncReq(http.MethodPost, "/x", tenantA, `{"name":"业务部A"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("create teamA: %d %s", w.Code, w.Body.String())
	}
	var teamA struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &teamA)
	if teamA.ID == "" {
		t.Fatalf("teamA id empty: %s", w.Body.String())
	}

	router := chi.NewRouter()
	router.Post("/admin/v1/portal-integration/teams/{id}/members", EnsureTeamMember(deps))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, userSyncReq(http.MethodPost, fmt.Sprintf("/admin/v1/portal-integration/teams/%s/members", teamA.ID),
		tenantA, fmt.Sprintf(`{"user_id":%q}`, r1.UserID)))
	if w.Code != http.StatusOK {
		t.Fatalf("assign to teamA: %d %s", w.Code, w.Body.String())
	}
	var memberCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM team_members WHERE user_id=$1 AND team_id=$2`,
		r1.UserID, teamA.ID).Scan(&memberCount); err != nil {
		t.Fatal(err)
	}
	if memberCount != 1 {
		t.Fatalf("expected 1 teamA membership after manual assignment, got %d", memberCount)
	}

	// 再建 teamB，把用户手工移到 teamB —— 模拟"部门移动到新部门"。
	w = httptest.NewRecorder()
	CreatePortalTeam(deps)(w, userSyncReq(http.MethodPost, "/x", tenantA, `{"name":"业务部B"}`))
	var teamB struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &teamB)
	if teamB.ID == "" {
		t.Fatalf("teamB id empty: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, userSyncReq(http.MethodPost, fmt.Sprintf("/admin/v1/portal-integration/teams/%s/members", teamB.ID),
		tenantA, fmt.Sprintf(`{"user_id":%q}`, r1.UserID)))
	if w.Code != http.StatusOK {
		t.Fatalf("assign to teamB: %d %s", w.Code, w.Body.String())
	}

	// 部门移动后：旧 teamA 成员投影必须立即失效，只保留 teamB（用户归属唯一部门）。
	var teamACount, teamBCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM team_members WHERE user_id=$1 AND team_id=$2`,
		r1.UserID, teamA.ID).Scan(&teamACount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM team_members WHERE user_id=$1 AND team_id=$2`,
		r1.UserID, teamB.ID).Scan(&teamBCount); err != nil {
		t.Fatal(err)
	}
	if teamACount != 0 {
		t.Fatalf("old department team membership must be invalidated immediately after department move, still %d", teamACount)
	}
	if teamBCount != 1 {
		t.Fatalf("new department team membership expected 1, got %d", teamBCount)
	}

	// 再次 EnsurePortalUser 委托 BindAndResolve：解析模式 = manual（人工指派），
	// 仍是新 teamB，不会"回退"到自动解析让旧 teamA 复活。
	w = httptest.NewRecorder()
	EnsurePortalUser(deps)(w, userSyncReq(http.MethodPost, "/x", tenantA, portalEnsureBody(subject, email, nil)))
	var r2 ensureUserResp
	_ = json.Unmarshal(w.Body.Bytes(), &r2)
	if r2.UserID != r1.UserID {
		t.Fatalf("idempotent ensure returned different user: %s vs %s", r1.UserID, r2.UserID)
	}
	if r2.Resolution != identitybinding.ModeManual {
		t.Fatalf("after manual assignment resolution must be manual, got %q", r2.Resolution)
	}
	if !r2.ChatAllowed {
		t.Fatalf("manual assignment must keep chat_allowed=true, got %s", w.Body.String())
	}
	// r2 返回的 department_id 必须是新 teamB
	var movedPersistedVersion int64
	if err := pool.QueryRow(ctx, `SELECT department_version FROM users WHERE id=$1`, r1.UserID).Scan(&movedPersistedVersion); err != nil {
		t.Fatal(err)
	}
	if movedPersistedVersion <= 0 || movedPersistedVersion == firstPersistedVersion || r2.DepartmentVersion != movedPersistedVersion {
		t.Fatalf("existing-user ensure must return advanced persisted revision: first=%d response=%d database=%d", firstPersistedVersion, r2.DepartmentVersion, movedPersistedVersion)
	}

	authorizationResponse := httptest.NewRecorder()
	GetPortalUserAuthorizationContext(deps).ServeHTTP(authorizationResponse, portalAuthorizationRequest(tenantA, r1.UserID))
	if authorizationResponse.Code != http.StatusOK {
		t.Fatalf("authorization context: %d %s", authorizationResponse.Code, authorizationResponse.Body.String())
	}
	var authorizationPayload struct {
		Data struct {
			DepartmentVersion int64 `json:"department_version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(authorizationResponse.Body.Bytes(), &authorizationPayload); err != nil {
		t.Fatal(err)
	}
	if authorizationPayload.Data.DepartmentVersion != r2.DepartmentVersion {
		t.Fatalf("ensure and authorization context revisions differ: ensure=%d authorization=%d", r2.DepartmentVersion, authorizationPayload.Data.DepartmentVersion)
	}

	if r2.DepartmentID != teamB.ID {
		t.Fatalf("expected department_id=%s (teamB), got %s", teamB.ID, r2.DepartmentID)
	}
}

// TestEnsurePortalUserQuotaExceeded：License MaxUsers 满 → 402 license_max_users_exceeded 降级，
// 不进 BindAndResolve，不建 user。配额闸仍在新建前拦一道，保留 license 保护语义。
func TestEnsurePortalUserQuotaExceeded(t *testing.T) {
	pool, tenantA, _ := setupUserSyncPool(t)
	deps := buildUserSyncDeps(pool)

	token, publicKeys := signedV2HandlerLicense(t, func(p *entlicense.PayloadV2) { p.MaxUsers = 1 })
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", publicKeys)
	deps.SystemRepo = &licenseSystemRepo{settings: map[string]string{LicenseSettingKey: token}}
	// 配额闸经 userStore(deps)=UserStore 统计 active 用户；置 1 个 active 令 1>=MaxUsers(1) 触 402。
	deps.UserStore = &licenseUserStore{users: map[string]*repository.User{
		"active-1": {ID: "active-1", TenantID: tenantA, Username: "active", Status: "active"},
	}}

	sub := "sso-quota-" + fmt.Sprintf("%d", time.Now().UnixNano())
	w := httptest.NewRecorder()
	EnsurePortalUser(deps)(w, userSyncReq(http.MethodPost, "/x", tenantA, portalEnsureBody(sub, "quota@corp.test", nil)))
	if w.Code != http.StatusPaymentRequired || !strings.Contains(w.Body.String(), "license_max_users_exceeded") {
		t.Fatalf("want 402 license_max_users_exceeded, got %d %s", w.Code, w.Body.String())
	}
	// 402 降级绝不进 BindAndResolve，不创建身份链接。
	var linkCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_identity_links WHERE tenant_id=$1 AND external_subject=$2`,
		tenantA, sub).Scan(&linkCount); err != nil {
		t.Fatal(err)
	}
	if linkCount != 0 {
		t.Fatalf("quota-exceeded must not create identity binding, got %d rows", linkCount)
	}
}

// TestEnsureTeamMemberDBFlow：挂 team 幂等 / 团队跨租户 404 / 用户跨租户 404。
func TestEnsureTeamMemberDBFlow(t *testing.T) {
	pool, tenantA, tenantB := setupUserSyncPool(t)
	deps := buildUserSyncDeps(pool)

	// 建 team（A）
	w := httptest.NewRecorder()
	CreatePortalTeam(deps)(w, userSyncReq(http.MethodPost, "/x", tenantA, `{"name":"研发部"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("create team: %d %s", w.Code, w.Body.String())
	}
	var team struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &team)
	if team.ID == "" {
		t.Fatalf("team id empty: %s", w.Body.String())
	}

	// 建 user（A）—— 任务7：用新契约 EnsurePortalUser。
	sub := "tm-sub-" + fmt.Sprintf("%d", time.Now().UnixNano())
	w = httptest.NewRecorder()
	EnsurePortalUser(deps)(w, userSyncReq(http.MethodPost, "/x", tenantA, portalEnsureBody(sub, "tm@corp.test", nil)))
	var ur ensureUserResp
	_ = json.Unmarshal(w.Body.Bytes(), &ur)
	if ur.UserID == "" {
		t.Fatalf("no user created: %s", w.Body.String())
	}

	router := chi.NewRouter()
	router.Post("/admin/v1/portal-integration/teams/{id}/members", EnsureTeamMember(deps))
	memberPath := fmt.Sprintf("/admin/v1/portal-integration/teams/%s/members", team.ID)
	memberBody := fmt.Sprintf(`{"user_id":%q}`, ur.UserID)
	identityEvidenceCounts := func() (auditCount, outboxCount int) {
		t.Helper()
		ctx := context.Background()
		if err := pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM audit_operations
			WHERE tenant_id=$1
			  AND action_type='identity.department.changed'
			  AND target_type='user'
			  AND target_id=$2
		`, tenantA, ur.UserID).Scan(&auditCount); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM identity_cache_invalidation_outbox
			WHERE tenant_id=$1 AND user_id=$2
		`, tenantA, ur.UserID).Scan(&outboxCount); err != nil {
			t.Fatal(err)
		}
		return auditCount, outboxCount
	}

	// 挂 team → 200。注意：EnsurePortalUser 委托 BindAndResolve 在用户首次绑定到未分配部门时
	// 也会写一条 identity.department.changed 审计 + outbox（首次绑定=首次有部门归属，是部门变更）。
	// 这里以挂 team 前的计数为 baseline，确认挂 team 这一动作恰好 +1/+1。
	baselineAudit, baselineOutbox := identityEvidenceCounts()

	// 挂 team → 200
	w = httptest.NewRecorder()
	router.ServeHTTP(w, userSyncReq(http.MethodPost, memberPath, tenantA, memberBody))
	if w.Code != http.StatusOK {
		t.Fatalf("ensure team member: %d %s", w.Code, w.Body.String())
	}
	var firstResponse EnsureTeamMemberResponse
	if err := json.Unmarshal(w.Body.Bytes(), &firstResponse); err != nil {
		t.Fatal(err)
	}
	firstBody := append([]byte(nil), w.Body.Bytes()...)
	firstAuditCount, firstOutboxCount := identityEvidenceCounts()
	if firstAuditCount != baselineAudit+1 || firstOutboxCount != baselineOutbox+1 {
		t.Fatalf("first assignment evidence delta: audit=%d->%d outbox=%d->%d, want +1/+1",
			baselineAudit, firstAuditCount, baselineOutbox, firstOutboxCount)
	}
	// 幂等再挂 → 200
	w = httptest.NewRecorder()
	router.ServeHTTP(w, userSyncReq(http.MethodPost, memberPath, tenantA, memberBody))
	if w.Code != http.StatusOK {
		t.Fatalf("ensure team member idempotent: %d %s", w.Code, w.Body.String())
	}
	var secondResponse EnsureTeamMemberResponse
	if err := json.Unmarshal(w.Body.Bytes(), &secondResponse); err != nil {
		t.Fatal(err)
	}
	if secondResponse != firstResponse || !bytes.Equal(w.Body.Bytes(), firstBody) {
		t.Fatalf("idempotent response changed: first=%s second=%s", firstBody, w.Body.Bytes())
	}
	secondAuditCount, secondOutboxCount := identityEvidenceCounts()
	if secondAuditCount != firstAuditCount || secondOutboxCount != firstOutboxCount {
		t.Fatalf(
			"second assignment duplicated evidence: audit=%d->%d outbox=%d->%d",
			firstAuditCount, secondAuditCount, firstOutboxCount, secondOutboxCount,
		)
	}

	var departmentID, assignmentMode, assignmentSource, membershipRole string
	if err := pool.QueryRow(context.Background(), `
		SELECT u.department_id,u.department_assignment_mode,
		       u.department_assignment_source,tm.role
		FROM users u
		JOIN team_members tm ON tm.user_id=u.id AND tm.team_id=u.department_id
		WHERE u.tenant_id=$1 AND u.id=$2
	`, tenantA, ur.UserID).Scan(
		&departmentID, &assignmentMode, &assignmentSource, &membershipRole,
	); err != nil {
		t.Fatal(err)
	}
	if departmentID != team.ID || assignmentMode != identitybinding.ModeManual ||
		assignmentSource != "admin" || membershipRole != "member" {
		t.Fatalf(
			"final assignment: department=%s mode=%s source=%s role=%s",
			departmentID, assignmentMode, assignmentSource, membershipRole,
		)
	}
	// DB 侧成员唯一
	members, _ := deps.TeamMemberRepo.ListByTeam(context.Background(), team.ID)
	got := 0
	for _, m := range members {
		if m.UserID == ur.UserID {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("expected exactly 1 membership, got %d", got)
	}

	// 团队跨租户 404：用 tenantB 头对 A 的 team 挂成员
	w = httptest.NewRecorder()
	EnsureTeamMember(deps)(w, chiCtxWithID(userSyncReq(http.MethodPost, "/x", tenantB, fmt.Sprintf(`{"user_id":%q}`, ur.UserID)), team.ID))
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant team: want 404, got %d %s", w.Code, w.Body.String())
	}

	// 用户跨租户 404：在 B 建 user，用 A 头挂到 A 的 team
	w = httptest.NewRecorder()
	EnsurePortalUser(deps)(w, userSyncReq(http.MethodPost, "/x", tenantB, portalEnsureBody("b-"+sub, "b@corp.test", nil)))
	var ubResp ensureUserResp
	_ = json.Unmarshal(w.Body.Bytes(), &ubResp)
	if ubResp.UserID == "" {
		t.Fatalf("no tenantB user: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	EnsureTeamMember(deps)(w, chiCtxWithID(userSyncReq(http.MethodPost, "/x", tenantA, fmt.Sprintf(`{"user_id":%q}`, ubResp.UserID)), team.ID))
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant user: want 404, got %d %s", w.Code, w.Body.String())
	}
}

// TestCreateUserRegularUsersStoreNullExternalSubject 回归：迁移105部分唯一索引
// WHERE external_subject IS NOT NULL 与常规建 user（external_subject 空）语义冲突——
// 空串满足 IS NOT NULL 而共用 (tenant,”)，同租户第二个常规 user 即撞
// uniq_users_tenant_external_subject(23505)。修复后 Create 对空 external_subject 落 NULL，
// 只有带真实 subject 的门户 user 参与该索引，同租户可建多个常规 user。
func TestCreateUserRegularUsersStoreNullExternalSubject(t *testing.T) {
	pool, tenantA, _ := setupUserSyncPool(t)
	repo := repository.NewUserRepository(pool)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		u := &repository.User{
			ID:           uuid.NewString(),
			TenantID:     tenantA,
			Username:     fmt.Sprintf("reg%d", i),
			Email:        fmt.Sprintf("reg%d@corp.test", i),
			PasswordHash: "$2yhash",
			Role:         "operator",
			Status:       "active",
			// ExternalSubject 留空——常规「用户管理」建用户路径从不设置
		}
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("regular user #%d create must succeed (migration 105 must not break plain user creation), got: %v", i, err)
		}
	}
	// 落库校验：两行 external_subject 均为 NULL（不参与部分唯一索引），而非空串
	var nullCnt int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE tenant_id=$1 AND external_subject IS NULL`, tenantA).Scan(&nullCnt)
	if nullCnt != 2 {
		t.Fatalf("both regular users must store NULL external_subject, got %d NULL rows", nullCnt)
	}
}

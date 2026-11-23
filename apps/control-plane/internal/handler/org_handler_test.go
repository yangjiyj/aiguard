package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/org"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// setupOrgHandlerPool opens a test DB pool and inserts a tenant + admin user fixture.
func setupOrgHandlerPool(t *testing.T) (*pgxpool.Pool, string, string) {
	t.Helper()
	if os.Getenv("JJD_PROVIDER_SECRET_KEY") == "" {
		t.Setenv("JJD_PROVIDER_SECRET_KEY", "fixture-redemption-encryption-secret")
	}
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		if os.Getenv("JJD_REQUIRE_IDENTITY_DB_TESTS") == "1" {
			t.Fatal("CONTENT_LOGS_TEST_DATABASE_URL is required when JJD_REQUIRE_IDENTITY_DB_TESTS=1")
		}
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID := "toh_" + sfx
	userID := "uoh_" + sfx

	_, err = pool.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, $3, $4, TRUE)`,
		tenantID, tenantID, "enterprise", "active")
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		userID, tenantID, userID, userID+"@test.com", "x", "platform_admin", "active")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	t.Cleanup(func() {
		defer pool.Close()
		cleanupStatements := []string{
			`DELETE FROM identity_sources WHERE tenant_id = $1`,
			`DELETE FROM team_members WHERE team_id IN (SELECT id FROM teams WHERE tenant_id = $1)`,
			`DELETE FROM users WHERE tenant_id = $1`,
			`DELETE FROM teams WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		}
		for _, statement := range cleanupStatements {
			if _, err := pool.Exec(ctx, statement, tenantID); err != nil {
				t.Errorf("cleanup org handler fixture %s: %v", tenantID, err)
				return
			}
		}
	})
	return pool, tenantID, userID
}

func TestSetupOrgHandlerPoolMarksTenantAsTest(t *testing.T) {
	pool, tenantID, _ := setupOrgHandlerPool(t)

	var isTest bool
	if err := pool.QueryRow(context.Background(),
		`SELECT is_test FROM tenants WHERE id = $1`, tenantID,
	).Scan(&isTest); err != nil {
		t.Fatalf("query test tenant marker: %v", err)
	}
	if !isTest {
		t.Fatal("setupOrgHandlerPool created a tenant visible as a business unit")
	}
}

func TestSetupOrgHandlerPoolCleansIdentitySourceDependencies(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	observer, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect observer: %v", err)
	}
	defer observer.Close()

	var tenantID string
	t.Cleanup(func() {
		if tenantID == "" {
			return
		}
		_, _ = observer.Exec(ctx, `DELETE FROM identity_sources WHERE tenant_id = $1`, tenantID)
		_, _ = observer.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
		_, _ = observer.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	t.Run("fixture", func(t *testing.T) {
		pool, id, _ := setupOrgHandlerPool(t)
		tenantID = id
		_, err := pool.Exec(ctx, `
			INSERT INTO identity_sources
				(id, tenant_id, display_name, issuer_url, client_id, client_secret_enc)
			VALUES ($1, $2, 'Test IdP', 'https://idp.example.com', 'test-client', 'enc:test')
		`, "ids_"+id, id)
		if err != nil {
			t.Fatalf("insert identity source: %v", err)
		}
	})

	var count int
	if err := observer.QueryRow(ctx,
		`SELECT COUNT(*) FROM tenants WHERE id = $1`, tenantID,
	).Scan(&count); err != nil {
		t.Fatalf("query tenant after fixture cleanup: %v", err)
	}
	if count != 0 {
		t.Fatalf("fixture cleanup left %d tenant rows behind", count)
	}
}

// withOrgUserCtx injects a repository.User into the chi request context.
func withOrgUserCtx(r *http.Request, tenantID, userID string) *http.Request {
	u := &repository.User{
		ID:       userID,
		TenantID: tenantID,
		Role:     "platform_admin",
		Status:   "active",
	}
	ctx := context.WithValue(r.Context(), auth.UserKey, u)
	return r.WithContext(ctx)
}

// buildOrgDeps builds a minimal Dependencies for org handler tests.
func buildOrgDeps(pool *pgxpool.Pool) *Dependencies {
	teamRepo := repository.NewTeamRepository(pool)
	teamMemberRepo := repository.NewTeamMemberRepository(pool)
	quotaRepo := repository.NewQuotaPolicyRepository(pool)
	orgSvc := org.NewService(teamRepo, teamMemberRepo, quotaRepo)

	return &Dependencies{
		UserRepo:               repository.NewUserRepository(pool),
		TeamRepo:               teamRepo,
		TeamMemberRepo:         teamMemberRepo,
		IdentityBindingService: identitybinding.NewService(repository.NewUserIdentityLinkRepository(pool)),
		OrgService:             orgSvc,
		SystemRepo:             &orgTestSystemRepo{},
	}
}

// orgTestSystemRepo is a minimal SystemRepo stub for logAudit.
type orgTestSystemRepo struct{}

func (r *orgTestSystemRepo) Get(_ context.Context, _ string) (*repository.SystemSetting, error) {
	return nil, nil
}
func (r *orgTestSystemRepo) GetAll(_ context.Context) ([]*repository.SystemSetting, error) {
	return nil, nil
}
func (r *orgTestSystemRepo) Set(_ context.Context, _, _ string) error                 { return nil }
func (r *orgTestSystemRepo) SetMultiple(_ context.Context, _ map[string]string) error { return nil }
func (r *orgTestSystemRepo) CreateAuditOperation(_ context.Context, _ *repository.AuditOperation) error {
	return nil
}
func (r *orgTestSystemRepo) ListAuditOperations(_ context.Context, _, _ int, _ string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, nil
}
func (r *orgTestSystemRepo) GetBool(_ context.Context, _ string) (bool, error) { return false, nil }

// chiCtxWithID injects a chi URLParam "id" into the request context.
func chiCtxWithID(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// chiCtxWithParams injects multiple chi URLParams into the request context.
func chiCtxWithParams(r *http.Request, params map[string]string) *http.Request {
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// TestTeamsCreateList is the end-to-end create+list test.
func TestTeamsCreateList(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildOrgDeps(pool)

	// --- CreateTeam ---
	body := strings.NewReader(`{"name":"\u7814\u53d1\u90e8"}`) // 研发部 in JSON
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/teams", body)
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()

	CreateTeam(deps)(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("CreateTeam: status=%d body=%s", w.Code, w.Body.String())
	}
	var created map[string]any
	if err := json.NewDecoder(bytes.NewReader(w.Body.Bytes())).Decode(&created); err != nil {
		t.Fatalf("decode created team: %v", err)
	}
	team, _ := created["team"].(map[string]any)
	createdID, _ := team["id"].(string)
	if createdID == "" {
		t.Fatalf("no id in response: %v", created)
	}

	// --- ListTeams ---
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/admin/v1/teams", nil)
	req2 = withOrgUserCtx(req2, tenantID, userID)
	ListTeams(deps)(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("ListTeams: status=%d body=%s", w2.Code, w2.Body.String())
	}
	var listResp struct {
		Data []map[string]any `json:"data"`
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &listResp)
	if len(listResp.Data) == 0 {
		t.Fatal("ListTeams returned empty data")
	}

	// --- DeleteTeam ---
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodDelete, "/admin/v1/teams/"+createdID, nil)
	req3 = withOrgUserCtx(req3, tenantID, userID)
	req3 = chiCtxWithID(req3, createdID)
	DeleteTeam(deps)(w3, req3)

	if w3.Code != http.StatusNoContent {
		t.Fatalf("DeleteTeam: status=%d body=%s", w3.Code, w3.Body.String())
	}
}

// TestTeamMemberAddRemove tests AddTeamMember and RemoveTeamMember.
func TestTeamMemberAddRemove(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildOrgDeps(pool)
	ctx := context.Background()

	// Create a team directly through repo
	teamRepo := repository.NewTeamRepository(pool)
	team := &repository.Team{
		ID:       "tmam_" + fmt.Sprintf("%d", time.Now().UnixNano()),
		TenantID: tenantID, Name: "测试组",
	}
	if err := teamRepo.Create(ctx, team, ""); err != nil {
		t.Fatalf("create team: %v", err)
	}

	// --- AddTeamMember ---
	body := strings.NewReader(`{"user_id":"` + userID + `","role":"admin"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/teams/"+team.ID+"/members", body)
	req = withOrgUserCtx(req, tenantID, userID)
	req = chiCtxWithID(req, team.ID)
	w := httptest.NewRecorder()
	AddTeamMember(deps)(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("AddTeamMember: status=%d body=%s", w.Code, w.Body.String())
	}
	var role string
	if err := pool.QueryRow(ctx, `
		SELECT role FROM team_members WHERE team_id=$1 AND user_id=$2
	`, team.ID, userID).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "owner" {
		t.Fatalf("legacy admin role stored as %q, want owner", role)
	}

	// --- RemoveTeamMember ---
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodDelete,
		"/admin/v1/teams/"+team.ID+"/members/"+userID, nil)
	req2 = withOrgUserCtx(req2, tenantID, userID)
	req2 = chiCtxWithParams(req2, map[string]string{"id": team.ID, "user_id": userID})
	RemoveTeamMember(deps)(w2, req2)

	if w2.Code != http.StatusNoContent {
		t.Fatalf("RemoveTeamMember: status=%d body=%s", w2.Code, w2.Body.String())
	}
}

func TestAddTeamMemberHidesUnavailableDepartmentTargetsIdentically(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildOrgDeps(pool)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	var systemDepartmentID string
	if err := pool.QueryRow(ctx, `
		SELECT id FROM teams WHERE tenant_id=$1 AND is_system=TRUE
	`, tenantID).Scan(&systemDepartmentID); err != nil {
		t.Fatal(err)
	}

	otherTenantID := "toh_other_" + suffix
	crossTenantDepartmentID := "toh_cross_dept_" + suffix
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id,name,edition,status,is_test)
		VALUES ($1,$1,'enterprise','active',TRUE)
	`, otherTenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO teams (id,tenant_id,name,path)
		VALUES ($1::varchar,$2::varchar,$1::varchar,'/' || $1::text)
	`, crossTenantDepartmentID, otherTenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, otherTenantID)
	})

	targets := []string{
		systemDepartmentID,
		"missing-department-" + suffix,
		crossTenantDepartmentID,
	}
	var responseBody string
	for index, targetDepartmentID := range targets {
		request := httptest.NewRequest(
			http.MethodPost,
			"/admin/v1/teams/"+targetDepartmentID+"/members",
			strings.NewReader(`{"user_id":"`+userID+`","role":"member"}`),
		)
		request = withOrgUserCtx(request, tenantID, userID)
		request = chiCtxWithID(request, targetDepartmentID)
		response := httptest.NewRecorder()

		AddTeamMember(deps)(response, request)

		if response.Code != http.StatusNotFound {
			t.Fatalf("target %q status=%d body=%s", targetDepartmentID, response.Code, response.Body.String())
		}
		if index == 0 {
			responseBody = response.Body.String()
		} else if response.Body.String() != responseBody {
			t.Fatalf("target %q body=%q, want %q", targetDepartmentID, response.Body.String(), responseBody)
		}
	}
}

func TestGetTeamEffectiveHidesUnavailableDepartmentTargetsIdentically(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildOrgDeps(pool)
	deps.TeamModelRepo = repository.NewTeamModelRepository(pool)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	var systemDepartmentID string
	if err := pool.QueryRow(ctx, `
		SELECT id FROM teams WHERE tenant_id=$1 AND is_system=TRUE
	`, tenantID).Scan(&systemDepartmentID); err != nil {
		t.Fatal(err)
	}

	otherTenantID := "toh_effective_other_" + suffix
	crossTenantDepartmentID := "toh_effective_cross_" + suffix
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id,name,edition,status,is_test)
		VALUES ($1,$1,'enterprise','active',TRUE)
	`, otherTenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO teams (id,tenant_id,name,path)
		VALUES ($1::varchar,$2::varchar,$1::varchar,'/' || $1::text)
	`, crossTenantDepartmentID, otherTenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, otherTenantID)
	})

	targets := []string{
		systemDepartmentID,
		"missing-effective-department-" + suffix,
		crossTenantDepartmentID,
	}
	var responseBody string
	for index, targetDepartmentID := range targets {
		request := httptest.NewRequest(
			http.MethodGet,
			"/admin/v1/teams/"+targetDepartmentID+"/effective",
			nil,
		)
		request = withOrgUserCtx(request, tenantID, userID)
		request = chiCtxWithID(request, targetDepartmentID)
		response := httptest.NewRecorder()

		GetTeamEffective(deps)(response, request)

		if response.Code != http.StatusNotFound {
			t.Fatalf("target %q status=%d body=%s", targetDepartmentID, response.Code, response.Body.String())
		}
		if index == 0 {
			responseBody = response.Body.String()
		} else if response.Body.String() != responseBody {
			t.Fatalf("target %q body=%q, want %q", targetDepartmentID, response.Body.String(), responseBody)
		}
	}
}

func (r *orgTestSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, r.Get, keys)
}

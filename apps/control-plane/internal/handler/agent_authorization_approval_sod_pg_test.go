package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type t15SoDAuditRepo struct {
	agentGuardAuditSystemRepo
	mu  sync.Mutex
	ops []*repository.AuditOperation
}

func (r *t15SoDAuditRepo) CreateAuditOperation(_ context.Context, op *repository.AuditOperation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops = append(r.ops, op)
	return nil
}

func (r *t15SoDAuditRepo) find(actionType string) []*repository.AuditOperation {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*repository.AuditOperation
	for _, op := range r.ops {
		if op.ActionType == actionType {
			out = append(out, op)
		}
	}
	return out
}

type t15SoDHandlerFixture struct {
	repo      *repository.AgentAuthorizationRepository
	db        *pgxpool.Pool
	api       *AgentAuthorizationApprovalAPI
	audit     *t15SoDAuditRepo
	principal repository.TrustedAgentPrincipal
	grantID   string
	seq       int
}

func newT15SoDHandlerFixture(t *testing.T) *t15SoDHandlerFixture {
	t.Helper()
	dsn := os.Getenv("AGENTGUARD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AGENTGUARD_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := fmt.Sprintf("t15_sod_h_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	})
	if _, err := db.Exec(ctx, `CREATE TABLE tenants (id VARCHAR(64) PRIMARY KEY); INSERT INTO tenants(id) VALUES ('tenant-a')`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"054_agentguard_policy_governance.sql", "065_agentguard_confirmation_replay.sql",
		"100_mcp_confirmation_source.sql", "861_trusted_agent_authorization.sql",
		"864_agent_authorization_retention_index.sql", "870_agent_authorization_approvals.sql",
		"872_agent_authorization_principal_rotated_by.sql", "874_agent_delegation_lifecycle.sql",
	} {
		body, err := os.ReadFile("../../../../deploy/migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, string(body)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
	repo := repository.NewAgentAuthorizationRepository(db)
	now := time.Now().UTC()
	created, err := repo.RegisterPrincipal(ctx, "tenant-a", repository.AgentAuthorizationPrincipalCreate{
		Name: "t15-sod-handler", ExpiresAt: now.Add(24 * time.Hour), CreatedBy: "creator-a",
		Grants: []repository.AgentAuthorizationGrant{{Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t15.txt",
			ExpiresAt: now.Add(12 * time.Hour), QuotaMax: 1000, QuotaWindowSeconds: 3600}},
	})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := repo.ResolvePrincipalCredential(ctx, repository.HashAgentToken(created.Credential))
	if err != nil || principal == nil {
		t.Fatalf("resolve principal: %v %v", principal, err)
	}
	audit := &t15SoDAuditRepo{}
	api := NewAgentAuthorizationApprovalAPI(repo, &Dependencies{SystemRepo: audit})
	return &t15SoDHandlerFixture{repo: repo, db: db, api: api, audit: audit, principal: *principal, grantID: created.Grants[0].ID}
}

func (f *t15SoDHandlerFixture) pending(t *testing.T) *repository.AgentAuthorizationApproval {
	t.Helper()
	f.seq++
	key := fmt.Sprintf("t13-sod-handler-call-%08d", f.seq)
	ctx := context.Background()
	if decision, err := f.repo.Authorize(ctx, f.principal, repository.AgentAuthorizationRequest{
		Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t15.txt", IdempotencyKey: key}); err != nil || !decision.Allowed {
		t.Fatalf("authorize: %+v %v", decision, err)
	}
	approval, _, err := f.repo.CreateAgentAuthorizationApproval(ctx, f.principal, f.grantID, repository.AgentAuthorizationApprovalInput{
		Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t15.txt",
		ArgumentsSHA256: strings.Repeat(fmt.Sprintf("%x", f.seq%16), 64), AuthorizationIdempotencyKey: key,
		ApprovalIdempotencyKey: "t15:req:" + strings.Repeat(fmt.Sprintf("%x", f.seq%16), 64)})
	if err != nil || approval.Status != "pending" {
		t.Fatalf("create approval: %+v %v", approval, err)
	}
	return approval
}

func (f *t15SoDHandlerFixture) status(t *testing.T, id string) string {
	t.Helper()
	var status string
	if err := f.db.QueryRow(context.Background(), `SELECT status FROM agentguard_confirmations WHERE id=$1`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func t15SoDAdminRequest(userID, role, path, id, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	user := &repository.User{ID: userID, TenantID: "tenant-a", Role: role, Status: "active"}
	ctx := context.WithValue(req.Context(), auth.UserKey, user)
	ctx = context.WithValue(ctx, auth.SessionKey, &repository.Session{ID: "session-" + userID, UserID: userID, TenantID: "tenant-a"})
	if id != "" {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", id)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	}
	return req.WithContext(ctx)
}

func (f *t15SoDHandlerFixture) resolve(userID, role, id, status string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	f.api.ResolveApproval(rr, t15SoDAdminRequest(userID, role, "/admin/v1/agent/approvals/"+id+"/resolve", id,
		`{"status":"`+status+`","note":"sod"}`))
	return rr
}

func (f *t15SoDHandlerFixture) createException(userID, role, seed string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"principal_id":%q,"grant_id":%q,"action":"file_write","resource_type":"file","resource_id":"/tmp/t15.txt","arguments_sha256":%q,"reason":"sod","ttl_seconds":60,"idempotency_key":%q}`,
		f.principal.ID, f.grantID, strings.Repeat(seed, 64), "t15:exception:"+strings.Repeat(seed, 64))
	rr := httptest.NewRecorder()
	f.api.CreateException(rr, t15SoDAdminRequest(userID, role, "/admin/v1/agent/approval-exceptions", "", body))
	return rr
}

func t15SoDErrorCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode error body %q: %v", rr.Body.String(), err)
	}
	return payload.Error.Code
}

func TestT15SoDHandlerPostgresCreatorResolveForbiddenAndAudited(t *testing.T) {
	f := newT15SoDHandlerFixture(t)
	for _, role := range []string{"tenant_admin", "platform_admin"} {
		for _, decision := range []string{"approved", "rejected"} {
			approval := f.pending(t)
			rr := f.resolve("creator-a", role, approval.ID, decision)
			if rr.Code != http.StatusForbidden || t15SoDErrorCode(t, rr) != "approval_self_resolution_forbidden" {
				t.Fatalf("%s/%s self resolve: status=%d body=%s", role, decision, rr.Code, rr.Body.String())
			}
			if got := f.status(t, approval.ID); got != "pending" {
				t.Fatalf("%s/%s self resolve changed status to %s", role, decision, got)
			}
		}
	}
	denied := f.audit.find("agent_authorization_approval.resolve_denied")
	if len(denied) != 4 || len(f.audit.find("agent_authorization_approval.resolve")) != 0 {
		t.Fatalf("audit ops=%d denied=%d", len(f.audit.ops), len(denied))
	}
	for _, op := range denied {
		detail := op.ActionDetail
		if op.UserID != "creator-a" || detail["reason"] != "self_resolution" || op.TargetType != "agent_authorization_approval" || op.TargetID == "" {
			t.Fatalf("denied audit shape: %+v", op)
		}
	}
}

func TestT15SoDHandlerPostgresOtherAdminResolvesAndViewerForbidden(t *testing.T) {
	f := newT15SoDHandlerFixture(t)
	approval := f.pending(t)
	if rr := f.resolve("viewer-c", "viewer", approval.ID, "approved"); rr.Code != http.StatusForbidden || t15SoDErrorCode(t, rr) != "forbidden" {
		t.Fatalf("viewer resolve: %d %s", rr.Code, rr.Body.String())
	}
	if rr := f.resolve("viewer-c", "viewer", approval.ID, "rejected"); rr.Code != http.StatusForbidden || t15SoDErrorCode(t, rr) != "forbidden" {
		t.Fatalf("viewer reject: %d %s", rr.Code, rr.Body.String())
	}
	if rr := f.resolve("reviewer-b", "tenant_admin", approval.ID, "approved"); rr.Code != http.StatusOK {
		t.Fatalf("independent approve: %d %s", rr.Code, rr.Body.String())
	}
	if got := f.status(t, approval.ID); got != "approved" {
		t.Fatalf("independent approve status %s", got)
	}
	rejected := f.pending(t)
	if rr := f.resolve("reviewer-b", "platform_admin", rejected.ID, "rejected"); rr.Code != http.StatusOK || f.status(t, rejected.ID) != "rejected" {
		t.Fatalf("independent reject: %d %s", rr.Code, rr.Body.String())
	}
	if n := len(f.audit.find("agent_authorization_approval.resolve")); n != 2 || len(f.audit.find("agent_authorization_approval.resolve_denied")) != 0 {
		t.Fatalf("resolve audit count=%d", n)
	}
}

func TestT15SoDHandlerPostgresCreatorExceptionForbidden(t *testing.T) {
	f := newT15SoDHandlerFixture(t)
	for i, role := range []string{"tenant_admin", "platform_admin"} {
		rr := f.createException("creator-a", role, fmt.Sprintf("%x", i+1))
		if rr.Code != http.StatusForbidden || t15SoDErrorCode(t, rr) != "approval_self_resolution_forbidden" {
			t.Fatalf("%s self exception: %d %s", role, rr.Code, rr.Body.String())
		}
	}
	var count int
	if err := f.db.QueryRow(context.Background(), `SELECT count(*) FROM agent_authorization_approval_exceptions`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("self exception persisted: %d %v", count, err)
	}
	denied := f.audit.find("agent_authorization_approval_exception.create_denied")
	if len(denied) != 2 {
		t.Fatalf("exception denied audit count=%d", len(denied))
	}
	if detail := denied[0].ActionDetail; detail["reason"] != "self_resolution" || denied[0].TargetID != f.principal.ID {
		t.Fatalf("exception denied audit shape: %+v", denied[0])
	}
	if rr := f.createException("viewer-c", "viewer", "9"); rr.Code != http.StatusForbidden || t15SoDErrorCode(t, rr) != "forbidden" {
		t.Fatalf("viewer exception: %d %s", rr.Code, rr.Body.String())
	}
	if rr := f.createException("reviewer-b", "tenant_admin", "a"); rr.Code != http.StatusCreated {
		t.Fatalf("independent exception: %d %s", rr.Code, rr.Body.String())
	}
}

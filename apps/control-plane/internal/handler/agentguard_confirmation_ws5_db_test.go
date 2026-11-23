package handler

import (
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

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type ws5DualApprovalSystemRepo struct {
	behaviorAuditRepo
	dual      bool
	allowSelf bool
}

func (f *ws5DualApprovalSystemRepo) GetBool(_ context.Context, key string) (bool, error) {
	switch key {
	case agentGuardDualApprovalSettingKey:
		return f.dual, nil
	case agentGuardAllowSelfApprovalSettingKey:
		return f.allowSelf, nil
	}
	return false, nil
}

type ws5NoopReplayer struct{}

func (ws5NoopReplayer) ReplayConfirmation(context.Context, *repository.AgentGuardConfirmation) (string, error) {
	return "", nil
}

func ws5ConfirmationDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	databaseURL := os.Getenv("AGENTGUARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("AGENTGUARD_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	tenantID := fmt.Sprintf("ws5cf%d", time.Now().UnixNano()%1_000_000_000)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenantID) })
	return pool, tenantID
}

func ws5CreateConfirmation(t *testing.T, deps *Dependencies, tenantID, callID, args string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"tool_call_id": callID, "tool_call_arguments": args, "tool_name": "network.upload",
		"trace_id": "trace-" + callID, "raw_decision": "confirm", "effective_decision": "confirm",
		"requester_user_id": "u_requester", "requester_client_id": "key_1",
		"expires_at": time.Now().Add(10 * time.Minute),
	})
	req := httptest.NewRequest(http.MethodPost, "/internal", strings.NewReader(string(body)))
	req.Header.Set("X-Tenant-ID", tenantID)
	rec := httptest.NewRecorder()
	CreateAgentGuardConfirmationInternal(deps)(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create confirmation: %d %s", rec.Code, rec.Body.String())
	}
	var created repository.AgentGuardConfirmation
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("decode created confirmation: %v %s", err, rec.Body.String())
	}
	return created.ID
}

func ws5Resolve(deps *Dependencies, tenantID, id, actorID, status string) *httptest.ResponseRecorder {
	user := &repository.User{ID: actorID, TenantID: tenantID, Role: "platform_admin"}
	req := withBehaviorUser(http.MethodPost, "/x", fmt.Sprintf(`{"status":%q}`, status), user)
	route := chi.NewRouteContext()
	route.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
	rec := httptest.NewRecorder()
	ResolveAgentGuardConfirmation(deps)(rec, req)
	return rec
}

func ws5Consume(t *testing.T, deps *Dependencies, tenantID, callID, userID, args string) bool {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"tool_call_id": callID, "tool_name": "network.upload", "tool_call_arguments": args,
		"requester_user_id": userID, "requester_client_id": "key_1", "request_id": "req-retry",
	})
	req := httptest.NewRequest(http.MethodPost, "/internal", strings.NewReader(string(body)))
	req.Header.Set("X-Tenant-ID", tenantID)
	rec := httptest.NewRecorder()
	ConsumeAgentGuardConfirmationInternal(deps)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("consume: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data struct {
			Consumed bool `json:"consumed"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode consume: %v", err)
	}
	return out.Data.Consumed
}

// W5 5.2 + 5.3 (real database): the requester cannot approve their own call;
// an approved confirmation is redeemable exactly once, only by the same
// requester with the same canonical arguments.
func TestWS5ConfirmationSingleUseRetryAndSelfApprovalDB(t *testing.T) {
	pool, tenantID := ws5ConfirmationDB(t)
	// 本人批准的审计经事务审计写 audit_operations.user_id（外键 users），批准人须是真实用户。
	ws5EnsureUser(t, pool, tenantID, "u_requester")
	sys := &ws5DualApprovalSystemRepo{}
	deps := &Dependencies{
		AgentGuardPolicyRepo: repository.NewAgentGuardPolicyRepository(pool),
		SystemRepo:           sys,
		ConfirmationReplayer: ws5NoopReplayer{},
	}
	id := ws5CreateConfirmation(t, deps, tenantID, "call_1", `{"url":"https://x.example/up","size":10}`)

	if ws5Consume(t, deps, tenantID, "call_1", "u_requester", `{"url":"https://x.example/up","size":10}`) {
		t.Fatal("pending confirmation must not be redeemable")
	}
	if rec := ws5Resolve(deps, tenantID, id, "u_requester", "approved"); rec.Code != http.StatusForbidden {
		t.Fatalf("self approval: want 403, got %d %s", rec.Code, rec.Body.String())
	}
	if rec := ws5Resolve(deps, tenantID, id, "u_admin", "approved"); rec.Code != http.StatusOK {
		t.Fatalf("admin approval: %d %s", rec.Code, rec.Body.String())
	}
	if ws5Consume(t, deps, tenantID, "call_1", "u_requester", `{"url":"https://evil.example/up","size":10}`) {
		t.Fatal("different arguments must not redeem the approval")
	}
	if ws5Consume(t, deps, tenantID, "call_1", "u_other", `{"url":"https://x.example/up","size":10}`) {
		t.Fatal("a different requester must not redeem the approval")
	}
	// Same arguments re-serialised with a new tool_call_id (model regeneration).
	if !ws5Consume(t, deps, tenantID, "call_2", "u_requester", `{ "size": 10, "url": "https://x.example/up" }`) {
		t.Fatal("approved confirmation must be redeemable once")
	}
	if ws5Consume(t, deps, tenantID, "call_1", "u_requester", `{"url":"https://x.example/up","size":10}`) {
		t.Fatal("approval must be single-use")
	}
	var replayStatus string
	if err := pool.QueryRow(context.Background(), `SELECT replay_status FROM agentguard_confirmations WHERE id=$1`, id).Scan(&replayStatus); err != nil || replayStatus != "executed" {
		t.Fatalf("replay_status: %q err=%v", replayStatus, err)
	}
	for _, op := range sys.operations {
		if op.ActionType == "agentguard_confirmation.self_approved" {
			t.Fatalf("a refused self approval must not be audited as approved: %+v", op)
		}
	}

	// 2.9.22 批次 2B：打开 agentguard_allow_self_approval 后允许本人批准，并写审计
	// agentguard_confirmation.self_approved（默认关，上面的 403 不变）。
	sys.allowSelf = true
	selfID := ws5CreateConfirmation(t, deps, tenantID, "call_self", `{"url":"https://x.example/self"}`)
	if rec := ws5Resolve(deps, tenantID, selfID, "u_requester", "approved"); rec.Code != http.StatusOK {
		t.Fatalf("self approval with the switch on: %d %s", rec.Code, rec.Body.String())
	}
	// 复审：本人批准的审计改由仓库用事务审计在批准的同一事务里写进 audit_operations（原断言查 handler
	// 经 SystemRepo 事后另写的记录），批准人在 user_id 列。
	var audited int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_operations
		WHERE action_type='agentguard_confirmation.self_approved' AND target_id=$1 AND user_id='u_requester' AND tenant_id=$2`, selfID, tenantID).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("self approval must be audited once: count=%d err=%v", audited, err)
	}
	if !ws5Consume(t, deps, tenantID, "call_self", "u_requester", `{"url":"https://x.example/self"}`) {
		t.Fatal("a self-approved confirmation is redeemable once")
	}
}

// W5 5.3 (real database): with dual approval on, the first approval keeps the
// confirmation pending, the same approver cannot approve twice, and a second
// approver completes it.
func TestWS5ConfirmationDualApprovalDB(t *testing.T) {
	pool, tenantID := ws5ConfirmationDB(t)
	deps := &Dependencies{
		AgentGuardPolicyRepo: repository.NewAgentGuardPolicyRepository(pool),
		SystemRepo:           &ws5DualApprovalSystemRepo{dual: true},
		ConfirmationReplayer: ws5NoopReplayer{},
	}
	id := ws5CreateConfirmation(t, deps, tenantID, "call_d", `{"url":"https://x.example/d"}`)
	if rec := ws5Resolve(deps, tenantID, id, "u_admin1", "approved"); rec.Code != http.StatusAccepted {
		t.Fatalf("first approval: want 202, got %d %s", rec.Code, rec.Body.String())
	}
	if ws5Consume(t, deps, tenantID, "call_d", "u_requester", `{"url":"https://x.example/d"}`) {
		t.Fatal("half-approved confirmation must not be redeemable")
	}
	if rec := ws5Resolve(deps, tenantID, id, "u_admin1", "approved"); rec.Code != http.StatusConflict {
		t.Fatalf("same approver twice: want 409, got %d %s", rec.Code, rec.Body.String())
	}
	if rec := ws5Resolve(deps, tenantID, id, "u_admin2", "approved"); rec.Code != http.StatusOK {
		t.Fatalf("second approval: %d %s", rec.Code, rec.Body.String())
	}
	if !ws5Consume(t, deps, tenantID, "call_d", "u_requester", `{"url":"https://x.example/d"}`) {
		t.Fatal("fully approved confirmation must be redeemable")
	}
}

func (f *ws5DualApprovalSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, f.Get, keys)
}

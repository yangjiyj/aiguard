package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAgentAuthClaimCannotBypassDispositionOnPostgres(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ns := fmt.Sprintf("tri_r2_auth_%d", time.Now().UnixNano())
	tenant, project, agentA, agentB := ns+"_tenant", ns+"_project", ns+"_a", ns+"_b"
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name,is_test) VALUES($1,$1,true)`, tenant)
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM integration_gateway_receipts WHERE instance_id=$1`, ns)
		_, _ = db.Exec(ctx, `DELETE FROM integration_gateway_instances WHERE instance_id=$1`, ns)
		_, _ = db.Exec(ctx, `DELETE FROM integration_agent_policies WHERE tenant_id=$1`, tenant)
		_, _ = db.Exec(ctx, `DELETE FROM security_events WHERE tenant_id=$1`, tenant)
		_, _ = db.Exec(ctx, `DELETE FROM request_logs WHERE tenant_id=$1`, tenant)
		_, _ = db.Exec(ctx, `DELETE FROM internal_keys WHERE tenant_id=$1`, tenant)
		_, _ = db.Exec(ctx, `DELETE FROM projects WHERE tenant_id=$1`, tenant)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenant)
	})
	exec(`INSERT INTO projects(id,tenant_id,name) VALUES($1,$2,$1)`, project, tenant)
	seedKey := func(name, bound, status string, expires *time.Time) string {
		t.Helper()
		raw := "synthetic-agent-auth-" + ns + "-" + name
		sum := sha256.Sum256([]byte(raw))
		exec(`INSERT INTO internal_keys(id,tenant_id,project_id,key_hash,key_prefix,scopes_json,status,agent_instance_id,expires_at) VALUES($1,$2,$3,$4,$5,'["chat","models","mcp"]',$6,NULLIF($7,''),$8)`, ns+"_"+name, tenant, project, hex.EncodeToString(sum[:]), raw[:8], status, bound, expires)
		return raw
	}
	legacy := seedKey("legacy", "", "active", nil)
	bound := seedKey("bound", agentA, "active", nil)
	other := seedKey("other", agentB, "active", nil)
	revoked := seedKey("revoked", agentA, "revoked", nil)
	expiry := time.Now().Add(-time.Hour)
	expiredAgent := ns + "_expired_agent"
	expired := seedKey("expired", expiredAgent, "active", &expiry)
	modelPolicy, mcpPolicy := ns+"_model_policy", ns+"_mcp_policy"
	exec(`INSERT INTO integration_agent_policies(id,tenant_id,agent_instance_id,action,enabled,mode,mcp_server_id) VALUES($1,$3,$4,'block_model_egress',true,'protect',''),($2,$3,$4,'disable_mcp',true,'protect','')`, modelPolicy, mcpPolicy, tenant, agentA)
	runtime := NewIntegrationPolicyRuntime(db, func(context.Context) bool { return false }, nil)
	runtime.instanceID = ns
	if err = runtime.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	forwarded := false
	seenAgent := ""
	next := func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		seenAgent = auth.GetAuthInfo(r).AgentInstanceID
		w.WriteHeader(204)
	}
	router := chi.NewRouter()
	router.Use(auth.NewAuthMiddleware(db, nil, nil).Middleware(&config.Config{}))
	router.With(runtime.Middleware).Post("/v1/chat/completions", next)
	router.With(runtime.Middleware).Get("/v1/models", next)
	router.With(runtime.Middleware).Post("/mcp/{serverID}", next)
	type requestCase struct {
		name, key, method, path, claim, identity, errorCode string
		status                                              int
		aux                                                 bool
		denialBound                                         *string
	}
	unboundIdentity := ""
	for _, tc := range []requestCase{
		{name: "legacy without claim", key: legacy, method: "POST", path: "/v1/chat/completions", status: 204},
		{name: "auxiliary headers grant no identity", key: legacy, method: "POST", path: "/v1/chat/completions", status: 204, aux: true},
		{name: "legacy claim model blocked before policy", key: legacy, method: "POST", path: "/v1/chat/completions", claim: agentA, status: 403, errorCode: "agent_identity_mismatch", denialBound: &unboundIdentity},
		{name: "legacy claim MCP blocked before policy", key: legacy, method: "POST", path: "/mcp/synthetic_mcp", claim: agentA, status: 403, errorCode: "agent_identity_mismatch", denialBound: &unboundIdentity},
		{name: "legacy malformed claim", key: legacy, method: "GET", path: "/v1/models", claim: "invalid/agent", status: 403, errorCode: "agent_identity_mismatch", denialBound: &unboundIdentity},
		{name: "bound no claim retains identity", key: bound, method: "GET", path: "/v1/models", status: 204, identity: agentA},
		{name: "bound matching claim retains identity", key: bound, method: "GET", path: "/v1/models", claim: agentA, status: 204, identity: agentA},
		{name: "bound matching claim model policy", key: bound, method: "POST", path: "/v1/chat/completions", claim: agentA, status: 403, errorCode: "agent_policy_blocked"},
		{name: "bound matching claim MCP policy", key: bound, method: "POST", path: "/mcp/synthetic_mcp", claim: agentA, status: 403, errorCode: "agent_policy_blocked"},
		{name: "bound wrong claim audited as bound", key: bound, method: "GET", path: "/v1/models", claim: agentB, status: 403, errorCode: "agent_identity_mismatch", denialBound: &agentA},
		{name: "other bound credential cannot claim A", key: other, method: "GET", path: "/v1/models", claim: agentA, status: 403, errorCode: "agent_identity_mismatch", denialBound: &agentB},
		{name: "revoked bound credential rejected", key: revoked, method: "GET", path: "/v1/models", claim: agentA, status: 401, errorCode: "key_revoked"},
		{name: "expired bound credential rejected", key: expired, method: "GET", path: "/v1/models", claim: expiredAgent, status: 401, errorCode: "key_expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forwarded, seenAgent = false, ""
			request := httptest.NewRequest(tc.method, tc.path, nil)
			request.Header.Set("Authorization", "Bearer "+tc.key)
			if tc.claim != "" {
				request.Header.Set("X-Agent-Instance-Id", tc.claim)
			}
			if tc.aux {
				request.Header.Set("X-Agent-Type", "codex")
				request.Header.Set("X-Agent-Session", "synthetic-session")
				request.Header.Set("X-Client-Id", agentA)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != tc.status || forwarded != (tc.status == 204) {
				t.Fatalf("status=%d want=%d forwarded=%t", response.Code, tc.status, forwarded)
			}
			if tc.status == 204 && seenAgent != tc.identity {
				t.Fatalf("trusted agent=%q want=%q", seenAgent, tc.identity)
			}
			var envelope struct {
				Error struct {
					Code      string `json:"code"`
					RequestID string `json:"request_id"`
				} `json:"error"`
			}
			_ = json.Unmarshal(response.Body.Bytes(), &envelope)
			if envelope.Error.Code != tc.errorCode {
				t.Fatalf("code=%q want=%q", envelope.Error.Code, tc.errorCode)
			}
			if tc.denialBound != nil {
				var requestAgent, eventAgent, metadataAgent, keyID, status string
				var requestUnbound, eventUnbound bool
				err := db.QueryRow(ctx, `SELECT COALESCE(rl.agent_instance_id,''),COALESCE(se.agent_instance_id,''),rl.agent_instance_id IS NULL,se.agent_instance_id IS NULL,COALESCE(se.matched_summary->>'agent_instance_id',''),rl.client_id,rl.request_status FROM request_logs rl JOIN security_events se ON se.request_id=rl.request_id AND se.tenant_id=rl.tenant_id WHERE rl.request_id=$1 AND rl.tenant_id=$2 AND se.event_type='agent_identity_mismatch'`, envelope.Error.RequestID, tenant).Scan(&requestAgent, &eventAgent, &requestUnbound, &eventUnbound, &metadataAgent, &keyID, &status)
				if err != nil {
					t.Fatalf("native denial audit missing: %v", err)
				}
				if requestAgent != *tc.denialBound || eventAgent != *tc.denialBound || metadataAgent != *tc.denialBound || status != "agent_identity_mismatch" {
					t.Fatalf("audit changed credential attribution: request=%q event=%q metadata=%q status=%q", requestAgent, eventAgent, metadataAgent, status)
				}
				if *tc.denialBound == "" && (!requestUnbound || !eventUnbound || keyID != ns+"_legacy") {
					t.Fatal("unbound rejection adopted claim or lost key identity")
				}
			}
		})
	}
	for _, policyID := range []string{modelPolicy, mcpPolicy} {
		var hits, blocked int
		if err = db.QueryRow(ctx, `SELECT hit_count,blocked_count FROM integration_gateway_receipts WHERE instance_id=$1 AND policy_id=$2`, ns, policyID).Scan(&hits, &blocked); err != nil || hits != 1 || blocked != 1 {
			t.Fatalf("bound policy receipt hits=%d blocked=%d err=%v", hits, blocked, err)
		}
	}
}

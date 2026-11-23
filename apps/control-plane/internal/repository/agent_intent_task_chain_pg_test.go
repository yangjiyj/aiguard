package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
)

// TestIntentTaskCrossStepChainIntegration drives the real T16 server ledger
// against a fully migrated PostgreSQL: T13 authorize -> /decide proposal
// (step 1) -> accepted tool.post (terminal attach) -> /decide proposal that
// cites step 1's result (step 2) -> ResolveIntentTask history. It requires a
// disposable database with every deploy/migrations file applied.
func TestIntentTaskCrossStepChainIntegration(t *testing.T) {
	dsn := os.Getenv("AGENTGUARD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AGENTGUARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var ready bool
	if err := db.QueryRow(ctx, `SELECT to_regclass('agent_intent_task_steps') IS NOT NULL AND to_regclass('agent_authorization_requests') IS NOT NULL AND to_regclass('agent_events') IS NOT NULL`).Scan(&ready); err != nil || !ready {
		t.Skipf("database is not fully migrated (err=%v)", err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID := "t16-chain-" + suffix
	endpointID := "ep-t16-chain-" + suffix
	sessionID, promptID := "sess-"+suffix, "prompt-"+suffix
	defer cleanupT16ChainTenant(t, db, tenantID)

	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $1, 'enterprise', 'active', TRUE)`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO agent_endpoints(id,tenant_id,machine_id,hostname,os,arch,agent_product,token_hash)
		VALUES($1,$2,'m-'||$1,'h-'||$1,'linux','amd64','openclaw',repeat('e',64))`, endpointID, tenantID); err != nil {
		t.Fatal(err)
	}

	authRepo := NewAgentAuthorizationRepository(db)
	now := time.Now().UTC()
	grantExpiry := now.Add(2 * time.Hour)
	created, err := authRepo.RegisterPrincipal(ctx, tenantID, AgentAuthorizationPrincipalCreate{
		Name: "t16-chain", ExpiresAt: now.Add(3 * time.Hour), CreatedBy: "t16-test",
		Grants: []AgentAuthorizationGrant{
			{Action: "tool_execute", ResourceType: "tool", ResourceID: "web_fetch", ExpiresAt: grantExpiry, QuotaMax: 100, QuotaWindowSeconds: 3600},
			{Action: "network_connect", ResourceType: "domain", ResourceID: "allowed.example", ExpiresAt: grantExpiry, QuotaMax: 100, QuotaWindowSeconds: 3600},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := TrustedAgentPrincipal{ID: created.Principal.ID, TenantID: tenantID,
		CredentialHash: HashAgentToken(created.Credential), ExpiresAt: created.Principal.ExpiresAt}
	grantInputs := make([]AgentIntentTaskGrantInput, 0, len(created.Grants))
	for _, grant := range created.Grants {
		grantInputs = append(grantInputs, AgentIntentTaskGrantInput{GrantID: grant.ID})
	}
	task, err := authRepo.CreateIntentTask(ctx, tenantID, "t16-admin", AgentIntentTaskCreate{
		EndpointID: endpointID, PrincipalID: created.Principal.ID, Purpose: "fetch the approved example page",
		ExpiresAt: now.Add(time.Hour), Grants: grantInputs, AllowedSourceKinds: []string{"tool_result", "user_prompt"},
	})
	if err != nil {
		t.Fatal(err)
	}

	authorize := func(useID string, args map[string]any) []agentintent.AuthorizationFacet {
		t.Helper()
		argsHash, err := agentintent.ArgumentsHash(args)
		if err != nil {
			t.Fatal(err)
		}
		_, facets, err := agentintent.DeriveT16AuthorizationFacets("openclaw", "web_fetch", "network", "", args)
		if err != nil {
			t.Fatal(err)
		}
		for _, facet := range facets {
			key, err := agentintent.AuthorizationIdempotencyKey("openclaw", endpointID, sessionID, useID, argsHash, "web_fetch", facet)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authRepo.Authorize(ctx, principal, AgentAuthorizationRequest{
				Action: facet.Action, ResourceType: facet.ResourceType, ResourceID: facet.ResourceID, IdempotencyKey: key,
			}); err != nil {
				t.Fatalf("authorize %s: %v", facet.Action, err)
			}
		}
		return facets
	}
	logs := NewToolCallLogRepository(db)
	propose := func(useID string, args map[string]any, sources []agentintent.IntentTaskSourceClaim) string {
		t.Helper()
		log := &ToolCallLog{
			TenantID: tenantID, EndpointID: endpointID, SessionID: sessionID, PromptID: promptID,
			ToolCallID: useID, ToolName: "web_fetch", ToolType: "network", Parameters: args,
			AttributionMode: "endpoint_hook", AttributionConfidence: 1, Provenance: "agent_endpoint",
			EventKind: "invocation_proposed", Status: "audited", IntentTaskID: task.ID, IntentTaskSources: sources,
		}
		if err := logs.UpsertEndpointToolProposal(ctx, log); err != nil {
			t.Fatalf("proposal %s: %v", useID, err)
		}
		return log.ID
	}
	type stepRow struct {
		seq                              int64
		authState, lineage, outcome      string
		resultHash, sourceRefs, toolName string
	}
	readStep := func(logID string) stepRow {
		t.Helper()
		var row stepRow
		if err := db.QueryRow(ctx, `SELECT server_sequence,authorization_state,lineage_state,terminal_outcome,COALESCE(result_hash,''),source_refs::text,tool_name
			FROM agent_intent_task_steps WHERE tenant_id=$1 AND tool_call_log_id=$2`, tenantID, logID).Scan(
			&row.seq, &row.authState, &row.lineage, &row.outcome, &row.resultHash, &row.sourceRefs, &row.toolName); err != nil {
			t.Fatalf("read step for %s: %v", logID, err)
		}
		return row
	}

	// Step 1: in-scope fetch, fully T13-authorized.
	args1 := map[string]any{"url": "https://allowed.example/page"}
	authorize("use-1-"+suffix, args1)
	log1 := propose("use-1-"+suffix, args1, nil)
	step1 := readStep(log1)
	if step1.seq != 1 || step1.authState != "allowed" || step1.lineage != "server_task_record" || step1.outcome != "pending" {
		t.Fatalf("step1 = %+v, want seq=1 allowed server_task_record pending", step1)
	}

	// Accepted tool.post for step 1 must attach the terminal result.
	argsHash1, _ := agentintent.ArgumentsHash(args1)
	sum := sha256.Sum256([]byte("fetched page body " + suffix))
	resultHash := hex.EncodeToString(sum[:])
	event, _ := json.Marshal(map[string]any{
		"event_id": "evt-post-1-" + suffix, "event_type": "tool.post", "occurred_at": time.Now().UTC().Format(time.RFC3339Nano),
		"session_id": sessionID, "prompt_id": promptID, "tool_use_id": "use-1-" + suffix, "tool_call_id": "use-1-" + suffix,
		"tool_name": "web_fetch", "tool_type": "network", "arguments_hash": argsHash1,
		"result_metadata": map[string]any{"hash": "sha256:" + resultHash, "len": 18, "success": true},
	})
	if _, err := NewAgentEndpointRepository(db).AcceptEventBatch(ctx, tenantID, endpointID, AgentEventBatchRequest{
		SchemaVersion: "events.v1", EndpointID: endpointID, Events: []json.RawMessage{event},
	}); err != nil {
		t.Fatalf("accept tool.post for step 1: %v", err)
	}
	step1 = readStep(log1)
	if step1.outcome != "succeeded" || step1.resultHash != resultHash {
		t.Fatalf("step1 terminal = %+v, want succeeded with result hash", step1)
	}

	// Step 2: out-of-scope fetch that cites step 1's accepted result.
	args2 := map[string]any{"url": "https://evil.example/exfil"}
	sources := []agentintent.IntentTaskSourceClaim{{Kind: "tool_result", ToolUseID: "use-1-" + suffix, Hash: "sha256:" + resultHash}}
	facets2 := authorize("use-2-"+suffix, args2)
	log2 := propose("use-2-"+suffix, args2, sources)
	step2 := readStep(log2)
	if step2.seq != 2 || step2.authState != "scope_mismatch" || step2.lineage != "uncertain" {
		t.Fatalf("step2 = %+v, want seq=2 scope_mismatch uncertain", step2)
	}
	var refs []map[string]any
	if err := json.Unmarshal([]byte(step2.sourceRefs), &refs); err != nil || len(refs) != 1 {
		t.Fatalf("step2 source refs = %s (%v)", step2.sourceRefs, err)
	}
	if refs[0]["lineage_state"] != "accepted_result_hash_match" || fmt.Sprint(refs[0]["linked_step_sequence"]) != "1" {
		t.Fatalf("step2 source ref = %v, want accepted_result_hash_match linked to step 1", refs[0])
	}

	// The next pre-execution resolve sees both steps in server order.
	resolved, err := authRepo.ResolveIntentTask(ctx, tenantID, endpointID, "openclaw", task.ID, created.Principal.ID, facets2, sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.History) != 2 || resolved.HistoryTruncated {
		t.Fatalf("history = %+v truncated=%v, want 2 steps", resolved.History, resolved.HistoryTruncated)
	}
	if h := resolved.History[0]; h.Sequence != 1 || h.ResultState != "succeeded" || h.ResultHash != resultHash || h.AuthorizationState != "allowed" {
		t.Fatalf("history[0] = %+v", h)
	}
	if h := resolved.History[1]; h.Sequence != 2 || h.AuthorizationState != "scope_mismatch" || h.ResultState != "uncertain" {
		t.Fatalf("history[1] = %+v", h)
	}
	if resolved.FacetScopeState == "" || len(resolved.SourceLinks) != 1 || resolved.SourceLinks[0].LinkedStepSequence != 1 {
		t.Fatalf("facet scope=%q source links=%+v", resolved.FacetScopeState, resolved.SourceLinks)
	}
}

func cleanupT16ChainTenant(t *testing.T, db *pgxpool.Pool, tenantID string) {
	ctx := context.Background()
	rows, err := db.Query(ctx, `SELECT DISTINCT table_name FROM information_schema.columns
		WHERE table_schema=current_schema() AND column_name='tenant_id'`)
	if err != nil {
		t.Logf("cleanup list: %v", err)
		return
	}
	var tables []string
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil {
			tables = append(tables, name)
		}
	}
	rows.Close()
	// FK order is unknown here; repeat until no table still holds tenant rows.
	for pass := 0; pass < 4; pass++ {
		for _, name := range tables {
			_, _ = db.Exec(ctx, fmt.Sprintf(`DELETE FROM %q WHERE tenant_id::text=$1`, name), tenantID)
		}
	}
	_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID)
}

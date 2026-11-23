package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func newAgentGuardConfirmationTestRepo(t *testing.T) (*AgentGuardPolicyRepository, *pgxpool.Pool) {
	t.Helper()
	databaseURL := os.Getenv("AGENTGUARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("AGENTGUARD_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect admin pool: %v", err)
	}
	t.Cleanup(admin.Close)
	schema := fmt.Sprintf("agentguard_confirmation_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse database config: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect isolated pool: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		if _, dropErr := admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); dropErr != nil {
			t.Errorf("drop schema: %v", dropErr)
		}
	})
	_, err = db.Exec(ctx, `
		CREATE TABLE agentguard_confirmations (
			id VARCHAR(64) PRIMARY KEY,
			tenant_id VARCHAR(64) NOT NULL,
			request_id VARCHAR(128),
			trace_id VARCHAR(128) NOT NULL,
			tool_name VARCHAR(256) NOT NULL,
			raw_decision VARCHAR(16) NOT NULL,
			effective_decision VARCHAR(16) NOT NULL,
			status VARCHAR(16) NOT NULL DEFAULT 'pending',
			timeout_action VARCHAR(16) NOT NULL DEFAULT 'block',
			reason TEXT,
			evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
			expires_at TIMESTAMPTZ NOT NULL,
			resolved_by VARCHAR(64),
			resolved_at TIMESTAMPTZ,
			resolution_note TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			tool_call_id VARCHAR(64),
			tool_call_arguments TEXT,
			choice_index INTEGER NOT NULL DEFAULT 0,
			replay_status VARCHAR(16) NOT NULL DEFAULT 'pending',
			replayed_at TIMESTAMPTZ,
			replay_tool_log_id VARCHAR(64),
			source VARCHAR(16) NOT NULL DEFAULT '',
			requester_user_id VARCHAR(64), requester_client_id VARCHAR(64), arguments_hash VARCHAR(64),
			first_approved_by VARCHAR(64), first_approved_at TIMESTAMPTZ, consumed_request_id VARCHAR(128) -- W5 migration 901
		);
		CREATE UNIQUE INDEX idx_confirmation_id_tenant ON agentguard_confirmations(id, tenant_id);
		CREATE TABLE mcp_confirmation_executions (
			confirmation_id VARCHAR(64) PRIMARY KEY,
			tenant_id VARCHAR(64) NOT NULL,
			invocation_id VARCHAR(64),
			scope_key CHAR(64),
			canonical_request_hash CHAR(64),
			principal_hash CHAR(64),
			replay_context_ciphertext TEXT NOT NULL,
			replay_context_hash CHAR(64) NOT NULL,
			tool_id VARCHAR(128) NOT NULL DEFAULT '',
			supply_chain_revision VARCHAR(128) NOT NULL DEFAULT '',
			approved_schema_hash VARCHAR(128) NOT NULL DEFAULT '',
			server_route_hash VARCHAR(128) NOT NULL DEFAULT '',
			execution_status VARCHAR(16) NOT NULL DEFAULT 'pending',
			evidence_status VARCHAR(16) NOT NULL DEFAULT 'pending',
			attempt_id VARCHAR(64),
			started_at TIMESTAMPTZ,
			gateway_claimed_at TIMESTAMPTZ,
			finished_at TIMESTAMPTZ,
			audit_request_id VARCHAR(128),
			audit_error_code VARCHAR(64),
			tool_log_id VARCHAR(64),
			response_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
			error_code VARCHAR(64),
			result_ciphertext TEXT,
			result_hash CHAR(64),
			result_plaintext_bytes BIGINT,
			result_http_status INTEGER,
			result_media_type VARCHAR(128),
			result_rpc_id VARCHAR(512),
			result_protocol VARCHAR(64),
			result_session_id VARCHAR(512),
			result_expires_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			FOREIGN KEY (confirmation_id, tenant_id) REFERENCES agentguard_confirmations(id, tenant_id)
		);
		CREATE UNIQUE INDEX idx_mcp_execution_scope ON mcp_confirmation_executions(tenant_id,scope_key);
		CREATE UNIQUE INDEX idx_mcp_execution_attempt ON mcp_confirmation_executions(attempt_id) WHERE attempt_id IS NOT NULL
	`)
	if err != nil {
		t.Fatalf("create confirmation table: %v", err)
	}
	return NewAgentGuardPolicyRepository(db), db
}

func testAgentGuardConfirmation(id string, expiresAt time.Time) *AgentGuardConfirmation {
	return &AgentGuardConfirmation{
		ID: id, TenantID: "tenant-a", RequestID: "req-1", TraceID: "trace-1",
		ToolName: "Bash", RawDecision: "confirm", EffectiveDecision: "confirm",
		ExpiresAt: expiresAt, ToolCallID: "call-1", ToolCallArguments: `{"command":"echo safe"}`,
	}
}

func TestResolveConfirmationConcurrentSameDispositionAppliesOnce(t *testing.T) {
	repo, _ := newAgentGuardConfirmationTestRepo(t)
	ctx := context.Background()
	if err := repo.CreateConfirmation(ctx, testAgentGuardConfirmation("agcf_concurrent", time.Now().Add(time.Minute))); err != nil {
		t.Fatalf("create confirmation: %v", err)
	}
	type result struct {
		confirmation *AgentGuardConfirmation
		err          error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, actor := range []string{"user-a", "user-b"} {
		actor := actor
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			confirmation, err := repo.ResolveConfirmation(ctx, "tenant-a", "agcf_concurrent", "approved", actor, actor)
			results <- result{confirmation: confirmation, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	applied := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("resolve confirmation: %v", result.err)
		}
		if result.confirmation == nil || result.confirmation.Status != "approved" {
			t.Fatalf("confirmation=%#v, want approved", result.confirmation)
		}
		if result.confirmation.ResolutionApplied {
			applied++
		}
	}
	if applied != 1 {
		t.Fatalf("ResolutionApplied count=%d, want 1", applied)
	}
}

func TestResolveConfirmationIdempotentConflictAndExpiry(t *testing.T) {
	repo, _ := newAgentGuardConfirmationTestRepo(t)
	ctx := context.Background()
	if err := repo.CreateConfirmation(ctx, testAgentGuardConfirmation("agcf_state", time.Now().Add(time.Minute))); err != nil {
		t.Fatalf("create confirmation: %v", err)
	}
	first, err := repo.ResolveConfirmation(ctx, "tenant-a", "agcf_state", "approved", "user-a", "first")
	if err != nil || first == nil || !first.ResolutionApplied {
		t.Fatalf("fresh resolution=(%#v, %v), want applied", first, err)
	}
	repeated, err := repo.ResolveConfirmation(ctx, "tenant-a", "agcf_state", "approved", "user-b", "repeat")
	if err != nil || repeated == nil || repeated.ResolutionApplied || repeated.ResolvedBy != "user-a" {
		t.Fatalf("idempotent resolution=(%#v, %v)", repeated, err)
	}
	conflict, err := repo.ResolveConfirmation(ctx, "tenant-a", "agcf_state", "rejected", "user-b", "conflict")
	if !errors.Is(err, ErrAgentGuardConfirmationResolutionConflict) || conflict == nil || conflict.Status != "approved" {
		t.Fatalf("conflicting resolution=(%#v, %v)", conflict, err)
	}

	if err := repo.CreateConfirmation(ctx, testAgentGuardConfirmation("agcf_expired", time.Now().Add(-time.Minute))); err != nil {
		t.Fatalf("create expired confirmation: %v", err)
	}
	expired, err := repo.ResolveConfirmation(ctx, "tenant-a", "agcf_expired", "approved", "user-a", "late")
	if !errors.Is(err, ErrAgentGuardConfirmationExpired) || expired == nil || expired.Status != "expired" || expired.ResolutionApplied {
		t.Fatalf("expired resolution=(%#v, %v)", expired, err)
	}
}

func TestMarkConfirmationReplayedRequiresExistingApprovedRow(t *testing.T) {
	repo, _ := newAgentGuardConfirmationTestRepo(t)
	err := repo.MarkConfirmationReplayed(context.Background(), "tenant-a", "missing", "pending", "tc_missing")
	if !errors.Is(err, ErrAgentGuardConfirmationReplayStateNotUpdated) {
		t.Fatalf("mark missing confirmation error=%v", err)
	}
}

func TestMCPConfirmationContextIsCiphertextOnlyAndClaimedOnce(t *testing.T) {
	repo, db := newAgentGuardConfirmationTestRepo(t)
	ctx := context.Background()
	confirmation := testAgentGuardConfirmation("agcf_mcp_once", time.Now().Add(time.Minute))
	confirmation.Source = "mcp"
	confirmation.ToolName = "demo__write"
	confirmation.ToolCallArguments = `{"must_not":"persist"}`
	const ciphertext = "enc:v1:dGVzdC1jaXBoZXJ0ZXh0"
	const contextHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := repo.CreateMCPConfirmation(ctx, confirmation, ciphertext, contextHash); err != nil {
		t.Fatalf("create mcp confirmation: %v", err)
	}

	var persistedArgs, persistedCiphertext string
	if err := db.QueryRow(ctx, `
		SELECT COALESCE(c.tool_call_arguments, ''), e.replay_context_ciphertext
		FROM agentguard_confirmations c
		JOIN mcp_confirmation_executions e ON e.confirmation_id = c.id
		WHERE c.id = $1
	`, confirmation.ID).Scan(&persistedArgs, &persistedCiphertext); err != nil {
		t.Fatalf("read persisted context: %v", err)
	}
	if persistedArgs != "" {
		t.Fatalf("plaintext arguments persisted: %q", persistedArgs)
	}
	if persistedCiphertext != ciphertext {
		t.Fatalf("ciphertext=%q", persistedCiphertext)
	}

	if _, err := repo.ResolveConfirmation(ctx, "tenant-a", confirmation.ID, "approved", "admin", "ok"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	type claimResult struct {
		state   *MCPConfirmationExecution
		claimed bool
		err     error
	}
	start := make(chan struct{})
	results := make(chan claimResult, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			state, claimed, err := repo.ClaimMCPConfirmationExecution(ctx, "tenant-a", confirmation.ID)
			results <- claimResult{state: state, claimed: claimed, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	claimedCount := 0
	var attemptID string
	for result := range results {
		if result.err != nil {
			t.Fatalf("claim: %v", result.err)
		}
		if result.state == nil || result.state.ExecutionStatus != "executing" {
			t.Fatalf("state=%#v", result.state)
		}
		if result.claimed {
			claimedCount++
			attemptID = result.state.AttemptID
		}
	}
	if claimedCount != 1 || attemptID == "" {
		t.Fatalf("claimed=%d attempt=%q", claimedCount, attemptID)
	}

	if err := repo.MarkMCPConfirmationUnknown(ctx, "tenant-a", confirmation.ID, attemptID, "gateway_response_unknown"); err != nil {
		t.Fatalf("mark unknown: %v", err)
	}
	state, claimed, err := repo.ClaimMCPConfirmationExecution(ctx, "tenant-a", confirmation.ID)
	if err != nil || claimed || state == nil || state.ExecutionStatus != "unknown" {
		t.Fatalf("second claim=(%#v,%v,%v)", state, claimed, err)
	}
}

func TestMCPConfirmationDeduplicatesScopeAndRejectsDifferentRequestHash(t *testing.T) {
	repo, db := newAgentGuardConfirmationTestRepo(t)
	ctx := context.Background()
	identity := MCPConfirmationIdentity{
		ScopeKey: strings.Repeat("1", 64), CanonicalRequestHash: strings.Repeat("2", 64),
		PrincipalHash: strings.Repeat("3", 64), ToolID: "tool-a",
		SupplyChainRevision: "revision-a", ApprovedSchemaHash: strings.Repeat("4", 64),
		ServerRouteHash: strings.Repeat("5", 64),
	}
	newConfirmation := func() *AgentGuardConfirmation {
		return &AgentGuardConfirmation{
			TenantID: "tenant-a", RequestID: "req", TraceID: "trace", ToolName: "demo__write",
			RawDecision: "confirm", EffectiveDecision: "confirm", Source: "mcp",
			ExpiresAt: time.Now().Add(time.Minute), ToolCallID: "number:9",
		}
	}
	first, created, err := repo.CreateMCPConfirmationDeduplicated(ctx, newConfirmation(), identity, "enc:v1:first", strings.Repeat("a", 64))
	if err != nil || !created || first == nil {
		t.Fatalf("first=(%#v,%v,%v)", first, created, err)
	}
	second, created, err := repo.CreateMCPConfirmationDeduplicated(ctx, newConfirmation(), identity, "enc:v1:second", strings.Repeat("b", 64))
	if err != nil || created || second == nil || second.ConfirmationID != first.ConfirmationID || second.InvocationID != first.InvocationID {
		t.Fatalf("duplicate=(%#v,%v,%v), first=%#v", second, created, err, first)
	}
	conflictIdentity := identity
	conflictIdentity.CanonicalRequestHash = strings.Repeat("6", 64)
	conflict, created, err := repo.CreateMCPConfirmationDeduplicated(ctx, newConfirmation(), conflictIdentity, "enc:v1:third", strings.Repeat("c", 64))
	if !errors.Is(err, ErrMCPReplayConflict) || created || conflict == nil || conflict.ConfirmationID != first.ConfirmationID {
		t.Fatalf("conflict=(%#v,%v,%v)", conflict, created, err)
	}
	var confirmations, executions int
	_ = db.QueryRow(ctx, `SELECT count(*) FROM agentguard_confirmations`).Scan(&confirmations)
	_ = db.QueryRow(ctx, `SELECT count(*) FROM mcp_confirmation_executions`).Scan(&executions)
	if confirmations != 1 || executions != 1 {
		t.Fatalf("confirmations=%d executions=%d", confirmations, executions)
	}
	if len(first.ConfirmationID) < 40 || len(first.InvocationID) < 40 {
		t.Fatalf("weak identifiers confirmation=%q invocation=%q", first.ConfirmationID, first.InvocationID)
	}
}
func TestMCPStaleExecutingConvergesToUnknownWithoutRetry(t *testing.T) {
	repo, db := newAgentGuardConfirmationTestRepo(t)
	ctx := context.Background()
	confirmation := testAgentGuardConfirmation("agcf_mcp_stale", time.Now().Add(time.Minute))
	confirmation.Source = "mcp"
	confirmation.ToolName = "demo__write"
	if err := repo.CreateMCPConfirmation(ctx, confirmation, "enc:v1:stale", strings.Repeat("a", 64)); err != nil {
		t.Fatalf("create MCP confirmation: %v", err)
	}
	if _, err := repo.ResolveConfirmation(ctx, "tenant-a", confirmation.ID, "approved", "admin", "ok"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	claimedState, claimed, err := repo.ClaimMCPConfirmationExecution(ctx, "tenant-a", confirmation.ID)
	if err != nil || !claimed || claimedState == nil {
		t.Fatalf("claim=(%#v,%v,%v)", claimedState, claimed, err)
	}
	_, err = db.Exec(ctx, `
		UPDATE mcp_confirmation_executions
		SET started_at=NOW()-INTERVAL '31 seconds',
		    gateway_claimed_at=NOW()-INTERVAL '31 seconds',
		    evidence_status='pending'
		WHERE confirmation_id=$1
	`, confirmation.ID)
	if err != nil {
		t.Fatalf("age executing row: %v", err)
	}

	state, err := repo.GetMCPConfirmationExecution(ctx, "tenant-a", confirmation.ID)
	if err != nil || state == nil || state.ExecutionStatus != "unknown" ||
		state.EvidenceStatus != "failed" || state.ErrorCode != "gateway_execution_stale" {
		t.Fatalf("converged state=%#v err=%v", state, err)
	}
	if forwarded, _ := state.ResponseSummary["execution_forwarded"].(bool); !forwarded {
		t.Fatalf("stale gateway claim must preserve uncertain forwarding fact: %#v", state.ResponseSummary)
	}
	again, claimedAgain, err := repo.ClaimMCPConfirmationExecution(ctx, "tenant-a", confirmation.ID)
	if err != nil || claimedAgain || again == nil || again.ExecutionStatus != "unknown" {
		t.Fatalf("retry claim=(%#v,%v,%v)", again, claimedAgain, err)
	}
}

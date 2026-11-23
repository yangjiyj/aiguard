package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPGMCPConfirmationExecutionStoreSanitizesDestructiveSummary(t *testing.T) {
	dsn := os.Getenv("MCP_CONFIRMATION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("MCP_CONFIRMATION_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)

	schema := "mcp_confirmation_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop test schema %s: %v", schema, err)
		}
	})

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(ctx, `
		CREATE TABLE agentguard_confirmations (
			id text NOT NULL,
			tenant_id text NOT NULL,
			status text NOT NULL,
			tool_call_id text,
			expires_at timestamptz NOT NULL,
			PRIMARY KEY (id, tenant_id)
		);
		CREATE TABLE mcp_confirmation_executions (
			confirmation_id text NOT NULL,
			invocation_id text,
			tenant_id text NOT NULL,
			execution_status text NOT NULL,
			evidence_status text NOT NULL,
			attempt_id text,
			replay_context_ciphertext text,
			replay_context_hash text,
			scope_key text,
			canonical_request_hash text,
			principal_hash text,
			tool_id text,
			supply_chain_revision text,
			approved_schema_hash text,
			server_route_hash text,
			audit_request_id text,
			audit_error_code text,
			tool_log_id text,
			response_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
			error_code text,
			result_ciphertext text,
			result_hash text,
			result_plaintext_bytes bigint,
			result_http_status integer,
			result_media_type text,
			result_rpc_id text,
			result_protocol text,
			result_session_id text,
			result_expires_at timestamptz,
			gateway_claimed_at timestamptz,
			finished_at timestamptz,
			updated_at timestamptz
		)
	`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `
		INSERT INTO agentguard_confirmations
			(id, tenant_id, status, tool_call_id, expires_at)
		VALUES ('agcf-pg', 'tenant-a', 'approved', 'number:9', NOW() + INTERVAL '1 hour');
		INSERT INTO mcp_confirmation_executions (
			confirmation_id, invocation_id, tenant_id, execution_status, evidence_status,
			attempt_id, replay_context_ciphertext, replay_context_hash, tool_id,
			supply_chain_revision, approved_schema_hash, server_route_hash, gateway_claimed_at
		) VALUES (
			'agcf-pg', 'invocation-pg', 'tenant-a', 'executing', 'pending',
			'attempt-pg', 'enc:v1:test', 'hash', 'tool-a',
			'revision-a', 'schema-hash', 'route-hash', NOW()
		)
	`)
	if err != nil {
		t.Fatal(err)
	}

	sensitive := "sensitive-confirmation-result"
	store := &pgMCPConfirmationExecutionStore{db: db}
	record, err := store.CompleteGatewayExecution(ctx, "tenant-a", "agcf-pg", "attempt-pg", mcpExecutionCompletion{
		Status:         "executed",
		EvidenceStatus: "complete",
		Destructive:    true,
		Summary: map[string]any{
			"outcome": "executed", "execution_forwarded": true, "result_observed": true,
			"result_hash": "hash-only", "result_excerpt": sensitive,
			"raw_body": sensitive, "token": "secret-token",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertMCPDestructiveSummarySanitized(t, record.ResponseSummary, sensitive)

	var raw []byte
	if err := db.QueryRow(ctx, `
		SELECT response_summary FROM mcp_confirmation_executions
		WHERE tenant_id='tenant-a' AND confirmation_id='agcf-pg'
	`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var persisted map[string]any
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	assertMCPDestructiveSummarySanitized(t, persisted, sensitive)
}

func assertMCPDestructiveSummarySanitized(t *testing.T, summary map[string]any, sensitive string) {
	t.Helper()
	raw, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{sensitive, "result_excerpt", "raw_body", "secret-token"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("destructive response summary leaked %q: %s", forbidden, raw)
		}
	}
	if summary["result_hash"] != "hash-only" || summary["execution_forwarded"] != true {
		t.Fatalf("safe metadata lost: %s", fmt.Sprint(summary))
	}
}

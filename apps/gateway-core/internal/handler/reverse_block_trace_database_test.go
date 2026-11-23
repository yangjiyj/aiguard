package handler

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReversePersistedBlockContainsExactEventIDDatabase(t *testing.T) {
	dsn := os.Getenv("PROXY_INSPECTION_TEST_DSN")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL: PROXY_INSPECTION_TEST_DSN")
	}
	ctx := withBlockLedger(context.Background())
	root, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	schema := "reverse_block_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := root.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer root.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(ctx, `CREATE TABLE security_events(id text PRIMARY KEY,request_id text,tenant_id text,project_id text,event_type text,severity text,rule_id text,action_taken text,matched_summary jsonb,evidence_ref text,created_at timestamptz,principal_key text,effective_severity text,class_key text)`); err != nil {
		t.Fatal(err)
	}
	recorder := &reverseProxyDBAuditRecorder{db: db}
	record := reverseProxyAuditRecord{RequestID: "request-reverse-db", TenantID: "tenant-reverse-db", Status: "blocked"}
	recorder.WriteReverseProxySecurityEvent(ctx, record, "output", "security_blocked", []SecurityFinding{passwordRuleFinding})
	block := requestBlockAttribution(ctx)
	if block == nil {
		t.Fatal("successful reverse event write left no trace")
	}
	var eventID, requestID string
	var summaryRaw []byte
	if err := db.QueryRow(ctx, "SELECT id,request_id,matched_summary FROM security_events WHERE id=$1 AND tenant_id=$2", block.BlockID, record.TenantID).Scan(&eventID, &requestID, &summaryRaw); err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Block blockAttribution `json:"block"`
	}
	if err := json.Unmarshal(summaryRaw, &summary); err != nil {
		t.Fatal(err)
	}
	notice := (&ReverseProxyHandler{}).reverseBlockNotice(ctx, requestID, "output", []SecurityFinding{passwordRuleFinding})
	if eventID != block.BlockID || summary.Block.BlockID != eventID || summary.Block.RequestID != requestID || notice.Attribution.BlockID != eventID || !strings.Contains(notice.Text, eventID) {
		t.Fatalf("reverse notice advertises an empty/wrong persisted ID: event=%s summary=%s notice=%s", eventID, summaryRaw, notice.Text)
	}
}

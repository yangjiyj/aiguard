package alert

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"testing"
)

func TestGroupBackfillCanLinkLegacyGroupOnlyInsideKnownScope(t *testing.T) {
	dsn := os.Getenv("ALERT_CLOSURE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ALERT_CLOSURE_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "backfill_scope_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	q := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+q); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec(ctx, "DROP SCHEMA "+q+" CASCADE"); admin.Close() })
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 2
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if _, err = db.Exec(ctx, `CREATE TABLE alert_groups (LIKE public.alert_groups INCLUDING ALL)`); err != nil {
		t.Fatal(err)
	}
	ev := &repository.SecurityEvent{TenantID: "tenant-a", ProjectID: "project-a", EventType: "security_check", MatchedSummary: map[string]any{"stage": "input", "findings": []any{map[string]any{"type": "custom", "rule_id": "rule"}}}}
	// The historic signature predates project/stage scoping.
	// Derive the original key directly from the same fingerprint primitives.
	parts := []string{leakFingerprint(ev.MatchedSummary["findings"].([]any)[0].(map[string]any))}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	legacy := hex.EncodeToString(sum[:])[:16]
	if _, err = db.Exec(ctx, `INSERT INTO alert_groups(id,tenant_id,project_id,group_key,status,severity,alert_type,title,first_seen_at,last_seen_at,created_at,updated_at,stage) VALUES('old','tenant-a','project-a',$1,'open','high','security_event','synthetic',NOW(),NOW(),NOW(),NOW(),'input')`, legacy); err != nil {
		t.Fatal(err)
	}
	g := NewGroupBackfill(db, nil, nil)
	id, err := g.lookupEventGroup(ctx, ev)
	if err != nil || id != "old" {
		t.Fatalf("legacy scoped evidence lookup failed: %s %v", id, err)
	}
	ev.ProjectID = "project-b"
	if id, err = g.lookupEventGroup(ctx, ev); err != nil || id != "" {
		t.Fatalf("legacy group crosses project: %s %v", id, err)
	}
	ev.ProjectID = "project-a"
	ev.MatchedSummary["stage"] = "output"
	if id, err = g.lookupEventGroup(ctx, ev); err != nil || id != "" {
		t.Fatalf("legacy group crosses stage: %s %v", id, err)
	}
	ev.MatchedSummary["stage"] = "input"
	ev.TenantID = "tenant-b"
	if id, err = g.lookupEventGroup(ctx, ev); err != nil || id != "" {
		t.Fatalf("legacy group crosses tenant: %s %v", id, err)
	}

}

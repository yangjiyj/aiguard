package repository

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEvidenceTimelineOutcomeTenantWindowAndAudit(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("integration database not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	id := fmt.Sprintf("outcome_%d", time.Now().UnixNano())
	other := id + "_other"
	t.Cleanup(func() {
		for _, table := range []string{"security_events", "request_logs", "projects", "tenants"} {
			if _, err := db.Exec(ctx, "DELETE FROM "+table+" WHERE "+map[string]string{"tenants": "id", "projects": "tenant_id", "request_logs": "tenant_id", "security_events": "tenant_id"}[table]+"=ANY($1)", []string{id, other}); err != nil {
				t.Error(err)
			}
		}
	})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range []string{id, other} {
		exec(`INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',true)`, tenant)
		exec(`INSERT INTO projects(id,tenant_id,name) VALUES($1,$1,$1)`, tenant)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for i, status := range []string{"blocked", "target_resolution_failed", "egress_denied", "in_progress"} {
		rid := fmt.Sprintf("%s_%d", id, i)
		exec(`INSERT INTO request_logs(id,request_id,tenant_id,request_status,upstream_status_code,created_at,environment_scope) VALUES($1,$1,$2,$3,403,$4,'customer')`, rid, id, status, now)
	}
	rid := id + "_0"
	exec(`INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,created_at) VALUES($1,$2,$3,$3,'security_check_failed','low','audit',$4)`, id+"_audit", rid, id, now)
	exec(`INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,created_at) VALUES($1,$2,$3,$3,'security_check_failed','low','block',$4)`, other+"_audit", rid, other, now)
	repo := NewRequestLogRepository(db)
	ids := []string{rid, id + "_1", id + "_2", id + "_3"}
	events, err := repo.ListEvidenceTimelineScoped(ctx, id, ids, now.Add(-time.Minute), now.Add(time.Minute), "customer")
	if err != nil {
		t.Fatal(err)
	}
	outcomes, audits, pending := 0, 0, 0
	for _, e := range events {
		if strings.Contains(e.ID, other) {
			t.Fatal("cross tenant evidence")
		}
		if e.Type == "request_outcome" {
			outcomes++
		}
		if e.Type == "security_event" {
			audits++
			if e.Status != "audit" || !strings.Contains(e.Detail, "仅作审计") {
				t.Fatalf("%+v", e)
			}
		}
		if e.Type == "model_calls" && e.Status == "in_progress" {
			pending = e.Count
		}
	}
	if outcomes != 3 || audits != 1 || pending != 1 {
		t.Fatalf("outcomes=%d audits=%d pending=%d: %+v", outcomes, audits, pending, events)
	}
	for _, scope := range []string{"home", "customer"} {
		start, end := now.Add(time.Hour), now.Add(2*time.Hour)
		if scope == "home" {
			start, end = now.Add(-time.Minute), now.Add(time.Minute)
		}
		events, err = repo.ListEvidenceTimelineScoped(ctx, id, ids, start, end, scope)
		if err != nil || len(events) != 0 {
			t.Fatalf("scope/window leak: %v %+v", err, events)
		}
	}
}

package repository

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 单元：buildSecurityEventsWhere 带 ProjectIDs 时补 se.project_id = ANY($n) 子句（index-backed）。
func TestBuildSecurityEventsWhereProjectIDs(t *testing.T) {
	_, where, args := buildSecurityEventsWhere("tenant_default", SecurityEventFilter{
		ProjectIDs: []string{"p1", "p2"},
	})
	if !strings.Contains(where, "se.project_id = ANY($2)") {
		t.Fatalf("where missing project_id ANY clause: %q", where)
	}
	if len(args) != 2 {
		t.Fatalf("args = %v, want [tenant, projectIDs]", args)
	}
	got, ok := args[1].([]string)
	if !ok || len(got) != 2 || got[0] != "p1" || got[1] != "p2" {
		t.Fatalf("args[1] = %#v, want []string{p1,p2}", args[1])
	}
}

// 空 ProjectIDs 不产生子句（回归：无参数即原行为）。
func TestBuildSecurityEventsWhereNoProjectIDs(t *testing.T) {
	_, where, args := buildSecurityEventsWhere("tenant_default", SecurityEventFilter{})
	if strings.Contains(where, "project_id") {
		t.Fatalf("no project_ids should not emit project clause: %q", where)
	}
	if len(args) != 1 {
		t.Fatalf("args = %v, want [tenant] only", args)
	}
}

// 集成（需 CONTENT_LOGS_TEST_DATABASE_URL）：ListFiltered 按 project_ids 服务端收窄。
func TestListFilteredProjectScope(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	sfx := time.Now().UnixNano()
	tenantID := fmt.Sprintf("tenant_se_proj_%d", sfx)
	userID := fmt.Sprintf("user_se_proj_%d", sfx)
	p1 := fmt.Sprintf("proj_se_a_%d", sfx)
	p2 := fmt.Sprintf("proj_se_b_%d", sfx)
	t.Cleanup(func() {
		for _, stmt := range []string{
			"DELETE FROM security_events WHERE tenant_id = $1",
			"DELETE FROM request_logs WHERE tenant_id = $1",
			"DELETE FROM projects WHERE tenant_id = $1",
			"DELETE FROM users WHERE tenant_id = $1",
			"DELETE FROM tenants WHERE id = $1",
		} {
			if _, err := db.Exec(ctx, stmt, tenantID); err != nil {
				t.Logf("cleanup %q: %v", stmt, err)
			}
		}
		db.Close()
	})
	must := func(sql string, args ...interface{}) {
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("exec %q: %v", sql, err)
		}
	}
	must(`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$2,'enterprise','active',TRUE)`, tenantID, tenantID)
	must(`INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1,$2,$3,'developer','active')`, userID, tenantID, userID)
	must(`INSERT INTO projects (id, tenant_id, name, owner_user_id, status) VALUES ($1,$2,$3,$4,'active')`, p1, tenantID, p1, userID)
	must(`INSERT INTO projects (id, tenant_id, name, owner_user_id, status) VALUES ($1,$2,$3,$4,'active')`, p2, tenantID, p2, userID)

	now := time.Now().UTC()
	insEvent := func(project string) {
		nanos := time.Now().UnixNano()
		rid := fmt.Sprintf("rl_%d", nanos)
		must(`INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status, created_at)
			VALUES ($1,$1,$2,$3,$4,'anthropic_messages','success',$5)`, rid, tenantID, project, userID, now)
		must(`INSERT INTO security_events (id, request_id, tenant_id, project_id, user_id, event_type, severity, action_taken, matched_summary, created_at)
			VALUES ($1,$2,$3,$4,$5,'security_check','high','security_audit_only','{}'::jsonb,$6)`,
			fmt.Sprintf("se_%d", nanos), rid, tenantID, project, userID, now)
	}
	insEvent(p1)
	insEvent(p1)
	insEvent(p2)

	repo := NewSecurityEventRepository(db)
	// 全租户（无 project 过滤）→ 3
	_, total, err := repo.ListFiltered(ctx, tenantID, SecurityEventFilter{}, 100, 0)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if total != 3 {
		t.Fatalf("full-tenant total = %d, want 3", total)
	}
	// project_ids=P1 → 2
	events, total, err := repo.ListFiltered(ctx, tenantID, SecurityEventFilter{ProjectIDs: []string{p1}}, 100, 0)
	if err != nil {
		t.Fatalf("list scoped: %v", err)
	}
	if total != 2 {
		t.Fatalf("scoped total = %d, want 2", total)
	}
	for _, e := range events {
		if e.ProjectID != p1 {
			t.Fatalf("scoped result leaked project %q", e.ProjectID)
		}
	}
}

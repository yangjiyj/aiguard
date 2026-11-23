package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestForwardProxyUndetectedSummaryRespectsInspectionAndTenantScope(t *testing.T) {
	databaseURL := os.Getenv("C_WHITELIST_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("C_WHITELIST_TEST_DATABASE_URL is required; use disposable PostgreSQL")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UnixNano()
	tenant := fmt.Sprintf("tenant_undetected_%d", suffix)
	other := tenant + "_other"
	t.Cleanup(func() {
		for _, id := range []string{tenant, other} {
			_, _ = db.Exec(ctx, "DELETE FROM request_logs WHERE tenant_id=$1", id)
			_, _ = db.Exec(ctx, "DELETE FROM tenants WHERE id=$1", id)
		}
		db.Close()
	})
	for _, id := range []string{tenant, other} {
		if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',true)`, id); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	for i, input := range []struct {
		tenant, mode, method, status string
		inspected                    any
		created                      time.Time
	}{
		{tenant, "forward", "CONNECT", "success", false, now},
		{tenant, "forward", "CONNECT", "success", true, now},
		{tenant, "forward", "POST", "success", false, now},
		{tenant, "reverse", "CONNECT", "success", false, now},
		{other, "forward", "CONNECT", "success", false, now},
		{tenant, "forward", "CONNECT", "success", false, now.Add(-48 * time.Hour)},
		{tenant, "forward", "CONNECT", "blocked", false, now},
		{tenant, "forward", "CONNECT", "pending", false, now},
		{tenant, "forward", "CONNECT", "success", nil, now},
	} {
		requestID := fmt.Sprintf("undetected_%d_%d", suffix, i)
		if _, err := db.Exec(ctx, `INSERT INTO request_logs(
			id,request_id,tenant_id,endpoint_type,request_status,proxy_mode,proxy_target_host,
			proxy_target_path,proxy_method,proxy_access_type,proxy_access_type_resolved,proxy_tls_inspected,
			risk_state,environment_scope,created_at
		) VALUES($1,$1,$2,'proxy',$7,$3,'api.example.test','/v1/chat/completions',$4,'llm','llm',$5,'normal','customer',$6)`,
			requestID, input.tenant, input.mode, input.method, input.inspected, input.created, input.status); err != nil {
			t.Fatal(err)
		}
	}
	repo := NewRequestLogRepository(db)
	for _, direction := range []string{"", "forward", "reverse"} {
		filter := ForwardProxyAccessFilter{AccessType: "all", Direction: direction, EnvironmentScope: "customer", StartTime: now.Add(-time.Hour), EndTime: now.Add(time.Hour)}
		full, err := repo.GetForwardProxyAccessSummary(ctx, tenant, filter)
		if err != nil {
			t.Fatal(err)
		}
		counts, err := repo.GetForwardProxyAccessCounts(ctx, tenant, filter)
		if err != nil {
			t.Fatal(err)
		}
		want := 1
		if direction == "reverse" {
			want = 0
		}
		for name, summary := range map[string]ForwardProxyAccessSummary{"full": full, "counts": counts} {
			if summary.UndetectedCount != want {
				t.Fatalf("%s direction=%q undetected count=%d want=%d summary=%+v", name, direction, summary.UndetectedCount, want, summary)
			}
		}
	}
}

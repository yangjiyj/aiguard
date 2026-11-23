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

// 命中原文超过 4096 字时数据面截断并写 raw_evidence_truncated；告警读接口随原文一起返回这个标记，
// 不带原文的读法（没请求或没权限）不返回。
func TestAlertOccurrenceCarriesRawTruncationWithRawOnly(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ALERT_CASES_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("ALERT_CASES_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	suffix := fmt.Sprint(time.Now().UnixNano())
	tenant, project, request, event := "trunc_t_"+suffix, "trunc_p_"+suffix, "trunc_r_"+suffix, "trunc_e_"+suffix
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM security_events WHERE tenant_id=$1`, `DELETE FROM request_logs WHERE tenant_id=$1`,
			`DELETE FROM alert_case_dirty WHERE tenant_id=$1`, `DELETE FROM projects WHERE tenant_id=$1`, `DELETE FROM tenants WHERE id=$1`} {
			_, _ = db.Exec(context.Background(), q, tenant)
		}
	})
	for _, step := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',TRUE)`, []any{tenant}},
		{`INSERT INTO projects(id,tenant_id,name) VALUES($1,$2,'应用')`, []any{project, tenant}},
		{`INSERT INTO request_logs(id,request_id,tenant_id,project_id,created_at) VALUES($1,$1,$2,$3,now())`, []any{request, tenant, project}},
		{`INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary) VALUES($1,$2,$3,$4,'security_check','high','flag',
 '{"findings":[{"type":"secret","category":"api_key","severity":"high","rule_id":"r","matched_location":"content[0:4096]","redacted_evidence":"sk-***","raw_evidence":"sk-很长的原文","raw_evidence_truncated":true}]}')`, []any{event, request, tenant, project}},
	} {
		if _, err := db.Exec(ctx, step.query, step.args...); err != nil {
			t.Fatal(err)
		}
	}
	repo := NewAlertOccurrenceRepository(db)
	for _, raw := range []bool{true, false} {
		page, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: tenant, EventID: event, IncludeRaw: raw, CanReadEvidence: true, IncludeSuppressed: true, IncludeDevTraffic: true, Limit: 10})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("list: %v %+v", err, page)
		}
		item := page.Items[0]
		if item.RawEvidenceTruncated != raw || (item.RawEvidence != "") != raw {
			t.Fatalf("include_raw=%v: raw=%q truncated=%v", raw, item.RawEvidence, item.RawEvidenceTruncated)
		}
	}
}

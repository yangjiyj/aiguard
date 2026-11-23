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

// 事件原文总量超限时数据面不存这条命中的原文，只标 raw_evidence_omitted（哈希照存，可从留存回捞）。
// 告警接口要把这个标记带出来（不是敏感信息，各角色都给），回捞不到原文时控制台据此提示到内容留存查看。
// 实时查询与物化读法给的一样。
func TestAlertOccurrencesExposeRawEvidenceOmitted(t *testing.T) {
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
	tenant := fmt.Sprintf("t_raw_omitted_%d", time.Now().UnixNano())
	defer func() {
		for _, sql := range []string{`DELETE FROM security_events WHERE tenant_id=$1`, `DELETE FROM request_logs WHERE tenant_id=$1`,
			`DELETE FROM projects WHERE tenant_id=$1`, `DELETE FROM alert_case_dirty WHERE tenant_id=$1`, `DELETE FROM alert_case_members WHERE tenant_id=$1`,
			`DELETE FROM alert_cases WHERE tenant_id=$1`, `DELETE FROM alert_case_backfill WHERE tenant_id=$1`, `DELETE FROM tenants WHERE id=$1`} {
			_, _ = db.Exec(context.Background(), sql, tenant)
		}
	}()
	for _, sql := range []string{
		`INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',TRUE)`,
		`INSERT INTO projects(id,tenant_id,name) VALUES($1||'_p',$1,'应用')`,
		`INSERT INTO request_logs(id,request_id,tenant_id,project_id,environment_scope,created_at) VALUES($1||'_r',$1||'_r',$1,$1||'_p','customer',now()-interval '1 minute')`,
		`INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary,created_at)
 VALUES($1||'_e',$1||'_r',$1,$1||'_p','security_check','high','flag',jsonb_build_object('findings',jsonb_build_array(
   jsonb_build_object('type','secret','category','api_key','severity','high','rule_id','r1','rule_name','接口密钥','message_index',0,
     'matched_location','content[0:10]','raw_evidence_sha256',repeat('a',64),'evidence_identity_sha256',repeat('b',64),'raw_evidence_omitted',true),
   jsonb_build_object('type','pii','category','email','severity','medium','rule_id','r2','rule_name','邮箱','message_index',0,
     'matched_location','content[20:30]','raw_evidence','a@example.invalid','evidence_identity_sha256',repeat('c',64)))),now()-interval '1 minute')`,
	} {
		if _, err := db.Exec(ctx, sql, tenant); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name string, repo *AlertOccurrenceRepository) {
		t.Helper()
		page, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: tenant, Grouping: "hits", IncludeSuppressed: true, IncludeDevTraffic: true, Limit: 10})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		omitted := map[string]bool{}
		for _, item := range page.Items {
			omitted[item.Category] = item.RawEvidenceOmitted
		}
		if len(omitted) != 2 || !omitted["api_key"] || omitted["email"] {
			t.Fatalf("%s: raw_evidence_omitted per category = %v", name, omitted)
		}
	}
	check("live", &AlertOccurrenceRepository{db: db, caseStoreDisabled: true})
	stored := NewAlertOccurrenceRepository(db)
	stored.caseStoreDisabled = false
	if err := stored.PrepareAlertCases(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	check("materialized", stored)
}

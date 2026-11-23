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

// 读之前的限时消化先处理最新登记的条目：有积压时，管理员刚做的处置（最后登记）也能在下一次读里看到，
// 积压里较早的条目留给后台按先后消化。事件不超过 200 条的告警组、凭据条目读前也顺带消化；
// 更大的告警组、凭据牵动上千条事件，读前不消化，留给后台。
func TestAlertCaseReadDrainTakesNewestEntriesFirst(t *testing.T) {
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
	tenant := fmt.Sprintf("t_read_drain_%d", time.Now().UnixNano())
	defer func() {
		for _, sql := range []string{`DELETE FROM security_events WHERE tenant_id=$1`, `DELETE FROM request_logs WHERE tenant_id=$1`,
			`DELETE FROM projects WHERE tenant_id=$1`, `DELETE FROM alert_case_dirty WHERE tenant_id=$1`, `DELETE FROM tenants WHERE id=$1`} {
			_, _ = db.Exec(context.Background(), sql, tenant)
		}
	}()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',TRUE)`, tenant)
	exec(`INSERT INTO projects(id,tenant_id,name) VALUES($1||'_p',$1,'应用')`, tenant)
	exec(`INSERT INTO request_logs(id,request_id,tenant_id,project_id,environment_scope,created_at) VALUES($1||'_r',$1||'_r',$1,$1||'_p','customer',now())`, tenant)
	// 大告警组：201 条事件。
	exec(`INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary,alert_group_id)
 SELECT $1||'_big_'||g,$1||'_r',$1,$1||'_p','security_check','low','flag','{}'::jsonb,'big_group' FROM generate_series(1,201) g`, tenant)
	exec(`DELETE FROM alert_case_dirty WHERE tenant_id=$1`, tenant)
	for i := 0; i < 5; i++ {
		exec(`INSERT INTO alert_case_dirty(tenant_id,kind,ref) VALUES ($1,'event',$2)`, tenant, fmt.Sprintf("missing_event_%d", i))
	}
	exec(`INSERT INTO alert_case_dirty(tenant_id,kind,ref) VALUES ($1,'group','big_group'),($1,'key','small_key'),($1,'group','small_group')`, tenant)
	remaining := func() []string {
		rows, err := db.Query(ctx, `SELECT ref FROM alert_case_dirty WHERE tenant_id=$1 ORDER BY id`, tenant)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		refs := []string{}
		for rows.Next() {
			var ref string
			_ = rows.Scan(&ref)
			refs = append(refs, ref)
		}
		return refs
	}
	if n, err := drainAlertCases(ctx, db, false, tenant, 3, alertCaseDrainBeforeRead); err != nil || n != 3 {
		t.Fatalf("read-side drain n=%d err=%v", n, err)
	}
	if got := strings.Join(remaining(), ","); got != "missing_event_0,missing_event_1,missing_event_2,missing_event_3,big_group" {
		t.Fatalf("read-side drain must take the newest narrow and small entries first, left %s", got)
	}
	if n, err := drainAlertCases(ctx, db, false, tenant, 2, alertCaseDrainMode{}); err != nil || n != 2 {
		t.Fatalf("background drain n=%d err=%v", n, err)
	}
	if got := strings.Join(remaining(), ","); got != "missing_event_2,missing_event_3,big_group" {
		t.Fatalf("background drain must keep arrival order, left %s", got)
	}
	if n, err := drainAlertCases(ctx, db, false, tenant, 10, alertCaseDrainBeforeRead); err != nil || n != 2 {
		t.Fatalf("read-side drain must leave the large group, n=%d err=%v", n, err)
	}
	if n, err := drainAlertCases(ctx, db, false, tenant, 10, alertCaseDrainMode{}); err != nil || n != 1 || len(remaining()) != 0 {
		t.Fatalf("background drain must take the large group, n=%d err=%v left=%v", n, err, remaining())
	}
}

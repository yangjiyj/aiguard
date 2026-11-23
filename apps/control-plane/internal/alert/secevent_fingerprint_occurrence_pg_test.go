package alert

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 网关指纹重放折叠后，库里是「1 条完整事件 + N 条轻量 occurrence」。告警桥只看完整事件：
// 不能因 occurrence 多出告警/收件箱条目；建组时要把挂账的 occurrence 认领进组、计数累加；
// 建组后网关再写的 occurrence（同语句 +1）也不触发新告警。按天计数只认完整事件。
// 行的形状与 gateway-core RealAuditWriter.WriteSecurityEvent / RecordSecurityEventOccurrence 写入的一致。
func TestSecEventBridgeFoldsGatewayFingerprintOccurrencesPostgres(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tenant := fmt.Sprintf("fpocc_bridge_%d", time.Now().UnixNano())
	must := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	must(`INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',true)`, tenant)
	defer func() {
		for _, table := range []string{"alert_inbox", "security_event_occurrences", "security_events", "alert_groups", "request_logs"} {
			_, _ = db.Exec(context.Background(), "DELETE FROM "+table+" WHERE tenant_id=$1", tenant)
		}
		_, _ = db.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant)
	}()
	t.Setenv("SECEVENT_ALERT_GRACE_SECONDS", "0")

	rep := tenant + "_evt"
	request := func(i int) string { return fmt.Sprintf("%s_req_%02d", tenant, i) }
	for i := 1; i <= 10; i++ {
		must(`INSERT INTO request_logs(id,request_id,tenant_id,project_id,endpoint_type,request_status) VALUES($1,$1,$2,'project_default','chat_completions','success')`, request(i), tenant)
	}
	created := time.Now().UTC().Add(-time.Second)
	must(`INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary,created_at,principal_key,conversation_key)
	      VALUES($1,$2,$3,'project_default','security_check','high','security_audit',
	      '{"confidence":1,"findings":[{"type":"prompt_injection","category":"classic_injection","severity":"high","confidence":1}]}',$4,'key-fpfold','conv-fpfold')`,
		rep, request(1), tenant, created)
	occurrence := func(i int) {
		t.Helper()
		// 与网关 RecordSecurityEventOccurrence 同一条 SQL：代表事件已入组则同语句 +1，否则挂账。
		must(`WITH inserted AS (
			INSERT INTO security_event_occurrences (tenant_id, representative_event_id, request_id, principal_key, conversation_key, context_key, alert_group_id, occurred_at)
			VALUES ($1, $2, $3, 'key-fpfold', 'conv-fpfold', 'ck-fpfold',
			        (SELECT se.alert_group_id FROM security_events se WHERE se.tenant_id = $1 AND se.id = $2), NOW())
			ON CONFLICT (tenant_id, representative_event_id, request_id) DO NOTHING
			RETURNING alert_group_id, occurred_at)
		UPDATE alert_groups ag SET occurrence_count = ag.occurrence_count + 1,
		       last_seen_at = GREATEST(ag.last_seen_at, inserted.occurred_at), updated_at = NOW()
		  FROM inserted WHERE ag.tenant_id = $1 AND ag.id = inserted.alert_group_id`, tenant, rep, request(i))
	}
	// 告警桥还没跑：前 5 次重放挂账（alert_group_id 为空）。
	for i := 2; i <= 6; i++ {
		occurrence(i)
	}

	groups := repository.NewAlertGroupRepository(db)
	bridge := NewSecEventBridge(repository.NewSecurityEventRepository(db), NewInboxService(repository.NewAlertInboxRepository(db)), &fakeNotifier{}).
		WithAlertGroups(groups).WithGroupCounters(groups).WithRuleDailyCounts(repository.NewSecurityEventRepository(db))
	if _, err := bridge.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// 建组之后的 4 次重放：网关同语句给组计数 +1。
	for i := 7; i <= 10; i++ {
		occurrence(i)
	}
	occurrence(10) // 同一请求重复写 occurrence 必须幂等
	if _, err := bridge.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}

	var groupCount, inboxCount, pending, count, distinct int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM alert_groups WHERE tenant_id=$1`, tenant).Scan(&groupCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM alert_inbox WHERE tenant_id=$1`, tenant).Scan(&inboxCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM security_event_occurrences WHERE tenant_id=$1 AND alert_group_id IS NULL`, tenant).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if groupCount != 1 || inboxCount != 1 {
		t.Fatalf("occurrence 不得新增告警: groups=%d inbox=%d", groupCount, inboxCount)
	}
	if pending != 0 {
		t.Fatalf("建组后挂账的 occurrence 应全部认领进组，剩 %d", pending)
	}
	if err := db.QueryRow(ctx, `SELECT ag.occurrence_count, COALESCE(ag.distinct_occurrences,0) FROM alert_groups ag WHERE ag.tenant_id=$1`, tenant).Scan(&count, &distinct); err != nil {
		t.Fatal(err)
	}
	if count != 10 {
		t.Fatalf("组发生次数应为 1 条完整 + 9 条 occurrence = 10，实际 %d", count)
	}
	if distinct != 1 {
		t.Fatalf("同一会话的重复只算 1 个会话，实际 %d", distinct)
	}
	daily, err := repository.NewSecurityEventRepository(db).CountAlertableDaily(ctx, []string{tenant}, created.Truncate(24*time.Hour), created.Truncate(24*time.Hour).Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, c := range daily {
		total += c.Count
	}
	if total != 1 {
		t.Fatalf("按天计数只认完整事件（occurrence 不计入）: %d", total)
	}
}

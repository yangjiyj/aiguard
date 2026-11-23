package repository

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed testdata/alert_perf_seed.sql
var alertPerfSeedSQL string

// TestAlertPerformanceRegression 在与客户现场同量级的数据上量告警与留存各接口的仓储耗时。
// 只在 ALERT_PERF_TEST_DATABASE_URL 指向一次性、已按正式流程迁移的库时运行；首次运行会灌数
// （约 1~2 分钟），之后复用。目标见 2.9.22 设计第 13 节。
func TestAlertPerformanceRegression(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ALERT_PERF_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("ALERT_PERF_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAlertPerfData(t, ctx, db)
	const tenant = "perf_t"
	now := time.Now().UTC()
	requests := NewRequestLogRepository(db)
	contents := NewContentLogRepository(db)
	alerts := NewAlertOccurrenceRepository(db)
	dispositions := NewAuditDispositionRepository(db)
	backfillStarted := time.Now()
	if err := alerts.PrepareAlertCases(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	t.Logf("告警案件物化回填/消化 %.1fs", time.Since(backfillStarted).Seconds())

	listFilter := AlertOccurrenceFilter{TenantID: tenant, Grouping: "cases", LaneAware: true, Lane: "action", RecentLimit: 100,
		Disposition: "pending", IncludeSuppressed: false, CanReadEvidence: true, Limit: 10, EndTime: &now}
	page, err := alerts.List(ctx, listFilter)
	if err != nil || len(page.Items) == 0 {
		t.Fatalf("list cases: %v %+v", err, page)
	}
	item := page.Items[0]
	dayAgo := now.Add(-24 * time.Hour)
	seen := now

	type measured struct {
		name    string
		budget  time.Duration
		run     func() error
		prepare func(sample int) error // 每次取样前执行、不计时（例如先写入一批事件，再量写入后的首读）
	}
	runID := now.UnixNano()
	// 写入一批新事件（复制最近的事件换编号），触发器把它们登记进待重算队列；下一次读要先消化。
	writeEvents := func(count int) func(int) error {
		return func(sample int) error {
			_, err := db.Exec(ctx, `INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary,principal_key,conversation_key,alert_group_id,created_at)
 SELECT 'perf_w_'||$1::text||'_'||id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary,principal_key,conversation_key,alert_group_id,now()
 FROM security_events WHERE tenant_id='perf_t' AND id LIKE 'perf_ev_%' ORDER BY created_at DESC LIMIT $2`, fmt.Sprintf("%d_%d_%d", runID, count, sample), count)
			return err
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM security_events WHERE tenant_id='perf_t' AND id LIKE 'perf_w_%'`)
		_, _ = db.Exec(context.Background(), `UPDATE internal_keys SET traffic_class='' WHERE id='perf_k9'`)
	})
	toggleKey := func(int) error {
		_, err := db.Exec(ctx, `UPDATE internal_keys SET traffic_class=CASE WHEN traffic_class='evaluation' THEN '' ELSE 'evaluation' END WHERE id='perf_k9'`)
		return err
	}
	byUser, bySession := listFilter, listFilter
	byUser.UserID, bySession.SessionID = "perf_u9", "perf_s17"
	dispositionToggle := 0
	busy := func() {}
	releaseBusy := func() { busy(); busy = func() {} }
	defer releaseBusy()
	cases := []measured{
		{"告警列表", 300 * time.Millisecond, func() error { _, err := alerts.List(ctx, listFilter); return err }, nil},
		{"告警汇总", 300 * time.Millisecond, func() error {
			_, err := alerts.SummarizeCases(ctx, AlertOccurrenceFilter{TenantID: tenant, Disposition: "pending", StartTime: &dayAgo, EndTime: &now, CanReadEvidence: true})
			return err
		}, nil},
		{"命中明细", 300 * time.Millisecond, func() error {
			_, err := alerts.List(ctx, AlertOccurrenceFilter{TenantID: tenant, Grouping: "hits", CaseID: item.CaseID, IncludeSuppressed: true, CanReadEvidence: true, Limit: 20, EndTime: &now})
			return err
		}, nil},
		{"处置授权", 300 * time.Millisecond, func() error {
			// 与 UpsertAuthorized 相同：事务外消化队列并决定读法，再在可串行化事务里按快照授权。
			materialized, err := dispositions.prepareAlertCaseAuthorization(ctx, tenant)
			if err != nil {
				return err
			}
			return pgx.BeginTxFunc(ctx, db, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, "SET LOCAL jit=off"); err != nil {
					return err
				}
				_, err := authorizeAlertCaseSnapshotWith(ctx, tx, tenant, item.CaseID, nil, &seen, materialized)
				return err
			})
		}, nil},
		// 有内容证据权限的角色带原文读：列表、命中明细各一项（控制台每页 10 条）。
		{"告警列表（带原文）", 300 * time.Millisecond, func() error {
			raw := listFilter
			raw.IncludeRaw = true
			_, err := alerts.List(ctx, raw)
			return err
		}, nil},
		{"命中明细（带原文）", 300 * time.Millisecond, func() error {
			_, err := alerts.List(ctx, AlertOccurrenceFilter{TenantID: tenant, Grouping: "hits", CaseID: item.CaseID, IncludeSuppressed: true, CanReadEvidence: true,
				IncludeRaw: true, Limit: 10, EndTime: &now})
			return err
		}, nil},
		{"证据页签", 100 * time.Millisecond, func() error {
			_, err := alerts.List(ctx, AlertOccurrenceFilter{TenantID: tenant, Grouping: "hits", EventID: item.EventID, RequestID: item.RequestID,
				IncludeRaw: true, CanReadEvidence: true, IncludeSuppressed: true, Limit: 100, IncludeDevTraffic: true})
			return err
		}, nil},
		{"留存概览 1 天", 300 * time.Millisecond, func() error {
			_, err := requests.GetForwardProxyAccessSummary(ctx, tenant, ForwardProxyAccessFilter{AccessType: "all", StartTime: dayAgo, EndTime: now, EnvironmentScope: "customer"})
			return err
		}, nil},
		{"留存概览 30 天", time.Second, func() error {
			_, err := requests.GetForwardProxyAccessSummary(ctx, tenant, ForwardProxyAccessFilter{AccessType: "all", StartTime: now.Add(-30 * 24 * time.Hour), EndTime: now, EnvironmentScope: "customer"})
			return err
		}, nil},
		{"留存详情 90 天窗口", 200 * time.Millisecond, func() error {
			_, err := contents.ListByRequestScoped(ctx, tenant, "perf_req_101", now.Add(-90*24*time.Hour), now, "customer")
			return err
		}, nil},
		{"关键字检索 英文", 500 * time.Millisecond, func() error {
			_, _, err := requests.ListForwardProxyAccess(ctx, tenant, ForwardProxyAccessFilter{AccessType: "all", Keyword: "perf-hit-0000123", StartTime: now.Add(-30 * 24 * time.Hour), EndTime: now, EnvironmentScope: "customer", Limit: 20})
			return err
		}, nil},
		{"关键字检索 中文", 500 * time.Millisecond, func() error {
			_, _, err := requests.ListForwardProxyAccess(ctx, tenant, ForwardProxyAccessFilter{AccessType: "all", Keyword: "会话17的历史消息", StartTime: now.Add(-30 * 24 * time.Hour), EndTime: now, EnvironmentScope: "customer", Limit: 20})
			return err
		}, nil},
		{"关键字检索 常见词", time.Second, func() error {
			_, _, err := requests.ListForwardProxyAccess(ctx, tenant, ForwardProxyAccessFilter{AccessType: "all", Keyword: "历史上下文正文", StartTime: now.Add(-30 * 24 * time.Hour), EndTime: now, EnvironmentScope: "customer", Limit: 20})
			return err
		}, nil},
		{"按用户筛选", 300 * time.Millisecond, func() error { _, err := alerts.List(ctx, byUser); return err }, nil},
		{"按会话筛选", 300 * time.Millisecond, func() error { _, err := alerts.List(ctx, bySession); return err }, nil},
		{"写入 500 条后首读", 300 * time.Millisecond, func() error { _, err := alerts.List(ctx, listFilter); return err }, writeEvents(500)},
		{"写入 1900 条后首读", 500 * time.Millisecond, func() error { _, err := alerts.List(ctx, listFilter); return err }, writeEvents(1900)},
		// 凭据改标记牵动上千条事件，读前不消化（这次读仍是旧车道），由后台维护重算；第二项量后台这一轮的耗时。
		{"凭据改测评后首读", 500 * time.Millisecond, func() error { _, err := alerts.List(ctx, listFilter); return err }, toggleKey},
		{"凭据改测评后台重算", time.Second, func() error { _, err := alerts.MaintainAlertCases(ctx, time.Minute); return err }, toggleKey},
		// 管理员标误报：处置接口提交后同步消化本次条目再返回；之后的首读不用再等。
		{"处置（含同步消化）", 500 * time.Millisecond, func() error {
			status := "false_positive"
			if dispositionToggle%2 == 1 {
				status = "open"
			}
			dispositionToggle++
			_, err := dispositions.UpsertAuthorized(ctx, &AuditDisposition{TenantID: tenant, SubjectType: "security_event", SubjectID: item.EventID,
				Status: status, OperatorID: "perf", OperatorName: "性能"}, nil, "", "")
			return err
		}, nil},
		{"处置后首读", 300 * time.Millisecond, func() error { _, err := alerts.List(ctx, listFilter); return err }, func(int) error {
			status := "false_positive"
			if dispositionToggle%2 == 1 {
				status = "open"
			}
			dispositionToggle++
			_, err := dispositions.UpsertAuthorized(ctx, &AuditDisposition{TenantID: tenant, SubjectType: "security_event", SubjectID: item.EventID,
				Status: status, OperatorID: "perf", OperatorName: "性能"}, nil, "", "")
			return err
		}},
		// 后台正在消化（占着租户锁）时又写入 500 条：读不等锁，直接读已物化结果。
		{"后台消化期间的读", 300 * time.Millisecond, func() error { _, err := alerts.List(ctx, listFilter); return err }, func(sample int) error {
			releaseBusy()
			if err := writeEvents(500)(sample + 100); err != nil {
				return err
			}
			conn, err := db.Acquire(ctx)
			if err != nil {
				return err
			}
			tx, err := conn.Begin(ctx)
			if err != nil {
				conn.Release()
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('jjd_alert_cases:'||$1,0))`, tenant); err != nil {
				_ = tx.Rollback(ctx)
				conn.Release()
				return err
			}
			busy = func() { _ = tx.Rollback(context.Background()); conn.Release() }
			return nil
		}},
	}
	slow := []string{}
	only := strings.TrimSpace(os.Getenv("ALERT_PERF_ONLY"))
	for _, c := range cases {
		if only != "" && !strings.Contains(c.name, only) {
			continue
		}
		samples := []time.Duration{}
		for i := 0; i < 3; i++ {
			if c.prepare != nil {
				if err := c.prepare(i); err != nil {
					t.Fatalf("%s prepare: %v", c.name, err)
				}
			}
			started := time.Now()
			if err := c.run(); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			samples = append(samples, time.Since(started))
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		median := samples[1]
		t.Logf("%-14s 中位数 %8.1fms（预算 %v）", c.name, float64(median.Microseconds())/1000, c.budget)
		if median > c.budget {
			slow = append(slow, c.name)
		}
	}
	if len(slow) > 0 {
		t.Fatalf("超出预算：%s", strings.Join(slow, "、"))
	}
}

func seedAlertPerfData(t *testing.T, ctx context.Context, db *pgxpool.Pool) {
	t.Helper()
	var seeded bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM security_events WHERE tenant_id='perf_t')`).Scan(&seeded); err != nil {
		t.Fatal(err)
	}
	if !seeded {
		seedAlertPerfRows(t, ctx, db)
	}
	// 留存预算列：与控制面启动时的回填相同，已算完时一轮即返回。
	repo := NewRequestLogRepository(db)
	for {
		n, err := repo.BackfillRiskColumns(ctx, 5000)
		if err != nil {
			t.Fatalf("risk columns: %v", err)
		}
		if n == 0 {
			break
		}
	}
	if _, err := db.Exec(ctx, `ANALYZE request_logs`); err != nil {
		t.Fatal(err)
	}
}

func seedAlertPerfRows(t *testing.T, ctx context.Context, db *pgxpool.Pool) {
	t.Helper()
	conn, err := db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Conn().PgConn().Exec(ctx, alertPerfSeedSQL).ReadAll(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := db.Exec(ctx, `SELECT jjdguard_refresh_request_customer_content_projection(tenant_id, request_id) FROM request_logs WHERE tenant_id='perf_t'`); err != nil {
		t.Fatalf("customer projection: %v", err)
	}
}

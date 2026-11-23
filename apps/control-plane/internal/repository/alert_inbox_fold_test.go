package repository

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 消息中心「同类折叠」与「按类别+时间范围批量已读」的仓储测试。
// 这些测试都连真实 PG（CONTENT_LOGS_TEST_DATABASE_URL，未设置则跳过）。

const foldTZ = "Asia/Shanghai"

type inboxSeed struct {
	ID       string
	Type     string
	Severity string
	Title    string
	Body     string // JSON 文本，空串=「{}」
	At       time.Time
	Read     bool
}

func seedInbox(t *testing.T, db *pgxpool.Pool, tenantID string, rows ...inboxSeed) {
	t.Helper()
	for _, r := range rows {
		body := r.Body
		if body == "" {
			body = "{}"
		}
		var readAt any
		if r.Read {
			readAt = r.At.Add(time.Minute)
		}
		if _, err := db.Exec(context.Background(),
			`INSERT INTO alert_inbox (id, tenant_id, severity, type, title, body_json, created_at, read_at)
			 VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8)`,
			r.ID, tenantID, r.Severity, r.Type, r.Title, body, r.At, readAt); err != nil {
			t.Fatalf("seed %s: %v", r.ID, err)
		}
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func findGroup(t *testing.T, page *AlertInboxFoldedPage, typ, day string) *AlertInboxFoldedGroup {
	t.Helper()
	for _, g := range page.Groups {
		if g.Type == typ && g.Day == day {
			return g
		}
	}
	t.Fatalf("没有找到分组 type=%s day=%s；现有=%s", typ, day, describeGroups(page))
	return nil
}

func describeGroups(page *AlertInboxFoldedPage) string {
	var parts []string
	for _, g := range page.Groups {
		parts = append(parts, fmt.Sprintf("%s/%s/%s/%s×%d", g.Type, g.Severity, g.Day, g.Sample.Title, g.Count))
	}
	return strings.Join(parts, "; ")
}

func TestListFoldedMergesSameTypeTitleAndDayWithoutLosingAnyRow(t *testing.T) {
	db, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(db)
	ctx := context.Background()
	gov := `{"reason":"model not allowed for team","alert_only":true}`
	seedInbox(t, db, tenantID,
		inboxSeed{ID: "g1", Type: "alert", Severity: "warning", Title: "governor 事件：alert", Body: gov, At: mustTime(t, "2026-10-10T01:00:00Z")},
		inboxSeed{ID: "g2", Type: "alert", Severity: "warning", Title: "governor 事件：alert", Body: gov, At: mustTime(t, "2026-10-10T05:00:00Z")},
		inboxSeed{ID: "g3", Type: "alert", Severity: "warning", Title: "governor 事件：alert", Body: gov, At: mustTime(t, "2026-10-10T09:30:00Z"), Read: true},
		inboxSeed{ID: "r1", Type: "model_route_degraded", Severity: "warning", Title: "模型仅剩一条健康线路", Body: `{"model_name":"gpt-a"}`, At: mustTime(t, "2026-10-10T02:00:00Z")},
	)

	page, err := repo.ListFolded(ctx, AlertInboxFilter{TenantID: tenantID}, foldTZ)
	if err != nil {
		t.Fatalf("ListFolded: %v", err)
	}
	if page.TotalItems != 4 || page.TotalGroups != 2 || len(page.Groups) != 2 {
		t.Fatalf("totals items=%d groups=%d len=%d：%s", page.TotalItems, page.TotalGroups, len(page.Groups), describeGroups(page))
	}
	g := findGroup(t, page, "alert", "2026-10-10")
	if g.Count != 3 || g.UnreadCount != 2 {
		t.Fatalf("治理事件组 count=%d unread=%d，want 3/2", g.Count, g.UnreadCount)
	}
	if !g.FirstAt.Equal(mustTime(t, "2026-10-10T01:00:00Z")) || !g.LastAt.Equal(mustTime(t, "2026-10-10T09:30:00Z")) {
		t.Fatalf("首末时间不对 first=%s last=%s", g.FirstAt, g.LastAt)
	}
	if g.Sample == nil || g.Sample.ID != "g3" || g.Sample.BodyJSON["reason"] != "model not allowed for team" {
		t.Fatalf("代表样本应是该组最新一条且带完整 body：%+v", g.Sample)
	}
	if g.Key == "" {
		t.Fatal("分组必须有稳定 key")
	}
}

func TestListFoldedSplitsDaysInTheRequestedTimezone(t *testing.T) {
	db, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(db)
	ctx := context.Background()
	for i, at := range []string{"2026-10-09T15:59:59Z", "2026-10-09T16:00:00Z", "2026-10-10T15:59:59Z", "2026-10-10T16:00:00Z"} {
		seedInbox(t, db, tenantID, inboxSeed{ID: fmt.Sprintf("d%d", i), Type: "alert", Severity: "warning", Title: "governor 事件：alert", At: mustTime(t, at)})
	}

	sh, err := repo.ListFolded(ctx, AlertInboxFilter{TenantID: tenantID}, foldTZ)
	if err != nil {
		t.Fatal(err)
	}
	if sh.TotalGroups != 3 {
		t.Fatalf("上海时区应按午夜 00:00 分成 3 天，实际 %d：%s", sh.TotalGroups, describeGroups(sh))
	}
	if g := findGroup(t, sh, "alert", "2026-10-09"); g.Count != 1 {
		t.Fatalf("10-09 应只有 23:59:59 一条，实际 %d", g.Count)
	}
	g := findGroup(t, sh, "alert", "2026-10-10")
	if g.Count != 2 || !g.DayStart.Equal(mustTime(t, "2026-10-09T16:00:00Z")) || !g.DayEnd.Equal(mustTime(t, "2026-10-10T16:00:00Z")) {
		t.Fatalf("10-10 组 count=%d start=%s end=%s", g.Count, g.DayStart, g.DayEnd)
	}

	utc, err := repo.ListFolded(ctx, AlertInboxFilter{TenantID: tenantID}, "UTC")
	if err != nil {
		t.Fatal(err)
	}
	if utc.TotalGroups != 2 {
		t.Fatalf("UTC 时区应分成 2 天，实际 %d：%s", utc.TotalGroups, describeGroups(utc))
	}
}

func TestListFoldedKeepsDifferentReasonSeverityActionApart(t *testing.T) {
	db, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(db)
	at := mustTime(t, "2026-10-10T03:00:00Z")
	seedInbox(t, db, tenantID,
		// 同 type 同标题，但原因不同：不能合到一起，否则「额度检查超时」会被「模型策略通知」吞掉。
		inboxSeed{ID: "a1", Type: "alert", Severity: "warning", Title: "governor 事件：alert", Body: `{"reason":"model not allowed for team"}`, At: at},
		inboxSeed{ID: "a2", Type: "alert", Severity: "warning", Title: "governor 事件：alert", Body: `{"reason":"fail-open: timeout"}`, At: at},
		// 同标题不同严重度：不能把高危藏进低危组。
		inboxSeed{ID: "s1", Type: "security_event", Severity: "high", Title: "安全告警【高危】安全检测", Body: `{"event_type":"security_check","action":"block"}`, At: at},
		inboxSeed{ID: "s2", Type: "security_event", Severity: "critical", Title: "安全告警【高危】安全检测", Body: `{"event_type":"security_check","action":"block"}`, At: at},
		// 处置不同：拦截与放行不能混在一行。
		inboxSeed{ID: "s3", Type: "security_event", Severity: "high", Title: "安全告警【高危】安全检测", Body: `{"event_type":"security_check","action":"allow"}`, At: at},
		// 模型不同的线路退化：分开展示才知道是哪个模型。
		inboxSeed{ID: "m1", Type: "model_route_degraded", Severity: "warning", Title: "模型仅剩一条健康线路", Body: `{"model_name":"gpt-a"}`, At: at},
		inboxSeed{ID: "m2", Type: "model_route_degraded", Severity: "warning", Title: "模型仅剩一条健康线路", Body: `{"model_name":"gpt-b"}`, At: at},
	)
	page, err := repo.ListFolded(context.Background(), AlertInboxFilter{TenantID: tenantID}, foldTZ)
	if err != nil {
		t.Fatal(err)
	}
	if page.TotalGroups != 7 || page.TotalItems != 7 {
		t.Fatalf("应当 7 组 7 条，实际 groups=%d items=%d：%s", page.TotalGroups, page.TotalItems, describeGroups(page))
	}
}

func TestListFoldedIgnoresCounterSuffixInSecurityTitles(t *testing.T) {
	db, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(db)
	body := `{"event_type":"data_security","action":"block","rule_name":"客户敏感词"}`
	seedInbox(t, db, tenantID,
		inboxSeed{ID: "c1", Type: "security_event", Severity: "high", Title: "安全告警【高危】数据泄露 · 独立事发 1 次 · 涉及 1 人", Body: body, At: mustTime(t, "2026-10-10T01:00:00Z")},
		inboxSeed{ID: "c2", Type: "security_event", Severity: "high", Title: "安全告警【高危】数据泄露 · 独立事发 7 次 · 涉及 3 人", Body: body, At: mustTime(t, "2026-10-10T02:00:00Z")},
		// 业务名里本来就带数字的标题（员工 / 模型）属于不同对象，必须分开。
		inboxSeed{ID: "b1", Type: "billing_budget_exhausted", Severity: "high", Title: "预算用尽断流 · 员工 wallet-1", At: mustTime(t, "2026-10-10T01:00:00Z")},
		inboxSeed{ID: "b2", Type: "billing_budget_exhausted", Severity: "high", Title: "预算用尽断流 · 员工 wallet-2", At: mustTime(t, "2026-10-10T01:00:00Z")},
	)
	page, err := repo.ListFolded(context.Background(), AlertInboxFilter{TenantID: tenantID}, foldTZ)
	if err != nil {
		t.Fatal(err)
	}
	if page.TotalGroups != 3 {
		t.Fatalf("应当 3 组（安全事件合并、两个员工分开），实际 %d：%s", page.TotalGroups, describeGroups(page))
	}
	if g := findGroup(t, page, "security_event", "2026-10-10"); g.Count != 2 {
		t.Fatalf("安全事件组 count=%d，want 2", g.Count)
	}
}

func TestListFoldedHonoursFiltersAndPaginatesByGroup(t *testing.T) {
	db, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(db)
	ctx := context.Background()
	// 5 天 × 每天 3 条（其中第一条已读）= 15 条，5 组。
	for d := 0; d < 5; d++ {
		for i := 0; i < 3; i++ {
			seedInbox(t, db, tenantID, inboxSeed{
				ID: fmt.Sprintf("p%d_%d", d, i), Type: "alert", Severity: "warning", Title: "governor 事件：alert",
				At: mustTime(t, "2026-10-01T04:00:00Z").AddDate(0, 0, d).Add(time.Duration(i) * time.Hour), Read: i == 0,
			})
		}
	}
	seedInbox(t, db, tenantID, inboxSeed{ID: "other", Type: "model_route_degraded", Severity: "info", Title: "x", At: mustTime(t, "2026-10-03T04:00:00Z")})

	all, err := repo.ListFolded(ctx, AlertInboxFilter{TenantID: tenantID, Type: "alert", Limit: 2, Offset: 0}, foldTZ)
	if err != nil {
		t.Fatal(err)
	}
	if all.TotalGroups != 5 || all.TotalItems != 15 || len(all.Groups) != 2 {
		t.Fatalf("分页应按组：total_groups=%d total_items=%d page=%d", all.TotalGroups, all.TotalItems, len(all.Groups))
	}
	if all.Groups[0].Day != "2026-10-05" || all.Groups[1].Day != "2026-10-04" {
		t.Fatalf("应按最近活动倒序：%s", describeGroups(all))
	}
	page3, err := repo.ListFolded(ctx, AlertInboxFilter{TenantID: tenantID, Type: "alert", Limit: 2, Offset: 4}, foldTZ)
	if err != nil || len(page3.Groups) != 1 || page3.Groups[0].Day != "2026-10-01" {
		t.Fatalf("最后一页应只剩最早一天：%v %s", err, describeGroups(page3))
	}

	unread, err := repo.ListFolded(ctx, AlertInboxFilter{TenantID: tenantID, Type: "alert", UnreadOnly: true}, foldTZ)
	if err != nil {
		t.Fatal(err)
	}
	if unread.TotalItems != 10 {
		t.Fatalf("仅未读时总条数应为 10，实际 %d", unread.TotalItems)
	}
	for _, g := range unread.Groups {
		if g.Count != 2 || g.UnreadCount != 2 {
			t.Fatalf("仅未读时每组 count/unread 都应为 2：%+v", g)
		}
	}

	ranged, err := repo.ListFolded(ctx, AlertInboxFilter{
		TenantID: tenantID, Type: "alert",
		From: mustTime(t, "2026-10-02T00:00:00Z"), To: mustTime(t, "2026-10-04T00:00:00Z"),
	}, foldTZ)
	if err != nil {
		t.Fatal(err)
	}
	if ranged.TotalGroups != 2 || ranged.TotalItems != 6 {
		t.Fatalf("时间范围筛选后应 2 组 6 条，实际 %d/%d", ranged.TotalGroups, ranged.TotalItems)
	}
}

func TestListFoldedItemsReturnsExactlyTheRowsOfOneGroup(t *testing.T) {
	db, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(db)
	ctx := context.Background()
	var want []string
	for i := 0; i < 45; i++ {
		id := fmt.Sprintf("x%02d", i)
		want = append(want, id)
		seedInbox(t, db, tenantID, inboxSeed{
			ID: id, Type: "alert", Severity: "warning", Title: "governor 事件：alert",
			Body: `{"reason":"model not allowed for team"}`, At: mustTime(t, "2026-10-10T00:00:00Z").Add(time.Duration(i) * time.Minute), Read: i%5 == 0,
		})
	}
	seedInbox(t, db, tenantID,
		inboxSeed{ID: "y_other_reason", Type: "alert", Severity: "warning", Title: "governor 事件：alert", Body: `{"reason":"fail-open: timeout"}`, At: mustTime(t, "2026-10-10T01:00:00Z")},
		inboxSeed{ID: "y_other_day", Type: "alert", Severity: "warning", Title: "governor 事件：alert", Body: `{"reason":"model not allowed for team"}`, At: mustTime(t, "2026-10-12T01:00:00Z")},
	)
	page, err := repo.ListFolded(ctx, AlertInboxFilter{TenantID: tenantID}, foldTZ)
	if err != nil {
		t.Fatal(err)
	}
	var target *AlertInboxFoldedGroup
	for _, g := range page.Groups {
		if g.Count == 45 {
			target = g
		}
	}
	if target == nil {
		t.Fatalf("没找到 45 条的组：%s", describeGroups(page))
	}

	var got []string
	total := -1
	for offset := 0; ; offset += 20 {
		items, n, err := repo.ListFoldedItems(ctx, AlertInboxFoldedItemsFilter{
			TenantID: tenantID, Key: target.Key, Type: target.Type, Severity: target.Severity,
			DayStart: target.DayStart, DayEnd: target.DayEnd, TZ: foldTZ, Limit: 20, Offset: offset,
		})
		if err != nil {
			t.Fatalf("ListFoldedItems: %v", err)
		}
		total = n
		for _, it := range items {
			got = append(got, it.ID)
		}
		if len(items) < 20 {
			break
		}
	}
	if total != 45 || len(got) != 45 {
		t.Fatalf("展开明细应与组条数一致：total=%d got=%d", total, len(got))
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("明细集合不等于该组的原始消息：\n got=%v\nwant=%v", got, want)
	}

	unreadOnly, n, err := repo.ListFoldedItems(ctx, AlertInboxFoldedItemsFilter{
		TenantID: tenantID, Key: target.Key, Type: target.Type, Severity: target.Severity,
		DayStart: target.DayStart, DayEnd: target.DayEnd, TZ: foldTZ, UnreadOnly: true, Limit: 100,
	})
	if err != nil || n != 36 || len(unreadOnly) != 36 {
		t.Fatalf("仅未读明细应为 36 条：err=%v n=%d len=%d", err, n, len(unreadOnly))
	}
}

func TestListFoldedItemsRejectsAKeyThatDoesNotMatchTheWindow(t *testing.T) {
	db, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(db)
	seedInbox(t, db, tenantID, inboxSeed{ID: "k1", Type: "alert", Severity: "warning", Title: "governor 事件：alert", At: mustTime(t, "2026-10-10T01:00:00Z")})
	items, n, err := repo.ListFoldedItems(context.Background(), AlertInboxFoldedItemsFilter{
		TenantID: tenantID, Key: "not-a-real-key", Type: "alert", Severity: "warning",
		DayStart: mustTime(t, "2026-10-09T16:00:00Z"), DayEnd: mustTime(t, "2026-10-10T16:00:00Z"), TZ: foldTZ, Limit: 20,
	})
	if err != nil || n != 0 || len(items) != 0 {
		t.Fatalf("伪造 key 不应取到任何消息：err=%v n=%d len=%d", err, n, len(items))
	}
}

func TestListFoldedAndItemsAreTenantScoped(t *testing.T) {
	db, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(db)
	ctx := context.Background()
	otherTenant := tenantID + "_other"
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$1,'enterprise','active', TRUE)`, otherTenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, otherTenant) })
	at := mustTime(t, "2026-10-10T01:00:00Z")
	seedInbox(t, db, tenantID, inboxSeed{ID: "mine", Type: "alert", Severity: "warning", Title: "governor 事件：alert", At: at})
	seedInbox(t, db, otherTenant, inboxSeed{ID: "theirs", Type: "alert", Severity: "warning", Title: "governor 事件：alert", At: at})

	mine, err := repo.ListFolded(ctx, AlertInboxFilter{TenantID: tenantID}, foldTZ)
	if err != nil || mine.TotalItems != 1 || mine.Groups[0].Sample.ID != "mine" {
		t.Fatalf("折叠列表串租户了：%v %+v", err, mine)
	}
	theirs, err := repo.ListFolded(ctx, AlertInboxFilter{TenantID: otherTenant}, foldTZ)
	if err != nil || theirs.TotalItems != 1 {
		t.Fatal(err)
	}
	// 拿对方租户的组 key 在我的租户下展开，必须一条都取不到。
	g := theirs.Groups[0]
	items, n, err := repo.ListFoldedItems(ctx, AlertInboxFoldedItemsFilter{
		TenantID: tenantID, Key: g.Key, Type: g.Type, Severity: g.Severity, DayStart: g.DayStart, DayEnd: g.DayEnd, TZ: foldTZ, Limit: 20,
	})
	if err != nil || n != 1 || items[0].ID != "mine" {
		t.Fatalf("展开必须只返回本租户的行（key 相同也不能串）：err=%v n=%d items=%v", err, n, items)
	}
	if _, err := repo.ListFolded(ctx, AlertInboxFilter{}, foldTZ); err == nil {
		t.Fatal("缺租户必须报错")
	}
	if _, err := repo.ListFolded(ctx, AlertInboxFilter{TenantID: tenantID}, "Mars/Olympus"); err == nil {
		t.Fatal("非法时区必须报错而不是静默按 UTC")
	}
}

func TestTypeSummaryReportsUnreadPerTypeAndMarksProtectedTypes(t *testing.T) {
	db, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(db)
	seedInbox(t, db, tenantID,
		inboxSeed{ID: "t1", Type: "alert", Severity: "warning", Title: "a", At: mustTime(t, "2026-09-04T01:00:00Z")},
		inboxSeed{ID: "t2", Type: "alert", Severity: "warning", Title: "a", At: mustTime(t, "2026-10-13T01:00:00Z")},
		inboxSeed{ID: "t3", Type: "alert", Severity: "warning", Title: "a", At: mustTime(t, "2026-10-01T01:00:00Z"), Read: true},
		inboxSeed{ID: "t4", Type: "security_event", Severity: "high", Title: "s", At: mustTime(t, "2026-10-01T01:00:00Z")},
	)
	sum, err := repo.TypeSummary(context.Background(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*AlertInboxTypeSummary{}
	for _, s := range sum {
		got[s.Type] = s
	}
	a := got["alert"]
	if a == nil || a.Unread != 2 || a.Total != 3 || !a.BulkReadAllowed {
		t.Fatalf("alert 汇总不对：%+v", a)
	}
	if !a.FirstAt.Equal(mustTime(t, "2026-09-04T01:00:00Z")) || !a.LastAt.Equal(mustTime(t, "2026-10-13T01:00:00Z")) {
		t.Fatalf("alert 首末时间不对：%+v", a)
	}
	if s := got["security_event"]; s == nil || s.BulkReadAllowed {
		t.Fatalf("安全事件类必须标为不允许批量已读：%+v", s)
	}
}

// ---------- 批量已读 ----------

func TestBulkReadAllowedTypesAreAnExplicitAllowList(t *testing.T) {
	for _, typ := range []string{"alert", "governor.model_downgraded", "governor.downgrade_fallback_alert", "quota.admission.reservation_overrun", "model_route_degraded", "model_route_recovered", "model_route_fallback", "model_route_flapping"} {
		if !BulkReadAllowedType(typ) {
			t.Errorf("%s 应允许批量已读", typ)
		}
	}
	// 凡是真实告警/故障/审计/计费类，一律不允许；未知类型默认也不允许（白名单而非黑名单）。
	for _, typ := range []string{"", "security_event", "security_event_daily_summary", "runtime_fault", "tool_execution_risk", "tool_attempt_blocked",
		"model_route_unavailable", "model_route_circuit_opened", "quota.admission.runtime_fault",
		"billing_budget_exhausted", "billing_finalize_failed", "audit_chain_verify_failed", "audit_chain_write_failed",
		"anomaly_cost", "forecast.done", "totally_new_type", "ALERT", " alert", "alert%", "alert,security_event"} {
		if BulkReadAllowedType(typ) {
			t.Errorf("%q 不应允许批量已读", typ)
		}
	}
}

type protectedSnapshot struct{ groups, events, otherInbox string }

func snapshotProtected(t *testing.T, db *pgxpool.Pool, tenantID string, inScopeIDs []string) protectedSnapshot {
	t.Helper()
	ctx := context.Background()
	var s protectedSnapshot
	q := func(sql string, args ...any) string {
		var v *string
		if err := db.QueryRow(ctx, sql, args...).Scan(&v); err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		if v == nil {
			return ""
		}
		return *v
	}
	s.groups = q(`SELECT md5(string_agg(g::text, '|' ORDER BY id)) FROM alert_groups g WHERE tenant_id = $1`, tenantID)
	s.events = q(`SELECT md5(string_agg(e::text, '|' ORDER BY id)) FROM security_events e WHERE tenant_id = $1`, tenantID)
	s.otherInbox = q(`SELECT md5(string_agg(i::text, '|' ORDER BY id)) FROM alert_inbox i WHERE tenant_id = $1 AND NOT (id = ANY($2))`, tenantID, inScopeIDs)
	return s
}

func inScopeColumnsExceptReadAt(t *testing.T, db *pgxpool.Pool, tenantID string, ids []string) string {
	t.Helper()
	var v string
	if err := db.QueryRow(context.Background(),
		`SELECT md5(string_agg((id, tenant_id, severity, type, title, body_json::text, COALESCE(target_url,''), created_at)::text, '|' ORDER BY id))
		   FROM alert_inbox WHERE tenant_id = $1 AND id = ANY($2)`, tenantID, ids).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func countAudit(t *testing.T, db *pgxpool.Pool, id string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(context.Background(), `SELECT COUNT(*) FROM audit_operations WHERE id = $1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func seedBulkFixture(t *testing.T, db *pgxpool.Pool, tenantID string) (inScope []string) {
	t.Helper()
	ctx := context.Background()
	gov := `{"reason":"model not allowed for team","alert_only":true}`
	seedInbox(t, db, tenantID,
		// 范围内：alert 类、未读、在 [09-04, 10-14) 之内
		inboxSeed{ID: "in1", Type: "alert", Severity: "warning", Title: "governor 事件：alert", Body: gov, At: mustTime(t, "2026-09-04T01:00:00Z")},
		inboxSeed{ID: "in2", Type: "alert", Severity: "warning", Title: "governor 事件：alert", Body: gov, At: mustTime(t, "2026-10-13T23:59:59Z")},
		inboxSeed{ID: "in3", Type: "alert", Severity: "high", Title: "governor 事件：alert", Body: gov, At: mustTime(t, "2026-09-20T08:00:00Z")},
		// 范围内但本来就已读：不计数、read_at 不得被改写
		inboxSeed{ID: "done", Type: "alert", Severity: "warning", Title: "governor 事件：alert", Body: gov, At: mustTime(t, "2026-09-10T08:00:00Z"), Read: true},
		// 范围外：时间之外（早一秒、等于 to 的那一刻）
		inboxSeed{ID: "early", Type: "alert", Severity: "warning", Title: "governor 事件：alert", Body: gov, At: mustTime(t, "2026-09-03T23:59:59Z")},
		inboxSeed{ID: "atTo", Type: "alert", Severity: "warning", Title: "governor 事件：alert", Body: gov, At: mustTime(t, "2026-10-14T00:00:00Z")},
		// 范围外：别的类别（含安全事件）
		inboxSeed{ID: "sec", Type: "security_event", Severity: "critical", Title: "安全告警【极高危】凭据泄露", At: mustTime(t, "2026-09-20T08:00:00Z")},
		inboxSeed{ID: "route", Type: "model_route_degraded", Severity: "warning", Title: "模型仅剩一条健康线路", At: mustTime(t, "2026-09-20T08:00:00Z")},
	)
	// 受保护表：同租户、同时间的告警组与安全事件，批量已读绝不能碰
	if _, err := db.Exec(ctx, `INSERT INTO alert_groups (id, tenant_id, group_key, status, severity, alert_type, title, first_seen_at, last_seen_at)
		VALUES ('grp-1', $1, 'k1', 'open', 'critical', 'security_event', '凭据泄露', '2026-09-20T08:00:00Z', '2026-09-20T08:00:00Z')`, tenantID); err != nil {
		t.Fatalf("seed alert_groups: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO security_events (id, tenant_id, event_type, severity, action_taken, matched_summary, created_at)
		VALUES ('sev-1', $1, 'credential_leak', 'critical', 'audit', '{"source":"agent_endpoint"}'::jsonb, '2026-09-20T08:00:00Z')`, tenantID); err != nil {
		t.Fatalf("seed security_events: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(ctx, `DELETE FROM security_events WHERE tenant_id = $1`, tenantID) })
	return []string{"in1", "in2", "in3"}
}

func bulkParams(tenantID string, expected int, auditID string) BulkReadParams {
	return BulkReadParams{
		TenantID: tenantID, Type: "alert",
		From: time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC),
		ExpectedCount: expected,
		Audit: &AuditOperation{
			ID: auditID, ActionType: "alert_inbox.bulk_read", TargetType: "alert_inbox", TargetID: "alert",
			ActionDetail: map[string]interface{}{"type": "alert"}, IPAddress: "127.0.0.1",
		},
	}
}

func TestBulkMarkReadOnlyTouchesTheSelectedTypeAndRangeAndOnlyReadAt(t *testing.T) {
	db, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(db)
	ctx := context.Background()
	inScope := seedBulkFixture(t, db, tenantID)
	auditID := "audit_" + tenantID
	t.Cleanup(func() { _, _ = db.Exec(ctx, `DELETE FROM audit_operations WHERE id = $1`, auditID) })

	preview, err := repo.PreviewBulkRead(ctx, tenantID, "alert", bulkParams(tenantID, 0, "").From, bulkParams(tenantID, 0, "").To)
	if err != nil {
		t.Fatalf("PreviewBulkRead: %v", err)
	}
	if preview.Matched != 3 || preview.FirstAt == nil || preview.LastAt == nil ||
		!preview.FirstAt.Equal(mustTime(t, "2026-09-04T01:00:00Z")) || !preview.LastAt.Equal(mustTime(t, "2026-10-13T23:59:59Z")) {
		t.Fatalf("预览应只数范围内未读 3 条：%+v", preview)
	}

	var doneReadAt time.Time
	if err := db.QueryRow(ctx, `SELECT read_at FROM alert_inbox WHERE id = 'done'`).Scan(&doneReadAt); err != nil {
		t.Fatal(err)
	}
	before := snapshotProtected(t, db, tenantID, inScope)
	colsBefore := inScopeColumnsExceptReadAt(t, db, tenantID, inScope)

	marked, err := repo.BulkMarkRead(ctx, bulkParams(tenantID, 3, auditID))
	if err != nil {
		t.Fatalf("BulkMarkRead: %v", err)
	}
	if marked != 3 {
		t.Fatalf("marked=%d want 3", marked)
	}

	// 范围内 3 条已读；其余所有行（含已读的 done、范围外、别的类别）逐字节不变。
	var unreadInScope int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_inbox WHERE tenant_id = $1 AND id = ANY($2) AND read_at IS NULL`, tenantID, inScope).Scan(&unreadInScope); err != nil || unreadInScope != 0 {
		t.Fatalf("范围内仍有未读：err=%v n=%d", err, unreadInScope)
	}
	after := snapshotProtected(t, db, tenantID, inScope)
	if after != before {
		t.Fatalf("范围外的消息 / alert_groups / security_events 被改动：\nbefore=%+v\n after=%+v", before, after)
	}
	if colsAfter := inScopeColumnsExceptReadAt(t, db, tenantID, inScope); colsAfter != colsBefore {
		t.Fatal("范围内消息除 read_at 以外的列被改动")
	}
	var doneAfter time.Time
	if err := db.QueryRow(ctx, `SELECT read_at FROM alert_inbox WHERE id = 'done'`).Scan(&doneAfter); err != nil || !doneAfter.Equal(doneReadAt) {
		t.Fatalf("本来就已读的消息 read_at 被改写：%v -> %v (%v)", doneReadAt, doneAfter, err)
	}
	if countAudit(t, db, auditID) != 1 {
		t.Fatal("批量已读必须同时写入一条操作审计")
	}
	var detail string
	if err := db.QueryRow(ctx, `SELECT action_detail::text FROM audit_operations WHERE id = $1`, auditID).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, `"marked_read": 3`) {
		t.Fatalf("审计详情必须记录实际标记条数：%s", detail)
	}

	// 幂等：再来一次，范围内已无未读，预期 3 条与实际 0 条不符 -> 拒绝，不改动任何东西。
	if _, err := repo.BulkMarkRead(ctx, bulkParams(tenantID, 3, auditID+"_2")); err == nil {
		t.Fatal("重复执行（预期条数已过期）必须被拒绝")
	}
}

func TestBulkMarkReadRollsBackEverythingWhenCountChanged(t *testing.T) {
	db, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(db)
	ctx := context.Background()
	inScope := seedBulkFixture(t, db, tenantID)
	auditID := "audit_cc_" + tenantID
	t.Cleanup(func() { _, _ = db.Exec(ctx, `DELETE FROM audit_operations WHERE id = $1`, auditID) })

	_, err := repo.BulkMarkRead(ctx, bulkParams(tenantID, 2, auditID)) // 预览时是 2 条，现在有 3 条
	var changed *BulkReadCountChangedError
	if !errors.As(err, &changed) || changed.Current != 3 {
		t.Fatalf("应返回 count_changed 且带当前条数 3：%v", err)
	}
	var unread int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_inbox WHERE tenant_id = $1 AND id = ANY($2) AND read_at IS NULL`, tenantID, inScope).Scan(&unread); err != nil || unread != 3 {
		t.Fatalf("条数不符必须整体回滚，仍应有 3 条未读：err=%v unread=%d", err, unread)
	}
	if countAudit(t, db, auditID) != 0 {
		t.Fatal("回滚后不应留下审计记录")
	}
}

func TestBulkMarkReadRollsBackWhenTheAuditRowCannotBeWritten(t *testing.T) {
	db, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(db)
	ctx := context.Background()
	inScope := seedBulkFixture(t, db, tenantID)
	p := bulkParams(tenantID, 3, "audit_fail_"+tenantID)
	p.Audit.UserID = "no-such-user" // 违反 audit_operations.user_id 外键，模拟审计写入失败

	if _, err := repo.BulkMarkRead(ctx, p); err == nil {
		t.Fatal("审计写不进去时必须失败（审计失败即不执行）")
	}
	var unread int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_inbox WHERE tenant_id = $1 AND id = ANY($2) AND read_at IS NULL`, tenantID, inScope).Scan(&unread); err != nil || unread != 3 {
		t.Fatalf("审计失败必须回滚已读标记：err=%v unread=%d", err, unread)
	}
}

func TestBulkMarkReadRefusesUnsafeScopeBeforeTouchingTheDatabase(t *testing.T) {
	db, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(db)
	ctx := context.Background()
	inScope := seedBulkFixture(t, db, tenantID)
	good := bulkParams(tenantID, 3, "audit_unsafe_"+tenantID)
	t.Cleanup(func() { _, _ = db.Exec(ctx, `DELETE FROM audit_operations WHERE id LIKE $1`, "audit_unsafe_%") })

	cases := map[string]func(p *BulkReadParams){
		"受保护类别":      func(p *BulkReadParams) { p.Type = "security_event" },
		"空类别=全表":     func(p *BulkReadParams) { p.Type = "" },
		"未知类别":       func(p *BulkReadParams) { p.Type = "totally_new_type" },
		"缺租户":        func(p *BulkReadParams) { p.TenantID = "" },
		"缺起点=不限下界":   func(p *BulkReadParams) { p.From = time.Time{} },
		"缺终点=不限上界":   func(p *BulkReadParams) { p.To = time.Time{} },
		"起点不早于终点":    func(p *BulkReadParams) { p.From, p.To = p.To, p.From },
		"预期条数为 0":    func(p *BulkReadParams) { p.ExpectedCount = 0 },
		"范围超过 366 天": func(p *BulkReadParams) { p.From = p.To.AddDate(0, 0, -367) },
		"没有审计信息":     func(p *BulkReadParams) { p.Audit = nil },
	}
	for name, mutate := range cases {
		p := good
		auditCopy := *good.Audit
		p.Audit = &auditCopy
		mutate(&p)
		if _, err := repo.BulkMarkRead(ctx, p); err == nil {
			t.Errorf("%s：必须被拒绝", name)
		}
	}
	var unread int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_inbox WHERE tenant_id = $1 AND id = ANY($2) AND read_at IS NULL`, tenantID, inScope).Scan(&unread); err != nil || unread != 3 {
		t.Fatalf("被拒绝的请求不得改动任何消息：err=%v unread=%d", err, unread)
	}
	if _, err := repo.PreviewBulkRead(ctx, tenantID, "security_event", good.From, good.To); err == nil {
		t.Error("预览也不应对受保护类别开放")
	}
}

func TestBulkMarkReadDoesNotCrossTenants(t *testing.T) {
	db, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(db)
	ctx := context.Background()
	seedBulkFixture(t, db, tenantID)
	other := tenantID + "_o"
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$1,'enterprise','active', TRUE)`, other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, other) })
	seedInbox(t, db, other, inboxSeed{ID: "o1", Type: "alert", Severity: "warning", Title: "governor 事件：alert", At: mustTime(t, "2026-09-20T01:00:00Z")})
	auditID := "audit_x_" + tenantID
	t.Cleanup(func() { _, _ = db.Exec(ctx, `DELETE FROM audit_operations WHERE id = $1`, auditID) })

	if _, err := repo.BulkMarkRead(ctx, bulkParams(tenantID, 3, auditID)); err != nil {
		t.Fatal(err)
	}
	var readAt *time.Time
	if err := db.QueryRow(ctx, `SELECT read_at FROM alert_inbox WHERE id = 'o1'`).Scan(&readAt); err != nil || readAt != nil {
		t.Fatalf("别的租户的消息被标记已读了：err=%v read_at=%v", err, readAt)
	}
}

// 代码层保险：批量已读用到的 SQL 里，只允许出现 alert_inbox，且只允许更新 read_at；
// 任何人以后想往里加 alert_groups / security_events / DELETE，都会让这个测试失败并逼他回答“为什么”。
func TestBulkMarkReadSQLNeverTouchesAnythingElse(t *testing.T) {
	norm := func(sql string) string { return strings.ToLower(strings.Join(strings.Fields(sql), " ")) }
	for name, sql := range map[string]string{"update": bulkMarkReadUpdateSQL, "preview": bulkReadPreviewSQL, "audit": bulkReadAuditInsertSQL} {
		low := norm(sql)
		for _, banned := range []string{"alert_groups", "security_events", "delete ", "truncate", "drop ", "security_execution_mode", "security_audit_only"} {
			if strings.Contains(low, banned) {
				t.Errorf("%s SQL 不应出现 %q：%s", name, banned, sql)
			}
		}
	}
	low := norm(bulkMarkReadUpdateSQL)
	if !strings.Contains(low, "update alert_inbox set read_at") {
		t.Errorf("批量已读只能是 UPDATE alert_inbox SET read_at：%q", bulkMarkReadUpdateSQL)
	}
	// SET 子句里只有 read_at 一列：取 "set " 与 " where" 之间的文本
	setAt, whereAt := strings.Index(low, " set "), strings.Index(low, " where ")
	if setAt < 0 || whereAt < setAt {
		t.Fatalf("批量已读的 UPDATE 必须带 SET 与 WHERE：%q", bulkMarkReadUpdateSQL)
	}
	if set := strings.TrimSpace(low[setAt+5 : whereAt]); strings.Contains(set, ",") || !strings.HasPrefix(set, "read_at") {
		t.Errorf("SET 子句只能更新 read_at：%q", set)
	}
	for _, must := range []string{"tenant_id", "type =", "created_at >=", "created_at <", "read_at is null"} {
		if !strings.Contains(low, must) {
			t.Errorf("批量已读的 WHERE 必须带 %q：%s", must, bulkMarkReadUpdateSQL)
		}
	}
}

func TestBulkReadScopeSpanBoundary(t *testing.T) {
	to := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	if err := validateBulkReadScope("t1", "alert", to.AddDate(0, 0, -366), to); err != nil {
		t.Fatalf("刚好 366 天应允许：%v", err)
	}
	err := validateBulkReadScope("t1", "alert", to.AddDate(0, 0, -366).Add(-time.Second), to)
	if !errors.Is(err, ErrBulkReadInvalid) {
		t.Fatalf("超过 366 天应拒绝为 ErrBulkReadInvalid：%v", err)
	}
}

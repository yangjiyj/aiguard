package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestRecordQuotaAdmissionErrorCarriesOverrunFacts(t *testing.T) {
	var recorded governor.Decision
	record := func(_ context.Context, decision governor.Decision) { recorded = decision }

	recordQuotaAdmissionError(context.Background(), record, &governor.AdmissionOverrunError{RequestID: "r1", EstimatedTokens: 100, ActualTokens: 180})
	if recorded.TriggeredMetric != "reservation_overrun" || !recorded.AlertOnly || recorded.Estimated != 100 || recorded.Actual != 180 {
		t.Fatalf("token overrun decision=%+v", recorded)
	}

	recorded = governor.Decision{}
	recordQuotaAdmissionError(context.Background(), record, &governor.AdmissionCostOverrunError{RequestID: "r2", EstimatedMicros: 50, ActualMicros: 90})
	if recorded.TriggeredMetric != "cost_reservation_overrun" || !recorded.AlertOnly || recorded.Estimated != 50 || recorded.Actual != 90 {
		t.Fatalf("cost overrun decision=%+v", recorded)
	}
}

func TestQuotaOverrunGroupKeySeparatesTenantPrincipalModelMetricAndDay(t *testing.T) {
	shanghai := time.FixedZone("CST", 8*3600)
	lateNight := time.Date(2026, 10, 22, 23, 30, 0, 0, shanghai)
	nextDay := time.Date(2026, 10, 23, 0, 10, 0, 0, shanghai)
	env := &modelrouter.RequestEnvelope{TenantID: "t1", UserID: "u1", ClientID: "k1", Model: "gpt-x"}
	const tokenType = "quota.admission.reservation_overrun"
	base := quotaOverrunGroupKey(tokenType, env, lateNight)

	if base == quotaOverrunGroupKey(tokenType, env, nextDay) {
		t.Fatal("跨过本地零点后应换新的聚合组")
	}
	if base != quotaOverrunGroupKey(tokenType, env, lateNight.Add(10*time.Minute)) {
		t.Fatal("同一天内必须落在同一个聚合组")
	}
	if base == quotaOverrunGroupKey("quota.admission.cost_reservation_overrun", env, lateNight) {
		t.Fatal("token 与金额超出是两种事实，不能合并")
	}
	other := *env
	other.Model = "gpt-y"
	if base == quotaOverrunGroupKey(tokenType, &other, lateNight) {
		t.Fatal("不同模型必须分开")
	}
	other = *env
	other.UserID = "u2"
	if base == quotaOverrunGroupKey(tokenType, &other, lateNight) {
		t.Fatal("不同用户必须分开")
	}
	// 同一用户换 key 仍是同一个人，聚合到一起。
	other = *env
	other.ClientID = "k2"
	if base != quotaOverrunGroupKey(tokenType, &other, lateNight) {
		t.Fatal("同一用户的不同 key 应聚合")
	}
	// 没有用户身份时退回按 key 聚合。
	anonA := &modelrouter.RequestEnvelope{TenantID: "t1", ClientID: "k1", Model: "gpt-x"}
	anonB := &modelrouter.RequestEnvelope{TenantID: "t1", ClientID: "k2", Model: "gpt-x"}
	if quotaOverrunGroupKey(tokenType, anonA, lateNight) == quotaOverrunGroupKey(tokenType, anonB, lateNight) {
		t.Fatal("无用户身份时应按 key 区分")
	}
}

func setupQuotaOverrunAlertDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("BILLING_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("BILLING_TEST_DATABASE_URL is required for the overrun alert aggregation test")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	schema := fmt.Sprintf("quota_overrun_%d", time.Now().UnixNano())
	name := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+name); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+name+" CASCADE")
		admin.Close()
	})
	if _, err := db.Exec(ctx, `CREATE TABLE alert_inbox (
		id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL, severity VARCHAR(16) NOT NULL,
		type VARCHAR(64) NOT NULL, title VARCHAR(256) NOT NULL, body_json JSONB NOT NULL,
		target_url VARCHAR(512), read_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW())`); err != nil {
		t.Fatal(err)
	}
	return db, ctx
}

func fixedOverrunClock(t *testing.T, at time.Time) {
	t.Helper()
	previous := quotaOverrunNow
	quotaOverrunNow = func() time.Time { return at }
	t.Cleanup(func() { quotaOverrunNow = previous })
}

type overrunRow struct {
	Type     string
	Severity string
	Read     bool
	Body     map[string]any
}

func readOverrunRows(t *testing.T, db *pgxpool.Pool, ctx context.Context) []overrunRow {
	t.Helper()
	rows, err := db.Query(ctx, `SELECT type, severity, read_at IS NOT NULL, body_json FROM alert_inbox ORDER BY created_at, id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []overrunRow
	for rows.Next() {
		var row overrunRow
		var raw []byte
		if err := rows.Scan(&row.Type, &row.Severity, &row.Read, &raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &row.Body); err != nil {
			t.Fatal(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func numberField(t *testing.T, body map[string]any, key string) int64 {
	t.Helper()
	value, ok := body[key].(float64)
	if !ok {
		t.Fatalf("body[%q]=%v(%T), want number; body=%v", key, body[key], body[key], body)
	}
	return int64(value)
}

func overrunDecision(metric string, estimated, actual int64) governor.Decision {
	return governor.Decision{
		Action: governor.ActionAlert, AlertOnly: true, TriggeredMetric: metric,
		Reason: "actual token usage exceeded the conservative reservation", Estimated: estimated, Actual: actual,
	}
}

func TestQuotaOverrunAlertsAreAggregatedPerUserModelDay(t *testing.T) {
	db, ctx := setupQuotaOverrunAlertDB(t)
	shanghai := time.FixedZone("CST", 8*3600)
	fixedOverrunClock(t, time.Date(2026, 10, 22, 10, 0, 0, 0, shanghai))

	env := func(request string) *modelrouter.RequestEnvelope {
		return &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "u1", ClientID: "k1", KeyPrefix: "jg-abc", Model: "gpt-x", RequestID: request}
	}
	const tokenType = "quota.admission.reservation_overrun"
	for i, actual := range []int64{150, 400, 220} {
		recordGovernorEvent(ctx, db, overrunDecision("reservation_overrun", 100, actual), env(fmt.Sprintf("req-%d", i)), tokenType)
	}
	rows := readOverrunRows(t, db, ctx)
	if len(rows) != 1 {
		t.Fatalf("同一用户/模型/天的 3 次超出应只留 1 条通知, got %d", len(rows))
	}
	body := rows[0].Body
	if rows[0].Type != tokenType || rows[0].Severity != "warning" {
		t.Fatalf("type=%s severity=%s", rows[0].Type, rows[0].Severity)
	}
	if got := numberField(t, body, "occurrence_count"); got != 3 {
		t.Fatalf("occurrence_count=%d, want 3", got)
	}
	if got := numberField(t, body, "max_actual"); got != 400 {
		t.Fatalf("max_actual=%d, want 400", got)
	}
	if got := numberField(t, body, "max_estimated"); got != 100 {
		t.Fatalf("max_estimated=%d, want 100", got)
	}
	if got := numberField(t, body, "total_overrun"); got != 50+300+120 {
		t.Fatalf("total_overrun=%d, want 470", got)
	}
	if body["sample_request_id"] != "req-2" || body["model"] != "gpt-x" || body["user_id"] != "u1" {
		t.Fatalf("聚合维度/样本缺失: %v", body)
	}
	if body["reason"] != "actual token usage exceeded the conservative reservation" || body["triggered_metric"] != "reservation_overrun" {
		t.Fatalf("原有字段必须保留，前端据此显示: %v", body)
	}
	if body["first_seen_at"] == nil || body["last_seen_at"] == nil || body["group_key"] == nil {
		t.Fatalf("缺少聚合簿记字段: %v", body)
	}

	// 不同模型、不同用户、金额类事件各自单独成条：不同事实不能被合并掉。
	other := env("req-other-model")
	other.Model = "gpt-y"
	recordGovernorEvent(ctx, db, overrunDecision("reservation_overrun", 100, 130), other, tokenType)
	user2 := env("req-user2")
	user2.UserID, user2.ClientID = "u2", "k2"
	recordGovernorEvent(ctx, db, overrunDecision("reservation_overrun", 100, 130), user2, tokenType)
	recordGovernorEvent(ctx, db, overrunDecision("cost_reservation_overrun", 50, 90), env("req-cost"), "quota.admission.cost_reservation_overrun")
	if rows = readOverrunRows(t, db, ctx); len(rows) != 4 {
		t.Fatalf("不同模型/用户/类型应分别成条, got %d", len(rows))
	}
}

func TestQuotaOverrunAlertOpensNewDayAndReopensAfterRead(t *testing.T) {
	db, ctx := setupQuotaOverrunAlertDB(t)
	shanghai := time.FixedZone("CST", 8*3600)
	env := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "u1", ClientID: "k1", Model: "gpt-x", RequestID: "req"}
	const tokenType = "quota.admission.reservation_overrun"

	fixedOverrunClock(t, time.Date(2026, 10, 22, 23, 30, 0, 0, shanghai))
	recordGovernorEvent(ctx, db, overrunDecision("reservation_overrun", 100, 130), env, tokenType)
	fixedOverrunClock(t, time.Date(2026, 10, 23, 0, 10, 0, 0, shanghai))
	recordGovernorEvent(ctx, db, overrunDecision("reservation_overrun", 100, 130), env, tokenType)
	if rows := readOverrunRows(t, db, ctx); len(rows) != 2 {
		t.Fatalf("跨本地零点应新开一条, got %d", len(rows))
	}

	// 运维已读后再次发生：重新开一条，而不是悄悄并进已读的旧条。
	if _, err := db.Exec(ctx, `UPDATE alert_inbox SET read_at = NOW()`); err != nil {
		t.Fatal(err)
	}
	recordGovernorEvent(ctx, db, overrunDecision("reservation_overrun", 100, 130), env, tokenType)
	rows := readOverrunRows(t, db, ctx)
	if len(rows) != 3 {
		t.Fatalf("已读之后再发生应重新开一条, got %d", len(rows))
	}
	unread := 0
	for _, row := range rows {
		if !row.Read {
			unread++
			if got := numberField(t, row.Body, "occurrence_count"); got != 1 {
				t.Fatalf("新开的一条应从 1 计数, got %d", got)
			}
		}
	}
	if unread != 1 {
		t.Fatalf("unread=%d, want 1", unread)
	}
}

func TestOtherQuotaAdmissionEventsStillWriteOneRowEach(t *testing.T) {
	db, ctx := setupQuotaOverrunAlertDB(t)
	fixedOverrunClock(t, time.Now())
	env := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "u1", ClientID: "k1", Model: "gpt-x", RequestID: "req"}
	fault := governor.Decision{Action: governor.ActionAlert, AlertOnly: true, TriggeredMetric: "runtime_fault", Reason: "quota admission runtime fault"}
	for i := 0; i < 3; i++ {
		recordGovernorEvent(ctx, db, fault, env, "quota.admission.runtime_fault")
	}
	if rows := readOverrunRows(t, db, ctx); len(rows) != 3 {
		t.Fatalf("非超出类事件不得被聚合或吞掉, got %d 条, want 3", len(rows))
	}
}

func TestQuotaOverrunAlertConcurrentSameKeyWritesOneRowWith40Occurrences(t *testing.T) {
	db, ctx := setupQuotaOverrunAlertDB(t)
	fixedOverrunClock(t, time.Date(2026, 10, 22, 10, 0, 0, 0, time.FixedZone("CST", 8*3600)))
	const tokenType = "quota.admission.reservation_overrun"
	const writers = 40
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			env := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "u1", Model: "gpt-x", RequestID: fmt.Sprintf("req-%d", i)}
			recordQuotaOverrunAlert(ctx, db, overrunDecision("reservation_overrun", 100, int64(200+i)), env, tokenType)
		}(i)
	}
	wg.Wait()
	rows := readOverrunRows(t, db, ctx)
	if len(rows) != 1 {
		t.Fatalf("40 个并发同键写入应只留 1 行, got %d", len(rows))
	}
	if got := numberField(t, rows[0].Body, "occurrence_count"); got != writers {
		t.Fatalf("occurrence_count=%d, want %d", got, writers)
	}
	if got := numberField(t, rows[0].Body, "max_actual"); got != 200+writers-1 {
		t.Fatalf("max_actual=%d", got)
	}
}

// 容量为 1 的连接池 + 并发同键写：排队必须发生在拿连接之前，否则排队者会占着唯一的连接，
// 持锁者拿不到连接（死锁到超时）。这里每次写都带 3 秒超时，任何一次超时都算失败。
func TestQuotaOverrunAlertQueuesBeforeAcquiringConnection(t *testing.T) {
	db, ctx := setupQuotaOverrunAlertDB(t)
	small := newQuotaOverrunPoolWithMaxConns(t, ctx, db, 1)
	fixedOverrunClock(t, time.Date(2026, 10, 22, 10, 0, 0, 0, time.FixedZone("CST", 8*3600)))
	const tokenType = "quota.admission.reservation_overrun"
	env := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "u1", Model: "gpt-x", RequestID: "req"}
	groupKey := quotaOverrunGroupKey(tokenType, env, quotaOverrunNow())

	// 先占住该键的进程内队列，再发起同键写：排队者此时不得持有任何池连接。
	release, err := lockQuotaOverrunKey(ctx, env.TenantID+"\x1f"+groupKey)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		writeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		recordQuotaOverrunAlert(writeCtx, small, overrunDecision("reservation_overrun", 100, 150), env, tokenType)
	}()
	time.Sleep(300 * time.Millisecond)
	if acquired := small.Stat().AcquiredConns(); acquired != 0 {
		t.Fatalf("同键排队期间不应占用连接, AcquiredConns=%d", acquired)
	}
	select {
	case <-done:
		t.Fatal("键锁被占用时写入不应完成")
	default:
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("释放键锁后写入未完成")
	}

	// 并发同键写在 MaxConns=1 下全部成功，无获取连接超时。
	var wg sync.WaitGroup
	var failed int32
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			writeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			recordQuotaOverrunAlert(writeCtx, small, overrunDecision("reservation_overrun", 100, 150), env, tokenType)
			if writeCtx.Err() != nil {
				atomic.AddInt32(&failed, 1)
			}
		}()
	}
	wg.Wait()
	if failed != 0 {
		t.Fatalf("%d 次写入超时", failed)
	}
	rows := readOverrunRows(t, small, ctx)
	if len(rows) != 1 || numberField(t, rows[0].Body, "occurrence_count") != 41 {
		t.Fatalf("rows=%d, 期望 1 行 occurrence_count=41", len(rows))
	}
}

func TestQuotaOverrunAlertRefreshesCreatedAtOnlyAfterThrottleWindow(t *testing.T) {
	db, ctx := setupQuotaOverrunAlertDB(t)
	start := time.Date(2026, 10, 22, 10, 0, 0, 0, time.FixedZone("CST", 8*3600))
	const tokenType = "quota.admission.reservation_overrun"
	env := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "u1", Model: "gpt-x", RequestID: "req"}
	createdAt := func() time.Time {
		var at time.Time
		if err := db.QueryRow(ctx, `SELECT created_at FROM alert_inbox`).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	write := func(at time.Time) {
		fixedOverrunClock(t, at)
		recordQuotaOverrunAlert(ctx, db, overrunDecision("reservation_overrun", 100, 150), env, tokenType)
	}
	write(start)
	write(start.Add(10 * time.Second))
	if got := createdAt(); !got.Equal(start) {
		t.Fatalf("窗口内的更新不应改 created_at(保 HOT), got %v", got)
	}
	later := start.Add(quotaOverrunCreatedAtRefreshInterval + time.Second)
	write(later)
	if got := createdAt(); !got.Equal(later) {
		t.Fatalf("超过窗口后应把 created_at 刷到最近发生时间 %v, got %v", later, got)
	}
}

func newQuotaOverrunPoolWithMaxConns(t *testing.T, ctx context.Context, base *pgxpool.Pool, maxConns int32) *pgxpool.Pool {
	t.Helper()
	cfg := base.Config().Copy()
	cfg.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

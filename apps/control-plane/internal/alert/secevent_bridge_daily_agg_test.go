package alert

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// aggUpsert 记录一次 UpsertByGroup 调用的全部客户可见要素,供断言聚合卡形状。
type aggUpsert struct {
	severity string
	typ      string
	title    string
	groupKey string
	body     map[string]any
}

// fakeAggPusher 与 fakeDedupPusher 同折叠语义(组键首次 created=true),
// 额外记录 type/title/body,用于校验日聚合卡的类型与中文文案。
type fakeAggPusher struct {
	upserts   []aggUpsert
	counts    map[string]int
	pushCalls int
}

func (f *fakeAggPusher) Push(ctx context.Context, tenantID, severity, typ, title string, body map[string]any, targetURL string) error {
	f.pushCalls++
	return nil
}

func (f *fakeAggPusher) UpsertByGroup(ctx context.Context, tenantID, severity, typ, title string, body map[string]any, targetURL, groupKey string) (bool, error) {
	if f.counts == nil {
		f.counts = map[string]int{}
	}
	f.counts[groupKey]++
	f.upserts = append(f.upserts, aggUpsert{severity: severity, typ: typ, title: title, groupKey: groupKey, body: body})
	return f.counts[groupKey] == 1, nil
}

type fakeRuleDailyCounter struct {
	counts []repository.SecurityEventRuleDailyCount
	calls  int
	err    error
}

func (f *fakeRuleDailyCounter) CountAlertableDaily(ctx context.Context, tenantIDs []string, from, to time.Time) ([]repository.SecurityEventRuleDailyCount, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.counts, nil
}

// aggBridge 构造一个显式设定单规则日上限的桥,不依赖环境变量。
func aggBridge(src secEventSource, inbox secInboxPusher, notifier secNotifier, limit int, counter *fakeRuleDailyCounter) *SecEventBridge {
	b := gateBridge(src, inbox, notifier, 0.5)
	b.ruleDailyLimit = limit
	return b.WithRuleDailyCounts(counter)
}

// dailyEventRule 构造一条走「findings[0].rule_id」维度的高置信审计事件。
func dailyEventRule(id, ruleID string, at time.Time) *repository.SecurityEvent {
	ev := secEventWithFindings(id, "audit", map[string]any{
		"confidence": 0.9, "rule_id": ruleID, "type": "custom",
	})
	ev.CreatedAt = at
	return ev
}

var aggDay = time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)

func TestSecEventBridge_DailyLimitRoutesToSummaryCard(t *testing.T) {
	// 当日该维度事件数(DB 锚定计数=5)已超上限(2)→ 后续事件不再逐条进收件箱,
	// 改投一张按日折叠的聚合卡;卡首建时通知一次,再次命中只折叠。
	counter := &fakeRuleDailyCounter{counts: []repository.SecurityEventRuleDailyCount{
		{TenantID: "tenant_x", Day: "2026-07-01", Dimension: "rule_hf", Count: 5},
	}}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		dailyEventRule("d1", "rule_hf", aggDay),
		dailyEventRule("d2", "rule_hf", aggDay.Add(time.Minute)),
	}}
	pusher := &fakeAggPusher{}
	notifier := &fakeNotifier{}

	n, err := aggBridge(src, pusher, notifier, 2, counter).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 new inbox alert (the summary card), got %d", n)
	}
	if len(pusher.upserts) != 2 {
		t.Fatalf("expected both events folded onto the daily card, got %d upserts", len(pusher.upserts))
	}
	wantKey := "daily_agg|rule_hf|2026-07-01"
	for _, u := range pusher.upserts {
		if u.groupKey != wantKey {
			t.Fatalf("daily card group key = %q, want %q", u.groupKey, wantKey)
		}
		if u.typ != "security_event_daily_summary" {
			t.Fatalf("daily card type = %q, want security_event_daily_summary", u.typ)
		}
		if !strings.Contains(u.title, "当日累计") || strings.Contains(u.title, "daily") {
			t.Fatalf("daily card title must be Chinese with累计数, got %q", u.title)
		}
		if u.body["daily_count"] != 5 {
			t.Fatalf("daily card body daily_count = %v, want 5", u.body["daily_count"])
		}
		if u.body["dimension"] != "rule_hf" || u.body["date"] != "2026-07-01" {
			t.Fatalf("daily card body missing dimension/date: %+v", u.body)
		}
	}
	if notifier.calls != 1 {
		t.Fatalf("expected exactly 1 external notify (card creation only), got %d", notifier.calls)
	}
	if len(src.markedIDs) != 1 || len(src.markedIDs[0]) != 2 {
		t.Fatalf("expected both events marked alerted, got %v", src.markedIDs)
	}
	if counter.calls != 1 {
		t.Fatalf("expected one grouped count query per tick, got %d", counter.calls)
	}
}
func TestSecEventBridge_DailyLimitEnforcementNotAggregated(t *testing.T) {
	// 数据面动过手的事件必须逐条可审计,不折叠进日聚合卡。
	ev := dailyEventRule("dblk", "rule_hf", aggDay)
	ev.ActionTaken = "block"
	counter := &fakeRuleDailyCounter{counts: []repository.SecurityEventRuleDailyCount{
		{TenantID: "tenant_x", Day: "2026-07-01", Dimension: "rule_hf", Count: 99},
	}}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakeAggPusher{}

	n, err := aggBridge(src, pusher, &fakeNotifier{}, 2, counter).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.upserts) != 1 || pusher.upserts[0].typ != "security_event" {
		t.Fatalf("expected enforcement event surfaced individually, got n=%d upserts=%+v", n, pusher.upserts)
	}
}

func TestSecEventBridge_DailyDimensionFallbackChain(t *testing.T) {
	// 维度使用主导 finding；旧顶层 category 不能覆盖结构化风险的维度;
	// 两者皆缺 → 不聚合,照常逐条。
	evCat := dailyEventRule("dcat", "rule_ignored", aggDay)
	evCat.MatchedSummary["category"] = "cat_top"
	evRule := dailyEventRule("drule", "rule_y", aggDay)
	evNone := secEventWithFindings("dnone", "audit", map[string]any{"confidence": 0.9, "type": "custom"})
	evNone.CreatedAt = aggDay
	counter := &fakeRuleDailyCounter{counts: []repository.SecurityEventRuleDailyCount{
		{TenantID: "tenant_x", Day: "2026-07-01", Dimension: "cat_top", Count: 9},
		{TenantID: "tenant_x", Day: "2026-07-01", Dimension: "rule_y", Count: 9},
		{TenantID: "tenant_x", Day: "2026-07-01", Dimension: "rule_ignored", Count: 9},
	}}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{evCat, evRule, evNone}}
	pusher := &fakeAggPusher{}

	if _, err := aggBridge(src, pusher, &fakeNotifier{}, 2, counter).RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(pusher.upserts) != 3 {
		t.Fatalf("expected 3 inbox upserts, got %d", len(pusher.upserts))
	}
	if pusher.upserts[0].groupKey != "daily_agg|rule_ignored|2026-07-01" {
		t.Fatalf("dominant finding must own the dimension instead of stale top-level category, got %q", pusher.upserts[0].groupKey)
	}
	if pusher.upserts[1].groupKey != "daily_agg|rule_y|2026-07-01" {
		t.Fatalf("missing category must fall back to findings[0].rule_id, got %q", pusher.upserts[1].groupKey)
	}
	if strings.HasPrefix(pusher.upserts[2].groupKey, "daily_agg|") || pusher.upserts[2].typ != "security_event" {
		t.Fatalf("event without dimension must not aggregate, got %+v", pusher.upserts[2])
	}
}

func TestSecEventBridge_DailyLimitZeroDisabled(t *testing.T) {
	// SECEVENT_RULE_DAILY_LIMIT=0(默认)→ 聚合闸关闭,连计数查询都不发。
	counter := &fakeRuleDailyCounter{counts: []repository.SecurityEventRuleDailyCount{
		{TenantID: "tenant_x", Day: "2026-07-01", Dimension: "rule_hf", Count: 999},
	}}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{dailyEventRule("doff", "rule_hf", aggDay)}}
	pusher := &fakeAggPusher{}

	n, err := aggBridge(src, pusher, &fakeNotifier{}, 0, counter).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if counter.calls != 0 {
		t.Fatalf("expected no count query when disabled, got %d", counter.calls)
	}
	if n != 1 || len(pusher.upserts) != 1 || pusher.upserts[0].typ != "security_event" {
		t.Fatalf("expected normal per-event alert when disabled, got n=%d upserts=%+v", n, pusher.upserts)
	}
}

func TestSecEventBridge_DailyBelowLimitStaysPerEvent(t *testing.T) {
	// 计数未超上限(count <= limit)→ 照常逐条。
	counter := &fakeRuleDailyCounter{counts: []repository.SecurityEventRuleDailyCount{
		{TenantID: "tenant_x", Day: "2026-07-01", Dimension: "rule_hf", Count: 2},
	}}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{dailyEventRule("dlow", "rule_hf", aggDay)}}
	pusher := &fakeAggPusher{}

	n, err := aggBridge(src, pusher, &fakeNotifier{}, 2, counter).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.upserts) != 1 || pusher.upserts[0].typ != "security_event" {
		t.Fatalf("expected per-event alert below limit, got n=%d upserts=%+v", n, pusher.upserts)
	}
}

func TestSecEventBridge_DailyCountErrorFailsOpen(t *testing.T) {
	// 计数查询失败 → fail open:照常逐条,绝不因统计故障丢告警。
	counter := &fakeRuleDailyCounter{err: errors.New("db down")}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{dailyEventRule("derr", "rule_hf", aggDay)}}
	pusher := &fakeAggPusher{}

	n, err := aggBridge(src, pusher, &fakeNotifier{}, 2, counter).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.upserts) != 1 || pusher.upserts[0].typ != "security_event" {
		t.Fatalf("expected fail-open per-event alert on count error, got n=%d upserts=%+v", n, pusher.upserts)
	}
}

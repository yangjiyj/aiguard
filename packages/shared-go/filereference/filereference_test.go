package filereference

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSettingKeyMatchesControlPlaneTenantKey(t *testing.T) {
	if SettingKey("") != "content_file_policy_json" || SettingKey("tenant_default") != "content_file_policy_json" {
		t.Fatal("默认租户沿用旧键")
	}
	// 与 control-plane contentFilePolicySettingKeyForTenant 同算法：键 + ":" + hex(sha256(tenant))。
	sum := sha256.Sum256([]byte("tenant-a"))
	if got, want := SettingKey("tenant-a"), "content_file_policy_json:"+hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("租户键 %s，期望 %s", got, want)
	}
}

func TestParsePolicyDefaultsToAlertAllow(t *testing.T) {
	site := `{"allowed_types":["pdf","png"],"max_file_mb":100,"max_zip_ratio":100,"max_attachments":10}`
	for _, raw := range []string{"", site, "not-json", `{"unverified_file_reference_action":"deny"}`} {
		p := ParsePolicy(raw)
		if p.Unverified != AlertAllow || p.LookupFailure != AlertAllow {
			t.Fatalf("%q 缺省应为告警放行：%+v", raw, p)
		}
	}
	p := ParsePolicy(`{"unverified_file_reference_action":"block","file_reference_lookup_failure_action":"allow"}`)
	if p.Unverified != Block || p.LookupFailure != Allow {
		t.Fatalf("配置未生效：%+v", p)
	}
}

func TestDecideFollowsVerdictAndPolicy(t *testing.T) {
	lookupErr := errors.New("engine unavailable")
	for _, tc := range []struct {
		status string
		err    error
		policy Policy
		action string
		reason string
	}{
		{"allow", nil, DefaultPolicy(), Allow, ""},
		{"block", nil, Policy{Unverified: Allow, LookupFailure: Allow}, Block, ReasonVerdictBlock},
		{"pending", nil, DefaultPolicy(), AlertAllow, ReasonPending},
		{"not_found", nil, DefaultPolicy(), AlertAllow, ReasonNotFound},
		{"", nil, DefaultPolicy(), AlertAllow, ReasonNotFound},
		{"pending", nil, Policy{Unverified: Block, LookupFailure: AlertAllow}, Block, ReasonPending},
		{"not_found", nil, Policy{Unverified: Allow, LookupFailure: Block}, Allow, ReasonNotFound},
		{"", lookupErr, DefaultPolicy(), AlertAllow, ReasonLookupFailed},
		{"", lookupErr, Policy{Unverified: AlertAllow, LookupFailure: Block}, Block, ReasonLookupFailed},
	} {
		got := Decide(tc.status, tc.err, tc.policy)
		if got.Action != tc.action || got.Reason != tc.reason {
			t.Fatalf("status=%q err=%v policy=%+v → %+v，期望 %s/%s", tc.status, tc.err, tc.policy, got, tc.action, tc.reason)
		}
		if got.Reason != "" && got.Message == "" {
			t.Fatalf("拦截或告警必须写明原因：%+v", got)
		}
	}
}

func TestCachedReaderUsesTenantKeyAndTTL(t *testing.T) {
	var calls atomic.Int32
	var lastKey atomic.Value
	reader := NewCachedReader(func(_ context.Context, key string) (string, bool, error) {
		calls.Add(1)
		lastKey.Store(key)
		return `{"unverified_file_reference_action":"block"}`, true, nil
	}, time.Minute)
	if p := reader.Policy(context.Background(), "tenant-a"); p.Unverified != Block {
		t.Fatalf("未读到租户配置：%+v", p)
	}
	_ = reader.Policy(context.Background(), "tenant-a")
	if calls.Load() != 1 || lastKey.Load() != SettingKey("tenant-a") {
		t.Fatalf("应按租户键读一次并缓存：calls=%d key=%v", calls.Load(), lastKey.Load())
	}
}

func TestCachedReaderKeepsLastGoodAndDefaultsOnFailure(t *testing.T) {
	fail := atomic.Bool{}
	reader := NewCachedReader(func(context.Context, string) (string, bool, error) {
		if fail.Load() {
			return "", false, errors.New("db down")
		}
		return `{"file_reference_lookup_failure_action":"block"}`, true, nil
	}, time.Nanosecond)
	if p := reader.Policy(context.Background(), "t"); p.LookupFailure != Block {
		t.Fatalf("初次读取失败：%+v", p)
	}
	fail.Store(true)
	time.Sleep(time.Millisecond)
	if p := reader.Policy(context.Background(), "t"); p.LookupFailure != Block {
		t.Fatalf("读取失败应保留上次值：%+v", p)
	}
	fresh := NewCachedReader(func(context.Context, string) (string, bool, error) { return "", false, errors.New("db down") }, time.Minute)
	if p := fresh.Policy(context.Background(), "t"); p != DefaultPolicy() {
		t.Fatalf("从未读到时取缺省：%+v", p)
	}
	var nilReader *CachedReader
	if p := nilReader.Policy(context.Background(), "t"); p != DefaultPolicy() {
		t.Fatalf("nil 读取器取缺省：%+v", p)
	}
}

// 客户端断开不该让策略读取失败：读取与请求生命周期脱钩，只受读取器自己的超时约束。
func TestCachedReaderIgnoresCallerCancellation(t *testing.T) {
	reader := NewCachedReader(func(ctx context.Context, _ string) (string, bool, error) {
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Error("读取必须带超时")
		}
		return `{"unverified_file_reference_action":"block"}`, true, nil
	}, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p := reader.Policy(ctx, "t"); p.Unverified != Block {
		t.Fatalf("调用方已取消时仍应读到租户配置：%+v", p)
	}
}

// 复审第四轮改动：原断言“超时结果不写缓存、下一次立刻重读”。改为超时结果只短缓存 5 秒：
// 5 秒内按缺省（或上次值）不再卡请求，过了 5 秒重新读，而不是在整个 TTL 内都用缺省。
func TestCachedReaderCachesTimeoutBriefly(t *testing.T) {
	var calls atomic.Int32
	reader := NewCachedReader(func(ctx context.Context, _ string) (string, bool, error) {
		if calls.Add(1) == 1 {
			<-ctx.Done()
			return "", false, ctx.Err()
		}
		return `{"unverified_file_reference_action":"block"}`, true, nil
	}, time.Minute)
	reader.timeout = 20 * time.Millisecond
	now := time.Now()
	reader.now = func() time.Time { return now }
	if p := reader.Policy(context.Background(), "t"); p != DefaultPolicy() {
		t.Fatalf("超时且从未读到时取缺省：%+v", p)
	}
	now = now.Add(4 * time.Second)
	if p := reader.Policy(context.Background(), "t"); p != DefaultPolicy() || calls.Load() != 1 {
		t.Fatalf("5 秒内不再读库：policy=%+v calls=%d", p, calls.Load())
	}
	now = now.Add(2 * time.Second)
	if p := reader.Policy(context.Background(), "t"); p.Unverified != Block || calls.Load() != 2 {
		t.Fatalf("过了 5 秒重新读：policy=%+v calls=%d", p, calls.Load())
	}
}

// 读取 panic 时清掉在途占位：调用方拿到缺省，等待者不被卡住，之后照常读。
func TestCachedReaderLoadPanicReleasesInflight(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	reader := NewCachedReader(func(context.Context, string) (string, bool, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
			panic("driver bug")
		}
		return `{"unverified_file_reference_action":"block"}`, true, nil
	}, time.Minute)
	now := time.Now()
	reader.now = func() time.Time { return now }
	first := make(chan Policy, 1)
	go func() { first <- reader.Policy(context.Background(), "t") }()
	<-entered
	waiter := make(chan Policy, 1)
	go func() { waiter <- reader.Policy(context.Background(), "t") }()
	time.Sleep(10 * time.Millisecond)
	close(release)
	for name, ch := range map[string]chan Policy{"读取方": first, "等待者": waiter} {
		select {
		case p := <-ch:
			if p != DefaultPolicy() {
				t.Fatalf("%s 应拿到缺省：%+v", name, p)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s 被 panic 留下的占位卡住", name)
		}
	}
	reader.mu.Lock()
	inflight := len(reader.inflight)
	reader.mu.Unlock()
	if inflight != 0 {
		t.Fatalf("占位没清：%d", inflight)
	}
	now = now.Add(6 * time.Second)
	if p := reader.Policy(context.Background(), "t"); p.Unverified != Block {
		t.Fatalf("panic 之后照常读：%+v", p)
	}
}

// 同一租户缓存过期时的并发请求只读一次库。
func TestCachedReaderMergesConcurrentLoads(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	reader := NewCachedReader(func(context.Context, string) (string, bool, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return `{"file_reference_lookup_failure_action":"block"}`, true, nil
	}, time.Minute)
	const n = 8
	results := make(chan Policy, n)
	go func() { results <- reader.Policy(context.Background(), "t") }()
	<-entered
	for i := 1; i < n; i++ {
		go func() { results <- reader.Policy(context.Background(), "t") }()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	for i := 0; i < n; i++ {
		if p := <-results; p.LookupFailure != Block {
			t.Fatalf("合并读取的结果不对：%+v", p)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("并发请求应只读一次库：calls=%d", calls.Load())
	}
}

// 网关和独立代理写进命中记录的形态来自同一张表。
func TestOutcomeFindingShape(t *testing.T) {
	policy := Policy{Unverified: Block, LookupFailure: AlertAllow}
	cases := []struct {
		outcome  Outcome
		category string
		ruleID   string
		action   string
	}{
		{Decide("block", nil, policy), "file_id_verdict_block", "file-id-verdict-block", "block"},
		{Decide("pending", nil, policy), "file_id_unverified", "file-id-unverified", "block"},
		{Decide("", nil, policy), "file_id_unverified", "file-id-unverified", "block"},
		{Decide("", errors.New("down"), policy), "file_id_lookup_failed", "file-id-lookup-failed", "alert"},
	}
	for _, tc := range cases {
		got := tc.outcome.Finding()
		if got.Category != tc.category || got.RuleID != tc.ruleID || got.Action != tc.action || got.RuleName == "" || got.Severity != "high" {
			t.Fatalf("%+v → %+v", tc.outcome, got)
		}
	}
	if (Outcome{Action: Allow}).Finding() != (Finding{}) {
		t.Fatal("放行没有命中")
	}
}

// 复审追加：未经扫描的文件引用（file-id-unverified）先过内容例外；查询失败（file-id-lookup-failed）
// 是故障类，检测结论阻断是引擎已按策略算出的结论，都不过例外。
func TestOutcomeExceptionEligibility(t *testing.T) {
	policy := Policy{Unverified: Block, LookupFailure: Block}
	for _, tc := range []struct {
		outcome Outcome
		want    bool
	}{
		{Decide("", nil, policy), true},
		{Decide("pending", nil, policy), true},
		{Decide("", errors.New("down"), policy), false},
		{Decide("block", nil, policy), false},
		{Decide("", nil, Policy{Unverified: Allow, LookupFailure: Allow}), false},
	} {
		if got := tc.outcome.ExceptionEligible(); got != tc.want {
			t.Errorf("%+v eligible=%v want %v", tc.outcome, got, tc.want)
		}
	}
}

// 命中例外：不拦不告警、只记录（命中动作 audit，带例外编号）。
func TestOutcomeWithExceptionRecordsOnly(t *testing.T) {
	outcome := Decide("", nil, Policy{Unverified: Block, LookupFailure: AlertAllow})
	if !outcome.Blocks() {
		t.Fatal("没有例外时按 block 拦")
	}
	exempted := outcome.WithException("e-1")
	if exempted.Blocks() {
		t.Fatal("命中例外不拦")
	}
	finding := exempted.Finding()
	if finding.Action != "audit" || finding.ExceptionID != "e-1" || finding.RuleID != "file-id-unverified" {
		t.Fatalf("命中例外只记录：%+v", finding)
	}
}

// 送引擎过例外的原始命中形态（引擎 /apply-context/ 严格校验字段）。
func TestOutcomeExceptionProbeShape(t *testing.T) {
	probe := Decide("", nil, Policy{Unverified: Block, LookupFailure: Block}).ExceptionProbe()
	want := map[string]any{
		"type": "file", "category": "file_id_unverified", "severity": "high", "rule_id": "file-id-unverified",
		"rule_name": "未经扫描的文件引用", "rule_type": "file_reference", "action": "block",
		"matched_text_preview": "引用的文件没有安全检测记录", "redacted_evidence": "引用的文件没有安全检测记录",
		"evidence_reason": "引用的文件没有安全检测记录", "matched_location": "file_reference",
	}
	if len(probe) != len(want) {
		t.Fatalf("probe=%v", probe)
	}
	for key, value := range want {
		if probe[key] != value {
			t.Fatalf("%s=%v want %v", key, probe[key], value)
		}
	}
}

// 合流前次要项：收住 panic 的日志带调用栈，便于排查。
func TestCachedReaderLoadPanicLogsStack(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	reader := NewCachedReader(func(context.Context, string) (string, bool, error) { panic("driver bug") }, time.Minute)
	if p := reader.Policy(context.Background(), "t"); p != DefaultPolicy() {
		t.Fatalf("panic 后取缺省：%+v", p)
	}
	if !strings.Contains(buf.String(), "driver bug") || !strings.Contains(buf.String(), "goroutine ") {
		t.Fatalf("panic 日志应带调用栈：%s", buf.String())
	}
}

// 合流前次要项：一次请求里所有该过例外的命中合成一次引擎调用，按序号把结果对回。
func TestExceptionBatchProbesAndApply(t *testing.T) {
	block := Policy{Unverified: Block, LookupFailure: Block}
	first, second, failed := Decide("", nil, block), Decide("pending", nil, block), Decide("", errors.New("down"), block)
	var batch ExceptionBatch
	for _, outcome := range []*Outcome{&first, &failed, &second} {
		batch.Add(outcome)
	}
	if batch.Len() != 2 || !batch.Blocking() {
		t.Fatalf("只收可过例外的两条，且含阻断：len=%d blocking=%v", batch.Len(), batch.Blocking())
	}
	probes := batch.Probes()
	if len(probes) != 2 || probes[0]["attachment_index"] != 0 || probes[1]["attachment_index"] != 1 {
		t.Fatalf("probes=%v", probes)
	}
	one := 1
	batch.Apply([]ExceptionResult{{RuleID: "file-id-unverified", AttachmentIndex: &one, ExceptionID: "e-2"}})
	if first.ExceptionID != "" || second.ExceptionID != "e-2" || !first.Blocks() || second.Blocks() {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	if first.NeedsExceptionCheck() || second.NeedsExceptionCheck() {
		t.Fatal("核对过的不再核对")
	}
	var again ExceptionBatch
	again.Add(&first)
	if again.Len() != 0 {
		t.Fatal("核对过的不再进批次")
	}
}

// 引擎调不通或超时：整批按文件策略原处置，且本次请求里不再重试。
func TestExceptionBatchFailureKeepsDisposition(t *testing.T) {
	outcome := Decide("", nil, Policy{Unverified: Block, LookupFailure: Block})
	var batch ExceptionBatch
	batch.Add(&outcome)
	batch.Apply(nil)
	if !outcome.Blocks() || outcome.NeedsExceptionCheck() {
		t.Fatalf("outcome=%+v", outcome)
	}
	if ExceptionCheckTimeout != 2*time.Second {
		t.Fatalf("例外核对超时应为 2 秒：%s", ExceptionCheckTimeout)
	}
}

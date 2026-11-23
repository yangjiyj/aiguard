package handler

// 复审 M-5：record 模式下红线命中写 security_events 会放大写入量（每次调用一条）。
// 复用仓库已有的「代表事件 + 窗口内重复折叠为 occurrence」框架：首次命中写完整 security_events；
// 同一 (租户, server, 工具, 红线规则集, 处置) 在窗口内的重复只写幂等 occurrence 行（告警组建立后计数 +1）。
// 要求：首次一定写、计数准确；tool_call_logs 逐条审计不受影响；真正的阻断/确认等高价值事件绝不折叠。

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

func redlineDecision(tool string, rules ...string) mcpToolCallDecision {
	d := mcpToolCallDecision{
		Qualified: tool, MCPServerID: "srv1",
		Decision: agentguard.Decision{RawDecision: agentguard.DecisionAudit, EffectiveDecision: agentguard.DecisionAudit, Mode: agentguard.ModeLight},
	}
	for _, r := range rules {
		d.Decision.Evidence = append(d.Decision.Evidence, agentguard.Evidence{RuleID: "mcp_redline_" + r, Category: "mcp_redline"})
	}
	return d
}

func countExecs(tx *fakeMCPAuditTx, substr string) int {
	n := 0
	for _, s := range tx.execedSQL {
		if strings.Contains(s, substr) {
			n++
		}
	}
	return n
}

func newDedupRecorder(now *time.Time, window time.Duration) (*mcpProxyAuditRecorder, *fakeMCPAuditDB) {
	db := newFakeAuditDB()
	rec := &mcpProxyAuditRecorder{db: db}
	rec.redlineDedupe = newMCPRedlineEventDedupe(window)
	rec.redlineDedupe.now = func() time.Time { return *now }
	return rec, db
}

func TestM5_FirstRedlineHitIsAlwaysAFullSecurityEvent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rec, db := newDedupRecorder(&now, 10*time.Minute)
	ds := []mcpToolCallDecision{redlineDecision("demo__echo", "pii")}
	if err := rec.writeMCPProxyAuditTx(context.Background(), mcpBlockRecord(), ds, true); err != nil {
		t.Fatal(err)
	}
	if got := countExecs(db.tx, "INSERT INTO security_events"); got != 1 {
		t.Fatalf("首次命中必须写完整 security_events，实际 %d", got)
	}
}

func TestM5_RepeatsInsideWindowFoldIntoOccurrencesWithAccurateCount(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rec, db := newDedupRecorder(&now, 10*time.Minute)
	ctx := context.Background()
	ds := func() []mcpToolCallDecision { return []mcpToolCallDecision{redlineDecision("demo__echo", "pii")} }
	for i := 0; i < 50; i++ {
		now = now.Add(time.Second)
		r := mcpBlockRecord()
		r.RequestID = "req_" + string(rune('a'+i%26)) + time.Duration(i).String()
		if err := rec.writeMCPProxyAuditTx(ctx, r, ds(), true); err != nil {
			t.Fatal(err)
		}
	}
	// 注意 fake tx 每次 Begin 返回同一个 tx，累计记录全部语句
	full := countExecs(db.tx, "INSERT INTO security_events")
	occ := countExecs(db.tx, "INSERT INTO security_event_occurrences")
	if full != 1 {
		t.Fatalf("窗口内 50 次相同红线命中只应有 1 条完整事件，实际 %d", full)
	}
	if occ != 49 {
		t.Fatalf("其余 49 次必须各记一条 occurrence（计数准确），实际 %d", occ)
	}
}

func TestM5_NewWindowOpensAFreshRepresentativeEvent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rec, db := newDedupRecorder(&now, 10*time.Minute)
	ctx := context.Background()
	ds := []mcpToolCallDecision{redlineDecision("demo__echo", "pii")}
	_ = rec.writeMCPProxyAuditTx(ctx, mcpBlockRecord(), ds, true)
	now = now.Add(11 * time.Minute)
	r := mcpBlockRecord()
	r.RequestID = "req_next_window"
	_ = rec.writeMCPProxyAuditTx(ctx, r, ds, true)
	if got := countExecs(db.tx, "INSERT INTO security_events"); got != 2 {
		t.Fatalf("窗口过期后应重新写一条完整事件，实际 %d", got)
	}
}

func TestM5_DifferentToolOrRuleOrServerAreNotFolded(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rec, db := newDedupRecorder(&now, 10*time.Minute)
	ctx := context.Background()
	write := func(id string, d mcpToolCallDecision) {
		r := mcpBlockRecord()
		r.RequestID = id
		if err := rec.writeMCPProxyAuditTx(ctx, r, []mcpToolCallDecision{d}, true); err != nil {
			t.Fatal(err)
		}
	}
	write("r1", redlineDecision("demo__echo", "pii"))
	write("r2", redlineDecision("demo__other", "pii"))    // 不同工具
	write("r3", redlineDecision("demo__echo", "api_key")) // 不同红线规则
	other := redlineDecision("demo__echo", "pii")
	other.MCPServerID = "srv2"
	write("r4", other) // 不同 server
	if got := countExecs(db.tx, "INSERT INTO security_events"); got != 4 {
		t.Fatalf("不同工具/规则/server 各自首次命中都必须完整写，实际 %d", got)
	}
}

func TestM5_RealEnforcementAndHighValueEventsAreNeverFolded(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rec, db := newDedupRecorder(&now, 10*time.Minute)
	ctx := context.Background()
	// 真实阻断（非 record 模式）
	for i := 0; i < 3; i++ {
		r := mcpBlockRecord()
		r.RequestID = "blk" + time.Duration(i).String()
		_ = rec.writeMCPProxyAuditTx(ctx, r, []mcpToolCallDecision{mcpBlockDecision("demo__delete_repo")}, false)
	}
	// record 模式下的 raw=block 也不折叠（它不是纯红线信号）
	for i := 0; i < 3; i++ {
		r := mcpBlockRecord()
		r.RequestID = "rawblk" + time.Duration(i).String()
		d := mcpBlockDecision("demo__rm")
		d.Decision.EffectiveDecision = agentguard.DecisionAudit
		_ = rec.writeMCPProxyAuditTx(ctx, r, []mcpToolCallDecision{d}, true)
	}
	if got := countExecs(db.tx, "INSERT INTO security_events"); got != 6 {
		t.Fatalf("真实阻断与 record 下的 raw=block 每次都必须完整写，实际 %d/6", got)
	}
	if occ := countExecs(db.tx, "INSERT INTO security_event_occurrences"); occ != 0 {
		t.Fatalf("高价值事件不得被折叠成 occurrence: %d", occ)
	}
}

func TestM5_DedupeIsDisabledWhenWindowIsZeroAndFailuresNeverDropRecords(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rec, db := newDedupRecorder(&now, 0)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		r := mcpBlockRecord()
		r.RequestID = "z" + time.Duration(i).String()
		_ = rec.writeMCPProxyAuditTx(ctx, r, []mcpToolCallDecision{redlineDecision("demo__echo", "pii")}, true)
	}
	if got := countExecs(db.tx, "INSERT INTO security_events"); got != 3 {
		t.Fatalf("窗口为 0 表示关闭去重，应逐条写: %d", got)
	}
	// occurrence 写失败不能丢事件：回退为完整事件
	rec2, db2 := newDedupRecorder(&now, 10*time.Minute)
	ds := []mcpToolCallDecision{redlineDecision("demo__echo", "pii")}
	_ = rec2.writeMCPProxyAuditTx(ctx, mcpBlockRecord(), ds, true)
	db2.tx.failSubstr = "security_event_occurrences"
	r := mcpBlockRecord()
	r.RequestID = "after_fail"
	if err := rec2.writeMCPProxyAuditTx(ctx, r, ds, true); err == nil {
		t.Fatalf("occurrence 写失败应让事务回滚并报错，不得静默丢记录")
	}
}

func TestM5_ToolCallLogsRemainPerCallRegardlessOfEventFolding(t *testing.T) {
	// 折叠只发生在 security_events 层；buildMCPToolAuditPayloads 对每次调用仍各产生审计载荷。
	for i := 0; i < 5; i++ {
		d := redlineDecision("demo__echo", "pii")
		if got := buildMCPToolAuditPayloads(&d); len(got) == 0 {
			t.Fatalf("每次调用都必须有 tool_call_logs 载荷")
		}
	}
}

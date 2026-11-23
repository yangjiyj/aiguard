package handler

// 幸存项 7 回归：MCP 审计写入事务化。
// 目标——① request_logs upsert 与 security_events insert 必须在单个事务内、父行先于子行；
// ② 父行/子行/提交任一步失败都整体回滚且打含 request_id 的结构化错误日志（供告警发现），
// 绝不像旧 best-effort 那样让已生效的 block/confirm 在告警链路上零留痕。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

// === 可注入失败的假事务/假 DB（实现 mcpAuditTx / mcpAuditDB）===

type fakeMCPAuditTx struct {
	execedSQL  []string // 记录每次 Exec 的 SQL（用于断言顺序：先父行后子行）
	execedArgs [][]any
	failSubstr string // Exec 的 SQL 含此子串时返回错误（注入父行/子行写失败）
	commitErr  error  // 非 nil 时模拟 COMMIT 失败
	committed  bool
	rolledBack bool
}

func (t *fakeMCPAuditTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	t.execedSQL = append(t.execedSQL, sql)
	t.execedArgs = append(t.execedArgs, append([]any(nil), args...))
	if t.failSubstr != "" && strings.Contains(sql, t.failSubstr) {
		return pgconn.CommandTag{}, errors.New("injected exec failure")
	}
	return pgconn.CommandTag{}, nil
}

func (t *fakeMCPAuditTx) Commit(ctx context.Context) error {
	t.committed = true
	return t.commitErr
}

func (t *fakeMCPAuditTx) Rollback(ctx context.Context) error {
	t.rolledBack = true
	return nil
}

type fakeMCPAuditDB struct {
	tx       *fakeMCPAuditTx
	beginErr error // 非 nil 时模拟 BEGIN 失败
	beginN   int
	execN    int // 直写路径（writeMCPAccess 轻审计）调用次数
}

func (d *fakeMCPAuditDB) Begin(ctx context.Context) (mcpAuditTx, error) {
	d.beginN++
	if d.beginErr != nil {
		return nil, d.beginErr
	}
	return d.tx, nil
}

func (d *fakeMCPAuditDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	d.execN++
	return pgconn.CommandTag{}, nil
}

func newFakeAuditDB() *fakeMCPAuditDB {
	return &fakeMCPAuditDB{tx: &fakeMCPAuditTx{}}
}

// captureLogOutput 把标准 log 输出重定向到缓冲区，返回获取文本的闭包与恢复函数。
func captureLogOutput(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	orig := log.Writer()
	flags := log.Flags()
	log.SetOutput(buf)
	t.Cleanup(func() {
		log.SetOutput(orig)
		log.SetFlags(flags)
	})
	return buf
}

func mcpBlockDecision(tool string) mcpToolCallDecision {
	return mcpToolCallDecision{
		Qualified: tool,
		PolicyID:  "mcppol_block",
		Decision: agentguard.Decision{
			RawDecision:       agentguard.DecisionBlock,
			EffectiveDecision: agentguard.DecisionBlock,
			Mode:              agentguard.ModeStrict,
		},
	}
}

func mcpAuditPassDecision(tool string) mcpToolCallDecision {
	// raw=allow/audit 且非 高风险 → 不该产生 security_events。
	return mcpToolCallDecision{
		Qualified: tool,
		Decision: agentguard.Decision{
			RawDecision:       agentguard.DecisionAllow,
			EffectiveDecision: agentguard.DecisionAllow,
			Mode:              agentguard.ModeStrict,
		},
	}
}

func mcpBlockRecord() mcpProxyAuditRecord {
	return mcpProxyAuditRecord{
		RequestID:  "req_mcp_tx",
		TenantID:   "tenant_test",
		ProjectID:  "project_default",
		ServerID:   "mcp_srv1",
		ServerName: "demo",
		Status:     "blocked",
		StatusCode: 200,
	}
}

// TestMCPProxyAuditTxParentBeforeChildAndCommit：block 决策下，事务内先写 request_logs、
// 再写 security_events，最后 COMMIT；allow 决策不产生 security_events。
func TestMCPProxyAuditTxParentBeforeChildAndCommit(t *testing.T) {
	db := newFakeAuditDB()
	rec := &mcpProxyAuditRecorder{db: db}

	decisions := []mcpToolCallDecision{
		mcpBlockDecision("demo__delete_repo"),
		mcpAuditPassDecision("demo__read_file"),
	}
	rec.writeMCPProxyAuditTx(context.Background(), mcpBlockRecord(), decisions, false)

	if db.beginN != 1 {
		t.Fatalf("应恰好开启一个事务: beginN=%d", db.beginN)
	}
	if len(db.tx.execedSQL) != 2 {
		t.Fatalf("应有 2 次 Exec（1 父行 + 1 子行，allow 不写）: got %d (%v)", len(db.tx.execedSQL), db.tx.execedSQL)
	}
	if !strings.Contains(db.tx.execedSQL[0], "INSERT INTO request_logs") {
		t.Fatalf("第 1 次 Exec 应为 request_logs（父行先落）: %s", db.tx.execedSQL[0])
	}
	if !strings.Contains(db.tx.execedSQL[1], "INSERT INTO security_events") {
		t.Fatalf("第 2 次 Exec 应为 security_events（子行后落）: %s", db.tx.execedSQL[1])
	}
	if !db.tx.committed {
		t.Fatalf("成功路径必须 COMMIT")
	}
}

// TestMCPProxyAuditTxParentFailRollsBack：request_logs 写失败 → 整体回滚，绝不尝试写
// security_events（消除孤儿 FK），且打含 request_id 的结构化错误日志。
func TestMCPProxyAuditTxParentFailRollsBack(t *testing.T) {
	logs := captureLogOutput(t)
	db := newFakeAuditDB()
	db.tx.failSubstr = "INSERT INTO request_logs"
	rec := &mcpProxyAuditRecorder{db: db}

	rec.writeMCPProxyAuditTx(context.Background(), mcpBlockRecord(), []mcpToolCallDecision{mcpBlockDecision("demo__delete_repo")}, false)

	if len(db.tx.execedSQL) != 1 {
		t.Fatalf("父行失败后不得再写子行: execedSQL=%v", db.tx.execedSQL)
	}
	if db.tx.committed {
		t.Fatalf("父行失败绝不能 COMMIT")
	}
	if !db.tx.rolledBack {
		t.Fatalf("父行失败必须回滚")
	}
	out := logs.String()
	if !strings.Contains(out, "request_logs 失败") || !strings.Contains(out, "req_mcp_tx") {
		t.Fatalf("父行失败应打含 request_id 的结构化错误日志（供告警发现）: %q", out)
	}
	if !strings.Contains(out, "enforced=block:demo__delete_repo") {
		t.Fatalf("错误日志应带已生效阻断摘要，暴露丢失的必留痕阻断: %q", out)
	}
}

// TestMCPProxyAuditTxChildFailRollsBack：security_events 写失败 → 整体回滚（父行不孤留），
// 并打含 tool/decision 的错误日志。
func TestMCPProxyAuditTxChildFailRollsBack(t *testing.T) {
	logs := captureLogOutput(t)
	db := newFakeAuditDB()
	db.tx.failSubstr = "INSERT INTO security_events"
	rec := &mcpProxyAuditRecorder{db: db}

	rec.writeMCPProxyAuditTx(context.Background(), mcpBlockRecord(), []mcpToolCallDecision{mcpBlockDecision("demo__delete_repo")}, false)

	if db.tx.committed {
		t.Fatalf("子行失败绝不能 COMMIT（父行须随之回滚，不留孤儿行）")
	}
	if !db.tx.rolledBack {
		t.Fatalf("子行失败必须回滚")
	}
	out := logs.String()
	if !strings.Contains(out, "security_events 失败") || !strings.Contains(out, "demo__delete_repo") {
		t.Fatalf("子行失败应打含 tool 的结构化错误日志: %q", out)
	}
}

// TestMCPProxyAuditTxCommitFailLogged：COMMIT 失败（已生效阻断留痕落库失败）必须打含
// request_id 的高危错误日志，绝不静默——这正是铁律「阻断了必留痕」的兜底可观测性。
func TestMCPProxyAuditTxCommitFailLogged(t *testing.T) {
	logs := captureLogOutput(t)
	db := newFakeAuditDB()
	db.tx.commitErr = errors.New("injected commit failure")
	rec := &mcpProxyAuditRecorder{db: db}

	rec.writeMCPProxyAuditTx(context.Background(), mcpBlockRecord(), []mcpToolCallDecision{mcpBlockDecision("demo__delete_repo")}, false)

	out := logs.String()
	if !strings.Contains(out, "提交失败") || !strings.Contains(out, "req_mcp_tx") {
		t.Fatalf("COMMIT 失败应打含 request_id 的结构化错误日志: %q", out)
	}
	if !strings.Contains(out, "enforced=block:demo__delete_repo") {
		t.Fatalf("提交失败日志应带已生效阻断摘要: %q", out)
	}
}

// TestMCPProxyAuditTxBeginFailLogged：BEGIN 失败即返回，绝不静默，打含 request_id 的日志。
func TestMCPProxyAuditTxBeginFailLogged(t *testing.T) {
	logs := captureLogOutput(t)
	db := newFakeAuditDB()
	db.beginErr = errors.New("injected begin failure")
	rec := &mcpProxyAuditRecorder{db: db}

	rec.writeMCPProxyAuditTx(context.Background(), mcpBlockRecord(), []mcpToolCallDecision{mcpBlockDecision("demo__delete_repo")}, false)

	if len(db.tx.execedSQL) != 0 || db.tx.committed {
		t.Fatalf("BEGIN 失败后不得写库/提交")
	}
	if out := logs.String(); !strings.Contains(out, "开启失败") || !strings.Contains(out, "req_mcp_tx") {
		t.Fatalf("BEGIN 失败应打含 request_id 的错误日志: %q", out)
	}
}

// TestMCPProxyAuditTxNilGuards：nil recorder / 空 tenant / 空 request_id 一律安全 no-op，
// 绝不开启事务（守住既有 DB 门控语义）。
func TestMCPProxyAuditTxNilGuards(t *testing.T) {
	var nilRec *mcpProxyAuditRecorder
	nilRec.writeMCPProxyAuditTx(context.Background(), mcpBlockRecord(), nil, false) // 不 panic 即通过

	db := newFakeAuditDB()
	rec := &mcpProxyAuditRecorder{db: db}

	// 空 tenant
	r1 := mcpBlockRecord()
	r1.TenantID = ""
	rec.writeMCPProxyAuditTx(context.Background(), r1, []mcpToolCallDecision{mcpBlockDecision("demo__x")}, false)
	// 空 request_id
	r2 := mcpBlockRecord()
	r2.RequestID = ""
	rec.writeMCPProxyAuditTx(context.Background(), r2, []mcpToolCallDecision{mcpBlockDecision("demo__x")}, false)

	if db.beginN != 0 {
		t.Fatalf("缺租户/请求 ID 时不得开启事务: beginN=%d", db.beginN)
	}
}

// TestMCPProxyAuditTxAllPassNoSecurityEvent：全 allow/audit（无阻断）时只写父行、无子行，
// 仍正常 COMMIT。
func TestMCPProxyAuditTxAllPassNoSecurityEvent(t *testing.T) {
	db := newFakeAuditDB()
	rec := &mcpProxyAuditRecorder{db: db}

	rec.writeMCPProxyAuditTx(context.Background(), mcpBlockRecord(), []mcpToolCallDecision{
		mcpAuditPassDecision("demo__read_file"),
		mcpAuditPassDecision("demo__list"),
	}, false)

	if len(db.tx.execedSQL) != 1 || !strings.Contains(db.tx.execedSQL[0], "INSERT INTO request_logs") {
		t.Fatalf("全 pass 应只写 1 条 request_logs、无 security_events: %v", db.tx.execedSQL)
	}
	if !db.tx.committed {
		t.Fatalf("全 pass 路径仍须 COMMIT")
	}
}

// TestMCPSecurityEventArgsSatisfiesFK：审计事件参数的 request_id 必须复用父行 record.RequestID，
// project_id 复用父行，且 evidence_ref 指向同一父行——从数据上证明外键指向一致（不产生孤儿）。
func TestMCPSecurityEventArgsSatisfiesFK(t *testing.T) {
	record := mcpBlockRecord()
	d := mcpBlockDecision("demo__delete_repo")
	args := mcpSecurityEventArgs(record, &d, false)

	// 位置：$2=request_id, $4=project_id, $10=evidence_ref（与 mcpSecurityEventSQL 对齐）。
	if args[1] != record.RequestID {
		t.Fatalf("security_events.request_id 应复用父行 request_id: got %v want %s", args[1], record.RequestID)
	}
	if args[3] != record.ProjectID {
		t.Fatalf("security_events.project_id 应复用父行 project_id: got %v want %s", args[3], record.ProjectID)
	}
	if args[9] != "request_logs:"+record.RequestID {
		t.Fatalf("evidence_ref 应指向同一父行: got %v", args[9])
	}
}

// TestMCPDecisionNeedsSecurityEvent：仅 block/confirm 需要落事件。
func TestMCPDecisionNeedsSecurityEvent(t *testing.T) {
	block := mcpBlockDecision("demo__x")
	pass := mcpAuditPassDecision("demo__y")
	confirm := mcpToolCallDecision{Qualified: "demo__c", Decision: agentguard.Decision{RawDecision: agentguard.DecisionConfirm, EffectiveDecision: agentguard.DecisionConfirm}}

	if !mcpDecisionNeedsSecurityEvent(&block, false) {
		t.Fatalf("block 需要事件")
	}
	if mcpDecisionNeedsSecurityEvent(&pass, false) {
		t.Fatalf("allow 不该产生事件")
	}
	if !mcpDecisionNeedsSecurityEvent(&confirm, false) {
		t.Fatalf("confirm 需要事件")
	}
	if mcpDecisionNeedsSecurityEvent(nil, false) {
		t.Fatalf("nil 不该产生事件")
	}
}

// === P1-D 任务7 验收：MCP 安全事件写点物化 principal_key（契约6）===

// TestMCPPrincipalKeyCoalesceOrder：principal_key = COALESCE(user_id, client_id, source_ip)，
// 首个非空（去空白后）胜出；全空返回空串。
func TestMCPPrincipalKeyCoalesceOrder(t *testing.T) {
	cases := []struct {
		record mcpProxyAuditRecord
		want   string
	}{
		{mcpProxyAuditRecord{UserID: "u1", ClientID: "c1", SourceIP: "1.2.3.4"}, "u1"},
		{mcpProxyAuditRecord{ClientID: "c1", SourceIP: "1.2.3.4"}, "c1"},
		{mcpProxyAuditRecord{SourceIP: "1.2.3.4"}, "1.2.3.4"},
		{mcpProxyAuditRecord{UserID: "  ", ClientID: "c1"}, "c1"},
		{mcpProxyAuditRecord{}, ""},
	}
	for i, c := range cases {
		if got := mcpPrincipalKey(c.record); got != c.want {
			t.Fatalf("case %d: principal_key want %q got %q", i, c.want, got)
		}
	}
}

// TestMCPSecurityEventArgsAppendsPrincipalKey：mcpSecurityEventArgs 末尾追加 principal_key，
// 参数个数 11，且 SQL 含 principal_key 列与对应 $11 占位。
func TestMCPSecurityEventArgsAppendsPrincipalKey(t *testing.T) {
	record := mcpBlockRecord()
	record.UserID = "user_mcp"
	d := mcpBlockDecision("demo__delete_repo")
	args := mcpSecurityEventArgs(record, &d, false)

	if len(args) != 11 {
		t.Fatalf("mcpSecurityEventArgs 应返回 11 个位置参数(追加 principal_key), got %d", len(args))
	}
	// principal_key 是第 11 个位置参数($11) -> args 下标 10。
	if got := args[10]; got != "user_mcp" {
		t.Fatalf("principal_key 应取 user_id 优先, got %v", got)
	}
	if !strings.Contains(mcpSecurityEventSQL, "principal_key") {
		t.Fatalf("mcpSecurityEventSQL 应包含 principal_key 列:\n%s", mcpSecurityEventSQL)
	}
	if !strings.Contains(mcpSecurityEventSQL, "$11") {
		t.Fatalf("mcpSecurityEventSQL 应含 $11 占位(principal_key):\n%s", mcpSecurityEventSQL)
	}
}

func TestMCPSecurityEventDestructiveExecutionOmitsResultExcerpt(t *testing.T) {
	record := mcpBlockRecord()
	d := mcpBlockDecision("demo__delete_repo")
	d.Decision.RiskCategory = agentguard.DestructiveRiskCategory
	d.ExecutionForwarded = true
	d.ResultObserved = true
	d.ResultExcerpt = `{"secret":"must-not-persist"}`

	args := mcpSecurityEventArgs(record, &d, false)
	var summary map[string]any
	if err := json.Unmarshal(args[8].([]byte), &summary); err != nil {
		t.Fatal(err)
	}
	if _, exists := summary["result_excerpt"]; exists {
		t.Fatalf("destructive security event leaked result excerpt: %#v", summary)
	}
	if summary["result_observed"] != true {
		t.Fatalf("destructive security event lost result_observed fact: %#v", summary)
	}
}

func TestMCPSecurityEventNonDestructiveKeepsSanitizedResultExcerpt(t *testing.T) {
	record := mcpBlockRecord()
	d := mcpBlockDecision("demo__read_file")
	d.ExecutionForwarded = true
	d.ResultObserved = true
	d.ResultExcerpt = "<redacted:secret>"

	args := mcpSecurityEventArgs(record, &d, false)
	var summary map[string]any
	if err := json.Unmarshal(args[8].([]byte), &summary); err != nil {
		t.Fatal(err)
	}
	if summary["result_excerpt"] != "<redacted:secret>" {
		t.Fatalf("non-destructive result excerpt compatibility lost: %#v", summary)
	}
}

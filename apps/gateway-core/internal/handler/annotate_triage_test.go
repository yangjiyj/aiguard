package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// FIX-2 (important): AnnotateTriage 必须按 request_id + stage(input) 精确定位该请求的
// security_event 行（而非"最近一行"），逐 finding 按身份(rule_id+matched_location)合并 triage 字段，
// 绝不整体覆盖 matched_summary；行不存在（outbox 异步未落库）时安全降级（不报错、RowsAffected==0）。

// TestAnnotateTriage_TargetsInputStageRow 验证 UPDATE 的 WHERE 子句按 stage='input' 精确定位，
// 而非 ORDER BY created_at DESC LIMIT 1（多消息请求会落多行 security_event，取"最近一行"会错位）。
func TestAnnotateTriage_TargetsInputStageRow(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB}

	env := &modelrouter.RequestEnvelope{RequestID: "req_multi", TenantID: "t1"}
	findings := []SecurityFinding{
		{Type: "prompt_injection", RuleID: "pi-001", MatchedLocation: "input",
			Triage: map[string]any{"verdict": "likely_false_positive"}},
	}

	writer.AnnotateTriage(context.Background(), env, findings)

	if mockDB.execCalls != 1 {
		t.Fatalf("expected 1 Exec call, got %d", mockDB.execCalls)
	}
	q := mockDB.queries[0]
	if strings.Contains(q, "ORDER BY created_at DESC") || strings.Contains(q, "LIMIT 1") {
		t.Fatalf("AnnotateTriage must target by request_id+stage(input), not latest row:\n%s", q)
	}
	if !strings.Contains(q, "request_id") || !strings.Contains(q, "tenant_id") {
		t.Fatalf("UPDATE must scope by tenant_id + request_id:\n%s", q)
	}
	// stage='input' 须出现在 WHERE（精确定位输入侧行）。
	if !strings.Contains(q, "stage") {
		t.Fatalf("UPDATE WHERE must filter on matched_summary stage=input:\n%s", q)
	}
	// stage 值作为参数传入（避免在多消息/多行下错位到 output 行）。
	var sawInputStageArg bool
	for _, a := range mockDB.args[0] {
		if s, ok := a.(string); ok && s == "input" {
			sawInputStageArg = true
		}
	}
	if !sawInputStageArg {
		t.Fatalf("expected 'input' stage arg passed to UPDATE, args=%#v", mockDB.args[0])
	}
}

// TestAnnotateTriage_MergesPerFindingDoesNotOverwrite 验证不再整体序列化覆盖 matched_summary，
// 而是用 jsonb_set 在既有 findings 数组上逐 finding 按身份补 triage 字段（保留其余 finding 与其它字段）。
func TestAnnotateTriage_MergesPerFindingDoesNotOverwrite(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB}

	env := &modelrouter.RequestEnvelope{RequestID: "req_merge", TenantID: "t1"}
	findings := []SecurityFinding{
		{Type: "prompt_injection", RuleID: "pi-001", MatchedLocation: "input",
			Triage: map[string]any{"verdict": "likely_false_positive"}},
	}

	writer.AnnotateTriage(context.Background(), env, findings)

	q := mockDB.queries[0]
	// 必须就地合并：用 jsonb_set 改 findings 数组，不能把整个 matched_summary 用一个序列化值替换。
	if !strings.Contains(q, "jsonb_set") {
		t.Fatalf("AnnotateTriage must merge in-place via jsonb_set, not overwrite whole matched_summary:\n%s", q)
	}
	if !strings.Contains(q, "findings") {
		t.Fatalf("merge must operate on matched_summary->findings:\n%s", q)
	}
	// 身份匹配须同时用 rule_id 与 matched_location（逐 finding 定位，避免误标到别的 finding）。
	if !strings.Contains(q, "rule_id") || !strings.Contains(q, "matched_location") {
		t.Fatalf("per-finding merge must match on rule_id + matched_location:\n%s", q)
	}
}

// TestAnnotateTriage_RowNotExistsSafeDegrade 验证 outbox 异步未落库（无目标行）时安全降级：
// RowsAffected==0 不报错、不 panic（丢标注=不压制=安全方向，fail-open）。
func TestAnnotateTriage_RowNotExistsSafeDegrade(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 0}}
	writer := &RealAuditWriter{db: mockDB}

	env := &modelrouter.RequestEnvelope{RequestID: "req_not_landed", TenantID: "t1"}
	findings := []SecurityFinding{
		{Type: "prompt_injection", RuleID: "pi-001", MatchedLocation: "input",
			Triage: map[string]any{"verdict": "likely_false_positive"}},
	}

	// 不应 panic；RowsAffected==0 视为目标行尚未落库，静默降级。
	writer.AnnotateTriage(context.Background(), env, findings)

	if mockDB.execCalls != 1 {
		t.Fatalf("expected 1 Exec call even when no row landed, got %d", mockDB.execCalls)
	}
}

// TestAnnotateTriage_NilEnvelopeOrEmptyFindings 边界守卫保持：空 envelope/空 request_id/空 findings 直接返回。
func TestAnnotateTriage_NilEnvelopeOrEmptyFindings(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB}

	writer.AnnotateTriage(context.Background(), nil, []SecurityFinding{{Type: "x"}})
	writer.AnnotateTriage(context.Background(), &modelrouter.RequestEnvelope{}, []SecurityFinding{{Type: "x"}})
	writer.AnnotateTriage(context.Background(), &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t"}, nil)

	if mockDB.execCalls != 0 {
		t.Fatalf("guards must short-circuit before any DB Exec, got %d calls", mockDB.execCalls)
	}
}

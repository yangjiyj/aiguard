package repository

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// 客户现场：explicit 模式的 tool_result（event_kind=result_observed、execution_observed=false）在
// UpsertByToolCallID "找不到已有行 -> Create" 一支被无条件写成 execution_observed=true，违反
// tool_call_logs_execution_fact_check。这里不连库，直接锁住事实推导函数的行为；
// 连真库的端到端用例见 tool_call_logs_execution_fact_db_test.go。

func TestPrepareUpsertCreateFactsExplicitNeverClaimsExecution(t *testing.T) {
	log := &ToolCallLog{
		EventKind: "result_observed", ExecutionObserved: false, ResultObserved: true,
		AttributionMode: "explicit", AttributionConfidence: 1,
	}
	if err := prepareUpsertCreateFacts(log); err != nil {
		t.Fatal(err)
	}
	if log.ExecutionObserved || !log.ResultObserved || log.AttributionMode != "explicit" {
		t.Fatalf("explicit tool_result facts = exec:%t result:%t mode:%q", log.ExecutionObserved, log.ResultObserved, log.AttributionMode)
	}
}

func TestPrepareUpsertCreateFactsExplicitDowngradesCallerExecutionClaim(t *testing.T) {
	for _, mode := range []string{"explicit", "linked", "inferred", "none"} {
		log := &ToolCallLog{EventKind: "result_observed", ExecutionObserved: true, ResultObserved: true, AttributionMode: mode, AttributionConfidence: 1}
		if err := prepareUpsertCreateFacts(log); err != nil {
			t.Fatalf("mode %s: %v", mode, err)
		}
		if log.ExecutionObserved {
			t.Fatalf("mode %s: 客户端自称执行不能记成网关观察到执行", mode)
		}
	}
}

func TestPrepareUpsertCreateFactsEndpointHookKeepsOriginalSemantics(t *testing.T) {
	log := &ToolCallLog{EventKind: "result_observed", AttributionMode: "endpoint_hook", AttributionConfidence: 1}
	if err := prepareUpsertCreateFacts(log); err != nil {
		t.Fatal(err)
	}
	if !log.ExecutionObserved || !log.ResultObserved || log.AttributionMode != "endpoint_hook" {
		t.Fatalf("endpoint_hook facts = exec:%t result:%t mode:%q", log.ExecutionObserved, log.ResultObserved, log.AttributionMode)
	}
}

func TestPrepareUpsertCreateFactsEmptyModeDefaultsToEndpointHook(t *testing.T) {
	log := &ToolCallLog{EventKind: "result_observed"}
	if err := prepareUpsertCreateFacts(log); err != nil {
		t.Fatal(err)
	}
	if log.AttributionMode != "endpoint_hook" || !log.ExecutionObserved || !log.ResultObserved {
		t.Fatalf("legacy caller facts = %+v", log)
	}
}

func TestNormalizeExecutionFacts(t *testing.T) {
	cases := []struct {
		name      string
		mode      string
		kind      string
		execIn    bool
		wantExec  bool
		wantError bool
	}{
		{"endpoint_hook 豁免: result_observed+exec=true 保持", "endpoint_hook", "result_observed", true, true, false},
		{"endpoint_hook 豁免: invocation_proposed+exec=true 不动", "endpoint_hook", "invocation_proposed", true, true, false},
		{"explicit: 只有 execution_forwarded 才为 true", "explicit", "execution_forwarded", true, true, false},
		{"explicit: result_observed 压成 false", "explicit", "result_observed", true, false, false},
		{"explicit: invocation_proposed 压成 false", "explicit", "invocation_proposed", true, false, false},
		{"explicit: confirmation_replay 压成 false", "explicit", "confirmation_replay", true, false, false},
		{"explicit: 本来就是 false 保持", "explicit", "result_observed", false, false, false},
		{"空归因模式按非 hook 处理", "", "result_observed", true, false, false},
		{"none 按非 hook 处理", "none", "definition_exposed", true, false, false},
		{"explicit: execution_forwarded 却 exec=false 自相矛盾，拒绝而不是替调用方补 true", "explicit", "execution_forwarded", false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log := &ToolCallLog{AttributionMode: tc.mode, EventKind: tc.kind, ExecutionObserved: tc.execIn}
			err := normalizeExecutionFacts(log)
			if tc.wantError {
				if !errors.Is(err, ErrToolLogFactsInvalid) || !IsPermanentToolCallLogError(err) {
					t.Fatalf("want ErrToolLogFactsInvalid, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if log.ExecutionObserved != tc.wantExec {
				t.Fatalf("execution_observed = %t, want %t", log.ExecutionObserved, tc.wantExec)
			}
			// 与库约束同一判据：非 hook 时 execution_observed == (event_kind='execution_forwarded')
			if tc.mode != "endpoint_hook" && log.ExecutionObserved != (log.EventKind == "execution_forwarded") {
				t.Fatalf("违反 tool_call_logs_execution_fact_check 的判据: %+v", log)
			}
		})
	}
}

func TestToolCallLogCheckViolationDetectsWrappedPgError(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23514", ConstraintName: "tool_call_logs_execution_fact_check", Message: "violates check constraint"}
	wrapped := fmt.Errorf("upsert tool call log: %w", fmt.Errorf("failed to create tool call log: %w", pgErr))
	name, ok := ToolCallLogCheckViolation(wrapped)
	if !ok || name != "tool_call_logs_execution_fact_check" {
		t.Fatalf("ToolCallLogCheckViolation = %q, %t", name, ok)
	}
	if !IsPermanentToolCallLogError(wrapped) {
		t.Fatal("约束违约必须被判为永久错误（重试无意义）")
	}
}

func TestToolCallLogTransientErrorsAreNotPermanent(t *testing.T) {
	for name, err := range map[string]error{
		"连接池耗尽":     &pgconn.PgError{Code: "53300", Message: "too many clients"},
		"唯一键冲突":     &pgconn.PgError{Code: "23505"},
		"序列化失败可重试":  &pgconn.PgError{Code: "40001"},
		"普通错误":      errors.New("context deadline exceeded"),
		"nil":       nil,
		"包装的非约束 pg": fmt.Errorf("x: %w", &pgconn.PgError{Code: "08006"}),
	} {
		if IsPermanentToolCallLogError(err) {
			t.Fatalf("%s 不应被判为永久错误", name)
		}
		if _, ok := ToolCallLogCheckViolation(err); ok {
			t.Fatalf("%s 不应被识别为 CHECK 违约", name)
		}
	}
}

// ON CONFLICT DO UPDATE 不改 event_kind，execution_observed 的 OR 合并不能越过已存的 event_kind。
func TestInsertQueryOnConflictGuardsExecutionFact(t *testing.T) {
	query, _, err := buildToolCallLogInsert(&ToolCallLog{
		TenantID: "t", OperationID: "op", EventType: "tool_destructive_intent", EventKind: "invocation_proposed",
		AttributionMode: "explicit", AttributionConfidence: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"execution_observed = CASE",
		"tool_call_logs.attribution_mode IS NOT DISTINCT FROM 'endpoint_hook'",
		"tool_call_logs.event_kind IS NOT DISTINCT FROM 'execution_forwarded'",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("ON CONFLICT 合并缺少 %q:\n%s", fragment, query)
		}
	}
}

// Upsert 的合并 UPDATE 同样要按已存行的归因模式走，不能把 exec=true 并进非 hook 的 result_observed 行。
func TestUpsertMergeSQLGuardsExecutionFact(t *testing.T) {
	for _, fragment := range []string{
		"t.attribution_mode IS NOT DISTINCT FROM 'endpoint_hook'",
		"t.event_kind IS NOT DISTINCT FROM 'execution_forwarded'",
	} {
		if !strings.Contains(upsertToolCallMergeSQL, fragment) {
			t.Fatalf("upsert 合并 SQL 缺少 %q:\n%s", fragment, upsertToolCallMergeSQL)
		}
	}
}

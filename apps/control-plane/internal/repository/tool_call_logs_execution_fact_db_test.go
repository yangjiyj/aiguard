package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 客户现场回归（2026-10-21 17:45 UTC 起）：
//
//	ERROR: new row for relation "tool_call_logs" violates check constraint "tool_call_logs_execution_fact_check"
//
// 网关把客户端带回来的 tool_result 上报为 event_kind=result_observed / execution_observed=false /
// attribution_mode=explicit；控制面 UpsertByToolCallID 找不到已有行时走 Create，却无条件写
// execution_observed=true，被 856 版约束拒绝，整条审计丢失。
//
// 这组用例在两个库上各跑一遍：
//  1. TOOL_CALL_LOGS_TEST_DATABASE_URL：隔离 schema + 迁移 112/854/856（可移植、CI 可跑）；
//  2. TOOL_CALL_LOGS_REAL_SCHEMA_TEST_DATABASE_URL：直接用库里 public.tool_call_logs（现场同款完整表与全部约束），
//     只给 `CREATE DATABASE x TEMPLATE jjdguard` 出来的一次性库使用。

type factRow struct {
	ID     string
	Kind   *string
	Exec   *bool
	Result *bool
	Mode   *string
	Status string
}

func (r factRow) String() string {
	s := func(p *string) string {
		if p == nil {
			return "NULL"
		}
		return *p
	}
	b := func(p *bool) string {
		if p == nil {
			return "NULL"
		}
		if *p {
			return "t"
		}
		return "f"
	}
	return "kind=" + s(r.Kind) + " exec=" + b(r.Exec) + " result=" + b(r.Result) + " mode=" + s(r.Mode) + " status=" + r.Status
}

func readFactRows(t *testing.T, ctx context.Context, db *pgxpool.Pool, tenantID, toolCallID string) []factRow {
	t.Helper()
	rows, err := db.Query(ctx, `SELECT id, event_kind, execution_observed, result_observed, attribution_mode, status
		FROM tool_call_logs WHERE tenant_id=$1 AND tool_call_id=$2 ORDER BY created_at, id`, tenantID, toolCallID)
	if err != nil {
		t.Fatalf("query fact rows: %v", err)
	}
	defer rows.Close()
	var out []factRow
	for rows.Next() {
		var r factRow
		if err := rows.Scan(&r.ID, &r.Kind, &r.Exec, &r.Result, &r.Mode, &r.Status); err != nil {
			t.Fatalf("scan fact row: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate fact rows: %v", err)
	}
	return out
}

func wantFacts(t *testing.T, got []factRow, kind string, exec, result bool, mode string) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("want exactly 1 row, got %d: %v", len(got), got)
	}
	r := got[0]
	if r.Kind == nil || *r.Kind != kind || r.Exec == nil || *r.Exec != exec || r.Result == nil || *r.Result != result || r.Mode == nil || *r.Mode != mode {
		t.Fatalf("facts = %s; want kind=%s exec=%t result=%t mode=%s", r, kind, exec, result, mode)
	}
}

// gatewayToolResult 与 gateway-core logToolResultObservations 上报的载荷一致。
func gatewayToolResult(tenantID, requestID, toolCallID string) *ToolCallLog {
	return &ToolCallLog{
		RequestID: requestID, TenantID: tenantID, ToolName: "tool_result", ToolType: "tool_result", RiskLevel: "low",
		Result: "authenticated client supplied a tool result", Status: "observed",
		EventKind: "result_observed", ExecutionObserved: false, ResultObserved: true,
		ToolCallID: toolCallID, AttributionMode: "explicit", AttributionConfidence: 1,
	}
}

func setupExecutionFactTestDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	db, ctx := setupRuntimeTruthTestDB(t)
	// 现场约束 = 112 建表 + 854 放开 attribution_mode + 856 的 endpoint_hook 豁免版 execution_fact_check。
	for _, name := range []string{"854_agent_endpoint_hook_attribution.sql", "856_agent_endpoint_execution_fact_scope.sql"} {
		sqlBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "migrations", name))
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		if _, err := db.Exec(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("apply migration %s in isolated schema: %v", name, err)
		}
	}
	return db, ctx
}

func setupExecutionFactRealSchemaDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	databaseURL := os.Getenv("TOOL_CALL_LOGS_REAL_SCHEMA_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TOOL_CALL_LOGS_REAL_SCHEMA_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect real-schema test database: %v", err)
	}
	t.Cleanup(db.Close)
	var def string
	if err := db.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid='tool_call_logs'::regclass AND conname='tool_call_logs_execution_fact_check'`).Scan(&def); err != nil {
		t.Fatalf("real schema must carry tool_call_logs_execution_fact_check: %v", err)
	}
	return db, ctx
}

func TestUpsertByToolCallIDExecutionFactIsolatedSchema(t *testing.T) {
	db, ctx := setupExecutionFactTestDB(t)
	runUpsertExecutionFactScenarios(t, ctx, db)
}

func TestUpsertByToolCallIDExecutionFactRealSchema(t *testing.T) {
	db, ctx := setupExecutionFactRealSchemaDB(t)
	runUpsertExecutionFactScenarios(t, ctx, db)
}

func runUpsertExecutionFactScenarios(t *testing.T, ctx context.Context, db *pgxpool.Pool) {
	repo := NewToolCallLogRepository(db)
	// 真库（public 表）会被多次运行共用：租户、tool_call_id、行 id 全部带本次运行的唯一后缀，结束时按后缀清理。
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	uniq := func(v string) string { return v + "-" + suffix }
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM tool_call_logs WHERE tenant_id LIKE $1`, "%-"+suffix)
	})

	t.Run("explicit_no_existing_row_creates_without_execution_claim", func(t *testing.T) {
		// 现场失败的那一支：找不到已有行 -> Create。
		tenant, call := uniq("tenant-fact-a"), uniq("toolu_bdrk_fact_a")
		updated, err := repo.UpsertByToolCallID(ctx, gatewayToolResult(tenant, "req-fact-a", call))
		if err != nil {
			t.Fatalf("explicit tool_result without a proposal row must be stored, got: %v", err)
		}
		if updated {
			t.Fatal("no row existed, updated must be false")
		}
		wantFacts(t, readFactRows(t, ctx, db, tenant, call), "result_observed", false, true, "explicit")
	})

	t.Run("explicit_caller_claiming_execution_is_downgraded", func(t *testing.T) {
		// 审计事实宁可少说：非 endpoint_hook 模式下，调用方自称"观察到执行"也不能落库为 true。
		tenant, call := uniq("tenant-fact-b"), uniq("toolu_bdrk_fact_b")
		entry := gatewayToolResult(tenant, "req-fact-b", call)
		entry.ExecutionObserved = true
		if _, err := repo.UpsertByToolCallID(ctx, entry); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		wantFacts(t, readFactRows(t, ctx, db, tenant, call), "result_observed", false, true, "explicit")
	})

	t.Run("explicit_report_is_idempotent", func(t *testing.T) {
		tenant, call := uniq("tenant-fact-c"), uniq("toolu_bdrk_fact_c")
		for i := 0; i < 3; i++ {
			if _, err := repo.UpsertByToolCallID(ctx, gatewayToolResult(tenant, "req-fact-c", call)); err != nil {
				t.Fatalf("upsert #%d: %v", i+1, err)
			}
		}
		wantFacts(t, readFactRows(t, ctx, db, tenant, call), "result_observed", false, true, "explicit")
	})

	t.Run("explicit_existing_proposal_row_is_merged", func(t *testing.T) {
		tenant, call := uniq("tenant-fact-d"), uniq("toolu_bdrk_fact_d")
		proposal := &ToolCallLog{
			RequestID: "req-fact-d", TenantID: tenant, ToolName: "Bash", ToolType: "system", RiskLevel: "low", Status: "audited",
			EventKind: "invocation_proposed", ToolCallID: call, AttributionMode: "explicit", AttributionConfidence: 1,
		}
		if err := repo.Create(ctx, proposal); err != nil {
			t.Fatalf("create proposal: %v", err)
		}
		updated, err := repo.UpsertByToolCallID(ctx, gatewayToolResult(tenant, "req-fact-d2", call))
		if err != nil || !updated {
			t.Fatalf("expected merge into existing row, updated=%t err=%v", updated, err)
		}
		wantFacts(t, readFactRows(t, ctx, db, tenant, call), "result_observed", false, true, "explicit")
	})

	t.Run("explicit_existing_execution_forwarded_row_keeps_its_execution_fact", func(t *testing.T) {
		// 已有行是网关真转发过的 execution_forwarded（exec=true）：并入客户端结果后，
		// 不能把 event_kind 改成 result_observed 却保留 exec=true（那会违约），也不能丢掉真实的转发事实。
		tenant, call := uniq("tenant-fact-e"), uniq("toolu_bdrk_fact_e")
		forwarded := &ToolCallLog{
			RequestID: "req-fact-e", TenantID: tenant, ToolName: "demo__run", ToolType: "mcp", RiskLevel: "low", Status: "forwarded",
			EventKind: "execution_forwarded", ExecutionObserved: true, ToolCallID: call, AttributionMode: "explicit", AttributionConfidence: 1,
		}
		if err := repo.Create(ctx, forwarded); err != nil {
			t.Fatalf("create forwarded row: %v", err)
		}
		updated, err := repo.UpsertByToolCallID(ctx, gatewayToolResult(tenant, "req-fact-e2", call))
		if err != nil || !updated {
			t.Fatalf("expected merge into forwarded row, updated=%t err=%v", updated, err)
		}
		wantFacts(t, readFactRows(t, ctx, db, tenant, call), "execution_forwarded", true, true, "explicit")
	})

	t.Run("explicit_legacy_null_kind_row_is_mergeable", func(t *testing.T) {
		tenant, call := uniq("tenant-fact-f"), uniq("toolu_bdrk_fact_f")
		if _, err := db.Exec(ctx, `INSERT INTO tool_call_logs (id, request_id, tenant_id, tool_name, tool_type, risk_level, status, tool_call_id)
			VALUES ($3, 'req-fact-f', $1, 'Bash', 'system', 'low', 'success', $2)`, tenant, call, uniq("tc-legacy-null-kind")); err != nil {
			t.Fatalf("insert legacy row: %v", err)
		}
		if _, err := repo.UpsertByToolCallID(ctx, gatewayToolResult(tenant, "req-fact-f2", call)); err != nil {
			t.Fatalf("merge into legacy row: %v", err)
		}
		got := readFactRows(t, ctx, db, tenant, call)
		if len(got) != 1 || got[0].Kind == nil || *got[0].Kind != "result_observed" || got[0].Exec == nil || *got[0].Exec || got[0].Result == nil || !*got[0].Result {
			t.Fatalf("legacy merge facts = %v", got)
		}
	})

	t.Run("endpoint_hook_no_existing_row_keeps_original_semantics", func(t *testing.T) {
		// endpoint_hook：钩子自己观察到工具执行完并带回结果，保持 exec=true / result=true。
		tenant, call := uniq("tenant-fact-g"), uniq("toolu_hook_fact_g")
		entry := &ToolCallLog{
			RequestID: "req-fact-g", TenantID: tenant, ToolName: "Bash", ToolType: "system", RiskLevel: "low", Status: "success",
			EventKind: "tool_post", ExecutionObserved: true, ResultObserved: true, ToolCallID: call,
			AttributionMode: "endpoint_hook", AttributionConfidence: 1,
		}
		if _, err := repo.UpsertByToolCallID(ctx, entry); err != nil {
			t.Fatalf("endpoint_hook upsert: %v", err)
		}
		wantFacts(t, readFactRows(t, ctx, db, tenant, call), "result_observed", true, true, "endpoint_hook")
	})

	t.Run("empty_attribution_mode_defaults_to_endpoint_hook", func(t *testing.T) {
		tenant, call := uniq("tenant-fact-h"), uniq("toolu_hook_fact_h")
		entry := &ToolCallLog{
			RequestID: "req-fact-h", TenantID: tenant, ToolName: "Bash", ToolType: "system", RiskLevel: "low", Status: "success",
			EventKind: "tool_post", ToolCallID: call,
		}
		if _, err := repo.UpsertByToolCallID(ctx, entry); err != nil {
			t.Fatalf("legacy-caller upsert: %v", err)
		}
		wantFacts(t, readFactRows(t, ctx, db, tenant, call), "result_observed", true, true, "endpoint_hook")
	})

	t.Run("on_conflict_merge_never_breaks_execution_fact_constraint", func(t *testing.T) {
		// 纵深防御，实际数据里 event_type 与 event_kind 一一对应，几乎走不到。
		// buildToolCallLogInsert 的 ON CONFLICT (tenant_id, operation_id, event_type) DO UPDATE 不改 event_kind，
		// 旧实现把 execution_observed 直接 OR 合并：已存行 invocation_proposed(exec=false) 并入一条
		// "待插入行本身合法"的 execution_forwarded(exec=true) 后，变成 kind=invocation_proposed + exec=true，违反约束。
		// 注意：PG 会先用待插入行检查 CHECK 再判冲突，所以这里的待插入行必须自身合法。
		tenant := uniq("tenant-fact-j")
		first := &ToolCallLog{
			RequestID: "req-fact-j", TenantID: tenant, ToolName: "demo__run", ToolType: "mcp", RiskLevel: "high", Status: "recorded",
			EventKind: "invocation_proposed", OperationID: "op-fact-j", EventType: "tool_destructive_intent",
			ToolCallID: uniq("toolu_bdrk_fact_j"), AttributionMode: "explicit", AttributionConfidence: 1,
			NotificationStatus: "skipped",
		}
		if err := repo.Create(ctx, first); err != nil {
			t.Fatalf("create destructive intent: %v", err)
		}
		replay := *first
		replay.ID = newToolCallLogID()
		replay.EventKind = "execution_forwarded"
		replay.ExecutionObserved = true
		replay.ExecutionForwarded = true
		query, args, err := buildToolCallLogInsert(&replay)
		if err != nil {
			t.Fatalf("build insert: %v", err)
		}
		var storedID string
		if err := db.QueryRow(ctx, query, args...).Scan(&storedID); err != nil {
			t.Fatalf("ON CONFLICT merge must not violate execution fact constraint: %v", err)
		}
		if storedID != first.ID {
			t.Fatalf("expected merge into existing row %s, got %s", first.ID, storedID)
		}
		// 已存行的 event_kind 没变，execution_observed 不能越过它。
		wantFacts(t, readFactRows(t, ctx, db, tenant, first.ToolCallID), "invocation_proposed", false, false, "explicit")
	})

	t.Run("endpoint_hook_existing_proposal_row_keeps_original_merge", func(t *testing.T) {
		tenant, call := uniq("tenant-fact-i"), uniq("toolu_hook_fact_i")
		proposal := &ToolCallLog{
			RequestID: "req-fact-i", TenantID: tenant, ToolName: "Bash", ToolType: "system", RiskLevel: "low", Status: "audited",
			EventKind: "invocation_proposed", ToolCallID: call, AttributionMode: "endpoint_hook", AttributionConfidence: 1,
		}
		if err := repo.Create(ctx, proposal); err != nil {
			t.Fatalf("create hook proposal: %v", err)
		}
		post := &ToolCallLog{
			TenantID: tenant, EventKind: "tool_post", ExecutionObserved: true, ResultObserved: true, ToolCallID: call,
			Status: "success", AttributionMode: "endpoint_hook",
		}
		updated, err := repo.UpsertByToolCallID(ctx, post)
		if err != nil || !updated {
			t.Fatalf("expected merge into hook proposal, updated=%t err=%v", updated, err)
		}
		wantFacts(t, readFactRows(t, ctx, db, tenant, call), "result_observed", true, true, "endpoint_hook")
	})
}

// 约束本身的语义（与代码无关）：同一组事实在 explicit 下违约、在 endpoint_hook 下合法；
// 违约错误是 SQLSTATE 23514 并带约束名（识别逻辑的前提）。
func TestExecutionFactConstraintSemantics(t *testing.T) {
	db, ctx := setupExecutionFactTestDB(t)
	insert := func(id, mode string) error {
		_, err := db.Exec(ctx, `INSERT INTO tool_call_logs (id, request_id, tenant_id, tool_name, tool_type, risk_level, status,
			event_kind, execution_observed, result_observed, tool_call_id, attribution_mode, attribution_confidence)
			VALUES ($1, 'req-sem', 'tenant-sem', 'tool_result', 'tool_result', 'low', 'observed',
			'result_observed', TRUE, TRUE, $3, $2, 1)`, id, mode, id)
		return err
	}
	err := insert("tc-sem-explicit", "explicit")
	if err == nil {
		t.Fatal("explicit + result_observed + execution_observed=true must violate tool_call_logs_execution_fact_check")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "tool_call_logs_execution_fact_check" {
		t.Fatalf("want SQLSTATE 23514 on tool_call_logs_execution_fact_check, got %v", err)
	}
	if err := insert("tc-sem-hook", "endpoint_hook"); err != nil {
		t.Fatalf("endpoint_hook is exempt from the execution fact scope: %v", err)
	}
}

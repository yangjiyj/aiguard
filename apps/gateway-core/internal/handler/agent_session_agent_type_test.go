package handler

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 名单必须以参数传入（= ANY($10::text[])），且就是 agentdetect 的共用名单，
// SQL 文本里不再拼任何字面量名单。
func TestAgentSessionUpsertPassesSharedOverwritableListAsParameter(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}
	writer.UpsertAgentSession(context.Background(), &modelrouter.RequestEnvelope{
		RequestID: "r", TenantID: "t", ProjectID: "p", SessionID: "s", AgentType: "workbuddy",
	})
	if mockDB.execCalls != 1 {
		t.Fatalf("exec calls=%d", mockDB.execCalls)
	}
	query, args := mockDB.queries[0], mockDB.args[0]
	if len(args) != 10 {
		t.Fatalf("args=%d, want 10 (9 columns + overwritable list)", len(args))
	}
	list, ok := args[9].([]string)
	if !ok {
		t.Fatalf("arg 10 is %T, want []string", args[9])
	}
	if !reflect.DeepEqual(list, agentdetect.SessionOverwritableIdentities()) {
		t.Fatalf("arg 10=%v, want agentdetect.SessionOverwritableIdentities()", list)
	}
	if !strings.Contains(query, "= ANY($10::text[])") || !strings.Contains(query, "<> ALL($10::text[])") {
		t.Fatalf("query must reference the parameterized list:\n%s", query)
	}
	for _, name := range append(agentdetect.GenericAgentIdentities(), agentdetect.UpgradeableRuntimeIdentities()...) {
		if strings.Contains(query, "'"+name+"'") {
			t.Fatalf("query must not inline literal %q", name)
		}
	}
	if !strings.Contains(query, "ELSE agent_sessions.agent_type") {
		t.Fatalf("conflict branch must preserve concrete stored agent_type:\n%s", query)
	}
}

// 真实 PostgreSQL 语义：空/通用 → 具体产品覆盖；具体产品不被覆盖；新值通用不覆盖。
// 需要已迁移的库（JJD_AGENT_SESSION_TEST_DATABASE_URL）。
func TestAgentSessionUpsertFirstConcreteValueSticksOnPostgres(t *testing.T) {
	url := os.Getenv("JJD_AGENT_SESSION_TEST_DATABASE_URL")
	if url == "" {
		skipOrFailWithoutDatabase(t, "JJD_AGENT_SESSION_TEST_DATABASE_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err = pool.Exec(ctx, `
INSERT INTO tenants(id,name,is_test) VALUES ('as_t','as_t',true) ON CONFLICT DO NOTHING;
INSERT INTO users(id,tenant_id,username,role) VALUES ('as_u','as_t','as_u','developer') ON CONFLICT DO NOTHING;
INSERT INTO projects(id,tenant_id,name) VALUES ('as_p','as_t','as_p') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(context.Background(), `DELETE FROM agent_sessions WHERE tenant_id='as_t'`)
	writer := &RealAuditWriter{db: &realDBExecutor{pool: pool}}
	cases := []struct {
		name     string
		sequence []string
		want     string
	}{
		{"empty then product", []string{"", "workbuddy"}, "workbuddy"},
		{"role then product", []string{"main", "workbuddy"}, "workbuddy"},
		{"spaced role then product", []string{"Sub_Agent", "deepseek-harness"}, "deepseek-harness"},
		{"product sticks over other product", []string{"workbuddy", "cursor"}, "workbuddy"},
		{"product sticks over role", []string{"workbuddy", "main"}, "workbuddy"},
		{"product sticks over empty", []string{"workbuddy", ""}, "workbuddy"},
		{"role stays role without product", []string{"main", "auxiliary"}, "main"},
		{"empty stays empty", []string{"", ""}, ""},
		{"vscode upgraded by product", []string{"vscode", "workbuddy"}, "workbuddy"},
		{"agent-tool-call upgraded by product", []string{"agent-tool-call", "cursor"}, "cursor"},
		{"spaced runtime upgraded by product", []string{" VSCode ", "claude-code"}, "claude-code"},
		{"product not overwritten by vscode", []string{"workbuddy", "vscode"}, "workbuddy"},
		{"product not overwritten by agent-tool-call", []string{"workbuddy", "agent-tool-call"}, "workbuddy"},
		{"vscode not replaced by role", []string{"vscode", "main"}, "vscode"},
		{"vscode not replaced by agent-tool-call", []string{"vscode", "agent-tool-call"}, "vscode"},
	}
	for i, tc := range cases {
		sid := fmt.Sprintf("as_s_%02d", i)
		for _, agentType := range tc.sequence {
			writer.UpsertAgentSession(ctx, &modelrouter.RequestEnvelope{
				RequestID: sid, TenantID: "as_t", ProjectID: "as_p", UserID: "as_u", SessionID: sid, AgentType: agentType,
			})
		}
		var got string
		if err = pool.QueryRow(ctx, `SELECT COALESCE(agent_type,'') FROM agent_sessions WHERE session_id=$1`, sid).Scan(&got); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s: agent_type=%q want %q", tc.name, got, tc.want)
		}
	}
}

// 缺少数据库变量时：CI 里必须失败（否则新 DB 测试在流水线里会悄悄不跑），本地才跳过。
func skipOrFailWithoutDatabase(t *testing.T, envName string) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatalf("%s is not set but CI is set: database tests must run in CI", envName)
	}
	t.Skipf("%s is not set", envName)
}

// 请求行回填 BackfillRequestAgentType 允许从哪些值升级，必须和会话用的共用可升级名单一致：
// SQL 里内联的字面量就是 agentdetect.UpgradeableRuntimeIdentities()，不多不少。
func TestBackfillRequestAgentTypeUpgradesOnlySharedRuntimeIdentities(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}
	writer.BackfillRequestAgentType(context.Background(), "t", "r", "workbuddy")
	if mockDB.execCalls != 1 {
		t.Fatalf("exec calls=%d", mockDB.execCalls)
	}
	query := mockDB.queries[0]
	upgradeable := agentdetect.UpgradeableRuntimeIdentities()
	for _, name := range upgradeable {
		if got := strings.Count(query, "'"+name+"'"); got != 2 {
			t.Fatalf("%q appears %d times in BackfillRequestAgentType SQL, want 2", name, got)
		}
	}
}

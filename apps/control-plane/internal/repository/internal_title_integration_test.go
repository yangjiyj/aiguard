package repository

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/internaltitle"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newInternalTitleEnv 只在显式测试库中建隔离 schema，绝不回落到 public。
// 复制结构但不复制触发器/外键；视图同时覆盖新消息与历史消息。
func newInternalTitleEnv(t *testing.T) *pgxpool.Pool {
	t.Helper()
	admin, dsn := riskRefreshAdminPool(t)
	ctx := context.Background()
	schema := "internal_title_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	for _, table := range []string{"request_logs", "access_content_logs", "content_log_entries", "content_log_bodies", "content_logs_legacy"} {
		if _, err := db.Exec(ctx, fmt.Sprintf("CREATE TABLE %s (LIKE public.%s INCLUDING ALL)", pgx.Identifier{table}.Sanitize(), pgx.Identifier{table}.Sanitize())); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `CREATE VIEW content_logs AS
 SELECT e.id,e.request_id,e.tenant_id,e.environment_scope,e.role,b.content,e.created_at,e.session_id
 FROM content_log_entries e JOIN content_log_bodies b USING(tenant_id,content_sha256)
 UNION ALL SELECT id,request_id,tenant_id,environment_scope,role,content,created_at,session_id FROM content_logs_legacy`); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestInternalTitleSQLProtocolAndThreeStates(t *testing.T) {
	db := newInternalTitleEnv(t)
	ctx := context.Background()
	const codexPrompt = "You are a helpful assistant. You will be presented with a user prompt, and your job is to provide a short title for a task that will be created from that prompt. The tasks typically have to do with coding-related tasks The title you generate will be shown in the UI to represent the prompt. Generate a clear, informative task title based solely on the prompt provided."
	type sample struct {
		name, agent, host, path, model, request, response, files string
		size                                                     int
		internal                                                 bool
	}
	samples := []sample{
		{"workbuddy", "workbuddy", "copilot.tencent.com", "/v2/chat/completions", "deepseek-v4-flash", "<session>x</session>", `{"isNewTopic":true,"title":"Hello"}`, "[]", 4096, true},
		{"workbuddy-reordered", "workbuddy", "copilot.tencent.com", "/v2/chat/completions?x=1", " DeepSeek-V4-Flash ", " <session>x</session> ", `{"title":"Hello","isNewTopic":true}`, "[]", 1, true},
		{"workbuddy-false-topic", "workbuddy", "copilot.tencent.com", "/v2/chat/completions", "deepseek-v4-flash", "<session>x</session>", `{"isNewTopic":false,"title":"Hello"}`, "[]", 50, false},
		{"workbuddy-empty-title", "workbuddy", "copilot.tencent.com", "/v2/chat/completions", "deepseek-v4-flash", "<session>x</session>", `{"isNewTopic":true,"title":"  "}`, "[]", 50, false},
		{"workbuddy-extra-field", "workbuddy", "copilot.tencent.com", "/v2/chat/completions", "deepseek-v4-flash", "<session>x</session>", `{"isNewTopic":true,"title":"Hello","extra":1}`, "[]", 50, false},
		{"workbuddy-tab-not-trimmed", "workbuddy", "copilot.tencent.com", "/v2/chat/completions", "deepseek-v4-flash", "\t<session>x</session>", `{"isNewTopic":true,"title":"Hello"}`, "[]", 50, false},
		{"codebuddy", "codebuddy", "copilot.tencent.com", "/v2/chat/completions", "deepseek-v4-pro", "Q: hello\r\nA: hi", "简短标题", "[]", 150, true},
		{"codebuddy-large", "codebuddy", "copilot.tencent.com", "/v2/chat/completions", "deepseek-v4-pro", "Q: hello\nA: hi", "title", "[]", 4097, false},
		{"codebuddy-files", "codebuddy", "copilot.tencent.com", "/v2/chat/completions", "deepseek-v4-pro", "Q: hello\nA: hi", "title", `[{"name":"a"}]`, 150, false},
		{"codebuddy-multiline", "codebuddy", "copilot.tencent.com", "/v2/chat/completions", "deepseek-v4-pro", "Q: hello\nA: hi", "line1\nline2", "[]", 150, false},
		{"codebuddy-no-answer", "codebuddy", "copilot.tencent.com", "/v2/chat/completions", "deepseek-v4-pro", "Q: hello", "title", "[]", 150, false},
		{"codex", "openai-codex", "any.example", "/v1/responses?x=1", "gpt-5.6-luna", codexPrompt, `{"description":"d","title":"t"}`, "[]", 9000, true},
		{"codex-wrong-model", "openai-codex", "any.example", "/v1/responses", "gpt-other", codexPrompt, `{"description":"d","title":"t"}`, "[]", 100, false},
		{"codex-partial", "openai-codex", "any.example", "/v1/responses", "gpt-5.6-luna", "Please generate a title", `{"description":"d","title":"t"}`, "[]", 100, false},
		{"codex-endpoint", "openai-codex", "any.example", "/v1/chat/completions", "gpt-5.6-luna", codexPrompt, `{"description":"d","title":"t"}`, "[]", 100, false},
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	wantVisible := 0
	expected := map[string]bool{}
	for _, s := range samples {
		exec(`INSERT INTO request_logs(created_at,id,request_id,tenant_id,environment_scope,agent_type,proxy_mode,proxy_target_host,proxy_target_path,proxy_request_bytes,has_retained_content,proxy_access_type_resolved) VALUES(now()-interval '1 hour',$1,$1,'t','customer',$2,'forward',$3,$4,$5,true,'ai_ide')`, s.name, s.agent, s.host, s.path, s.size)
		exec(`INSERT INTO access_content_logs(id,request_id,tenant_id,environment_scope,model,request_content_redacted,response_content_redacted,file_metadata_json) VALUES($1,$1,'t','customer',$2,$3,$4,$5::jsonb)`, s.name, s.model, s.request, s.response, s.files)
		expected[s.name] = s.internal
		if !s.internal {
			wantVisible++
		}
	}
	// 反向 workbuddy 协议：每个请求的 system/user/assistant 分散在历史表和新表。
	for _, s := range []struct {
		name, agent, system, user, response, source string
		internal                                    bool
	}{
		{"mixed", "other", "Generate a concise, sentence-case title (3-7 words) only summarize its intent", "<session>\nx", `{"title":"Hello","isNewTopic":true}`, "", true},
		{"reverse-workbuddy", "workbuddy", "unrelated", "<session>\nx", `{"isNewTopic":true,"title":"Hello"}`, "", true},
		{"near-user", "other", "Generate a concise, sentence-case title (3-7 words) only summarize its intent", "<session>x", `{"isNewTopic":true,"title":"Hello"}`, "", false},
		{"near-system", "other", "Please generate a title only summarize its intent", "<session>\nx", `{"isNewTopic":true,"title":"Hello"}`, "", false},
		{"has-run", "workbuddy", "", "<session>\nx", `{"isNewTopic":true,"title":"Hello"}`, "workspace", false},
	} {
		exec(`INSERT INTO request_logs(created_at,id,request_id,tenant_id,environment_scope,agent_type,proxy_mode,endpoint_type,evidence_run_source,has_retained_content,proxy_access_type_resolved) VALUES(now()-interval '1 hour',$1,$1,'t','customer',$2,'chat_completion','chat',$3,true,'llm')`, s.name, s.agent, s.source)
		exec(`INSERT INTO content_logs_legacy(id,request_id,tenant_id,environment_scope,role,content) VALUES($1,$2,'t','customer','system',$3)`, s.name+"-system", s.name, s.system)
		for i, m := range []struct{ role, text string }{{"user", s.user}, {"assistant", s.response}} {
			hash := make([]byte, 32)
			copy(hash, []byte(fmt.Sprintf("%s-%d", s.name, i)))
			exec(`INSERT INTO content_log_bodies(tenant_id,content_sha256,content,customer_text) VALUES('t',$1,$2,true)`, hash, m.text)
			exec(`INSERT INTO content_log_entries(id,request_id,tenant_id,environment_scope,role,content_sha256,customer_text) VALUES($1,$2,'t','customer',$3,$4,true)`, fmt.Sprintf("%s-%d", s.name, i), s.name, m.role, hash)
		}
		expected[s.name] = s.internal
		if !s.internal {
			wantVisible++
		}
	}

	// 近似反例不能借用其他租户、环境或角色的系统指纹。
	for i, scope := range []struct{ tenant, env, role string }{{"foreign", "customer", "system"}, {"t", "home", "system"}, {"t", "customer", "assistant"}} {
		exec(`INSERT INTO content_logs_legacy(id,request_id,tenant_id,environment_scope,role,content) VALUES($1,'near-system',$2,$3,$4,'Generate a concise, sentence-case title (3-7 words) only summarize its intent')`, fmt.Sprintf("isolation-%d", i), scope.tenant, scope.env, scope.role)
	}
	// 旧 SQL 是独立快照，逐行比较，防止“新规则与自己的缓存相等”掩盖规则漂移。
	assertEqual := func() {
		t.Helper()
		var mismatches int
		q := "SELECT count(*) FROM request_logs rl WHERE (" + legacyInternalTitlePredicate + ") IS DISTINCT FROM (" + internaltitle.Predicate() + ")"
		if err := db.QueryRow(ctx, q).Scan(&mismatches); err != nil {
			t.Fatal(err)
		}
		if mismatches != 0 {
			t.Fatalf("新旧规则有 %d 行不一致", mismatches)
		}
		result, err := NewRequestLogRepository(db).GetForwardProxyAccessCounts(ctx, "t", ForwardProxyAccessFilter{ContentOnly: true, EnvironmentScope: "customer"})
		if err != nil {
			t.Fatal(err)
		}
		if result.Total != wantVisible {
			t.Fatalf("counts=%d，期望 %d", result.Total, wantVisible)
		}
	}
	assertEqual()
	for id, want := range expected {
		var got bool
		if err := db.QueryRow(ctx, "SELECT NOT ("+internaltitle.RawPredicate()+") FROM request_logs rl WHERE id=$1", id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("协议样本 %s：内部=%v，期望 %v", id, got, want)
		}
	}
	// 缓存先全部计算，再将三分之一重新置 NULL，必须覆盖 true、false、NULL 混合读取。
	exec("UPDATE request_logs rl SET internal_title_request = NOT (" + internaltitle.RawPredicate() + ")")
	exec("UPDATE request_logs SET internal_title_request=NULL WHERE id IN ('mixed','workbuddy','codex-partial')")
	assertEqual()
	repo := NewRequestLogRepository(db)
	for {
		n, err := repo.BackfillInternalTitleRequests(ctx, 2)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}
	assertEqual()
	if n, err := repo.BackfillInternalTitleRequests(ctx, 500); err != nil || n != 0 {
		t.Fatalf("回填必须可重入：%d %v", n, err)
	}
	// 写路径不维护该列：沉淀窗口内的新请求保持 NULL，按原规则实时计算。
	if _, err := db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,environment_scope,created_at) VALUES('fresh','fresh','t','customer',now())`); err != nil {
		t.Fatal(err)
	}
	if n, err := repo.BackfillInternalTitleRequests(ctx, 500); err != nil || n != 0 {
		t.Fatalf("沉淀窗口内的新请求不得补算：%d %v", n, err)
	}
	var fresh *bool
	if err := db.QueryRow(ctx, `SELECT internal_title_request FROM request_logs WHERE id='fresh'`).Scan(&fresh); err != nil || fresh != nil {
		t.Fatalf("新请求必须保持 NULL：%v %v", fresh, err)
	}
	// 控制面改写（智能体识别、工具调用归类）会把缓存置回 NULL，再由补算按当前内容重算。
	if _, err := db.Exec(ctx, `UPDATE request_logs SET internal_title_request = NULL WHERE id='mixed'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE content_logs_legacy SET content='普通系统提示' WHERE request_id='mixed'`); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.BackfillInternalTitleRequests(ctx, 500); err != nil {
		t.Fatal(err)
	}
	var internal bool
	if err := db.QueryRow(ctx, `SELECT internal_title_request FROM request_logs WHERE id='mixed'`).Scan(&internal); err != nil || internal {
		t.Fatalf("失效后重算未生效：%v %v", internal, err)
	}
	// 正文自然过期后旧规则会变化，原保留期清理也必须使缓存失效。
	tag, err := internaltitle.Prune(ctx, db, "access_content_logs", "request_id = $1", false, 500, "workbuddy")
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("清理失败：%v", err)
	}
	var cached *bool
	if err = db.QueryRow(ctx, `SELECT internal_title_request FROM request_logs WHERE id='workbuddy'`).Scan(&cached); err != nil || cached != nil {
		t.Fatal("清理必须将派生列置 NULL")
	}
	var visible bool
	if err = db.QueryRow(ctx, "SELECT "+internaltitle.Predicate()+" FROM request_logs rl WHERE id='workbuddy'").Scan(&visible); err != nil || !visible {
		t.Fatalf("清理后的回退必须符合旧规则：%v", err)
	}

}

func TestInternalTitleBackfillSkipsLocksAndResumes(t *testing.T) {
	db := newInternalTitleEnv(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,created_at) VALUES('locked','locked','t',now()-interval '1 hour')`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT id FROM request_logs WHERE id='locked' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	repo := NewRequestLogRepository(db)
	if n, err := repo.BackfillInternalTitleRequests(ctx, 1); err != nil || n != 0 {
		t.Fatalf("必须跳过写入锁：%d %v", n, err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := repo.BackfillInternalTitleRequests(ctx, 1); err != nil || n != 1 {
		t.Fatalf("释放锁后必须可恢复：%d %v", n, err)
	}
	if n, err := repo.BackfillInternalTitleRequests(ctx, 1); err != nil || n != 0 {
		t.Fatalf("重复运行不得重写：%d %v", n, err)
	}
}

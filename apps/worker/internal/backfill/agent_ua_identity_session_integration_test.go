package backfill

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/yangjiyj/aiguard/packages/shared-go/aiadapters"
	"github.com/jackc/pgx/v5/pgxpool"
)

const agentUATestDatabaseEnv = "JJD_BACKFILL_AGENT_UA_TEST_DATABASE_URL"

// 缺少数据库变量时：CI 里必须失败（否则新 DB 测试在流水线里会悄悄不跑），本地才跳过。
func openAgentUATestDB(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv(agentUATestDatabaseEnv)
	if url == "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("%s is not set but CI is set: database tests must run in CI", agentUATestDatabaseEnv)
		}
		t.Skipf("%s is not set", agentUATestDatabaseEnv)
	}
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

// 把回填任务重置为待跑并跑完。
func runAgentUATaskFresh(t *testing.T, ctx context.Context, db *pgxpool.Pool, owner string, batchSize int) {
	t.Helper()
	if _, err := db.Exec(ctx, `UPDATE migration_backfill_tasks SET state='paused',pause_requested=true WHERE task_name<>$1`, AgentUAIdentityTask); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
UPDATE migration_backfill_tasks SET state='pending',pause_requested=false,checkpoint='{}',scan_upper_bound='{}',
 lease_owner=NULL,lease_expires_at=NULL,scanned=0,updated=0,skipped=0,batch_size=$2
WHERE task_name=$1`, AgentUAIdentityTask, batchSize); err != nil {
		t.Fatal(err)
	}
	store := NewPostgresStore(db)
	for {
		task, err := store.Claim(ctx, owner, 15*time.Second)
		if err != nil || task == nil || task.Name != AgentUAIdentityTask {
			t.Fatalf("claim: task=%+v err=%v", task, err)
		}
		result, err := store.RunBatch(ctx, task, owner, 15*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if result.Done {
			if err = store.Complete(ctx, task, owner, result); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
}

type sessionRow struct {
	id, ua, declared, prevType, source, session string
	ageHours                                    int
}

// 会话同步：被修复行的"前值"决定会话能否被纠正。
func TestAgentUAIdentitySessionCorrectionOnMigratedSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db := openAgentUATestDB(t, ctx)

	// 会话已存值 -> 期望的会话终值。
	sessions := []struct{ session, stored, want string }{
		{"us_a", "openai-codex", "workbuddy"},           // 会话存了错误具体值，且等于被修复行前值 -> 纠正
		{"us_b", "claude-code", "claude-code"},          // 会话存了别的具体值，与被修复行前值不同 -> 不动
		{"us_c", "vscode", "workbuddy"},                 // 可升级运行时值 -> 纠正
		{"us_d", "agent-tool-call", "deepseek-harness"}, // 另一个可升级运行时值 -> 纠正
		{"us_e", "OpenAI_Codex", "workbuddy"},           // 大小写/下划线归一化后等于前值 -> 纠正
		{"us_f", "main", "workbuddy"},                   // 通用值 -> 纠正（回归）
		{"us_g", "", "workbuddy"},                       // 空值 -> 纠正（回归）
		{"us_h", "cursor", "cursor"},                    // 同批多行：最早一行前值不是会话值 -> 不动
		{"us_i", "claude-code", "workbuddy"},            // 同批多行：最早一行前值等于会话值 -> 纠正为最早一行的产品
		{"us_j", "openai-codex", "workbuddy"},           // 多会话多产品：最早一行是 WorkBuddy
		{"us_k", "dify-coze", "deepseek-harness"},       // 多会话多产品：最早一行是 DeepSeek Harness
	}
	rows := []sessionRow{
		{id: "us_r_a", ua: wbUA, declared: "main", prevType: "openai-codex", source: "message_protocol", session: "us_a"},
		{id: "us_r_b", ua: wbUA, declared: "main", prevType: "openai-codex", source: "message_protocol", session: "us_b"},
		{id: "us_r_c", ua: wbUA, declared: "main", prevType: "cursor", source: "content", session: "us_c"},
		{id: "us_r_d", ua: ds1UA, prevType: "dify-coze", source: "content", session: "us_d"},
		{id: "us_r_e", ua: wbUA, declared: "main", prevType: "openai-codex", source: "message_protocol", session: "us_e"},
		{id: "us_r_f", ua: wbUA, declared: "main", prevType: "openai-codex", source: "message_protocol", session: "us_f"},
		{id: "us_r_g", ua: wbUA, declared: "main", prevType: "openai-codex", source: "message_protocol", session: "us_g"},
		// us_h：最早一行（72h）前值 openai-codex 不等于会话值 cursor；较晚一行（24h）前值 cursor 等于会话值，但按最早一行取。
		{id: "us_r_h1", ua: wbUA, declared: "main", prevType: "openai-codex", source: "message_protocol", session: "us_h", ageHours: 72},
		{id: "us_r_h2", ua: ds2UA, prevType: "cursor", source: "message_protocol", session: "us_h", ageHours: 24},
		// us_i：最早一行（72h）WorkBuddy 前值 claude-code 等于会话值；较晚一行是另一个产品。
		{id: "us_r_i1", ua: wbUA, declared: "main", prevType: "claude-code", source: "message_protocol", session: "us_i", ageHours: 72},
		{id: "us_r_i2", ua: ds2UA, prevType: "claude-code", source: "message_protocol", session: "us_i", ageHours: 24},
		{id: "us_r_j1", ua: wbUA, declared: "main", prevType: "openai-codex", source: "message_protocol", session: "us_j", ageHours: 48},
		{id: "us_r_j2", ua: ds1UA, prevType: "openai-codex", source: "content", session: "us_j", ageHours: 12},
		{id: "us_r_k1", ua: ds1UA, prevType: "dify-coze", source: "content", session: "us_k", ageHours: 48},
		{id: "us_r_k2", ua: wbUA, declared: "main", prevType: "dify-coze", source: "message_protocol", session: "us_k", ageHours: 12},
	}

	if _, err := db.Exec(ctx, `
INSERT INTO tenants(id,name,is_test) VALUES ('us_t','us_t',true) ON CONFLICT DO NOTHING;
INSERT INTO users(id,tenant_id,username,role) VALUES ('us_u','us_t','us_u','developer') ON CONFLICT DO NOTHING;
INSERT INTO projects(id,tenant_id,name) VALUES ('us_p','us_t','us_p') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec(context.Background(), `
DELETE FROM migration_backfill_retry_rows WHERE row_id LIKE 'us_r_%';
DELETE FROM agent_protocol_repairs WHERE tenant_id='us_t';
DELETE FROM request_logs WHERE tenant_id='us_t';
DELETE FROM agent_sessions WHERE tenant_id='us_t'`)
	})
	for _, s := range sessions {
		if _, err := db.Exec(ctx, `INSERT INTO agent_sessions(id,tenant_id,project_id,user_id,session_id,agent_type)
VALUES ('as_'||$1::text,'us_t','us_p','us_u',$1::text,$2)`, s.session, s.stored); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range rows {
		headers, _ := json.Marshal(map[string]string{
			"user_agent": r.ua, "declared_name": "", "declared_type": r.declared,
			"header_source": r.source, "header_product": r.prevType,
		})
		if _, err := db.Exec(ctx, `
INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,proxy_mode,environment_scope,
 proxy_user_agent,agent_identity_headers,agent_type,agent_detection_source,agent_detection_confidence,
 session_id,created_at)
VALUES ($1,$1,'us_t','us_p','us_u','api','customer',$2,$3::jsonb,$4,$5,0.9,$6,
 NOW() - make_interval(hours => $7))`,
			r.id, r.ua, string(headers), r.prevType, r.source, r.session, r.ageHours); err != nil {
			t.Fatalf("insert %s: %v", r.id, err)
		}
	}

	// 一批装下全部行：DISTINCT ON 的"同批同会话取最早一行"语义只在同批内成立。
	runAgentUATaskFresh(t, ctx, db, "us-worker", 100)

	for _, s := range sessions {
		var got string
		if err := db.QueryRow(ctx, `SELECT COALESCE(agent_type,'') FROM agent_sessions WHERE tenant_id='us_t' AND session_id=$1`, s.session).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != s.want {
			t.Errorf("session %s (stored %q): agent_type=%q, want %q", s.session, s.stored, got, s.want)
		}
	}
	// 被修复的请求行都有前值留档。
	var repaired int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_protocol_repairs WHERE migration='991' AND tenant_id='us_t'`).Scan(&repaired); err != nil || repaired != len(rows) {
		t.Fatalf("repairs=%d err=%v, want %d", repaired, err, len(rows))
	}
}

// 名单一致性：注册表里每个具体产品（非通用、非可升级运行时）都必须被
// agent_identity_known 认可，否则身份确认页会把它当成"待识别"。
func TestAgentRegistryTypesAreKnownToIdentityFunctionOnMigratedSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db := openAgentUATestDB(t, ctx)
	checked := 0
	for _, def := range aiadapters.AgentDefinitions() {
		if agentdetect.IsGenericAgentIdentity(def.Type) || agentdetect.IsUpgradeableRuntimeIdentity(def.Type) {
			continue
		}
		var known bool
		if err := db.QueryRow(ctx, `SELECT agent_identity_known($1)`, def.Type).Scan(&known); err != nil {
			t.Fatal(err)
		}
		if !known {
			t.Errorf("registry type %q is not in agent_identity_known(); add it to a migration", def.Type)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no registry types checked")
	}
	for _, name := range append(agentdetect.GenericAgentIdentities(), agentdetect.UpgradeableRuntimeIdentities()...) {
		var known bool
		if err := db.QueryRow(ctx, `SELECT agent_identity_known($1)`, name).Scan(&known); err != nil {
			t.Fatal(err)
		}
		if known {
			t.Errorf("%q is generic/runtime and must not be a known product", name)
		}
	}
}

package backfill

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

const wbUA = "WorkBuddy/5.9.3 WorkBuddy/5.9.3 CLI/2.165.0"
const ds1UA = "deepseek-harness/0.1.0-rc.6 (+https://github.com/deepseek-ai/deepseek-harness)"
const ds2UA = "deepseek-harness/0.2.1-rc.2 (+https://github.com/deepseek-ai/deepseek-harness)"

// request_logs.agent_detection_confidence 是 real，往返后有 float32 精度。
func approx(a, b float64) bool { return a-b < 1e-5 && b-a < 1e-5 }

type uaFixture struct {
	id, ua, declared, agentType, source string
	confidence                          float64
	session                             string
	ageDays                             int
	wantType, wantSource                string
	wantRepair                          bool
}

// 需要完整 schema 且已应用 991 的库（JJD_BACKFILL_AGENT_UA_TEST_DATABASE_URL）。
func TestAgentUAIdentityBackfillOnMigratedSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db := openAgentUATestDB(t, ctx)

	fixtures := []uaFixture{
		// 现场表格里的每一类行
		{id: "ua_wb_main", ua: wbUA, declared: "main", agentType: "openai-codex", source: "message_protocol", confidence: 0.9, session: "ua_sess_main", wantType: "workbuddy", wantSource: "user_agent", wantRepair: true},
		{id: "ua_wb_aux", ua: wbUA, declared: "auxiliary", agentType: "auxiliary", source: "client_header", confidence: 0.95, session: "ua_sess_main", wantType: "workbuddy", wantSource: "user_agent", wantRepair: true},
		{id: "ua_wb_comp", ua: wbUA, declared: "compaction", agentType: "compaction", source: "client_header", confidence: 0.95, wantType: "workbuddy", wantSource: "user_agent", wantRepair: true},
		{id: "ua_ds1", ua: ds1UA, declared: "", agentType: "dify-coze", source: "content", confidence: 0.98, wantType: "deepseek-harness", wantSource: "user_agent", wantRepair: true},
		{id: "ua_ds2", ua: ds2UA, declared: "", agentType: "cursor", source: "message_protocol", confidence: 0.8, session: "ua_sess_keep", wantType: "deepseek-harness", wantSource: "user_agent", wantRepair: true},
		{id: "ua_oai", ua: "OpenAI/Python 2.24.0", agentType: "openai-codex", source: "content", confidence: 0.98, wantType: "openai-codex", wantSource: "content"},
		{id: "ua_go", ua: "Go-http-client/1.1", agentType: "claude-code", source: "message_protocol", confidence: 0.8, wantType: "claude-code", wantSource: "message_protocol"},
		// 绝不碰的来源
		{id: "ua_explicit", ua: wbUA, declared: "cursor", agentType: "cursor", source: "explicit_header", confidence: 1, wantType: "cursor", wantSource: "explicit_header"},
		{id: "ua_product", ua: wbUA, agentType: "claude-code", source: "product_identity", confidence: 0.98, wantType: "claude-code", wantSource: "product_identity"},
		{id: "ua_client_concrete", ua: wbUA, declared: "cursor", agentType: "cursor", source: "client_header", confidence: 0.95, wantType: "cursor", wantSource: "client_header"},
		{id: "ua_client_mixed", ua: wbUA, declared: "main", agentType: "cursor", source: "client_header", confidence: 0.95, wantType: "cursor", wantSource: "client_header"},
		{id: "ua_user_agent_src", ua: wbUA, declared: "main", agentType: "cursor", source: "user_agent", confidence: 0.85, wantType: "cursor", wantSource: "user_agent"},
		// 窗口外与无 UA
		{id: "ua_old", ua: wbUA, declared: "main", agentType: "openai-codex", source: "message_protocol", confidence: 0.9, ageDays: 40, wantType: "openai-codex", wantSource: "message_protocol"},
		{id: "ua_no_ua", ua: "", declared: "main", agentType: "openai-codex", source: "message_protocol", confidence: 0.9, wantType: "openai-codex", wantSource: "message_protocol"},
	}

	var err error
	if _, err = db.Exec(ctx, `
INSERT INTO tenants(id,name,is_test) VALUES ('ua_t','ua_t',true) ON CONFLICT DO NOTHING;
INSERT INTO users(id,tenant_id,username,role) VALUES ('ua_u','ua_t','ua_u','developer') ON CONFLICT DO NOTHING;
INSERT INTO projects(id,tenant_id,name) VALUES ('ua_p','ua_t','ua_p') ON CONFLICT DO NOTHING;
INSERT INTO agent_sessions(id,tenant_id,project_id,user_id,session_id,agent_type) VALUES
 ('ua_as_main','ua_t','ua_p','ua_u','ua_sess_main','main'),
 ('ua_as_keep','ua_t','ua_p','ua_u','ua_sess_keep','cursor')`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(context.Background(), `
DELETE FROM migration_backfill_retry_rows WHERE row_id LIKE 'ua_%';
DELETE FROM agent_protocol_repairs WHERE tenant_id='ua_t';
DELETE FROM request_logs WHERE tenant_id='ua_t';
DELETE FROM agent_sessions WHERE tenant_id='ua_t'`)

	for _, f := range fixtures {
		headers, _ := json.Marshal(map[string]string{
			"user_agent": f.ua, "declared_name": "", "declared_type": f.declared,
			"header_source": f.source, "header_product": f.agentType,
		})
		var session any
		if f.session != "" {
			session = f.session
		}
		_, err = db.Exec(ctx, `
INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,proxy_mode,environment_scope,
 proxy_user_agent,agent_identity_headers,agent_type,agent_detection_source,agent_detection_confidence,
 session_id,created_at)
VALUES ($1,$1,'ua_t','ua_p','ua_u','api','customer',NULLIF($2,''),$3::jsonb,$4,$5,$6,$7,
 NOW() - make_interval(days => $8))`,
			f.id, f.ua, string(headers), f.agentType, f.source, f.confidence, session, f.ageDays)
		if err != nil {
			t.Fatalf("insert %s: %v", f.id, err)
		}
	}
	// 触发器应已把每行同步进证据索引；记下变更前的有效名称。
	var indexBefore string
	if err = db.QueryRow(ctx, `SELECT effective_agent_type FROM evidence_run_request_index WHERE request_log_id='ua_wb_main'`).Scan(&indexBefore); err != nil || indexBefore != "openai-codex" {
		t.Fatalf("index before=%q err=%v", indexBefore, err)
	}

	if _, err = db.Exec(ctx, `
UPDATE migration_backfill_tasks SET state='paused',pause_requested=true WHERE task_name<>'agent_ua_identity_v1';
UPDATE migration_backfill_tasks SET state='pending',pause_requested=false,batch_size=3
WHERE task_name='agent_ua_identity_v1'`); err != nil {
		t.Fatal(err)
	}
	store := NewPostgresStore(db)
	runToCompletion := func(owner string, crashAfterFirstBatch bool) {
		t.Helper()
		first := true
		for {
			task, claimErr := store.Claim(ctx, owner, 15*time.Second)
			if claimErr != nil || task == nil || task.Name != AgentUAIdentityTask {
				t.Fatalf("claim: task=%+v err=%v", task, claimErr)
			}
			result, runErr := store.RunBatch(ctx, task, owner, 15*time.Second)
			if runErr != nil {
				t.Fatal(runErr)
			}
			if crashAfterFirstBatch && first {
				// 模拟进程崩溃：租约过期，换一个 worker 从 checkpoint 继续。
				first = false
				if result.Done {
					t.Fatal("test fixture should need more than one batch")
				}
				if _, err = db.Exec(ctx, `UPDATE migration_backfill_tasks SET lease_expires_at=NOW()-INTERVAL '1 second' WHERE task_name=$1`, AgentUAIdentityTask); err != nil {
					t.Fatal(err)
				}
				owner = owner + "-resumed"
				continue
			}
			if result.Done {
				if err = store.Complete(ctx, task, owner, result); err != nil {
					t.Fatal(err)
				}
				return
			}
		}
	}
	runToCompletion("ua-worker", true)

	check := func(stage string) {
		t.Helper()
		repairs := 0
		for _, f := range fixtures {
			var gotType, gotSource string
			var gotConf float64
			if err = db.QueryRow(ctx, `SELECT COALESCE(agent_type,''),COALESCE(agent_detection_source,''),COALESCE(agent_detection_confidence,0)
FROM request_logs WHERE id=$1`, f.id).Scan(&gotType, &gotSource, &gotConf); err != nil {
				t.Fatal(err)
			}
			if gotType != f.wantType || gotSource != f.wantSource {
				t.Fatalf("%s %s: type=%q source=%q, want %q/%q", stage, f.id, gotType, gotSource, f.wantType, f.wantSource)
			}
			if f.wantRepair && !approx(gotConf, 0.85) {
				t.Fatalf("%s %s: confidence=%v, want user_agent confidence 0.85", stage, f.id, gotConf)
			}
			if !f.wantRepair && !approx(gotConf, f.confidence) {
				t.Fatalf("%s %s: untouched row confidence changed to %v", stage, f.id, gotConf)
			}
			var effective string
			if err = db.QueryRow(ctx, `SELECT effective_agent_type FROM evidence_run_request_index WHERE request_log_id=$1`, f.id).Scan(&effective); err != nil || effective != f.wantType {
				t.Fatalf("%s %s: index effective_agent_type=%q err=%v, want %q", stage, f.id, effective, err, f.wantType)
			}
			var prevType, prevSource string
			var prevConf float64
			var n int
			err = db.QueryRow(ctx, `SELECT COUNT(*),COALESCE(MAX(previous_identity->>'agent_type'),''),COALESCE(MAX(previous_identity->>'source'),''),COALESCE(MAX((previous_identity->>'confidence')::float8),0)
FROM agent_protocol_repairs WHERE migration='991' AND tenant_id='ua_t' AND request_id=$1`, f.id).Scan(&n, &prevType, &prevSource, &prevConf)
			if err != nil {
				t.Fatal(err)
			}
			if f.wantRepair {
				repairs++
				if n != 1 || prevType != f.agentType || prevSource != f.source || !approx(prevConf, f.confidence) {
					t.Fatalf("%s %s: repair n=%d prev=%s/%s/%v, want 1 row with %s/%s/%v", stage, f.id, n, prevType, prevSource, prevConf, f.agentType, f.source, f.confidence)
				}
			} else if n != 0 {
				t.Fatalf("%s %s: unexpected repair row", stage, f.id)
			}
		}
		var total int
		if err = db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_protocol_repairs WHERE migration='991' AND tenant_id='ua_t'`).Scan(&total); err != nil || total != repairs {
			t.Fatalf("%s: repairs=%d want %d err=%v", stage, total, repairs, err)
		}
		var mainSession, keepSession string
		if err = db.QueryRow(ctx, `SELECT
 (SELECT agent_type FROM agent_sessions WHERE session_id='ua_sess_main'),
 (SELECT agent_type FROM agent_sessions WHERE session_id='ua_sess_keep')`).Scan(&mainSession, &keepSession); err != nil {
			t.Fatal(err)
		}
		// keep 会话存的 cursor 恰好等于被修复行 ua_ds2 的前值（cursor 是回填刚判定为错的值），
		// 所以一并纠正；"别的具体值不动"见 TestAgentUAIdentitySessionCorrectionOnMigratedSchema。
		if mainSession != "workbuddy" || keepSession != "deepseek-harness" {
			t.Fatalf("%s: sessions main=%q keep=%q, want workbuddy/deepseek-harness (generic and wrong-previous-value upgraded)", stage, mainSession, keepSession)
		}
	}
	check("first run")

	var sessionPrev string
	if err = db.QueryRow(ctx, `SELECT COALESCE(MAX(previous_identity->>'session_agent_type'),'<none>') FROM agent_protocol_repairs
WHERE migration='991' AND tenant_id='ua_t' AND request_id IN ('ua_wb_main','ua_wb_aux')
  AND previous_identity->>'session_agent_type'='main'`).Scan(&sessionPrev); err != nil || sessionPrev != "main" {
		t.Fatalf("session before-image not recorded: %q err=%v", sessionPrev, err)
	}

	// 幂等：任务整体重置后重跑，不新增 repairs，也不改动任何行。
	if _, err = db.Exec(ctx, fmt.Sprintf(`UPDATE migration_backfill_tasks SET state='pending',checkpoint='{}',scan_upper_bound='{}',
 lease_owner=NULL,lease_expires_at=NULL,scanned=0,updated=0,skipped=0 WHERE task_name='%s'`, AgentUAIdentityTask)); err != nil {
		t.Fatal(err)
	}
	runToCompletion("ua-worker-rerun", false)
	check("rerun")
	var rerunUpdated int64
	if err = db.QueryRow(ctx, `SELECT updated FROM migration_backfill_tasks WHERE task_name=$1`, AgentUAIdentityTask).Scan(&rerunUpdated); err != nil || rerunUpdated != 0 {
		t.Fatalf("rerun updated=%d err=%v, want 0", rerunUpdated, err)
	}
}

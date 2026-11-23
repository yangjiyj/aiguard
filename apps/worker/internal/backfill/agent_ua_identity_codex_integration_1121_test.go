package backfill

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

type codexUAFixture struct {
	id, proxyUA, headerUA, originator, declared, agentType, source string
	confidence                                                     float64
	session                                                        string
	ageDays                                                        int
	wantType, wantSource                                           string
	wantRepair                                                     bool
}

// 需要完整 schema 且已应用 1011 的库（JJD_BACKFILL_AGENT_UA_TEST_DATABASE_URL）。
// 用客户现场的 UA：codex-tui / codex_vscode 被内容兜底错判成 dify-coze 的行改回 openai-codex。
func TestAgentUAIdentityCodexBackfillOnMigratedSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db := openAgentUATestDB(t, ctx)

	fixtures := []codexUAFixture{
		{id: "cx_tui", proxyUA: siteCodexTUIUA, headerUA: siteCodexTUIUA, agentType: "dify-coze", source: "content", confidence: 0.98, session: "cx_sess", wantType: "openai-codex", wantSource: "user_agent", wantRepair: true},
		{id: "cx_tui_mp", proxyUA: siteCodexTUIUA, headerUA: siteCodexTUIUA, agentType: "dify-coze", source: "message_protocol", confidence: 0.8, session: "cx_sess", wantType: "openai-codex", wantSource: "user_agent", wantRepair: true},
		{id: "cx_vsc", proxyUA: siteCodexVSCodeUA, headerUA: siteCodexVSCodeUA, agentType: "vscode", source: "user_agent_runtime", confidence: 0.35, wantType: "openai-codex", wantSource: "user_agent", wantRepair: true},
		{id: "cx_empty_src", proxyUA: siteCodexTUIUA, headerUA: siteCodexTUIUA, agentType: "", source: "", confidence: 0, wantType: "openai-codex", wantSource: "user_agent", wantRepair: true},
		// 原生 /v1/responses 路径不写 proxy_user_agent，UA 只在 agent_identity_headers 里
		{id: "cx_header_only", headerUA: siteCodexTUIUA, agentType: "dify-coze", source: "content", confidence: 0.98, wantType: "openai-codex", wantSource: "user_agent", wantRepair: true},
		{id: "cx_originator", headerUA: "node", originator: "codex_vscode", agentType: "dify-coze", source: "content", confidence: 0.98, wantType: "openai-codex", wantSource: "user_agent", wantRepair: true},
		{id: "cx_60d", proxyUA: siteCodexTUIUA, headerUA: siteCodexTUIUA, agentType: "dify-coze", source: "content", confidence: 0.98, ageDays: 60, wantType: "openai-codex", wantSource: "user_agent", wantRepair: true},
		// 不碰
		{id: "cx_120d", proxyUA: siteCodexTUIUA, headerUA: siteCodexTUIUA, agentType: "dify-coze", source: "content", confidence: 0.98, ageDays: 120, wantType: "dify-coze", wantSource: "content"},
		{id: "cx_client_generic", proxyUA: siteCodexTUIUA, headerUA: siteCodexTUIUA, declared: "main", agentType: "main", source: "client_header", confidence: 0.95, wantType: "main", wantSource: "client_header"},
		{id: "cx_explicit", proxyUA: siteCodexTUIUA, headerUA: siteCodexTUIUA, declared: "cursor", agentType: "cursor", source: "explicit_header", confidence: 1, wantType: "cursor", wantSource: "explicit_header"},
		{id: "cx_desktop_ok", proxyUA: siteCodexDeskUA, headerUA: siteCodexDeskUA, agentType: "openai-codex", source: "user_agent", confidence: 0.85, wantType: "openai-codex", wantSource: "user_agent"},
		{id: "cx_wb_v1_scope", proxyUA: wbUA, headerUA: wbUA, agentType: "openai-codex", source: "message_protocol", confidence: 0.9, wantType: "openai-codex", wantSource: "message_protocol"},
		{id: "cx_cherry", proxyUA: siteCherryUA, headerUA: siteCherryUA, agentType: "dify-coze", source: "content", confidence: 0.98, wantType: "dify-coze", wantSource: "content"},
		{id: "cx_node", proxyUA: "node-fetch", headerUA: "node-fetch", agentType: "dify-coze", source: "content", confidence: 0.98, wantType: "dify-coze", wantSource: "content"},
	}

	if _, err := db.Exec(ctx, `
INSERT INTO tenants(id,name,is_test) VALUES ('cx_t','cx_t',true) ON CONFLICT DO NOTHING;
INSERT INTO users(id,tenant_id,username,role) VALUES ('cx_u','cx_t','cx_u','developer') ON CONFLICT DO NOTHING;
INSERT INTO projects(id,tenant_id,name) VALUES ('cx_p','cx_t','cx_p') ON CONFLICT DO NOTHING;
INSERT INTO agent_sessions(id,tenant_id,project_id,user_id,session_id,agent_type) VALUES
 ('cx_as','cx_t','cx_p','cx_u','cx_sess','dify-coze')`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(context.Background(), `
DELETE FROM migration_backfill_retry_rows WHERE row_id LIKE 'cx_%';
DELETE FROM agent_protocol_repairs WHERE tenant_id='cx_t';
DELETE FROM security_events WHERE tenant_id='cx_t';
DELETE FROM request_logs WHERE tenant_id='cx_t';
DELETE FROM agent_sessions WHERE tenant_id='cx_t'`)

	for _, f := range fixtures {
		observed := map[string]string{"user_agent": f.headerUA, "declared_name": "", "declared_type": f.declared,
			"header_source": f.source, "header_product": f.agentType}
		if f.originator != "" {
			observed["originator"] = f.originator
		}
		headers, _ := json.Marshal(observed)
		var session any
		if f.session != "" {
			session = f.session
		}
		if _, err := db.Exec(ctx, `
INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,proxy_mode,environment_scope,
 proxy_user_agent,agent_identity_headers,agent_type,agent_detection_source,agent_detection_confidence,
 session_id,created_at)
VALUES ($1,$1,'cx_t','cx_p','cx_u','api','customer',NULLIF($2,''),$3::jsonb,NULLIF($4,''),NULLIF($5,''),$6,$7,
 NOW() - make_interval(days => $8))`,
			f.id, f.proxyUA, string(headers), f.agentType, f.source, f.confidence, session, f.ageDays); err != nil {
			t.Fatalf("insert %s: %v", f.id, err)
		}
	}
	// 991 早先给这一行留过修复记录，1011 的幂等屏障按迁移号区分，不能被它挡住。
	if _, err := db.Exec(ctx, `INSERT INTO agent_protocol_repairs(migration,tenant_id,request_id,previous_identity)
VALUES ('991','cx_t','cx_tui','{}'::jsonb)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO security_events(id,tenant_id,project_id,request_id,event_type,severity,action_taken,created_at)
VALUES ('cx_ev','cx_t','cx_p','cx_tui','security_audit','medium','audit',NOW())`); err != nil {
		t.Fatal(err)
	}

	run := func(owner string) int64 {
		t.Helper()
		if _, err := db.Exec(ctx, `UPDATE migration_backfill_tasks SET state='paused',pause_requested=true WHERE task_name<>$1`, AgentUAIdentityCodexTask); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `
UPDATE migration_backfill_tasks SET state='pending',pause_requested=false,batch_size=4,checkpoint='{}',scan_upper_bound='{}',
 started_at=NULL,lease_owner=NULL,lease_expires_at=NULL,scanned=0,updated=0,skipped=0 WHERE task_name=$1`, AgentUAIdentityCodexTask); err != nil {
			t.Fatal(err)
		}
		store := NewPostgresStore(db)
		for {
			task, err := store.Claim(ctx, owner, 15*time.Second)
			if err != nil || task == nil || task.Name != AgentUAIdentityCodexTask {
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
				break
			}
		}
		var updated int64
		if err := db.QueryRow(ctx, `SELECT updated FROM migration_backfill_tasks WHERE task_name=$1`, AgentUAIdentityCodexTask).Scan(&updated); err != nil {
			t.Fatal(err)
		}
		return updated
	}

	check := func(stage string) {
		t.Helper()
		repairs := 0
		for _, f := range fixtures {
			var gotType, gotSource, effective string
			var gotConf float64
			if err := db.QueryRow(ctx, `SELECT COALESCE(agent_type,''),COALESCE(agent_detection_source,''),COALESCE(agent_detection_confidence,0)
FROM request_logs WHERE id=$1`, f.id).Scan(&gotType, &gotSource, &gotConf); err != nil {
				t.Fatal(err)
			}
			if gotType != f.wantType || gotSource != f.wantSource {
				t.Fatalf("%s %s: type=%q source=%q, want %q/%q", stage, f.id, gotType, gotSource, f.wantType, f.wantSource)
			}
			if f.wantRepair && !approx(gotConf, 0.85) {
				t.Fatalf("%s %s: confidence=%v want 0.85", stage, f.id, gotConf)
			}
			if err := db.QueryRow(ctx, `SELECT effective_agent_type FROM evidence_run_request_index WHERE request_log_id=$1`, f.id).Scan(&effective); err != nil || effective != f.wantType {
				t.Fatalf("%s %s: evidence index=%q err=%v want %q", stage, f.id, effective, err, f.wantType)
			}
			var n int
			var prevType string
			if err := db.QueryRow(ctx, `SELECT COUNT(*),COALESCE(MAX(previous_identity->>'agent_type'),'')
FROM agent_protocol_repairs WHERE migration='1011' AND tenant_id='cx_t' AND request_id=$1`, f.id).Scan(&n, &prevType); err != nil {
				t.Fatal(err)
			}
			if f.wantRepair {
				repairs++
				if n != 1 || prevType != f.agentType {
					t.Fatalf("%s %s: repairs=%d prev=%q, want 1 with %q", stage, f.id, n, prevType, f.agentType)
				}
			} else if n != 0 {
				t.Fatalf("%s %s: unexpected repair", stage, f.id)
			}
		}
		var total int
		if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_protocol_repairs WHERE migration='1011' AND tenant_id='cx_t'`).Scan(&total); err != nil || total != repairs {
			t.Fatalf("%s: repairs=%d want %d err=%v", stage, total, repairs, err)
		}
		var session, eventAgent string
		if err := db.QueryRow(ctx, `SELECT
 (SELECT agent_type FROM agent_sessions WHERE session_id='cx_sess' AND tenant_id='cx_t'),
 (SELECT COALESCE(rl.agent_type,'') FROM security_events se JOIN request_logs rl
   ON rl.tenant_id=se.tenant_id AND rl.request_id=se.request_id WHERE se.id='cx_ev')`).Scan(&session, &eventAgent); err != nil {
			t.Fatal(err)
		}
		if session != "openai-codex" || eventAgent != "openai-codex" {
			t.Fatalf("%s: session=%q event agent=%q, want openai-codex", stage, session, eventAgent)
		}
	}

	if updated := run("cx-worker"); updated != int64(countCodexRepairs(fixtures)) {
		t.Fatalf("first run updated=%d", updated)
	}
	check("first run")
	if updated := run("cx-worker-rerun"); updated != 0 {
		t.Fatalf("rerun updated=%d, want 0 (idempotent)", updated)
	}
	check("rerun")
}

func countCodexRepairs(fixtures []codexUAFixture) int {
	n := 0
	for _, f := range fixtures {
		if f.wantRepair {
			n++
		}
	}
	return n
}

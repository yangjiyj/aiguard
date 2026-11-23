package backfill

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// 跨批次：batchSize=1 时同一会话的多行分到不同批。第一批把会话纠正为最早一行的产品后，
// 后续批次里前值仍是旧错误值的行不应再改写会话（会话值已不等于该行前值，也不是可覆盖值）。
func TestAgentUAIdentitySessionCorrectionAcrossBatchesOnMigratedSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db := openAgentUATestDB(t, ctx)

	sessions := []struct{ session, stored, want string }{
		{"ub_a", "openai-codex", "workbuddy"}, // 两行都是 WorkBuddy，前值都是 openai-codex
		{"ub_b", "openai-codex", "workbuddy"}, // 最早一行 WorkBuddy，较晚一行 DeepSeek Harness，前值都是 openai-codex
		{"ub_c", "claude-code", "claude-code"},
	}
	rows := []sessionRow{
		{id: "ub_r_a1", ua: wbUA, declared: "main", prevType: "openai-codex", source: "message_protocol", session: "ub_a", ageHours: 72},
		{id: "ub_r_a2", ua: wbUA, declared: "main", prevType: "openai-codex", source: "message_protocol", session: "ub_a", ageHours: 24},
		{id: "ub_r_b1", ua: wbUA, declared: "main", prevType: "openai-codex", source: "message_protocol", session: "ub_b", ageHours: 60},
		{id: "ub_r_b2", ua: ds1UA, prevType: "openai-codex", source: "content", session: "ub_b", ageHours: 12},
		{id: "ub_r_c1", ua: wbUA, declared: "main", prevType: "openai-codex", source: "message_protocol", session: "ub_c", ageHours: 48},
	}

	if _, err := db.Exec(ctx, `
INSERT INTO tenants(id,name,is_test) VALUES ('ub_t','ub_t',true) ON CONFLICT DO NOTHING;
INSERT INTO users(id,tenant_id,username,role) VALUES ('ub_u','ub_t','ub_u','developer') ON CONFLICT DO NOTHING;
INSERT INTO projects(id,tenant_id,name) VALUES ('ub_p','ub_t','ub_p') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec(context.Background(), `
DELETE FROM migration_backfill_retry_rows WHERE row_id LIKE 'ub_r_%';
DELETE FROM agent_protocol_repairs WHERE tenant_id='ub_t';
DELETE FROM request_logs WHERE tenant_id='ub_t';
DELETE FROM agent_sessions WHERE tenant_id='ub_t'`)
	})
	for _, s := range sessions {
		if _, err := db.Exec(ctx, `INSERT INTO agent_sessions(id,tenant_id,project_id,user_id,session_id,agent_type)
VALUES ('as_'||$1::text,'ub_t','ub_p','ub_u',$1::text,$2)`, s.session, s.stored); err != nil {
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
VALUES ($1,$1,'ub_t','ub_p','ub_u','api','customer',$2,$3::jsonb,$4,$5,0.9,$6,
 NOW() - make_interval(hours => $7))`,
			r.id, r.ua, string(headers), r.prevType, r.source, r.session, r.ageHours); err != nil {
			t.Fatalf("insert %s: %v", r.id, err)
		}
	}

	runAgentUATaskFresh(t, ctx, db, "ub-worker", 1)

	for _, s := range sessions {
		var got string
		if err := db.QueryRow(ctx, `SELECT COALESCE(agent_type,'') FROM agent_sessions WHERE tenant_id='ub_t' AND session_id=$1`, s.session).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != s.want {
			t.Errorf("session %s (stored %q): agent_type=%q, want %q", s.session, s.stored, got, s.want)
		}
	}
	// 请求行本身都按各自 UA 修正，前值留档齐全。
	want := map[string]string{"ub_r_a1": "workbuddy", "ub_r_a2": "workbuddy", "ub_r_b1": "workbuddy", "ub_r_b2": "deepseek-harness", "ub_r_c1": "workbuddy"}
	for id, w := range want {
		var got string
		if err := db.QueryRow(ctx, `SELECT agent_type FROM request_logs WHERE id=$1`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != w {
			t.Errorf("row %s: agent_type=%q want %q", id, got, w)
		}
	}
	var repaired int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM agent_protocol_repairs WHERE migration='991' AND tenant_id='ub_t'`).Scan(&repaired); err != nil || repaired != len(rows) {
		t.Fatalf("repairs=%d err=%v, want %d", repaired, err, len(rows))
	}
}

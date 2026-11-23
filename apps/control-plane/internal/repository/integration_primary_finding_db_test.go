package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 2.9.22 起 primary_finding 不再整条复制 findings 里的那一条（去掉原文、加 findings_index），
// 集成接口按“与 primary_finding 整条相等”选主命中会选错。改为先按 findings_index 对上序号，旧数据再按整条相等。
// 需要 ALERT_RAW_EVIDENCE_TEST_DATABASE_URL 指向按正式流程迁移到最新的库。
func TestCredentialHitsPicksPrimaryFindingByIndexOnPostgres(t *testing.T) {
	dsn := os.Getenv("ALERT_RAW_EVIDENCE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ALERT_RAW_EVIDENCE_TEST_DATABASE_URL not set; skipping migrated-database integration read test")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ns := fmt.Sprintf("rawint%d", time.Now().UnixNano())
	tenant, project, key := "tenant_"+ns, "proj_"+ns, "key_"+ns
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%v: %s", err, query)
		}
	}
	exec(`INSERT INTO tenants (id, name, is_test) VALUES ($1, $1, TRUE)`, tenant)
	exec(`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $1)`, project, tenant)
	exec(`INSERT INTO internal_keys (id, tenant_id, project_id, key_hash, key_prefix, agent_instance_id) VALUES ($1, $2, $3, $4, 'sk-int', $5)`, key, tenant, project, "hash_"+key, "agent_"+key)
	t.Cleanup(func() {
		c := context.Background()
		for _, q := range []string{`DELETE FROM security_events WHERE tenant_id=$1`, `DELETE FROM request_logs WHERE tenant_id=$1`,
			`DELETE FROM internal_keys WHERE tenant_id=$1`, `DELETE FROM projects WHERE tenant_id=$1`, `DELETE FROM tenants WHERE id=$1`} {
			_, _ = db.Exec(c, q, tenant)
		}
	})
	dlp := func(category, rule string, extra map[string]any) map[string]any {
		f := map[string]any{"type": "data_leak", "category": category, "severity": "high", "rule_id": rule,
			"policy_scene": "data_leak", "policy_code": "pc_" + category, "matched_capabilities": []any{category}, "action": "block"}
		for k, v := range extra {
			f[k] = v
		}
		return f
	}
	phone := dlp("pii_phone", "r_phone", nil)
	keyHit := dlp("openai_key", "r_key", map[string]any{"raw_evidence": "sk-proj-RAW", "evidence_context": "key=sk-proj-RAW"})
	reference := dlp("openai_key", "r_key", map[string]any{"findings_index": 1})
	insert := func(id string, summary map[string]any) {
		t.Helper()
		request := id + "_" + ns
		exec(`INSERT INTO request_logs (id, request_id, tenant_id, project_id, client_id, created_at) VALUES ($1, $1, $2, $3, $4, now())`, request, tenant, project, key)
		body, _ := json.Marshal(summary)
		exec(`INSERT INTO security_events (id, request_id, tenant_id, project_id, event_type, severity, action_taken, matched_summary, created_at)
			VALUES ($1, $2, $3, $4, 'security_check', 'high', 'block', $5::jsonb, now())`, "evt_"+request, request, tenant, project, string(body))
	}
	insert("new", map[string]any{"findings": []any{phone, keyHit}, "primary_finding": reference})
	insert("legacy", map[string]any{"findings": []any{phone, keyHit}, "primary_finding": keyHit})

	page, err := NewIntegrationRepository(db).CredentialHits(ctx, tenant, CredentialHitsQuery{KeyID: key})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Data) != 2 {
		t.Fatalf("两个事件各一条主命中: %+v", page.Data)
	}
	for _, hit := range page.Data {
		if hit.Category != "dlp:openai_key" || hit.PolicyID != "r_key" {
			t.Fatalf("主命中应是 findings[1]（新数据按 findings_index，旧数据按整条相等）: %+v", hit)
		}
	}
}

package repository

import (
	"context"
	"github.com/jackc/pgx/v5"
	"os"
	"strings"
	"testing"
)

// A real PostgreSQL query guards visibility, including tenant boundaries.
func TestDefaultAlertQueueRestoresEveryAgentClassification(t *testing.T) {
	dsn := os.Getenv("ALERT_VISIBILITY_TEST_DSN")
	if dsn == "" {
		t.Skip("ALERT_VISIBILITY_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)
	_, err = db.Exec(ctx, `CREATE TEMP TABLE alert_groups(id text, tenant_id text, request_id text, class_key text, alert_type text, is_canary bool DEFAULT false);
 CREATE TEMP TABLE request_logs(tenant_id text, request_id text, agent_type text, environment_scope text DEFAULT 'customer');
 CREATE TEMP TABLE security_events(id text, tenant_id text, request_id text, alert_group_id text, matched_summary jsonb);
 INSERT INTO request_logs(tenant_id,request_id,agent_type) VALUES ('t1','r1','openai-codex'),('t1','r2','cursor'),('t2','r1','openai-codex');
 INSERT INTO alert_groups(id,tenant_id,request_id,class_key,alert_type) SELECT c,'t1','r1',c,'security_event' FROM unnest(ARRAY['illegal_system_command_instructions','illegal_organ_trade','ssrf_metadata_instruction','supply_model_weight_theft','illegal_violence_terror','zero_width_char','injection_payload_splitting','destructive_change','plugin_attack','prompt_leak_attack','sensitive_file_hr_data','secret','pii','semantic_jailbreak']) c;
 INSERT INTO alert_groups(id,tenant_id,request_id,class_key,alert_type) VALUES ('runtime','t1','r2','engine_failure','runtime_fault'),('foreign','t2','r1','secret','security_event');`)
	if err != nil {
		t.Fatal(err)
	}
	for _, include := range []bool{false, true} {
		where, args, err := buildAlertGroupPageWhere(AlertGroupListFilter{TenantID: "t1", IncludeDevTraffic: include})
		if err != nil {
			t.Fatal(err)
		}
		var count int
		err = db.QueryRow(ctx, "SELECT count(*) FROM alert_groups ag WHERE "+strings.Join(where, " AND "), args...).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count != 15 {
			t.Errorf("include_dev=%v: visible=%d want 15 (all classes, own tenant only)", include, count)
		}
	}
}

package repository

import (
	"context"
	"github.com/jackc/pgx/v5"
	"os"
	"strings"
	"testing"
)

func TestDevelopmentAlertScopePostgresPreservesAllOtherRisk(t *testing.T) {
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
	_, err = db.Exec(ctx, `CREATE TEMP TABLE alert_groups(id text,tenant_id text,request_id text,class_key text,alert_type text,is_canary bool);
 CREATE TEMP TABLE request_logs(tenant_id text,request_id text,environment_scope text,agent_type text);
 CREATE TEMP TABLE security_events(id text,tenant_id text,request_id text,alert_group_id text,matched_summary jsonb);
 INSERT INTO request_logs VALUES ('t1','customer','customer','openai-codex'),('t1','codex','codex','unknown'),('t1','claude','claude','ordinary-browser'),('t1','unknown',NULL,'openai-codex');`)
	if err != nil {
		t.Fatal(err)
	}
	classes := []string{"semantic_jailbreak", "illegal_organ_trade", "illegal_system_command_instructions", "ssrf_metadata_instruction", "supply_model_weight_theft", "illegal_violence_terror", "zero_width_char", "injection_payload_splitting", "destructive_change", "plugin_attack", "prompt_leak_attack", "sensitive_file_hr_data", "secret", "pii", "runtime"}
	for _, scope := range []string{"customer", "codex", "claude", "unknown"} {
		for _, class := range classes {
			id := scope + "/" + class
			kind := "security_event"
			if class == "runtime" {
				kind = "runtime_fault"
			}
			_, err = db.Exec(ctx, "INSERT INTO alert_groups VALUES($1,'t1',$2,$3,$4,false)", id, scope, class, kind)
			if err != nil {
				t.Fatal(err)
			}
			findingType := "data_security"
			if class == "semantic_jailbreak" {
				findingType = "semantic_attack"
			}
			if class == "runtime" {
				findingType = "semantic_telemetry"
			}
			_, err = db.Exec(ctx, "INSERT INTO security_events VALUES($1,'t1',$2,$1,jsonb_build_object('findings',jsonb_build_array(jsonb_build_object('type',$3::text))))", id, scope, findingType)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	_, err = db.Exec(ctx, `INSERT INTO alert_groups VALUES('mixed','t1','codex','semantic_jailbreak','security_event',false),('canary','t1','codex','semantic_jailbreak','security_event',true),('foreign','t2','codex','secret','security_event',false);
 INSERT INTO security_events VALUES ('mixed-customer','t1','customer','mixed','{}');`)
	if err != nil {
		t.Fatal(err)
	}
	for _, include := range []bool{false, true} {
		where, args, err := buildAlertGroupPageWhere(AlertGroupListFilter{TenantID: "t1", IncludeDevTraffic: include})
		if err != nil {
			t.Fatal(err)
		}
		rs, err := db.Query(ctx, "SELECT id FROM alert_groups ag WHERE "+strings.Join(where, " AND "), args...)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for rs.Next() {
			var id string
			if err = rs.Scan(&id); err != nil {
				t.Fatal(err)
			}
			got[id] = true
		}
		rs.Close()
		for _, scope := range []string{"customer", "codex", "claude", "unknown"} {
			for _, class := range classes {
				folded := !include && (scope == "codex" || scope == "claude") && (class == "semantic_jailbreak" || class == "runtime")
				if got[scope+"/"+class] == folded {
					t.Errorf("include=%v scope=%s class=%s visible=%v", include, scope, class, !folded)
				}
			}
		}
		if !got["mixed"] || !got["canary"] || got["foreign"] {
			t.Fatalf("unsafe mixed scope/canary/tenant visibility: %v", got)
		}
		eventWhere, eventArgs := alertOccurrenceEventScope(AlertOccurrenceFilter{TenantID: "t1", IncludeDevTraffic: include}, []any{"t1"})
		ers, err := db.Query(ctx, "SELECT id FROM security_events se WHERE "+eventWhere, eventArgs...)
		if err != nil {
			t.Fatal(err)
		}
		eventGot := map[string]bool{}
		for ers.Next() {
			var id string
			ers.Scan(&id)
			eventGot[id] = true
		}
		ers.Close()
		for _, scope := range []string{"customer", "codex", "claude", "unknown"} {
			for _, class := range classes {
				if eventGot[scope+"/"+class] != got[scope+"/"+class] {
					t.Fatalf("list/count/summary visibility mismatch for %s/%s", scope, class)
				}
			}
		}

	}
}

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGovernanceRiskAlertPersistsThroughRealAuditWriter(t *testing.T) {
	dsn := os.Getenv("TOOL_RISK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TOOL_RISK_TEST_DATABASE_URL is required for real alert persistence validation")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("connect isolated fixture")
	}
	schema := fmt.Sprintf("governance_alert_%d", time.Now().UnixNano())
	name := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+name); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("parse isolated fixture")
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("connect isolated schema")
	}
	t.Cleanup(func() { db.Close(); _, _ = admin.Exec(ctx, "DROP SCHEMA "+name+" CASCADE"); admin.Close() })
	_, err = db.Exec(ctx, `CREATE TABLE rules(id text PRIMARY KEY);
	 CREATE TABLE security_events(
	  id text PRIMARY KEY,request_id text,tenant_id text,project_id text,user_id text,event_type text,
	  severity text,rule_id text REFERENCES rules(id),action_taken text,matched_summary jsonb,
	  created_at timestamptz,principal_key text,conversation_key text,effective_severity text,class_key text, agent_instance_id varchar(128));`)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"record", "alert_allow"} {
		t.Run(action, func(t *testing.T) {
			h, _, logs := governanceRuntimeHandler(t, "", action, false)
			h.auditWriter = NewRealAuditWriter(db, nil)
			call := governanceCall()
			call.Function.Arguments = `{"executable":"curl","args":["--version"]}`
			if _, _, err := h.applyOutputSecurity(ctx, governanceEnvelope(), nil, destructiveChatResponse(t, "", call, call)); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := db.QueryRow(ctx, "SELECT count(*) FROM security_events").Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 0
			if action == "alert_allow" {
				want = 1
			}
			if count != want || len(*logs) != 1 {
				t.Fatalf("actual audit persistence=%d want=%d proposedlogs=%d", count, want, len(*logs))
			}
			if action == "alert_allow" {
				var taken, severity string
				var summary json.RawMessage
				var ruleID *string
				if err := db.QueryRow(ctx, "SELECT action_taken,severity,matched_summary,rule_id FROM security_events").Scan(&taken, &severity, &summary, &ruleID); err != nil {
					t.Fatal(err)
				}
				if taken != "alert" || severity != "high" || ruleID != nil || !strings.Contains(string(summary), "policy-center-system_command") || !strings.Contains(string(summary), "command_not_allowlisted") {
					t.Fatalf("persisted semantic mismatch action=%s severity=%s rule=%v summary=%s", taken, severity, ruleID, summary)
				}
			}
		})
	}
}

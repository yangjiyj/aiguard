package repository

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestWorkBuddyMultiTurnRepairAndTitleHelperIntegration(t *testing.T) {
	db, ctx, tenant, user, project := setupAuditStatsRegressionFixture(t)
	base := time.Now().UTC().Add(-time.Hour)
	insert := func(i int, agent, run, source, system, input, output string) {
		t.Helper()
		id := fmt.Sprintf("wb_%s_%d", tenant, i)
		_, err := db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,agent_type,agent_detection_source,evidence_run_id,evidence_run_source,proxy_mode,endpoint_type,proxy_access_type_resolved,has_retained_content,environment_scope,created_at) VALUES($1,$1,$2,$3,$4,$5,$6,NULLIF($7,''),NULLIF($8,''),'chat_completion','chat','llm',true,'customer',$9)`, id, tenant, project, user, agent, source, run, func() string {
			if run != "" {
				return "chat_tool_call_id"
			}
			return ""
		}(), base.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		for j, m := range []struct{ role, text string }{{"system", system}, {"user", input}, {"assistant", output}} {
			_, err = db.Exec(ctx, `INSERT INTO content_logs(id,request_id,tenant_id,role,content,tokens,environment_scope,message_index,created_at) VALUES($1,$2,$3,$4,$5,0,'customer',$6,$7)`, fmt.Sprintf("%s_%d", id, j), id, tenant, m.role, m.text, j, base)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	envelope := `<system-reminder data-role="user-context"><user_info>
Workspace Folder: /Users/test/WorkBuddy/unique-task
</user_info><product_identity>You are WorkBuddy, a powerful AI assistant.</product_identity></system-reminder><user_query>%s</user_query>`
	for i := 0; i < 6; i++ {
		insert(i, "openai-codex", fmt.Sprintf("old-chain-%d", i/2), "message_protocol", "Memory mentions You are Codex.", fmt.Sprintf(envelope, fmt.Sprintf("question %d", i/2)), "answer")
	}
	insert(6, "main", "", "client_header", "Generate a concise, sentence-case title (3-7 words) for this session; only summarize its intent", "<session>\nquestion 0\n</session>", `{"isNewTopic":true,"title":"WorkBuddy task"}`)
	// A real human mention must not be converted into a client identity.
	insert(7, "openai-codex", "ordinary", "message_protocol", "You are Codex.", "Explain <product_identity>You are WorkBuddy</product_identity>", "explanation")
	migration, err := os.ReadFile("../../../../deploy/migrations/831_workbuddy_product_identity_tasks.sql")
	if err != nil {
		t.Fatal(err)
	}
	// 831 keeps only the before-image audit table. Identity repair moved into the
	// resumable workbuddy_identity_v1 task, so the migration itself must no longer
	// carry an executable identity update.
	active := activeMigrationSQL(string(migration))
	if !strings.Contains(active, "create table if not exists agent_protocol_repairs") {
		t.Fatal("migration 831 must keep the agent_protocol_repairs before-image table")
	}
	if strings.Contains(active, "update request_logs") {
		t.Fatal("migration 831 must not update request identities inline")
	}
	if _, err = db.Exec(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	// Reproduce the post-backfill state that workbuddy_identity_v1 produces: the
	// six envelope turns collapse into one workspace evidence run while the
	// ordinary mention turn stays its own run.
	if _, err = db.Exec(ctx, `
		UPDATE request_logs
		SET agent_type = 'workbuddy',
		    agent_detection_source = 'product_identity',
		    agent_detection_confidence = 0.98,
		    evidence_run_source = 'workbuddy_workspace',
		    evidence_run_id = 'run_workbuddy_fixture'
		WHERE tenant_id = $1 AND evidence_run_id LIKE 'old-chain-%'
	`, tenant); err != nil {
		t.Fatal(err)
	}
	records, _, err := NewRequestLogRepository(db).ListEvidenceRuns(ctx, tenant, "agent_tasks", ForwardProxyAccessFilter{EnvironmentScope: "customer", ContentOnly: true, StartTime: base.Add(-time.Minute), EndTime: base.Add(10 * time.Minute), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("want one WorkBuddy task plus ordinary Codex task, got %+v", records)
	}
	seen := false
	for _, record := range records {
		if record.AgentType == "workbuddy" {
			seen = true
			if record.RequestCount != 6 || record.CorrelationSource != "workbuddy_workspace" {
				t.Fatalf("split task: %+v", record)
			}
		}
	}
	if !seen {
		t.Fatal("WorkBuddy task missing")
	}
	var kept int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM request_logs WHERE tenant_id=$1`, tenant).Scan(&kept); err != nil || kept != 8 {
		t.Fatalf("audit data lost %d %v", kept, err)
	}
}

// activeMigrationSQL strips line and block comments so migration contract
// assertions only inspect executable SQL.
func activeMigrationSQL(migration string) string {
	blockComment := regexp.MustCompile(`(?s)/\*.*?\*/`)
	active := blockComment.ReplaceAllString(migration, "")
	lines := strings.Split(active, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		kept = append(kept, line)
	}
	return strings.ToLower(strings.Join(kept, "\n"))
}

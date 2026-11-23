package repository

import (
	"context"
	"strings"
	"testing"
	"time"
)

// departmentNameFixture is the department label used by the attribution fixtures.
// Written as escapes so the source file stays ASCII; the codepoints are asserted
// below so a mis-shaped glyph can never slip through.
const departmentNameFixture = "\u98ce\u63a7\u90e8"

// attributionFixtureTemplate seeds one tenant with four attribution shapes.
// @departments@ is replaced with the quoted department name before execution.
const attributionFixtureTemplate = `
		INSERT INTO tenants(id,name) VALUES ('tenant-a','Tenant A');
		INSERT INTO users(id,tenant_id,username) VALUES
			('user-a','tenant-a','User A'), ('user-b','tenant-a','User B');
		INSERT INTO teams(id,tenant_id,name,path) VALUES
			('team-risk','tenant-a',@departments@,'/team-risk'),
			('team-alpha','tenant-a','Alpha Team','/team-alpha');
		INSERT INTO team_members(team_id,user_id,created_at) VALUES ('team-alpha','user-b',NOW());
		INSERT INTO alert_groups(id,tenant_id,status) VALUES ('group-a','tenant-a','open');
		INSERT INTO request_logs(
			id,request_id,tenant_id,project_id,user_id,session_id,client_id,environment_scope,
			agent_type,proxy_mode,source_ip,proxy_source_ip,principal_context_json,created_at
		) VALUES
			('log-dep','request-dep','tenant-a','project-a','user-a','session-dep',NULL,'customer',
			 'openai-codex','reverse','10.0.0.5',NULL,
			 '{"application_department_id":"team-risk","identity_source":"principal_key","principal_key":"user_a1b2c3"}'::jsonb, NOW()),
			('log-cred','request-cred','tenant-a','project-a',NULL,'session-cred',NULL,'customer',
			 'claude-code','reverse','203.0.113.9',NULL,
			 '{"identity_source":"upstream_credential","principal_key":"upstream:credential:11fb3c8a93d4e5f6"}'::jsonb, NOW()),
			('log-nat','request-nat','tenant-a','project-a',NULL,NULL,NULL,'customer',
			 'claude-code','forward','192.168.56.1','192.168.56.1','{}'::jsonb, NOW()),
			('log-team','request-team','tenant-a','project-a','user-b','session-team',NULL,'customer',
			 'codex','reverse','10.0.0.6',NULL,'{}'::jsonb, NOW());
		INSERT INTO content_logs(id,request_id,tenant_id,user_id,session_id,role,content,tokens,environment_scope,created_at) VALUES
			('content-dep','log-dep','tenant-a','user-a','session-dep','user','needle dep',1,'customer',NOW()),
			('content-cred','log-cred','tenant-a',NULL,'session-cred','user','needle cred',1,'customer',NOW()),
			('content-team','log-team','tenant-a','user-b','session-team','user','needle team',1,'customer',NOW());
		INSERT INTO access_content_logs(id,request_id,tenant_id,environment_scope,conversation_id,created_at) VALUES
			('access-nat','request-nat','tenant-a','customer','conv-nat-1',NOW());
		INSERT INTO security_events(id,request_id,tenant_id,project_id,user_id,event_type,severity,action_taken,matched_summary,alert_group_id,created_at) VALUES
			('event-dep','request-dep','tenant-a','project-a','user-a','security_check','high','block','{"category":"prompt_injection"}','group-a',NOW()),
			('event-cred','request-cred','tenant-a','project-a',NULL,'security_check','high','block','{"category":"prompt_injection"}','group-a',NOW()),
			('event-nat','request-nat','tenant-a','project-a',NULL,'security_check','high','block','{"category":"prompt_injection"}','group-a',NOW()),
			('event-team','request-team','tenant-a','project-a','user-b','security_check','high','block','{"category":"prompt_injection"}','group-a',NOW());
`

// 归属投影只有落到真库才算数：列数对齐、join 侧写位置、$n 占位符、以及部门回退
// 顺序，纯字符串测试都证明不了。这里两支会话查询都跑一遍真 PostgreSQL。
func TestContentSessionAttributionQueryExecutesOnPostgres(t *testing.T) {
	if codes := []rune(departmentNameFixture); len(codes) != 3 || codes[0] != 0x98CE || codes[1] != 0x63A7 || codes[2] != 0x90E8 {
		t.Fatalf("department fixture codepoints drifted: %#v", codes)
	}

	db := verifiedModelsTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := db.Exec(ctx, `
		ALTER TABLE request_logs
			ADD COLUMN project_id TEXT,
			ADD COLUMN user_id TEXT,
			ADD COLUMN session_id TEXT,
			ADD COLUMN proxy_source_ip TEXT,
			ADD COLUMN source_ip TEXT,
			ADD COLUMN proxy_provider TEXT,
			ADD COLUMN proxy_target_host TEXT,
			ADD COLUMN client_id TEXT,
			ADD COLUMN input_tokens INTEGER,
			ADD COLUMN output_tokens INTEGER,
			ADD COLUMN environment_scope TEXT,
			ADD COLUMN agent_type TEXT,
			ADD COLUMN proxy_mode TEXT,
			ADD COLUMN principal_context_json JSONB;
		CREATE TABLE users (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, username TEXT);
		CREATE TABLE rules (id TEXT PRIMARY KEY, name TEXT, rule_type TEXT);
		CREATE TABLE internal_keys (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, user_id TEXT, name TEXT, key_prefix TEXT, key_hash TEXT, agent_instance_id varchar(128));
		CREATE TABLE teams (
			id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
			parent_team_id TEXT, path TEXT NOT NULL DEFAULT '/',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE TABLE team_members (
			team_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY (team_id, user_id)
		);
		CREATE TABLE content_logs (
			id TEXT PRIMARY KEY, request_id TEXT, tenant_id TEXT NOT NULL, user_id TEXT,
			session_id TEXT, role TEXT, content TEXT, tokens INTEGER, message_index INTEGER,
			environment_scope TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE TABLE alert_groups (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, status TEXT NOT NULL);
		CREATE TABLE audit_dispositions (
			tenant_id TEXT NOT NULL, subject_type TEXT NOT NULL, subject_id TEXT NOT NULL,
			status TEXT NOT NULL, UNIQUE (tenant_id, subject_type, subject_id)
		);
		CREATE TABLE security_events (
			id TEXT PRIMARY KEY, request_id TEXT, tenant_id TEXT NOT NULL, project_id TEXT,
			user_id TEXT, event_type TEXT, severity TEXT, rule_id TEXT, action_taken TEXT,
			matched_summary JSONB NOT NULL DEFAULT '{}'::jsonb, evidence_ref TEXT,
			alert_group_id TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), agent_instance_id varchar(128));
		CREATE TABLE access_content_logs (
			id TEXT PRIMARY KEY, request_id TEXT, tenant_id TEXT NOT NULL, environment_scope TEXT,
			conversation_id TEXT, request_content_redacted TEXT, response_content_redacted TEXT,
			file_metadata_json JSONB, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE FUNCTION jjdguard_customer_content_text(value text)
		RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
			SELECT COALESCE(BTRIM(value), '') <> ''
			   AND value !~* '^[[:space:]]*system[[:space:]]+prompt:'
		$$;
	`); err != nil {
		t.Fatal(err)
	}

	fixture := strings.Replace(attributionFixtureTemplate, "@departments@", "'"+departmentNameFixture+"'", 1)
	if _, err := db.Exec(ctx, fixture); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	repo := NewContentLogRepository(db)
	base := ContentSessionListFilter{
		TenantID: "tenant-a", EnvironmentScope: "customer", ProjectIDs: []string{"project-a"},
		StartTime: now.Add(-time.Minute), EndTime: now.Add(time.Minute), Limit: 10,
	}

	bySession := func(rows []map[string]interface{}) map[string]map[string]interface{} {
		index := make(map[string]map[string]interface{}, len(rows))
		for _, row := range rows {
			id, _ := row["session_id"].(string)
			index[id] = row
		}
		return index
	}
	expect := func(path, sessionID string, index map[string]map[string]interface{}, want map[string]interface{}) {
		t.Helper()
		row, ok := index[sessionID]
		if !ok {
			t.Fatalf("%s: session %s missing from %d rows: %v", path, sessionID, len(index), index)
		}
		for key, expected := range want {
			if got := row[key]; got != expected {
				t.Fatalf("%s: session %s [%s] = %#v, want %#v", path, sessionID, key, got, expected)
			}
		}
	}

	// ---- fast path (alert_only / skip_total) ----
	fastFilter := base
	fastFilter.AlertOnly, fastFilter.SkipTotal = true, true
	fastRows, _, err := repo.ListSessionsFiltered(ctx, fastFilter)
	if err != nil {
		t.Fatalf("fast attribution query did not execute: %v", err)
	}
	if len(fastRows) != 4 {
		t.Fatalf("fast path returned %d sessions, want 4: %v", len(fastRows), bySession(fastRows))
	}
	fast := bySession(fastRows)
	expect("fast", "session-dep", fast, map[string]interface{}{
		"department_id": "team-risk", "department_name": departmentNameFixture,
		"agent_type": "openai-codex", "conversation_id": "session-dep",
		"principal_key": "user_a1b2c3", "principal_source": "principal_key",
		"principal_source_ip": "10.0.0.5", "principal_proxy_nat": false,
		"principal_label": principalLabelUserPrefix + "User A",
	})
	expect("fast", "session-cred", fast, map[string]interface{}{
		"department_id": "", "department_name": "",
		"agent_type": "claude-code", "conversation_id": "session-cred",
		"principal_key": "upstream:credential:11fb3c8a93d4e5f6", "principal_source": "upstream_credential",
		"principal_source_ip": "203.0.113.9", "principal_proxy_nat": false,
		"principal_label": principalLabelCredentialPrefix + "11fb3c8a93d4e5f6",
	})
	// 正向代理只留会话键作为 session_id，对话 ID 必须来自 access_content_logs。
	expect("fast", "request-nat", fast, map[string]interface{}{
		"department_id": "", "agent_type": "claude-code", "conversation_id": "conv-nat-1",
		"principal_source_ip": "192.168.56.1", "principal_proxy_nat": true,
		"principal_label": principalLabelSourcePrefix + "192.168.56.1" + principalLabelNATSuffix,
	})
	expect("fast", "session-team", fast, map[string]interface{}{
		"department_id": "team-alpha", "department_name": "Alpha Team",
		"agent_type": "codex", "conversation_id": "session-team",
		"principal_label": principalLabelUserPrefix + "User B",
	})

	// ---- full path (exact total) ----
	fullFilter := base
	fullFilter.AlertOnly, fullFilter.SkipTotal = false, false
	fullRows, total, err := repo.ListSessionsFiltered(ctx, fullFilter)
	if err != nil {
		t.Fatalf("full attribution query did not execute: %v", err)
	}
	if total != 3 || len(fullRows) != 3 {
		t.Fatalf("full path rows=%d total=%d, want 3/3: %v", len(fullRows), total, bySession(fullRows))
	}
	full := bySession(fullRows)
	expect("full", "session-dep", full, map[string]interface{}{
		"department_id": "team-risk", "department_name": departmentNameFixture,
		"agent_type": "openai-codex", "conversation_id": "session-dep",
		"principal_label": principalLabelUserPrefix + "User A",
	})
	expect("full", "session-cred", full, map[string]interface{}{
		"department_id": "", "conversation_id": "session-cred",
		"principal_label": principalLabelCredentialPrefix + "11fb3c8a93d4e5f6",
	})
	expect("full", "session-team", full, map[string]interface{}{
		"department_id": "team-alpha", "department_name": "Alpha Team",
		"principal_label": principalLabelUserPrefix + "User B",
	})

	// ---- pagination and total must be untouched by the extra projection ----
	page1 := fullFilter
	page1.Limit, page1.Offset = 2, 0
	rows1, total1, err := repo.ListSessionsFiltered(ctx, page1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows1) != 2 || total1 != 3 {
		t.Fatalf("page 1 rows=%d total=%d, want 2/3", len(rows1), total1)
	}
	page2 := fullFilter
	page2.Limit, page2.Offset = 2, 2
	rows2, total2, err := repo.ListSessionsFiltered(ctx, page2)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows2) != 1 || total2 != 3 {
		t.Fatalf("page 2 rows=%d total=%d, want 1/3", len(rows2), total2)
	}
	seen := bySession(rows1)
	for id, row := range bySession(rows2) {
		if _, dup := seen[id]; dup {
			t.Fatalf("paging returned %s twice: %v", id, seen)
		}
		seen[id] = row
	}
	if len(seen) != 3 {
		t.Fatalf("two pages covered %d sessions, want 3", len(seen))
	}
	for _, row := range seen {
		if _, ok := row["principal_label"]; !ok {
			t.Fatalf("paged session lost its principal label: %#v", row)
		}
	}
}

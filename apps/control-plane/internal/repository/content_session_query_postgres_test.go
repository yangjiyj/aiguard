package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func contentSessionQueryErrorContext(err error, query string) string {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return ""
	}
	position := int(pgErr.Position)
	start, end := position-160, position+160
	if start < 0 {
		start = 0
	}
	if end > len(query) {
		end = len(query)
	}
	return query[start:end]
}

func TestContentSessionCombinedFilterQueriesExecuteOnPostgres(t *testing.T) {
	db := verifiedModelsTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := db.Exec(ctx, `
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
		CREATE TABLE teams (
			id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
			parent_team_id TEXT, path TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE TABLE team_members (
			team_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY (team_id, user_id)
		);
		CREATE TABLE rules (id TEXT PRIMARY KEY, name TEXT, rule_type TEXT);
		CREATE TABLE internal_keys (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, user_id TEXT, name TEXT, key_prefix TEXT, key_hash TEXT, agent_instance_id varchar(128));
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
			id TEXT PRIMARY KEY, request_id TEXT, tenant_id TEXT NOT NULL, environment_scope TEXT, conversation_id TEXT,
			request_content_redacted TEXT, response_content_redacted TEXT,
				file_metadata_json JSONB, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
			);
			CREATE FUNCTION jjdguard_customer_content_text(value text)
			RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
				SELECT COALESCE(BTRIM(value), '') <> ''
				   AND value !~* '^[[:space:]]*system[[:space:]]+prompt:'
			$$;
	`)
	if err != nil {
		t.Fatal(err)
	}
	filter := ContentSessionListFilter{
		TenantID: "tenant-a", EnvironmentScope: "customer", ProjectIDs: []string{"project-a"},
		UserID: "user-a", Keyword: "越权", Categories: []string{"prompt_injection"},
		Severities: []string{"high"}, Dispositions: []string{"open"},
		StartTime: time.Now().Add(-time.Hour), EndTime: time.Now().Add(time.Hour),
		Limit: 2, AlertOnly: true, SkipTotal: true,
	}
	repo := NewContentLogRepository(db)
	if _, _, err := repo.ListSessionsFiltered(ctx, filter); err != nil {
		args := []interface{}{filter.TenantID, filter.StartTime, filter.EndTime, filter.Limit, filter.Offset, EnvironmentScopesForRead(filter.EnvironmentScope), filter.ProjectIDs}
		query := scopeContentSessionProjectQuery(buildContentSessionListQueryScopedWithAlertOnly(true, filter.EnvironmentScope, true), 7)
		query = scopeContentSessionAlertFilters(query, filter, 6, &args)
		query = addContentSessionDispositionProjection(query)
		t.Fatalf("fast combined query did not execute: %v\nnear: %s", err, contentSessionQueryErrorContext(err, query))
	}
	filter.AlertOnly = false
	filter.SkipTotal = false
	if _, _, err := repo.ListSessionsFiltered(ctx, filter); err != nil {
		t.Fatalf("full combined query did not execute: %v", err)
	}

	now := time.Now().UTC()
	_, err = db.Exec(ctx, `
			INSERT INTO tenants(id,name) VALUES ('tenant-a','Tenant A'),('tenant-b','Tenant B');
			INSERT INTO users(id,tenant_id,username) VALUES
				('user-a','tenant-a','User A'),('user-c','tenant-a','User C'),('user-b','tenant-b','User B');
		INSERT INTO internal_keys(id,tenant_id,user_id,name,key_hash) VALUES
			('key-a','tenant-a','user-a','Key A',repeat('a',64)),
			('key-c','tenant-a','user-c','Key C',repeat('d',64));
		INSERT INTO alert_groups(id,tenant_id,status) VALUES
			('group-a','tenant-a','open'),('group-access','tenant-a','open'),
				('group-caller','tenant-a','open'),('group-suppressed','tenant-a','open'),('group-hidden','tenant-a','open'),
				('group-denied','tenant-a','open'),('group-b','tenant-b','open');
			INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,client_id,environment_scope,created_at) VALUES
				('log-a','request-a','tenant-a','project-a','user-a','key-a','customer',NOW()),
				('log-access','request-access','tenant-a','project-a','user-a','key-a','customer',NOW()),
				('log-caller','request-caller','tenant-a','project-a',NULL,'caller_dddddddddddd','customer',NOW()),
				('log-suppressed','request-suppressed','tenant-a','project-a','user-a','key-a','customer',NOW()),
				('log-hidden','request-hidden','tenant-a','project-a','user-a','key-a','customer',NOW()),
				('log-denied','request-denied','tenant-a','project-b','user-a','key-a','customer',NOW()),
				('log-b','request-b','tenant-b','project-b','user-b',NULL,'customer',NOW());
			INSERT INTO content_logs(id,request_id,tenant_id,user_id,session_id,role,content,tokens,environment_scope,created_at) VALUES
				('content-a','log-a','tenant-a','user-a','session-mixed','user','needle in content store',1,'customer',NOW()),
				('content-access','log-access','tenant-a','user-a','session-access','user','content without search term',1,'customer',NOW()),
				('content-caller','log-caller','tenant-a',NULL,'session-caller','user','needle caller',1,'customer',NOW()),
				('content-suppressed','log-suppressed','tenant-a','user-a','session-suppressed','user','needle suppressed',1,'customer',NOW()),
				('content-hidden','log-hidden','tenant-a','user-a','session-hidden','user','system prompt: hidden-only',1,'customer',NOW()),
				('content-denied','log-denied','tenant-a','user-a','session-mixed','assistant','needle must stay hidden',1,'customer',NOW()),
				('content-b','log-b','tenant-b','user-b','session-b','user','needle other tenant',1,'customer',NOW());
			INSERT INTO access_content_logs(id,request_id,tenant_id,environment_scope,request_content_redacted,created_at) VALUES
				('access-a','request-access','tenant-a','customer','needle in access store',NOW());
			INSERT INTO security_events(id,request_id,tenant_id,project_id,user_id,event_type,severity,action_taken,matched_summary,alert_group_id,created_at) VALUES
				('event-a','request-a','tenant-a','project-a','user-a','security_check','high','block','{"category":"prompt_injection"}','group-a',NOW()),
				('event-access','request-access','tenant-a','project-a','user-a','security_check','high','block','{"category":"prompt_injection"}','group-access',NOW()),
				('event-caller','request-caller','tenant-a','project-a',NULL,'security_check','high','block','{"category":"prompt_injection"}','group-caller',NOW()),
				('event-suppressed','request-suppressed','tenant-a','project-a','user-a','security_check','high','block',
				'{"category":"actual_risk","findings":[{"category":"inventory_only","counts_as_security_finding":false},{"category":"actual_risk","counts_as_security_finding":true}]}',
				'group-suppressed',NOW()),
				('event-hidden','request-hidden','tenant-a','project-a','user-a','security_check','high','block','{"category":"prompt_injection"}','group-hidden',NOW()),
				('event-denied','request-denied','tenant-a','project-b','user-a','security_check','high','block','{"category":"prompt_injection"}','group-denied',NOW()),
				('event-b','request-b','tenant-b','project-b','user-b','security_check','high','block','{"category":"prompt_injection"}','group-b',NOW());
		`)
	if err != nil {
		t.Fatal(err)
	}
	filter.StartTime, filter.EndTime = now.Add(-time.Minute), now.Add(time.Minute)
	filter.Keyword = "needle"
	filter.Limit = 10
	fast, _, err := repo.ListSessionsFiltered(ctx, filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(fast) != 2 {
		t.Fatalf("combined two-store filter returned %d sessions: %#v", len(fast), fast)
	}
	for _, session := range fast {
		if session["session_id"] == "session-mixed" && session["message_count"] != 1 {
			t.Fatalf("cross-project member entered mixed session: %#v", session)
		}
	}
	filter.AlertOnly, filter.SkipTotal = false, false
	full, total, err := repo.ListSessionsFiltered(ctx, filter)
	if err != nil || len(full) != 2 || total != 2 {
		t.Fatalf("full combined filter rows=%d total=%d err=%v data=%#v", len(full), total, err, full)
	}

	filter.AlertOnly, filter.SkipTotal = true, true
	filter.UserID, filter.Keyword = "user-c", ""
	callerRows, _, err := repo.ListSessionsFiltered(ctx, filter)
	if err != nil || len(callerRows) != 1 || callerRows[0]["session_id"] != "session-caller" {
		t.Fatalf("caller hash user mapping failed: rows=%#v err=%v", callerRows, err)
	}
	filter.UserID, filter.Categories = "", []string{"inventory_only"}
	suppressedRows, _, err := repo.ListSessionsFiltered(ctx, filter)
	if err != nil || len(suppressedRows) != 0 {
		t.Fatalf("suppressed category became an alert candidate: rows=%#v err=%v", suppressedRows, err)
	}
	filter.Categories, filter.Keyword = []string{"prompt_injection"}, "hidden-only"
	hiddenRows, _, err := repo.ListSessionsFiltered(ctx, filter)
	if err != nil || len(hiddenRows) != 0 {
		t.Fatalf("hidden system content affected keyword results: rows=%#v err=%v", hiddenRows, err)
	}

	hiddenMessages, _, err := repo.SearchPage(ctx, ContentLogSearchFilter{
		TenantID: "tenant-a", EnvironmentScope: "customer", Keyword: "hidden-only",
		StartTime: now.Add(-time.Minute), EndTime: now.Add(time.Minute), Limit: 20,
	})
	if err != nil || len(hiddenMessages) != 0 {
		t.Fatalf("direct keyword search exposed hidden system content: rows=%#v err=%v", hiddenMessages, err)
	}

	emptyPage, emptyTotal, err := repo.ListBySessionPageScoped(
		ctx, "tenant-a", "session-mixed", true, 20, 99,
		now.Add(-time.Minute), now.Add(time.Minute), "customer",
	)
	if err != nil || len(emptyPage) != 0 || emptyTotal != -1 {
		t.Fatalf("empty page rows=%#v total=%d err=%v, want unknown total -1", emptyPage, emptyTotal, err)
	}
}

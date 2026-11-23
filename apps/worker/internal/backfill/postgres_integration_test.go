package backfill

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresCustomerProjectionCrashAndLockRecovery(t *testing.T) {
	url := os.Getenv("JJD_BACKFILL_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("JJD_BACKFILL_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(ctx, `
CREATE FUNCTION jjdguard_customer_content_text(value text)
RETURNS boolean LANGUAGE sql IMMUTABLE
AS $$ SELECT COALESCE(BTRIM(value), '') <> '' AND value NOT LIKE '<system>%' $$;
CREATE TABLE schema_migrations (
 version varchar(255) PRIMARY KEY, checksum varchar(64) NOT NULL, applied_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO schema_migrations(version,checksum) VALUES ('834_customer_content_projection_backfill.sql',repeat('a',64));
CREATE TABLE request_logs (
 id varchar(64) PRIMARY KEY, request_id varchar(64) NOT NULL UNIQUE,
 tenant_id varchar(64) NOT NULL,project_id varchar(64),user_id varchar(64),
 client_id varchar(64),provider_id varchar(64),proxy_mode varchar(32),
 proxy_target_host text,model_id varchar(64),proxy_user_agent text,
 latency_ms bigint,total_cost numeric,
 agent_type varchar(64),agent_runtime varchar(64),agent_detection_source varchar(64),
 agent_detection_confidence double precision,
 agent_identity_rule_id varchar(64),
 session_id varchar(128),evidence_run_id varchar(128),evidence_run_source varchar(64),
 content_evidence_retention_until timestamptz,
 environment_scope varchar(32) default 'legacy-unclassified',
 has_customer_content boolean, has_customer_request_body boolean,
 has_customer_response_body boolean,
 customer_content_rule_version smallint NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE content_logs (
 id varchar(64) PRIMARY KEY, request_id varchar(64) NOT NULL REFERENCES request_logs(id) ON DELETE CASCADE,
 tenant_id varchar(64) NOT NULL, role varchar(32) NOT NULL, content text NOT NULL,
 environment_scope varchar(32) default 'legacy-unclassified',
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE access_content_logs (
 id varchar(64) PRIMARY KEY, request_id varchar(64) NOT NULL REFERENCES request_logs(request_id) ON DELETE CASCADE,
 tenant_id varchar(64) NOT NULL, request_content_redacted text,
 response_content_redacted text, file_metadata_json jsonb NOT NULL DEFAULT '[]'::jsonb,
 retention_until timestamptz, environment_scope varchar(32) default 'legacy-unclassified',
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE retained_artifacts (
 id varchar(64) PRIMARY KEY,tenant_id varchar(64) NOT NULL,source_request_id varchar(64) NOT NULL,
 environment_scope varchar(32) default 'legacy-unclassified',created_at timestamptz default now()
);
CREATE TABLE access_content_artifact_links (
 id varchar(64) PRIMARY KEY,tenant_id varchar(64) NOT NULL,request_id varchar(64) NOT NULL,
 environment_scope varchar(32) default 'legacy-unclassified',created_at timestamptz default now()
);
CREATE TABLE evidence_run_request_index (
 tenant_id varchar(64) NOT NULL,request_log_id varchar(64) NOT NULL,
 created_at timestamptz NOT NULL,
 effective_agent_type varchar(64),effective_agent_runtime varchar(64),
 effective_detection_source varchar(64),effective_detection_confidence double precision,
 session_id varchar(128),evidence_run_id varchar(128),evidence_run_source varchar(64),
 title_hash char(32) NOT NULL DEFAULT '',chain_dirty boolean default false,
 updated_at timestamptz default now(),
 PRIMARY KEY(tenant_id,request_log_id)
);
CREATE TABLE usage_rollup_hourly (
 tenant_id varchar(64) NOT NULL,bucket_start timestamptz NOT NULL,
 project_id varchar(64) NOT NULL DEFAULT '',user_id varchar(64) NOT NULL DEFAULT '',
 client_id varchar(64) NOT NULL DEFAULT '',provider_id varchar(64) NOT NULL DEFAULT '',
 model_id varchar(64) NOT NULL DEFAULT '',latency_count bigint NOT NULL DEFAULT 0,
 first_priced_at timestamptz,
 PRIMARY KEY(tenant_id,bucket_start,project_id,user_id,client_id,provider_id,model_id)
);
CREATE TABLE security_events (
 id varchar(64) PRIMARY KEY,alerted_at timestamptz,created_at timestamptz
);
INSERT INTO request_logs(id,request_id,tenant_id,proxy_mode,has_customer_content,
 has_customer_request_body,has_customer_response_body,created_at)
VALUES ('log-a','req-a','tenant-a','api',false,false,false,'2026-01-01'),
       ('log-b','req-b','tenant-a','api',false,false,false,'2026-01-02');
INSERT INTO content_logs(id,request_id,tenant_id,role,content)
VALUES ('content-a','log-a','tenant-a','user','synthetic prompt'),
       ('content-b','log-b','tenant-a','assistant','synthetic response');
INSERT INTO retained_artifacts(id,tenant_id,source_request_id)
VALUES ('artifact-a','tenant-a','req-a');
INSERT INTO access_content_artifact_links(id,tenant_id,request_id)
VALUES ('link-a','tenant-a','req-a');
INSERT INTO evidence_run_request_index(
 tenant_id,request_log_id,created_at,effective_agent_type,
 evidence_run_source,title_hash,chain_dirty
) VALUES (
 'tenant-a','log-a','2026-01-01','main',
 'responses_prompt_cache_key',md5('legacy system envelope'),false
);
INSERT INTO usage_rollup_hourly(tenant_id,bucket_start,model_id)
VALUES ('tenant-a','2026-01-01','model-a');
INSERT INTO security_events(id,alerted_at,created_at) VALUES
 ('event-a','2026-01-03','2026-01-03'),
 ('event-b',NULL,'2026-01-04'),
 ('event-null-time','2026-01-05',NULL);
`)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"../../../../deploy/migrations/151_customer_content_noise_boundary.sql",
		"../../../../deploy/migrations/813_workbuddy_workspace_evidence_runs.sql",
		"../../../../deploy/migrations/816_security_event_delivery_disposition.sql",
		"../../../../deploy/migrations/820_customer_content_projection_triggers.sql",
		"../../../../deploy/migrations/821_serialize_customer_content_projection.sql",
		"../../../../deploy/migrations/831_workbuddy_product_identity_tasks.sql",
		"../../../../deploy/migrations/832_migration_backfill_framework.sql",
		"../../../../deploy/migrations/834_customer_content_projection_backfill.sql",
		"../../../../deploy/migrations/835_request_log_compatibility_backfill.sql",
		"../../../../deploy/migrations/836_customer_environment_scope_backfill.sql",
		"../../../../deploy/migrations/838_evidence_agent_projection_backfill.sql",
		"../../../../deploy/migrations/839_security_event_delivery_backfill_index.sql",
		"../../../../deploy/migrations/840_security_event_delivery_backfill.sql",
		"../../../../deploy/migrations/841_evidence_title_noise_backfill_index.sql",
		"../../../../deploy/migrations/842_evidence_title_noise_backfill.sql",
		"../../../../deploy/migrations/843_workbuddy_identity_backfill.sql",
		"../../../../deploy/migrations/844_usage_rollup_dimensions_backfill.sql",
		"../../../../deploy/migrations/845_security_event_delivery_reconcile.sql",
	} {
		body, readErr := os.ReadFile(name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if _, err = db.Exec(ctx, string(body)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
	var unexpectedReconcile int
	if err = db.QueryRow(ctx, `SELECT COUNT(*) FROM migration_backfill_tasks
WHERE task_name='security_event_delivery_v1' AND task_version=2`).Scan(&unexpectedReconcile); err != nil {
		t.Fatal(err)
	}
	if unexpectedReconcile != 0 {
		t.Fatal("fresh upgrade must not register a duplicate security-event scan")
	}
	var before bool
	if err = db.QueryRow(ctx, "SELECT has_customer_content FROM request_logs WHERE id='log-a'").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before {
		t.Fatal("synchronous 820/821 unexpectedly rewrote historical row")
	}
	var synchronousSecurityUpdates int
	if err = db.QueryRow(ctx, `SELECT COUNT(*) FROM security_events
WHERE processed_at IS NOT NULL OR delivery IS NOT NULL`).Scan(&synchronousSecurityUpdates); err != nil {
		t.Fatal(err)
	}
	if synchronousSecurityUpdates != 0 {
		t.Fatal("synchronous 816 unexpectedly rewrote historical security events")
	}
	var synchronousTitleChanges int
	if err = db.QueryRow(ctx, `SELECT COUNT(*) FROM evidence_run_request_index
WHERE request_log_id='log-a' AND title_hash=md5('synthetic prompt')`).Scan(&synchronousTitleChanges); err != nil {
		t.Fatal(err)
	}
	if synchronousTitleChanges != 0 {
		t.Fatal("synchronous 151 unexpectedly rewrote historical evidence titles")
	}
	_, err = db.Exec(ctx, `UPDATE migration_backfill_tasks
SET batch_size=2,lock_timeout_ms=100,statement_timeout_ms=5000
WHERE task_name='customer_content_projection_v1';
UPDATE migration_backfill_tasks SET state='paused',pause_requested=true
	WHERE task_name IN (
	  'request_log_compatibility_v1','evidence_agent_projection_v1',
	  'security_event_delivery_v1','evidence_title_noise_v1',
	  'workbuddy_identity_v1','usage_rollup_dimensions_v1'
	);`)
	if err != nil {
		t.Fatal(err)
	}

	locker, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = locker.Exec(ctx, "SELECT 1 FROM request_logs WHERE id='log-b' FOR NO KEY UPDATE"); err != nil {
		t.Fatal(err)
	}

	store := NewPostgresStore(db)
	task, err := store.Claim(ctx, "integration-a", 15*time.Second)
	if err != nil || task == nil {
		t.Fatalf("claim: task=%v err=%v", task, err)
	}
	otherTask, otherErr := store.Claim(ctx, "integration-concurrent", 15*time.Second)
	if otherErr != nil || otherTask != nil {
		t.Fatalf("active lease must exclude a second worker: task=%v err=%v", otherTask, otherErr)
	}
	result, err := store.RunBatch(ctx, task, "integration-a", 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.Scanned != 2 || result.Skipped != 1 {
		t.Fatalf("locked batch result=%+v", result)
	}
	if err = locker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `UPDATE migration_backfill_retry_rows SET next_retry_at=NOW()
WHERE task_name='customer_content_projection_v1'`)
	if err != nil {
		t.Fatal(err)
	}

	task, err = store.Claim(ctx, "integration-a", 15*time.Second)
	if err != nil || task == nil {
		t.Fatalf("reclaim: task=%v err=%v", task, err)
	}
	result, err = store.RunBatch(ctx, task, "integration-a", 15*time.Second)
	if err != nil || result.Scanned != 1 {
		t.Fatalf("retry batch=%+v err=%v", result, err)
	}
	task, err = store.Claim(ctx, "integration-a", 15*time.Second)
	if err != nil || task == nil {
		t.Fatalf("final claim: task=%v err=%v", task, err)
	}
	result, err = store.RunBatch(ctx, task, "integration-a", 15*time.Second)
	if err != nil || !result.Done {
		t.Fatalf("final batch=%+v err=%v", result, err)
	}
	if err = store.Complete(ctx, task, "integration-a", result); err != nil {
		t.Fatal(err)
	}

	var shape, state, validation string
	err = db.QueryRow(ctx, `
SELECT string_agg(id||':'||has_customer_content||':'||has_customer_request_body||':'||has_customer_response_body,',' ORDER BY id)
FROM request_logs`).Scan(&shape)
	if err != nil {
		t.Fatal(err)
	}
	if shape != "log-a:true:true:false,log-b:true:false:true" {
		t.Fatalf("projection shape=%s", shape)
	}
	err = db.QueryRow(ctx, `SELECT state,validation_status FROM migration_backfill_tasks
WHERE task_name='customer_content_projection_v1'`).Scan(&state, &validation)
	if err != nil || state != "completed" || validation != "passed" {
		t.Fatalf("state=%s validation=%s err=%v", state, validation, err)
	}

	_, err = db.Exec(ctx, `
UPDATE request_logs SET proxy_mode='reverse',proxy_target_host='',model_id='model-a',
 proxy_user_agent='codex_cli/1.2.3',agent_type='',agent_detection_source=''
WHERE id='log-a';
INSERT INTO access_content_logs(id,request_id,tenant_id,retention_until)
VALUES ('access-a','req-a','tenant-a','2027-01-01');
UPDATE migration_backfill_tasks SET state='pending',pause_requested=false
WHERE task_name='request_log_compatibility_v1';`)
	if err != nil {
		t.Fatal(err)
	}
	for {
		task, err = store.Claim(ctx, "integration-b", 15*time.Second)
		if err != nil || task == nil || task.Name != RequestLogCompatibilityTask {
			t.Fatalf("compatibility claim: task=%+v err=%v", task, err)
		}
		result, err = store.RunBatch(ctx, task, "integration-b", 15*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if result.Done {
			if err = store.Complete(ctx, task, "integration-b", result); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	var proxyMode, agentType, source string
	var confidence float64
	var retention time.Time
	err = db.QueryRow(ctx, `
SELECT proxy_mode,agent_type,agent_detection_source,agent_detection_confidence,
       content_evidence_retention_until
FROM request_logs WHERE id='log-a'`).Scan(&proxyMode, &agentType, &source, &confidence, &retention)
	if err != nil {
		t.Fatal(err)
	}
	if proxyMode != "chat_completion" || agentType != "openai-codex" ||
		source != "user_agent" || confidence != 0.85 || retention.Year() != 2027 {
		t.Fatalf("compatibility values mode=%s agent=%s source=%s confidence=%v retention=%s",
			proxyMode, agentType, source, confidence, retention)
	}

	activation, err := os.ReadFile("../../../../deploy/docker-compose/customer-environment-scope-repair.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, string(activation)); err != nil {
		t.Fatal(err)
	}
	for {
		task, err = store.Claim(ctx, "integration-scope", 15*time.Second)
		if err != nil || task == nil || task.Name != CustomerEnvironmentScopeTask {
			t.Fatalf("scope claim: task=%+v err=%v", task, err)
		}
		result, err = store.RunBatch(ctx, task, "integration-scope", 15*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if result.Done {
			if err = store.Complete(ctx, task, "integration-scope", result); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	var nonCustomer int
	err = db.QueryRow(ctx, `
SELECT (SELECT COUNT(*) FROM request_logs WHERE environment_scope<>'customer')+
       (SELECT COUNT(*) FROM content_logs WHERE environment_scope<>'customer')+
       (SELECT COUNT(*) FROM access_content_logs WHERE environment_scope<>'customer')+
       (SELECT COUNT(*) FROM retained_artifacts WHERE environment_scope<>'customer')+
       (SELECT COUNT(*) FROM access_content_artifact_links WHERE environment_scope<>'customer')`).Scan(&nonCustomer)
	if err != nil || nonCustomer != 0 {
		t.Fatalf("scope repair non_customer=%d err=%v", nonCustomer, err)
	}

	_, err = db.Exec(ctx, `
UPDATE request_logs SET agent_type='workbuddy',agent_runtime='desktop',
 agent_detection_source='explicit_header',agent_detection_confidence=0.99,
 session_id='session-b',evidence_run_id='run-b',evidence_run_source='header'
WHERE id='log-b';
INSERT INTO evidence_run_request_index(
 tenant_id,request_log_id,created_at,effective_agent_type,effective_detection_source,
 effective_detection_confidence,chain_dirty
) VALUES ('tenant-a','log-b','2026-01-02','openai-codex','content',0.98,false);
UPDATE migration_backfill_tasks SET state='pending',pause_requested=false
WHERE task_name='evidence_agent_projection_v1';`)
	if err != nil {
		t.Fatal(err)
	}
	for {
		task, err = store.Claim(ctx, "integration-evidence", 15*time.Second)
		if err != nil || task == nil || task.Name != EvidenceAgentProjectionTask {
			t.Fatalf("evidence claim: task=%+v err=%v", task, err)
		}
		result, err = store.RunBatch(ctx, task, "integration-evidence", 15*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if result.Done {
			if err = store.Complete(ctx, task, "integration-evidence", result); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	var effectiveType, effectiveSource string
	var chainDirty bool
	err = db.QueryRow(ctx, `SELECT effective_agent_type,effective_detection_source,chain_dirty
FROM evidence_run_request_index WHERE request_log_id='log-b'`).Scan(
		&effectiveType, &effectiveSource, &chainDirty)
	if err != nil || effectiveType != "workbuddy" || effectiveSource != "explicit_header" || !chainDirty {
		t.Fatalf("evidence repair type=%s source=%s dirty=%v err=%v",
			effectiveType, effectiveSource, chainDirty, err)
	}

	_, err = db.Exec(ctx, `UPDATE migration_backfill_tasks
SET state='pending',pause_requested=false,batch_size=1
WHERE task_name='security_event_delivery_v1'`)
	if err != nil {
		t.Fatal(err)
	}
	for {
		task, err = store.Claim(ctx, "integration-security", 15*time.Second)
		if err != nil || task == nil || task.Name != SecurityEventDeliveryTask {
			t.Fatalf("security event claim: task=%+v err=%v", task, err)
		}
		result, err = store.RunBatch(ctx, task, "integration-security", 15*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if result.Done {
			if err = store.Complete(ctx, task, "integration-security", result); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	var delivered, untouched int
	err = db.QueryRow(ctx, `SELECT
  COUNT(*) FILTER (WHERE alerted_at IS NOT NULL
    AND processed_at=alerted_at AND delivery='delivered'),
  COUNT(*) FILTER (WHERE alerted_at IS NULL
    AND processed_at IS NULL AND delivery IS NULL)
FROM security_events`).Scan(&delivered, &untouched)
	if err != nil || delivered != 2 || untouched != 1 {
		t.Fatalf("security delivery repair delivered=%d untouched=%d err=%v",
			delivered, untouched, err)
	}

	_, err = db.Exec(ctx, `
INSERT INTO request_logs(
 id,request_id,tenant_id,proxy_mode,environment_scope,
 has_customer_content,has_customer_request_body,has_customer_response_body,
 agent_type,agent_detection_source,created_at
) VALUES
 ('log-workbuddy','req-workbuddy','tenant-a','api','customer',
  false,false,false,'workbuddy','user_agent',NOW()),
 ('log-product','req-product','tenant-a','api','customer',
  false,false,false,'main','client_header',NOW());
INSERT INTO content_logs(id,request_id,tenant_id,role,content,environment_scope)
VALUES
 ('content-workbuddy','log-workbuddy','tenant-a','user',
  E'context\nWorkspace Folder: C:\\projects\\alpha','customer'),
 ('content-product','log-product','tenant-a','user',
  '<system-reminder data-role="user-context"><user_info>Workspace Folder: C:\projects\beta</user_info><product_identity>You are WorkBuddy, an AI coding assistant.</product_identity></system-reminder><user_query>synthetic</user_query>',
  'customer');
UPDATE migration_backfill_tasks SET state='pending',pause_requested=false,batch_size=1
WHERE task_name='workbuddy_identity_v1';`)
	if err != nil {
		t.Fatal(err)
	}
	for {
		task, err = store.Claim(ctx, "integration-workbuddy", 15*time.Second)
		if err != nil || task == nil || task.Name != WorkBuddyIdentityTask {
			t.Fatalf("workbuddy claim: task=%+v err=%v", task, err)
		}
		result, err = store.RunBatch(ctx, task, "integration-workbuddy", 15*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if result.Done {
			if err = store.Complete(ctx, task, "integration-workbuddy", result); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	var workBuddyRepaired, repairAudits int
	err = db.QueryRow(ctx, `SELECT
  COUNT(*) FILTER (WHERE agent_type='workbuddy'
    AND evidence_run_source='workbuddy_workspace'
    AND evidence_run_id LIKE 'run_%'),
  (SELECT COUNT(*) FROM agent_protocol_repairs WHERE migration='831')
FROM request_logs WHERE id IN ('log-workbuddy','log-product')`).Scan(
		&workBuddyRepaired, &repairAudits)
	if err != nil || workBuddyRepaired != 2 || repairAudits != 1 {
		t.Fatalf("workbuddy repair rows=%d audits=%d err=%v",
			workBuddyRepaired, repairAudits, err)
	}

	_, err = db.Exec(ctx, `UPDATE migration_backfill_tasks
SET state='pending',pause_requested=false,batch_size=1
WHERE task_name='evidence_title_noise_v1'`)
	if err != nil {
		t.Fatal(err)
	}
	for {
		task, err = store.Claim(ctx, "integration-title", 15*time.Second)
		if err != nil || task == nil || task.Name != EvidenceTitleNoiseTask {
			t.Fatalf("title claim: task=%+v err=%v", task, err)
		}
		result, err = store.RunBatch(ctx, task, "integration-title", 15*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if result.Done {
			if err = store.Complete(ctx, task, "integration-title", result); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	var titleRepaired bool
	err = db.QueryRow(ctx, `SELECT title_hash=md5('synthetic prompt') AND chain_dirty
FROM evidence_run_request_index WHERE request_log_id='log-a'`).Scan(&titleRepaired)
	if err != nil || !titleRepaired {
		t.Fatalf("evidence title repair=%v err=%v", titleRepaired, err)
	}

	_, err = db.Exec(ctx, `
UPDATE request_logs SET latency_ms=125,total_cost=1.25 WHERE id='log-a';
UPDATE migration_backfill_tasks
SET state='pending',pause_requested=false,batch_size=1
WHERE task_name='usage_rollup_dimensions_v1'`)
	if err != nil {
		t.Fatal(err)
	}
	for {
		task, err = store.Claim(ctx, "integration-rollup", 15*time.Second)
		if err != nil || task == nil || task.Name != UsageRollupDimensionsTask {
			t.Fatalf("usage rollup claim: task=%+v err=%v", task, err)
		}
		result, err = store.RunBatch(ctx, task, "integration-rollup", 15*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if result.Done {
			if err = store.Complete(ctx, task, "integration-rollup", result); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	var latencyCount int64
	var firstPriced time.Time
	err = db.QueryRow(ctx, `SELECT latency_count,first_priced_at
FROM usage_rollup_hourly
WHERE tenant_id='tenant-a' AND bucket_start='2026-01-01' AND model_id='model-a'`).Scan(
		&latencyCount, &firstPriced)
	if err != nil || latencyCount != 1 || firstPriced.Day() != 1 {
		t.Fatalf("usage rollup latency_count=%d first_priced=%s err=%v",
			latencyCount, firstPriced, err)
	}
}

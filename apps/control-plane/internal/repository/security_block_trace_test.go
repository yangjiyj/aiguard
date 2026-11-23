package repository

import (
	"context"
	"strings"
	"testing"
)

func TestBlockRecordSearchRequiresExactCompleteIdentifier(t *testing.T) {
	repo, db := newBlockRecordsTestRepo(t)
	ctx := context.Background()
	for _, query := range []string{
		"op_5f1b100aea3d3d597ee318442e7f628c18",
		"op_5f1b100aea3d3d597ee318442e7f628d",
	} {
		records, total, err := repo.ListBlockRecords(ctx, "t1", SecurityBlockRecordFilter{Query: query})
		if err != nil || total != 0 || len(records) != 0 {
			t.Fatalf("incorrect full identifier %q must not find another block: records=%+v total=%d err=%v", query, records, total, err)
		}
	}
	if _, err := db.Exec(ctx, `UPDATE request_logs SET tenant_id='t2' WHERE request_id='req-input'`); err != nil {
		t.Fatal(err)
	}
	// A request-id collision or corrupted historical FK must never attach
	// another tenant's request metadata to our security record.
	record, err := repo.GetBlockRecord(ctx, "t1", "evt_input")
	if err != nil || record.TraceID != "" || record.Model != "" {
		t.Fatalf("foreign request joined into block: record=%+v err=%v", record, err)
	}
	records, _, err := repo.ListBlockRecords(ctx, "t1", SecurityBlockRecordFilter{Query: "trace-f53bc1b9"})
	if err != nil || len(records) != 0 {
		t.Fatalf("foreign trace ID search: %+v err=%v", records, err)
	}
}

func TestBlockAuditMetadataFollowsExactTenantRequestAndContainsNoBodies(t *testing.T) {
	repo, db := newBlockRecordsTestRepo(t)
	ctx := context.Background()
	for _, stmt := range []string{
		`ALTER TABLE request_logs ADD COLUMN id TEXT, ADD COLUMN project_id TEXT, ADD COLUMN created_at TIMESTAMPTZ DEFAULT now(),
		 ADD COLUMN session_id TEXT, ADD COLUMN input_tokens INT, ADD COLUMN output_tokens INT,
		 ADD COLUMN latency_ms INT, ADD COLUMN proxy_content_retained BOOL, ADD COLUMN content_evidence_retention_until TIMESTAMPTZ`,
		`UPDATE request_logs SET id='log-'||request_id, project_id='p1', session_id='session-one', input_tokens=11, output_tokens=22, latency_ms=44 WHERE tenant_id='t1'`,
		`CREATE TABLE content_logs (id TEXT, tenant_id TEXT, request_id TEXT, role TEXT, content TEXT, tokens INT, created_at TIMESTAMPTZ DEFAULT now(), environment_scope TEXT DEFAULT 'customer')`,
		`CREATE TABLE access_content_logs (id TEXT, tenant_id TEXT, request_id TEXT, created_at TIMESTAMPTZ DEFAULT now(),
		 request_content_redacted TEXT, response_content_redacted TEXT, conversation_id TEXT, file_metadata_json JSONB, environment_scope TEXT DEFAULT 'customer')`,
		`ALTER TABLE tool_call_logs ADD COLUMN tool_name TEXT, ADD COLUMN tool_type TEXT, ADD COLUMN status TEXT`,
		`INSERT INTO content_logs (id,tenant_id,request_id,role,content,tokens,environment_scope) VALUES
		 ('content-ours','t1','log-req-input','user','PRIVATE_PROMPT_SHOULD_NEVER_BE_PROJECTED',11,'customer'),
		 ('content-foreign','t2','log-req-input','user','FOREIGN_BODY',999,'customer'),
		 ('content-other-request','t1','log-req-tool','user','OTHER_REQUEST',888,'customer'),
		 ('content-development','t1','log-req-input','user','DEV_BODY',777,'development')`,
		`INSERT INTO access_content_logs(id,tenant_id,request_id,request_content_redacted,conversation_id) VALUES
		 ('access-ours','t1','req-input','PRIVATE_ACCESS_BODY','conversation-one'), ('access-foreign','t2','req-input','FOREIGN_ACCESS_BODY','conversation-foreign')`,
		`INSERT INTO tool_call_logs(id,tenant_id,request_id,event_type,tool_name,tool_type,status,operation_id) VALUES
		 ('tool-ours','t1','req-input','tool_attempt_blocked','delete_file','function','blocked','op-one'),
		 ('tool-foreign','t2','req-input','tool_attempt_blocked','FOREIGN_TOOL','function','blocked','op-foreign')`,
	} {
		if _, err := db.Exec(ctx, stmt); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	metadata, err := repo.GetBlockAuditMetadata(ctx, "t1", "req-input", nil)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Request == nil || metadata.Request.RecordID != "log-req-input" || metadata.Request.InputTokens != 11 || metadata.Request.OutputTokens != 22 || metadata.Request.ConversationID != "conversation-one" {
		t.Fatalf("request metadata: %+v", metadata.Request)
	}
	if len(metadata.ContentRecords) != 2 || metadata.ContentCount != 2 || !metadata.HasContent || len(metadata.ToolRecords) != 1 || metadata.ToolCount != 1 || metadata.ToolRecords[0].ID != "tool-ours" {
		t.Fatalf("related metadata: %+v", metadata)
	}
	for _, record := range metadata.ContentRecords {
		if strings.Contains(record.ID, "foreign") || strings.Contains(record.ID, "development") {
			t.Fatalf("unscoped record: %+v", record)
		}
	}
	for _, projects := range [][]string{{}, {"p2"}} {
		got, err := repo.GetBlockAuditMetadata(ctx, "t1", "req-input", projects)
		if err != nil || got.Request != nil || len(got.ContentRecords) != 0 || len(got.ToolRecords) != 0 {
			t.Fatalf("unauthorized projects %v: metadata=%+v err=%v", projects, got, err)
		}
	}
	missing, err := repo.GetBlockAuditMetadata(ctx, "t1", "missing", nil)
	if err != nil || missing.Request != nil {
		t.Fatalf("missing request: %+v err=%v", missing, err)
	}
}

func TestGetBlockRecordPrefersRealEventIDOverLegacyNoticeAlias(t *testing.T) {
	repo, db := newBlockRecordsTestRepo(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO security_events(id,request_id,tenant_id,project_id,user_id,event_type,severity,action_taken,matched_summary,created_at)
		VALUES('evt_alias_newer','req-legacy','t1','p2','u1','security_check','high','block',
		'{"block":{"block_id":"evt_input","rule_name":"legacy alias"}}',NOW())`); err != nil {
		t.Fatal(err)
	}
	record, err := repo.GetBlockRecord(ctx, "t1", "evt_input")
	if err != nil || record.BlockID != "evt_input" || record.RequestID != "req-input" {
		t.Fatalf("exact event ID must win over a newer legacy alias: %+v err=%v", record, err)
	}
}

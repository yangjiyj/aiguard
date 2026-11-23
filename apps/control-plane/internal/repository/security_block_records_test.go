package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newBlockRecordsTestRepo(t *testing.T) (*SecurityEventRepository, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("SECURITY_BLOCK_RECORDS_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("RULES_TEST_DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("SECURITY_BLOCK_RECORDS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	schema := fmt.Sprintf("block_records_%d", time.Now().UnixNano())
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+ident+" CASCADE")
		admin.Close()
	})
	for _, stmt := range []string{
		`CREATE TABLE projects (id VARCHAR(64) PRIMARY KEY, name VARCHAR(255))`,
		`CREATE TABLE users (id VARCHAR(64) PRIMARY KEY, username VARCHAR(255))`,
		`CREATE TABLE rule_sets (id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64), source_type VARCHAR(32), published BOOLEAN DEFAULT TRUE)`,
		`CREATE TABLE rules (id VARCHAR(64) PRIMARY KEY, name VARCHAR(255), rule_type VARCHAR(64), rule_set_id VARCHAR(64), scope_json JSONB DEFAULT '{}')`,
		`INSERT INTO rule_sets VALUES ('rs_t1','t1','custom',TRUE), ('rs_sys','tenant_system','builtin',TRUE), ('rs_draft','t1','custom',FALSE), ('rs_t2','t2','custom',TRUE)`,
		`CREATE TABLE models (id VARCHAR(64) PRIMARY KEY, model_name VARCHAR(255))`,
		`CREATE TABLE request_logs (request_id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64), model_id VARCHAR(64),
			agent_type VARCHAR(64), endpoint_type VARCHAR(32), request_status VARCHAR(32), upstream_status_code INTEGER,
			trace_id VARCHAR(128), source_ip VARCHAR(64), agent_instance_id varchar(128))`,
		`CREATE TABLE security_events (id VARCHAR(64) PRIMARY KEY, request_id VARCHAR(64), tenant_id VARCHAR(64),
			project_id VARCHAR(64), user_id VARCHAR(64), event_type VARCHAR(64), severity VARCHAR(32), rule_id VARCHAR(64),
			action_taken VARCHAR(32), matched_summary JSONB DEFAULT '{}', created_at TIMESTAMPTZ DEFAULT NOW(), agent_instance_id varchar(128))`,
		`CREATE TABLE tool_call_logs (id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64), request_id VARCHAR(64),
			operation_id VARCHAR(128), event_type VARCHAR(48), public_event_id VARCHAR(64), trace_id VARCHAR(128),
			created_at TIMESTAMPTZ DEFAULT NOW())`,
		`INSERT INTO projects VALUES ('p1','研发一部'), ('p2','财务')`,
		`INSERT INTO users VALUES ('u1','zhangsan')`,
		`INSERT INTO models VALUES ('m1','custom-local.glm-5.2')`,
		`INSERT INTO request_logs (request_id,tenant_id,model_id,agent_type,endpoint_type,request_status,upstream_status_code,trace_id,source_ip) VALUES
			('req-input','t1','m1','codebuddy','chat','security_blocked',403,'trace-f53bc1b9','192.168.121.6'),
			('req-tool','t1','m1','codebuddy','chat','success',200,'',''),
			('req-legacy','t1','m1','codebuddy','chat','security_blocked',403,'',''),
			('req-audit','t1','m1','codebuddy','chat','success',200,'',''),
			('req-other-tenant','t2','m1','codebuddy','chat','security_blocked',403,'','')`,
		`INSERT INTO security_events (id,request_id,tenant_id,project_id,user_id,event_type,severity,action_taken,matched_summary,created_at) VALUES
			('evt_input','req-input','t1','p1','u1','security_check','critical','security_blocked',
			 '{"stage":"input","block":{"block_id":"evt_input","layer":"input_content","reason":"输入内容命中安全规则","rule_id":"rule_525f3078","rule_name":"密码明文检测","detail":"pass****i996","basis":"规则「密码明文检测」的处置动作为阻断"}}', NOW() - interval '3 minutes'),
			('evt_tool','req-tool','t1','p1','u1','security_check','high','tool_attempt_blocked',
			 '{"stage":"tool","block":{"block_id":"evt_tool","layer":"destructive_operation","reason":"模型准备调用删除或破坏性工具（删除文件）","rule_id":"destructive_operation","rule_name":"删除与破坏","operation_id":"op_5f1b100aea3d3d597ee318442e7f628c","basis":"策略中心「智能体行为 → 删除与破坏」动作为阻断"}}', NOW() - interval '2 minutes'),
			('evt_legacy','req-legacy','t1','p2',NULL,'security_check','critical','security_blocked',
			 '{"stage":"input","rule_name":"硬编码凭据示例","findings":[{"rule_id":"rule_eca2480f","rule_name":"硬编码凭据示例","action":"block","matched_text_preview":"AKIA****MPLE"}]}', NOW() - interval '1 minutes'),
			('evt_audit','req-audit','t1','p1','u1','security_check','high','security_audit','{}', NOW()),
			('evt_failed','req-audit','t1','p1','u1','security_check_failed','low','block','{}', NOW()),
			('evt_other','req-other-tenant','t2','p1',NULL,'security_check','high','security_blocked','{}', NOW())`,
		`INSERT INTO tool_call_logs VALUES
			('tc1','t1','req-tool','op_5f1b100aea3d3d597ee318442e7f628c','tool_attempt_blocked','evt_public_tool','trace-tool', NOW())`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("fixture %q: %v", stmt[:40], err)
		}
	}
	return NewSecurityEventRepository(pool), pool
}

func TestListBlockRecordsListsOnlyTenantBlocksNewestFirst(t *testing.T) {
	repo, _ := newBlockRecordsTestRepo(t)
	records, total, err := repo.ListBlockRecords(context.Background(), "t1", SecurityBlockRecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(records) != 3 {
		t.Fatalf("want 3 blocks (no audit, no check-failed, no other tenant), got total=%d %+v", total, records)
	}
	if records[0].BlockID != "evt_legacy" || records[2].BlockID != "evt_input" {
		t.Fatalf("order: %s %s %s", records[0].BlockID, records[1].BlockID, records[2].BlockID)
	}
	input := records[2]
	if input.RuleName != "密码明文检测" || input.Detail != "pass****i996" || input.Model != "custom-local.glm-5.2" ||
		input.TraceID != "trace-f53bc1b9" || input.UserName != "zhangsan" || input.ProjectName != "研发一部" {
		t.Fatalf("input record projection: %+v", input)
	}
	legacy := records[0]
	if legacy.RuleName != "硬编码凭据示例" || legacy.RuleID != "rule_eca2480f" || legacy.Detail != "AKIA****MPLE" ||
		legacy.Layer != "input_content" || legacy.Basis == "" {
		t.Fatalf("legacy event must fall back to its blocking finding: %+v", legacy)
	}
}

func TestListBlockRecordsFindsEveryIdentifierAnAgentShows(t *testing.T) {
	repo, _ := newBlockRecordsTestRepo(t)
	cases := map[string]string{
		"evt_input":                           "evt_input",
		"req-legacy":                          "evt_legacy",
		"trace-f53bc1b9":                      "evt_input",
		"op_5f1b100aea3d3d597ee318442e7f628c": "evt_tool",
		// explicitly truncated screenshot identifiers
		"op_5f1b100aea3d...": "evt_tool",
		"op_5f1b100aea3d…":   "evt_tool",
		"evt_public_tool":    "evt_tool",
		"密码明文":               "evt_input",
		"rule_525f3078":      "evt_input",
	}
	for query, want := range cases {
		records, _, err := repo.ListBlockRecords(context.Background(), "t1", SecurityBlockRecordFilter{Query: query})
		if err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		if len(records) != 1 || records[0].BlockID != want {
			t.Fatalf("query %q: want %s, got %+v", query, want, records)
		}
	}
	tool, err := repo.GetBlockRecord(context.Background(), "t1", "evt_tool")
	if err != nil {
		t.Fatal(err)
	}
	if tool.OperationID != "op_5f1b100aea3d3d597ee318442e7f628c" || tool.Layer != "destructive_operation" {
		t.Fatalf("tool block: %+v", tool)
	}
	if _, err := repo.GetBlockRecord(context.Background(), "t2", "evt_tool"); err == nil {
		t.Fatal("another tenant must not read the block")
	}
}

func TestListBlockRecordsFiltersByLayerAndProject(t *testing.T) {
	repo, _ := newBlockRecordsTestRepo(t)
	records, total, err := repo.ListBlockRecords(context.Background(), "t1", SecurityBlockRecordFilter{Layer: "destructive_operation"})
	if err != nil || total != 1 || records[0].BlockID != "evt_tool" {
		t.Fatalf("layer filter: total=%d records=%+v err=%v", total, records, err)
	}
	records, total, err = repo.ListBlockRecords(context.Background(), "t1", SecurityBlockRecordFilter{ProjectIDs: []string{"p2"}})
	if err != nil || total != 1 || records[0].BlockID != "evt_legacy" {
		t.Fatalf("project filter: total=%d records=%+v err=%v", total, records, err)
	}
}

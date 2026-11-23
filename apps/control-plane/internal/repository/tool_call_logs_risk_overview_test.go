package repository

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func prepareRiskOverviewTruthTables(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	_, err := db.Exec(ctx, `
		CREATE TABLE users (id varchar(128), tenant_id varchar(128), username varchar(255));
		CREATE TABLE projects (id varchar(128), tenant_id varchar(128), name varchar(255));
		CREATE TABLE internal_keys (id varchar(128), tenant_id varchar(128), key_prefix varchar(255), agent_instance_id varchar(128));
		CREATE TABLE agentguard_confirmations (
			id varchar(64) PRIMARY KEY, tenant_id varchar(128) NOT NULL, request_id varchar(128),
			trace_id varchar(128) NOT NULL, tool_name varchar(256) NOT NULL,
			raw_decision varchar(16) NOT NULL, effective_decision varchar(16) NOT NULL,
			status varchar(16) NOT NULL, timeout_action varchar(16) NOT NULL DEFAULT 'block',
			reason text, evidence_json jsonb NOT NULL DEFAULT '{}'::jsonb,
			expires_at timestamptz NOT NULL, resolved_by varchar(64), resolved_at timestamptz,
			resolution_note text, created_at timestamptz NOT NULL,
			tool_call_id varchar(64), tool_call_arguments text, choice_index integer NOT NULL DEFAULT 0,
			replay_status varchar(16) NOT NULL DEFAULT 'pending', replayed_at timestamptz,
			replay_tool_log_id varchar(64), source varchar(16) NOT NULL DEFAULT '',
			requester_user_id VARCHAR(64), requester_client_id VARCHAR(64), arguments_hash VARCHAR(64),
			first_approved_by VARCHAR(64), first_approved_at TIMESTAMPTZ, consumed_request_id VARCHAR(128) -- W5 migration 901
		);
		CREATE TABLE mcp_confirmation_executions (
			confirmation_id varchar(64) PRIMARY KEY,
			invocation_id varchar(96) NOT NULL,
			tenant_id varchar(128) NOT NULL,
			execution_status varchar(16) NOT NULL,
			evidence_status varchar(16) NOT NULL,
			audit_request_id varchar(128), tool_log_id varchar(64), started_at timestamptz
		);
	`)
	if err != nil {
		t.Fatalf("create risk overview truth tables: %v", err)
	}
}

func TestRiskOverviewLifecycleUsesProvableFacts(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	prepareRiskOverviewTruthTables(t, db, ctx)
	now := time.Now().UTC()
	tenantID := "tenant-risk-overview"

	_, err := db.Exec(ctx, `
		INSERT INTO users (id, tenant_id, username) VALUES
			('user-high', $1, 'High User'), ('user-critical', $1, 'Critical User'),
			('user-legacy-confirm', $1, 'Legacy Confirm')
	`, tenantID)
	if err != nil {
		t.Fatalf("insert users: %v", err)
	}
	_, err = db.Exec(ctx, `
		INSERT INTO request_logs (request_id, tenant_id, agent_type) VALUES
			('req-high', $1, 'cursor'), ('req-critical', $1, 'claude-code'),
			('req-legacy-confirm', $1, 'legacy-agent')
	`, tenantID)
	if err != nil {
		t.Fatalf("insert request logs: %v", err)
	}
	_, err = db.Exec(ctx, `
		INSERT INTO tool_call_logs (
			id, request_id, session_id, tenant_id, user_id, tool_name, tool_type, risk_level,
			parameters, result, status, raw_decision, effective_decision, mode,
			event_kind, execution_observed, result_observed, tool_call_id, provenance, created_at
		) VALUES
			('tc-def-new', 'req-def-new', '', $1, '', 'Read', 'file', 'low', '{}', '', 'success', NULL, NULL, NULL, 'definition_exposed', false, false, NULL, NULL, $2),
			('tc-proposal-allow', 'req-allow', '', $1, '', 'Read', 'file', 'low', '{}', '', 'success', 'allow', 'allow', 'strict', 'invocation_proposed', false, false, 'call-allow', NULL, $2),
			('tc-high-audit', 'req-high', '', $1, 'user-high', 'WebSearch', 'network', 'high', '{}', '', 'audited', 'block', 'audit', 'audit', 'invocation_proposed', false, false, 'call-high', NULL, $2),
			('tc-critical-block', 'req-critical', '', $1, 'user-critical', 'Bash', 'system', 'critical', '{}', '', 'blocked', 'block', 'block', 'strict', 'invocation_proposed', false, false, 'call-critical', NULL, $2),
			('tc-mcp-execution', 'req-mcp', '', $1, '', 'demo__write', 'mcp', 'low', '{}', '', 'success', 'allow', 'allow', 'strict', 'execution_forwarded', true, false, 'call-mcp', 'mcp_gateway', $2),
			('tc-mcp-result', 'req-mcp', '', $1, '', 'demo__write', 'mcp', 'low', '{}', 'ok', 'success', NULL, NULL, NULL, 'result_observed', false, true, 'call-mcp', 'mcp_gateway', $2),
			('tc-def-legacy', 'req-def-legacy', '', $1, '', 'Read', 'file', 'low', '{}', 'request tool passed policy check', 'success', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, $2),
			('tc-proposal-legacy', 'req-legacy-confirm', '', $1, 'user-legacy-confirm', 'LegacyTool', 'unknown', 'low', '{}', '', 'success', 'confirm', 'audit', 'audit', NULL, NULL, NULL, 'call-legacy', NULL, $2),
			('tc-mcp-success-legacy', 'req-mcp-legacy', '', $1, '', 'demo__read', 'mcp', 'low', '{}', '', 'success', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'mcp_gateway', $2),
			('tc-critical-unknown', 'req-critical-unknown', '', $1, '', 'Unknown', 'unknown', 'critical', '{}', '', 'success', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, $2),
			('tc-outside', 'req-outside', '', $1, '', 'Bash', 'system', 'critical', '{}', '', 'blocked', 'block', 'block', 'strict', 'invocation_proposed', false, false, 'call-outside', NULL, $3),
			('tc-other-tenant', 'req-other', '', 'tenant-other', '', 'Bash', 'system', 'critical', '{}', '', 'blocked', 'block', 'block', 'strict', 'invocation_proposed', false, false, 'call-other', NULL, $2)
	`, tenantID, now, now.Add(-48*time.Hour))
	if err != nil {
		t.Fatalf("insert lifecycle matrix: %v", err)
	}

	overview, err := NewToolCallLogRepository(db).GetRiskOverview(ctx, tenantID, now.Add(-time.Hour), now.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("get risk overview: %v", err)
	}
	if overview.DefinitionExposedCount != 2 || overview.InvocationProposedCount != 4 ||
		overview.ExecutionForwardedCount != 1 || overview.ResultObservedCount != 1 || overview.UnknownEventCount != 2 {
		t.Fatalf("lifecycle counts = %#v", overview)
	}
	// 审计草案曾写 attempts=4，遗漏了旧双决策也必须派生 invocation_proposed。
	// MCP execution 同时证明一次调用尝试；同 tool_call_id 的 result 不重复计尝试。
	if overview.ToolCallAttempts != 5 || overview.TotalToolCalls != overview.ToolCallAttempts {
		t.Fatalf("attempts=%d compatibility total=%d", overview.ToolCallAttempts, overview.TotalToolCalls)
	}
	if overview.HighRiskCalls != 2 {
		t.Fatalf("high-risk count=%d", overview.HighRiskCalls)
	}
	if overview.RawDecisions["allow"] != 2 || overview.RawDecisions["block"] != 2 || overview.RawDecisions["confirm"] != 1 {
		t.Fatalf("raw decisions = %#v", overview.RawDecisions)
	}
	if overview.EffectiveDecisions["allow"] != 2 || overview.EffectiveDecisions["audit"] != 2 || overview.EffectiveDecisions["block"] != 1 {
		t.Fatalf("effective decisions = %#v", overview.EffectiveDecisions)
	}
	if len(overview.TopUsers) != 2 || len(overview.TopAgents) != 2 {
		t.Fatalf("high-risk top users=%#v agents=%#v", overview.TopUsers, overview.TopAgents)
	}
}

func TestRiskOverviewStatusSuccessNeverProvesExecution(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	prepareRiskOverviewTruthTables(t, db, ctx)
	now := time.Now().UTC()
	_, err := db.Exec(ctx, `INSERT INTO tool_call_logs
		(id, request_id, tenant_id, tool_name, tool_type, risk_level, parameters, status, provenance, created_at)
		VALUES ('tc-success-only', 'req-success-only', 'tenant-success-only', 'demo__read', 'mcp', 'low', '{}', 'success', 'mcp_gateway', $1)`, now)
	if err != nil {
		t.Fatalf("insert success-only row: %v", err)
	}
	overview, err := NewToolCallLogRepository(db).GetRiskOverview(ctx, "tenant-success-only", now.Add(-time.Hour), now.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("get risk overview: %v", err)
	}
	if overview.ExecutionForwardedCount != 0 || overview.UnknownEventCount != 1 {
		t.Fatalf("success-only row was treated as execution: %#v", overview)
	}
}

func TestRiskOverviewConfirmationCountsUseRealTable(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	prepareRiskOverviewTruthTables(t, db, ctx)
	now := time.Now().UTC()
	tenantID := "tenant-confirmation-overview"

	_, err := db.Exec(ctx, `
		INSERT INTO tool_call_logs (
			id, request_id, tenant_id, tool_name, tool_type, risk_level, parameters, status,
			event_kind, execution_observed, result_observed, tool_call_id, provenance, created_at
		) VALUES
			('tc-fake-replay', 'req-fake', $1, 'Bash', 'system', 'low', '{}', 'success',
			 'confirmation_replay', false, false, 'call-fake', 'agentguard_confirmation_replay', $2),
			('tc-real-execution', 'req-real', $1, 'demo__write', 'mcp', 'low', '{}', 'success',
			 'execution_forwarded', true, false, 'call-real', 'mcp_gateway', $2),
			('tc-network-proposal', 'req-network', $1, 'WebSearch', 'network', 'low', '{}', 'audited',
			 'invocation_proposed', false, false, 'call-network', NULL, $2),
			('tc-wrong-call', 'req-wrong-call', $1, 'demo__write', 'mcp', 'low', '{}', 'success',
			 'execution_forwarded', true, false, 'call-actual', 'mcp_gateway', $2),
			('tc-wrong-tool', 'req-wrong-tool', $1, 'demo__read', 'mcp', 'low', '{}', 'success',
			 'execution_forwarded', true, false, 'call-wrong-tool', 'mcp_gateway', $2),
			('tc-wrong-request', 'req-actual', $1, 'demo__write', 'mcp', 'low', '{}', 'success',
			 'execution_forwarded', true, false, 'call-wrong-request', 'mcp_gateway', $2),
			('tc-early-execution', 'req-early', $1, 'demo__write', 'mcp', 'low', '{}', 'success',
			 'execution_forwarded', true, false, 'call-early', 'mcp_gateway', $3),
			('tc-wrong-provenance', 'req-wrong-provenance', $1, 'demo__write', 'mcp', 'low', '{}', 'success',
			 'execution_forwarded', true, false, 'call-wrong-provenance', 'legacy_gateway', $2)
	`, tenantID, now, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("insert confirmation link facts: %v", err)
	}
	_, err = db.Exec(ctx, `
		INSERT INTO agentguard_confirmations (
			id, tenant_id, request_id, trace_id, tool_name, raw_decision, effective_decision,
			status, expires_at, created_at, tool_call_id, replay_status, replay_tool_log_id, source
		) VALUES
			('cf-pending', $1, 'req-pending', 'tr-pending', 'Bash', 'confirm', 'confirm', 'pending', $3, $2, 'call-pending', 'pending', '', ''),
			('cf-pending-expired', $1, 'req-pending-expired', 'tr-pending-expired', 'Bash', 'confirm', 'confirm', 'pending', $4, $2, 'call-pending-expired', 'pending', '', ''),
			('cf-approved-fake', $1, 'req-fake', 'tr-fake', 'Bash', 'confirm', 'confirm', 'approved', $3, $2, 'call-fake', 'executed', 'tc-fake-replay', ''),
			('cf-approved-real', $1, 'req-real', 'tr-real', 'demo__write', 'confirm', 'confirm', 'approved', $3, $2, 'call-real', 'executed', 'tc-real-execution', ''),
			('cf-approved-incidental', $1, 'req-real', 'tr-incidental', 'demo__write', 'confirm', 'confirm', 'approved', $3, $2, 'call-real', 'pending', '', ''),
			('cf-wrong-call', $1, 'req-wrong-call', 'tr-wrong-call', 'demo__write', 'confirm', 'confirm', 'approved', $3, $2, 'call-expected', 'executed', 'tc-wrong-call', ''),
			('cf-wrong-tool', $1, 'req-wrong-tool', 'tr-wrong-tool', 'demo__write', 'confirm', 'confirm', 'approved', $3, $2, 'call-wrong-tool', 'executed', 'tc-wrong-tool', ''),
			('cf-wrong-request', $1, 'req-expected', 'tr-wrong-request', 'demo__write', 'confirm', 'confirm', 'approved', $3, $2, 'call-wrong-request', 'executed', 'tc-wrong-request', ''),
			('cf-early', $1, 'req-early', 'tr-early', 'demo__write', 'confirm', 'confirm', 'approved', $3, $2, 'call-early', 'executed', 'tc-early-execution', ''),
			('cf-wrong-provenance', $1, 'req-wrong-provenance', 'tr-wrong-provenance', 'demo__write', 'confirm', 'confirm', 'approved', $3, $2, 'call-wrong-provenance', 'executed', 'tc-wrong-provenance', ''),
			('cf-rejected', $1, 'req-rejected', 'tr-rejected', 'Bash', 'confirm', 'confirm', 'rejected', $3, $2, 'call-rejected', 'pending', '', ''),
			('cf-expired', $1, 'req-expired', 'tr-expired', 'Bash', 'confirm', 'confirm', 'expired', $4, $2, 'call-expired', 'pending', '', ''),
			('cf-network', $1, 'req-network', 'tr-network', 'WebSearch', 'confirm', 'confirm', 'pending', $3, $2, 'call-network', 'pending', '', ''),
			('cf-mcp', $1, 'req-mcp', 'tr-mcp', 'demo__delete', 'confirm', 'confirm', 'pending', $3, $2, 'call-mcp', 'pending', '', 'mcp'),
			('cf-other', 'tenant-other', 'req-other', 'tr-other', 'Bash', 'confirm', 'confirm', 'pending', $3, $2, 'call-other', 'pending', '', '')
	`, tenantID, now, now.Add(time.Hour), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("insert confirmation matrix: %v", err)
	}

	overview, err := NewToolCallLogRepository(db).GetRiskOverview(ctx, tenantID, now.Add(-time.Hour), now.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("get confirmation overview: %v", err)
	}
	if overview.ConfirmationReplayCount != 1 || overview.UnknownEventCount != 0 ||
		overview.ConfirmationPending != 3 || overview.ConfirmationApproved != 8 ||
		overview.ConfirmationRejected != 1 || overview.ConfirmationExpired != 2 || overview.ConfirmationExecuted != 1 {
		t.Fatalf("confirmation counts = %#v", overview)
	}
	if overview.PendingConfirm != overview.ConfirmationPending {
		t.Fatalf("pending compatibility=%d canonical=%d", overview.PendingConfirm, overview.ConfirmationPending)
	}

	mcp, err := NewToolCallLogRepository(db).GetRiskOverview(ctx, tenantID, now.Add(-time.Hour), now.Add(time.Hour), "mcp")
	if err != nil {
		t.Fatalf("get MCP confirmation overview: %v", err)
	}
	if mcp.ConfirmationPending != 1 || mcp.ConfirmationApproved != 0 || mcp.ConfirmationExecuted != 0 {
		t.Fatalf("MCP source confirmation counts = %#v", mcp)
	}
	network, err := NewToolCallLogRepository(db).GetRiskOverview(ctx, tenantID, now.Add(-2*time.Hour), now.Add(time.Hour), "network")
	if err != nil {
		t.Fatalf("get network confirmation overview: %v", err)
	}
	if network.ConfirmationPending != 1 || network.ConfirmationApproved != 0 || network.ConfirmationExecuted != 0 {
		t.Fatalf("network-linked confirmation counts = %#v", network)
	}
	system, err := NewToolCallLogRepository(db).GetRiskOverview(ctx, tenantID, now.Add(-2*time.Hour), now.Add(time.Hour), "system")
	if err != nil {
		t.Fatalf("get system confirmation overview: %v", err)
	}
	if system.ConfirmationApproved != 1 || system.ConfirmationExecuted != 0 {
		t.Fatalf("system-linked confirmation counts = %#v", system)
	}
}

func TestRiskOverviewMCPExecutionCountsUseExecutionAndEvidenceState(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	prepareRiskOverviewTruthTables(t, db, ctx)
	now := time.Now().UTC()
	tenantID := "tenant-mcp-execution-overview"

	_, err := db.Exec(ctx, `
		INSERT INTO tool_call_logs (
			id, request_id, tenant_id, tool_name, tool_type, risk_level, parameters, status,
			event_kind, execution_observed, result_observed, tool_call_id, provenance, created_at
		) VALUES
			('tc-executed', 'req-executed', $1, 'demo__write', 'mcp', 'low', '{}', 'success',
			 'execution_forwarded', TRUE, FALSE, 'call-executed', 'mcp_gateway', $2),
			('tc-evidence-failed', 'req-evidence-failed', $1, 'demo__write', 'mcp', 'low', '{}', 'success',
			 'execution_forwarded', TRUE, FALSE, 'call-evidence-failed', 'mcp_gateway', $2)
	`, tenantID, now)
	if err != nil {
		t.Fatalf("insert MCP tool evidence: %v", err)
	}

	_, err = db.Exec(ctx, `
		INSERT INTO agentguard_confirmations (
			id, tenant_id, request_id, trace_id, tool_name, raw_decision, effective_decision,
			status, expires_at, resolved_at, created_at, tool_call_id, source
		) VALUES
			('cf-executed', $1, 'req-executed', 'tr-1', 'demo__write', 'confirm', 'confirm', 'approved', $3, $2, $2, 'call-executed', 'mcp'),
			('cf-evidence-failed', $1, 'req-evidence-failed', 'tr-2', 'demo__write', 'confirm', 'confirm', 'approved', $3, $2, $2, 'call-evidence-failed', 'mcp'),
			('cf-executing', $1, 'req-executing', 'tr-3', 'demo__write', 'confirm', 'confirm', 'approved', $3, $2, $2, 'call-executing', 'mcp'),
			('cf-failed', $1, 'req-failed', 'tr-4', 'demo__write', 'confirm', 'confirm', 'approved', $3, $2, $2, 'call-failed', 'mcp'),
			('cf-unknown', $1, 'req-unknown', 'tr-5', 'demo__write', 'confirm', 'confirm', 'approved', $3, $2, $2, 'call-unknown', 'mcp')
	`, tenantID, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("insert MCP confirmations: %v", err)
	}

	// Legacy replay flags on MCP rows must never add to the execution-table truth.
	_, err = db.Exec(ctx, `
		UPDATE agentguard_confirmations
		SET replay_status='executed', replay_tool_log_id=
			CASE WHEN id='cf-executed' THEN 'tc-executed' ELSE 'tc-evidence-failed' END
		WHERE id IN ('cf-executed', 'cf-evidence-failed')
	`)
	if err != nil {
		t.Fatalf("seed stale MCP replay flags: %v", err)
	}
	_, err = db.Exec(ctx, `
		INSERT INTO mcp_confirmation_executions (
			confirmation_id, invocation_id, tenant_id, execution_status, evidence_status,
			audit_request_id, tool_log_id, started_at
		) VALUES
			('cf-executed', 'inv-1', $1, 'executed', 'complete', 'req-executed', 'tc-executed', $2),
			('cf-evidence-failed', 'inv-2', $1, 'executed', 'failed', 'req-evidence-failed', 'tc-evidence-failed', $2),
			('cf-executing', 'inv-3', $1, 'executing', 'pending', 'req-executing', NULL, $2),
			('cf-failed', 'inv-4', $1, 'failed', 'failed', 'req-failed', NULL, $2),
			('cf-unknown', 'inv-5', $1, 'unknown', 'failed', 'req-unknown', NULL, $2)
	`, tenantID, now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("insert MCP execution states: %v", err)
	}

	overview, err := NewToolCallLogRepository(db).GetRiskOverview(
		ctx, tenantID, now.Add(-time.Hour), now.Add(time.Hour), "mcp",
	)
	if err != nil {
		t.Fatalf("get MCP risk overview: %v", err)
	}
	if overview.ConfirmationExecuted != 1 ||
		overview.ConfirmationExecuting != 1 ||
		overview.ConfirmationFailed != 1 ||
		overview.ConfirmationUnknown != 1 ||
		overview.ConfirmationEvidenceFailed != 3 {
		t.Fatalf("MCP execution/evidence counts = %#v", overview)
	}
}

func TestListConfirmationsNormalizesPendingExpiry(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	prepareRiskOverviewTruthTables(t, db, ctx)
	now := time.Now().UTC()
	_, err := db.Exec(ctx, `
		INSERT INTO agentguard_confirmations (
			id, tenant_id, trace_id, tool_name, raw_decision, effective_decision, status, expires_at, created_at
		) VALUES
			('cf-list-pending', 'tenant-list', 'tr-1', 'Bash', 'confirm', 'confirm', 'pending', $1, $2),
			('cf-list-pending-expired', 'tenant-list', 'tr-2', 'Bash', 'confirm', 'confirm', 'pending', $3, $2),
			('cf-list-expired', 'tenant-list', 'tr-3', 'Bash', 'confirm', 'confirm', 'expired', $3, $2)
	`, now.Add(time.Hour), now, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("insert list confirmation matrix: %v", err)
	}
	repo := NewAgentGuardPolicyRepository(db)
	pending, err := repo.ListConfirmations(ctx, "tenant-list", "pending", "")
	if err != nil || len(pending) != 1 || pending[0].Status != "pending" {
		t.Fatalf("pending confirmations=%#v err=%v", pending, err)
	}
	expired, err := repo.ListConfirmations(ctx, "tenant-list", "expired", "")
	if err != nil || len(expired) != 2 {
		t.Fatalf("expired confirmations=%#v err=%v", expired, err)
	}
	for _, item := range expired {
		if item.Status != "expired" {
			t.Fatalf("expired filter returned stale status: %#v", item)
		}
	}
}

func TestRiskOverviewLegacyPartialDecisionAndRequestScopedAttemptKey(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	prepareRiskOverviewTruthTables(t, db, ctx)
	now := time.Now().UTC()
	_, err := db.Exec(ctx, `
		INSERT INTO tool_call_logs (
			id, request_id, tenant_id, tool_name, tool_type, risk_level, parameters, status,
			raw_decision, effective_decision, mode, event_kind, execution_observed, result_observed,
			tool_call_id, provenance, created_at
		) VALUES
			('tc-raw-only', 'req-raw', 'tenant-normalize', 'Read', 'file', 'low', '{}', 'success',
			 'allow', NULL, NULL, NULL, NULL, NULL, 'call-shared', NULL, $1),
			('tc-replay', 'req-replay', 'tenant-normalize', 'Bash', 'system', 'low', '{}', 'success',
			 'confirm', 'audit', 'audit', 'confirmation_replay', false, false, 'call-replay', 'agentguard_confirmation_replay', $1),
			('tc-exec-a', 'req-a', 'tenant-normalize', 'demo__read', 'mcp', 'low', '{}', 'success',
			 'allow', 'allow', 'strict', 'execution_forwarded', true, false, 'jsonrpc-1', 'mcp_gateway', $1),
			('tc-exec-b', 'req-b', 'tenant-normalize', 'demo__read', 'mcp', 'low', '{}', 'success',
			 'allow', 'allow', 'strict', 'execution_forwarded', true, false, 'jsonrpc-1', 'mcp_gateway', $1)
	`, now)
	if err != nil {
		t.Fatalf("insert normalization edge matrix: %v", err)
	}
	overview, err := NewToolCallLogRepository(db).GetRiskOverview(ctx, "tenant-normalize", now.Add(-time.Hour), now.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("get normalization overview: %v", err)
	}
	if overview.InvocationProposedCount != 1 || overview.ExecutionForwardedCount != 2 ||
		overview.ConfirmationReplayCount != 1 || overview.UnknownEventCount != 0 ||
		overview.ToolCallAttempts != 3 {
		t.Fatalf("normalization counts = %#v", overview)
	}
	if overview.RawDecisions["allow"] != 3 || overview.EffectiveDecisions["allow"] != 2 ||
		overview.EffectiveDecisions["unknown"] != 1 {
		t.Fatalf("normalization decisions raw=%#v effective=%#v", overview.RawDecisions, overview.EffectiveDecisions)
	}
}

func TestToolStatsAndTrendUseCallFactsBeforeCurrentTime(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	now := time.Now().UTC().Add(-time.Second)
	_, err := db.Exec(ctx, `
		INSERT INTO tool_call_logs (
			id, request_id, tenant_id, tool_name, tool_type, risk_level, parameters, status,
			raw_decision, effective_decision, event_kind, execution_observed, result_observed,
			tool_call_id, provenance, created_at
		) VALUES
			('tc-stats-definition', 'req-def', 'tenant-stats', 'Read', 'file', 'high', '{}', 'success',
			 NULL, NULL, 'definition_exposed', false, false, NULL, NULL, $1),
			('tc-stats-invocation', 'req-call', 'tenant-stats', 'Bash', 'system', 'high', '{}', 'audited',
			 'block', 'audit', 'invocation_proposed', false, false, 'call-stats', NULL, $1),
			('tc-stats-execution', 'req-mcp', 'tenant-stats', 'demo__read', 'mcp', 'low', '{}', 'success',
			 'allow', 'allow', 'execution_forwarded', true, false, 'rpc-stats', 'mcp_gateway', $1),
			('tc-stats-result', 'req-mcp', 'tenant-stats', 'demo__read', 'mcp', 'critical', '{}', 'success',
			 NULL, NULL, 'result_observed', false, true, 'rpc-stats', 'mcp_gateway', $1),
			('tc-stats-unknown', 'req-unknown', 'tenant-stats', 'Unknown', 'unknown', 'critical', '{}', 'success',
			 NULL, NULL, NULL, NULL, NULL, NULL, NULL, $1),
			('tc-stats-replay', 'req-replay', 'tenant-stats', 'Bash', 'system', 'low', '{}', 'success',
			 NULL, NULL, 'confirmation_replay', false, false, 'call-replay', 'agentguard_confirmation_replay', $1),
			('tc-stats-future', 'req-future', 'tenant-stats', 'Bash', 'system', 'critical', '{}', 'blocked',
			 'block', 'block', 'invocation_proposed', false, false, 'call-future', NULL, $2),
			('tc-stats-old', 'req-old', 'tenant-stats', 'Fetch', 'network', 'medium', '{}', 'audited',
			 'audit', 'audit', 'invocation_proposed', false, false, 'call-old', NULL, $3),
			('tc-stats-other', 'req-other', 'tenant-other', 'Bash', 'system', 'critical', '{}', 'blocked',
			 'block', 'block', 'invocation_proposed', false, false, 'call-other', NULL, $1)
	`, now, now.Add(24*time.Hour), now.Add(-48*time.Hour))
	if err != nil {
		t.Fatalf("insert stats truth matrix: %v", err)
	}
	repo := NewToolCallLogRepository(db)
	stats, err := repo.GetStats(ctx, "tenant-stats")
	if err != nil {
		t.Fatalf("get stats: %v", err)
	}
	byType := map[string]ToolCallStats{}
	for _, item := range stats {
		byType[item.ToolType] = item
	}
	if len(byType) != 5 || byType["system"].Count != 1 || byType["system"].HighCount != 1 ||
		byType["system"].InvocationProposedCount != 1 || byType["system"].ConfirmationReplayCount != 1 ||
		byType["mcp"].Count != 1 || byType["mcp"].LowCount != 1 ||
		byType["mcp"].ExecutionForwardedCount != 1 || byType["mcp"].ResultObservedCount != 1 ||
		byType["file"].Count != 0 || byType["file"].DefinitionExposedCount != 1 ||
		byType["unknown"].Count != 0 || byType["unknown"].UnknownEventCount != 1 ||
		byType["network"].Count != 1 {
		t.Fatalf("call fact stats = %#v", stats)
	}
	windowed, err := repo.GetStatsWindow(ctx, "tenant-stats", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("get windowed stats: %v", err)
	}
	if len(windowed) != 4 {
		t.Fatalf("windowed stats = %#v", windowed)
	}
	trend, err := repo.GetRiskTrend(ctx, "tenant-stats", 1)
	if err != nil {
		t.Fatalf("get risk trend: %v", err)
	}
	if len(trend) != 1 || trend[0].HighCount != 1 || trend[0].CriticalCount != 0 {
		t.Fatalf("call fact trend = %#v", trend)
	}
}

func TestRiskOverviewCTEProjectsOnlyRequiredColumns(t *testing.T) {
	if strings.Contains(riskOverviewNormalizedCTE, "SELECT tcl.*") {
		t.Fatal("risk overview CTE must not sort full tool_call_logs rows")
	}
}

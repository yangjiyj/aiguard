package repository

import (
	"os"
	"strings"
	"testing"
)

func agentAdminRepositorySource(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("agent_admin.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestAgentAdminRepositoryTenantScopesObjectAccess(t *testing.T) {
	source := agentAdminRepositorySource(t)
	for _, query := range []string{
		"FROM agent_endpoints WHERE tenant_id=$1 AND id=$2",
		"WHERE tenant_id=$1 AND id=$2 RETURNING",
		"WHERE tenant_id=$1 AND id=$2 AND status",
		"FROM agent_sessions WHERE tenant_id=$1 AND (id=$2 OR session_id=$2)",
		"FROM agent_turns WHERE tenant_id=$1 AND session_id=$2",
		"FROM tool_call_logs WHERE tenant_id=$1 AND session_id=$2",
	} {
		if !strings.Contains(source, query) {
			t.Errorf("missing tenant-scoped SQL contract %q", query)
		}
	}
	for _, forbidden := range []string{"WHERE id=$1", "WHERE id=$2 RETURNING"} {
		if strings.Contains(source, forbidden) {
			t.Errorf("found unscoped object SQL %q", forbidden)
		}
	}
}

func TestAgentAdminStaleSQLContract(t *testing.T) {
	source := agentAdminRepositorySource(t)
	for _, required := range []string{
		"COUNT(*) FILTER(WHERE status='active' AND (last_heartbeat_at IS NULL OR last_heartbeat_at<now()-interval '15 minutes'))",
		`clauses = append(clauses, "status='active'")`,
		`clauses = append(clauses, "(last_heartbeat_at IS NULL OR last_heartbeat_at<now()-interval '15 minutes')")`,
		`clauses = append(clauses, "last_heartbeat_at IS NOT NULL AND last_heartbeat_at>=now()-interval '15 minutes'")`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("missing stale SQL contract %q", required)
		}
	}
	for _, forbidden := range []string{
		"status='stale' OR",
		`clauses = append(clauses, "(last_heartbeat_at IS NULL OR last_heartbeat_at>=now()-interval '15 minutes')")`,
	} {
		if strings.Contains(source, forbidden) {
			t.Errorf("found inconsistent stale SQL %q", forbidden)
		}
	}
}

func TestAgentAdminNullableAndEnrollmentSQLContract(t *testing.T) {
	source := agentAdminRepositorySource(t)
	for _, required := range []string{
		"COALESCE(risk_score,0)",
		"COALESCE(turn_count,0)",
		"COALESCE(event_count,0)",
		"COALESCE(tool_call_count,0)",
		"COALESCE(blocked_count,0)",
		"COALESCE(would_block_count,0)",
		"COALESCE(gateway_request_count,0)",
		"COALESCE(created_at,to_timestamp(0)) FROM tool_call_logs",
		"COALESCE(tool_call_log_id,''),severity FROM agent_events",
		"&x.ServerDecision, &x.ToolCallLogID, &x.Severity",
		"COALESCE(a.created_at,to_timestamp(0)) FROM alerts",
		`addAgentFilter(&clauses, &args, "enabled=$%d", *f.Enabled)`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("missing SQL contract %q", required)
		}
	}
}

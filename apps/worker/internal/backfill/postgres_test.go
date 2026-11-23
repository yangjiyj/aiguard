package backfill

import (
	"os"
	"strings"
	"testing"
)

func TestCustomerProjectionBatchContract(t *testing.T) {
	body, err := os.ReadFile("../../../../deploy/migrations/834_customer_content_projection_backfill.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(body))
	for _, required := range []string{
		"migration_backfill_tasks",
		"customer_content_projection_v1",
		"scan_upper_bound",
		"batch_size",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("registration migration missing %q", required)
		}
	}

	implementation := strings.ToLower(customerContentProjectionBatchSQL)
	for _, required := range []string{
		"for no key update of rl skip locked",
		"set local lock_timeout",
		"set local statement_timeout",
		"order by rl.created_at, rl.id",
		"migration_backfill_retry_rows",
		"jjdguard_customer_content_text",
	} {
		if !strings.Contains(implementation, required) {
			t.Fatalf("batch implementation missing %q", required)
		}
	}
	if strings.Contains(implementation, " offset ") {
		t.Fatal("backfill must use keyset pagination, not OFFSET")
	}
}

func TestRequestLogCompatibilityBatchContract(t *testing.T) {
	implementation := strings.ToLower(requestLogCompatibilityBatchSQL)
	for _, required := range []string{
		"for no key update of rl skip locked",
		"order by rl.created_at,rl.id",
		"migration_backfill_retry_rows",
		"content_evidence_retention_until",
		// Codex UA 特征由调用方按 agentdetect.ProductPatterns 传入（$9），与网关识别同源。
		"unnest($9::text[]) ua_pattern",
	} {
		if !strings.Contains(implementation, required) {
			t.Fatalf("compatibility implementation missing %q", required)
		}
	}
	if strings.Contains(implementation, " offset ") {
		t.Fatal("compatibility backfill must use keyset pagination")
	}
}

func TestCustomerEnvironmentScopeBatchContract(t *testing.T) {
	for _, implementation := range []string{
		strings.ToLower(customerEnvironmentScopeBatchSQL),
		strings.ToLower(customerEnvironmentScopeDedupBatchSQL),
	} {
		for _, required := range []string{
			"for no key update of rl skip locked",
			"access_locked", "content_locked", "artifact_locked", "link_locked",
			"blocked_parents", "migration_backfill_retry_rows",
		} {
			if !strings.Contains(implementation, required) {
				t.Fatalf("environment scope implementation missing %q", required)
			}
		}
	}
}

// 迁移 987 之后 content_logs 是视图，不能 FOR NO KEY UPDATE，也不该经视图 UPDATE：两张底表各自加锁、各自更新。
func TestCustomerEnvironmentScopeDedupBatchLocksBaseTables(t *testing.T) {
	implementation := strings.ToLower(customerEnvironmentScopeDedupBatchSQL)
	for _, required := range []string{
		"from content_log_entries cl", "from content_logs_legacy cl",
		"update content_log_entries cl", "update content_logs_legacy cl",
	} {
		if !strings.Contains(implementation, required) {
			t.Fatalf("dedup environment scope batch missing %q", required)
		}
	}
	for _, forbidden := range []string{"from content_logs cl", "update content_logs cl"} {
		if strings.Contains(implementation, forbidden) {
			t.Fatalf("dedup environment scope batch must not touch the content_logs view: %q", forbidden)
		}
	}
}

func TestEvidenceAgentProjectionBatchContract(t *testing.T) {
	implementation := strings.ToLower(evidenceAgentProjectionBatchSQL)
	for _, required := range []string{
		"for no key update of rl skip locked", "evidence_run_request_index",
		"effective_agent_type='openai-codex'", "chain_dirty=true",
		"migration_backfill_retry_rows",
	} {
		if !strings.Contains(implementation, required) {
			t.Fatalf("evidence projection implementation missing %q", required)
		}
	}
}

func TestSecurityEventDeliveryBatchContract(t *testing.T) {
	implementation := strings.ToLower(securityEventDeliveryBatchSQL)
	for _, required := range []string{
		"from security_events", "for no key update of se skip locked",
		"migration_backfill_retry_rows", "processed_at=coalesce",
		"delivery=coalesce", "coalesce(se.created_at,'0001-01-01",
	} {
		if !strings.Contains(implementation, required) {
			t.Fatalf("security event delivery implementation missing %q", required)
		}
	}
	if strings.Contains(implementation, " offset ") {
		t.Fatal("security event delivery backfill must use keyset pagination")
	}
	upper, estimate := taskSourceQueries(SecurityEventDeliveryTask)
	if !strings.Contains(upper, "security_events") || !strings.Contains(estimate, "security_events") {
		t.Fatal("security event task must derive its bound and estimate from security_events")
	}
}

func TestEvidenceTitleNoiseBatchContract(t *testing.T) {
	implementation := strings.ToLower(evidenceTitleNoiseBatchSQL)
	for _, required := range []string{
		"from evidence_run_request_index", "for no key update of eri skip locked",
		"jjdguard_customer_content_text", "title_hash=derived.title_hash",
		"migration_backfill_retry_rows",
	} {
		if !strings.Contains(implementation, required) {
			t.Fatalf("evidence title implementation missing %q", required)
		}
	}
	upper, estimate := taskSourceQueries(EvidenceTitleNoiseTask)
	if !strings.Contains(upper, "evidence_run_request_index") ||
		!strings.Contains(estimate, "evidence_run_request_index") {
		t.Fatal("title task must derive its bound and estimate from the evidence index")
	}
}

func TestWorkBuddyIdentityBatchContract(t *testing.T) {
	implementation := strings.ToLower(workBuddyIdentityBatchSQL)
	for _, required := range []string{
		"for no key update of rl skip locked", "agent_protocol_repairs",
		"product_identity", "workbuddy_workspace", "audit_barrier",
		"count(distinct match.workspace)=1", "migration_backfill_retry_rows",
	} {
		if !strings.Contains(implementation, required) {
			t.Fatalf("workbuddy implementation missing %q", required)
		}
	}
	if strings.Contains(implementation, " offset ") {
		t.Fatal("workbuddy backfill must use keyset pagination")
	}
}

func TestUsageRollupDimensionsBatchContract(t *testing.T) {
	implementation := strings.ToLower(usageRollupDimensionsBatchSQL)
	for _, required := range []string{
		"for key share of rl skip locked", "affected as materialized",
		"latency_count=aggregated.latency_count",
		"first_priced_at=aggregated.first_priced_at",
		"is distinct from", "migration_backfill_retry_rows",
	} {
		if !strings.Contains(implementation, required) {
			t.Fatalf("usage rollup implementation missing %q", required)
		}
	}
	if strings.Contains(implementation, " offset ") {
		t.Fatal("usage rollup backfill must use keyset pagination")
	}
}

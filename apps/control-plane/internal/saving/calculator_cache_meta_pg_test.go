package saving

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// 网关响应缓存命中的行：自身 token 为 0，省下的量和实际计费成本记在 output_audit_result.response_metadata.cache。
func TestRunOnceReadsGatewayCacheMetadata(t *testing.T) {
	pool := getTestPool(t)
	defer pool.Close()
	ctx := context.Background()
	suffix := time.Now().UnixNano()
	tenantID := fmt.Sprintf("tenant-saving-meta-%d", suffix)
	projectCost := fmt.Sprintf("proj-saving-cost-%d", suffix)
	projectTokens := fmt.Sprintf("proj-saving-tok-%d", suffix)
	modelID := fmt.Sprintf("model-saving-meta-%d", suffix)
	t.Cleanup(func() {
		for _, stmt := range []string{
			"DELETE FROM saving_metrics WHERE tenant_id = $1",
			"DELETE FROM request_logs WHERE tenant_id = $1",
			"DELETE FROM projects WHERE tenant_id = $1",
			"DELETE FROM tenants WHERE id = $1",
		} {
			_, _ = pool.Exec(context.Background(), stmt, tenantID)
		}
		_, _ = pool.Exec(context.Background(), "DELETE FROM models WHERE id = $1", modelID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM providers WHERE tenant_id = $1", tenantID)
	})
	mustExec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	mustExec(`INSERT INTO tenants (id, name) VALUES ($1, $1)`, tenantID)
	for _, p := range []string{projectCost, projectTokens} {
		mustExec(`INSERT INTO projects (id, name, tenant_id) VALUES ($1, $1, $2)`, p, tenantID)
	}
	providerID := fmt.Sprintf("prov-saving-meta-%d", suffix)
	mustExec(`INSERT INTO providers (id, tenant_id, name, provider_type) VALUES ($1, $2, $1, 'openai')`, providerID, tenantID)
	mustExec(`INSERT INTO models (id, provider_id, model_name, pricing_json) VALUES ($1, $2, $1, '{"input": 10.0, "output": 30.0}')`, modelID, providerID)
	// 有实际计费成本（CNY 7.2 元 = 1 美元）：按成本算，不看定价。
	mustExec(`INSERT INTO request_logs (id, request_id, tenant_id, project_id, model_id, cache_hit, input_tokens, output_tokens, created_at, output_audit_result)
		VALUES ($1, $1, $2, $3, $4, TRUE, 0, 0, NOW(), '{"response_metadata":{"cache":{"hit":true,"saved_input_tokens":100000,"saved_output_tokens":50000,"saved_cost_micros":7200000,"currency":"CNY"}}}')`,
		fmt.Sprintf("rl-meta-cost-%d", suffix), tenantID, projectCost, modelID)
	// 没有成本：按省下的 token 乘定价（100k×$10/M + 50k×$30/M = $2.50）。
	mustExec(`INSERT INTO request_logs (id, request_id, tenant_id, project_id, model_id, cache_hit, input_tokens, output_tokens, created_at, output_audit_result)
		VALUES ($1, $1, $2, $3, $4, TRUE, 0, 0, NOW(), '{"response_metadata":{"cache":{"hit":true,"saved_input_tokens":100000,"saved_output_tokens":50000}}}')`,
		fmt.Sprintf("rl-meta-tok-%d", suffix), tenantID, projectTokens, modelID)

	calc := NewCalculator(pool, &mockFx{rate: 7.2}, &mockWatermark{ts: time.Now().UTC().Add(-time.Hour)})
	if _, err := calc.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	read := func(project string) float64 {
		t.Helper()
		var usd float64
		if err := pool.QueryRow(ctx, `SELECT saving_usd FROM saving_metrics WHERE tenant_id = $1 AND project_id = $2 AND source = 'cache_hit'`, tenantID, project).Scan(&usd); err != nil {
			t.Fatalf("read saving for %s: %v", project, err)
		}
		return usd
	}
	if got := read(projectCost); got != 1.0 {
		t.Fatalf("billed-cost saving = %v, want 1.0 USD", got)
	}
	if got := read(projectTokens); got != 2.5 {
		t.Fatalf("token-priced saving = %v, want 2.5 USD", got)
	}
}

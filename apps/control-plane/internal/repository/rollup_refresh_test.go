package repository

import (
	"fmt"
	"testing"
	"time"
)

func TestRefreshUsageHourlyRecomputesWindow(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	repo := NewRollupReadModelRepository(db)
	bucket := time.Date(2026, 6, 18, 13, 0, 0, 0, time.UTC)
	reqA := fmt.Sprintf("req_rollup_usage_a_%d", time.Now().UnixNano())
	reqB := fmt.Sprintf("req_rollup_usage_b_%d", time.Now().UnixNano())
	providerID := fmt.Sprintf("prov_rollup_usage_%d", time.Now().UnixNano())
	modelID := fmt.Sprintf("model_rollup_usage_%d", time.Now().UnixNano())

	if _, err := db.Exec(ctx, `
		INSERT INTO providers (id, tenant_id, name, provider_type, status)
		VALUES ($1, $2, '测试供应商', 'openai', 'active')
	`, providerID, tenantID); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO models (id, provider_id, model_name, model_label, status)
		VALUES ($1, $2, 'model_rollup', 'model_rollup', 'active')
	`, modelID, providerID); err != nil {
		t.Fatalf("insert model: %v", err)
	}

	for requestID, inputTokens := range map[string]int{reqA: 100, reqB: 25} {
		if _, err := db.Exec(ctx, `
            INSERT INTO request_logs (
                id, request_id, tenant_id, project_id, user_id, client_id, provider_id, model_id,
                endpoint_type, request_status, latency_ms, input_tokens, output_tokens, total_cost, created_at
            ) VALUES ($1,$1,$2,$3,$4,'key_rollup',$5,$6,'chat','success',200,$7,10,0.25,$8)
        `, requestID, tenantID, projectID, userID, providerID, modelID, inputTokens, bucket.Add(5*time.Minute)); err != nil {
			t.Fatalf("insert request %s: %v", requestID, err)
		}
	}

	win := RollupRefreshWindow{TenantID: tenantID, From: bucket, To: bucket.Add(time.Hour)}
	if err := repo.RefreshUsageHourly(ctx, win); err != nil {
		t.Fatalf("first refresh usage: %v", err)
	}
	if err := repo.RefreshUsageHourly(ctx, win); err != nil {
		t.Fatalf("second refresh usage: %v", err)
	}
	summary, err := repo.GetUsageSummary(ctx, tenantID, bucket, bucket.Add(time.Hour))
	if err != nil {
		t.Fatalf("summary after refresh: %v", err)
	}
	if summary.Requests != 2 || summary.InputTokens != 125 || summary.OutputTokens != 20 || summary.TotalCost != 0.5 {
		t.Fatalf("refresh should recompute usage without duplication: %+v", summary)
	}

	if _, err := db.Exec(ctx, `UPDATE request_logs SET input_tokens = 300 WHERE request_id = $1`, reqA); err != nil {
		t.Fatalf("update source request: %v", err)
	}
	if err := repo.RefreshUsageHourly(ctx, win); err != nil {
		t.Fatalf("third refresh usage: %v", err)
	}
	summary, err = repo.GetUsageSummary(ctx, tenantID, bucket, bucket.Add(time.Hour))
	if err != nil {
		t.Fatalf("summary after compensation: %v", err)
	}
	if summary.Requests != 2 || summary.InputTokens != 325 {
		t.Fatalf("refresh should replace stale usage values, got %+v", summary)
	}
}

func TestRefreshAccessHourlyRecomputesRiskSummary(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	repo := NewRollupReadModelRepository(db)
	bucket := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)
	blockedReq := fmt.Sprintf("req_rollup_blocked_%d", time.Now().UnixNano())
	normalReq := fmt.Sprintf("req_rollup_normal_%d", time.Now().UnixNano())

	insertAccess := func(requestID, status string) {
		t.Helper()
		if _, err := db.Exec(ctx, `
            INSERT INTO request_logs (
                id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status,
                proxy_mode, proxy_target_host, proxy_access_type, proxy_access_type_resolved, proxy_provider, created_at
            ) VALUES ($1,$1,$2,$3,$4,'proxy',$5,'forward','api.openai.com','llm','llm','openai',$6)
        `, requestID, tenantID, projectID, userID, status, bucket.Add(10*time.Minute)); err != nil {
			t.Fatalf("insert access request %s: %v", requestID, err)
		}
	}
	insertAccess(blockedReq, "blocked")
	insertAccess(normalReq, "success")

	win := RollupRefreshWindow{TenantID: tenantID, From: bucket, To: bucket.Add(time.Hour)}
	if err := repo.RefreshAccessHourly(ctx, win); err != nil {
		t.Fatalf("first refresh access: %v", err)
	}
	if err := repo.RefreshAccessHourly(ctx, win); err != nil {
		t.Fatalf("second refresh access: %v", err)
	}

	summary, err := repo.GetAccessSummary(ctx, tenantID, bucket, bucket.Add(time.Hour))
	if err != nil {
		t.Fatalf("access summary after refresh: %v", err)
	}
	if summary.Total != 2 || summary.BlockedCount != 1 || summary.NormalCount != 1 || summary.ForwardCount != 2 || summary.LLMCount != 2 {
		t.Fatalf("refresh should recompute access summary without duplication: %+v", summary)
	}
}

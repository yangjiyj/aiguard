package repository

import (
	"testing"
	"time"
)

func TestUsageRollupUpsertIsIdempotent(t *testing.T) {
	db, ctx, tenantID, _, projectID := setupAuditStatsRegressionFixture(t)
	repo := NewRollupReadModelRepository(db)
	bucket := time.Date(2026, 6, 18, 10, 0, 0, 0, time.UTC)
	input := UsageRollupInput{
		TenantID: tenantID, BucketStart: bucket, ProjectID: projectID, UserID: "user_a",
		ClientID: "key_a", ProviderID: "provider_a", ModelID: "model_a",
		RequestCount: 3, SuccessCount: 2, PricedRequestCount: 1,
		InputTokens: 100, OutputTokens: 20, TotalCost: 0.5, LatencyMsSum: 900,
		FirstSeenAt: bucket.Add(5 * time.Minute), LastSeenAt: bucket.Add(15 * time.Minute),
	}

	if err := repo.UpsertUsageHourly(ctx, input); err != nil {
		t.Fatalf("first upsert usage rollup: %v", err)
	}
	if err := repo.UpsertUsageHourly(ctx, input); err != nil {
		t.Fatalf("second upsert usage rollup: %v", err)
	}

	summary, err := repo.GetUsageSummary(ctx, tenantID, bucket, bucket.Add(time.Hour))
	if err != nil {
		t.Fatalf("get usage summary: %v", err)
	}
	if summary.Requests != 3 || summary.InputTokens != 100 || summary.OutputTokens != 20 || summary.TotalCost != 0.5 || summary.PricedRequests != 1 {
		t.Fatalf("usage rollup should be replaced, not doubled: %+v", summary)
	}
	if summary.TotalTokens() != 120 {
		t.Fatalf("total tokens = %d, want 120", summary.TotalTokens())
	}
}

func TestUsageRollupSummaryIsTenantScoped(t *testing.T) {
	db, ctx, tenantA, _, projectA := setupAuditStatsRegressionFixture(t)
	_, _, tenantB, _, projectB := setupAuditStatsRegressionFixture(t)
	repo := NewRollupReadModelRepository(db)
	bucket := time.Date(2026, 6, 18, 11, 0, 0, 0, time.UTC)

	if err := repo.UpsertUsageHourly(ctx, UsageRollupInput{TenantID: tenantA, BucketStart: bucket, ProjectID: projectA, RequestCount: 2, InputTokens: 10}); err != nil {
		t.Fatalf("upsert tenant A: %v", err)
	}
	if err := repo.UpsertUsageHourly(ctx, UsageRollupInput{TenantID: tenantB, BucketStart: bucket, ProjectID: projectB, RequestCount: 7, InputTokens: 70}); err != nil {
		t.Fatalf("upsert tenant B: %v", err)
	}

	summary, err := repo.GetUsageSummary(ctx, tenantA, bucket, bucket.Add(time.Hour))
	if err != nil {
		t.Fatalf("get tenant A summary: %v", err)
	}
	if summary.Requests != 2 || summary.InputTokens != 10 {
		t.Fatalf("summary should include only tenant A, got %+v", summary)
	}
}

func TestAccessRollupUpsertSummarizesWithoutDuplication(t *testing.T) {
	db, ctx, tenantID, _, _ := setupAuditStatsRegressionFixture(t)
	repo := NewRollupReadModelRepository(db)
	bucket := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	input := AccessRollupInput{
		TenantID: tenantID, BucketStart: bucket, Direction: "forward", AccessType: "llm",
		Provider: "openai", TargetHost: "api.openai.com", RiskState: "risk",
		RequestCount: 4, RiskCount: 4, LLMCount: 4, ForwardCount: 4, RetainedContentCount: 2,
	}

	if err := repo.UpsertAccessHourly(ctx, input); err != nil {
		t.Fatalf("first upsert access rollup: %v", err)
	}
	if err := repo.UpsertAccessHourly(ctx, input); err != nil {
		t.Fatalf("second upsert access rollup: %v", err)
	}

	summary, err := repo.GetAccessSummary(ctx, tenantID, bucket, bucket.Add(time.Hour))
	if err != nil {
		t.Fatalf("get access summary: %v", err)
	}
	if summary.Total != 4 || summary.RiskCount != 4 || summary.LLMCount != 4 || summary.ForwardCount != 4 || summary.RetainedContentCount != 2 {
		t.Fatalf("access rollup should be replaced, not doubled: %+v", summary)
	}
	if len(summary.TopProviders) != 1 || summary.TopProviders[0].Name != "openai" || summary.TopProviders[0].Count != 4 {
		t.Fatalf("unexpected provider dimension: %+v", summary.TopProviders)
	}
	if len(summary.TopTargets) != 1 || summary.TopTargets[0].Name != "api.openai.com" || summary.TopTargets[0].RiskCount != 4 {
		t.Fatalf("unexpected target dimension: %+v", summary.TopTargets)
	}
}

func TestAccessRollupSummaryFilteredUsesDimensions(t *testing.T) {
	db, ctx, tenantID, _, _ := setupAuditStatsRegressionFixture(t)
	repo := NewRollupReadModelRepository(db)
	bucket := time.Date(2026, 6, 18, 15, 0, 0, 0, time.UTC)
	if err := repo.UpsertAccessHourly(ctx, AccessRollupInput{TenantID: tenantID, BucketStart: bucket, Direction: "forward", AccessType: "llm", Provider: "openai", TargetHost: "api.openai.com", RiskState: "risk", RequestCount: 4, RiskCount: 4, LLMCount: 4, ForwardCount: 4}); err != nil {
		t.Fatalf("upsert risk access: %v", err)
	}
	if err := repo.UpsertAccessHourly(ctx, AccessRollupInput{TenantID: tenantID, BucketStart: bucket, Direction: "forward", AccessType: "normal_public", Provider: "example", TargetHost: "example.com", RiskState: "normal", RequestCount: 6, NormalCount: 6, NormalPublicCount: 6, ForwardCount: 6}); err != nil {
		t.Fatalf("upsert normal access: %v", err)
	}

	summary, err := repo.GetAccessSummaryFiltered(ctx, tenantID, ForwardProxyAccessFilter{RiskState: "risk", AccessType: "llm", Provider: "OPENAI", TargetHost: "openai"})
	if err != nil {
		t.Fatalf("filtered access summary: %v", err)
	}
	if summary.Total != 4 || summary.RiskCount != 4 || summary.LLMCount != 4 || summary.ForwardCount != 4 {
		t.Fatalf("unexpected filtered summary: %+v", summary)
	}
	if len(summary.TopProviders) != 1 || summary.TopProviders[0].Name != "openai" {
		t.Fatalf("unexpected providers: %+v", summary.TopProviders)
	}
	if len(summary.TopTargets) != 1 || summary.TopTargets[0].Name != "api.openai.com" {
		t.Fatalf("unexpected targets: %+v", summary.TopTargets)
	}
}

func TestUsageRollupSummaryScopedFiltersProjectAndUser(t *testing.T) {
	db, ctx, tenantID, userA, projectA := setupAuditStatsRegressionFixture(t)
	repo := NewRollupReadModelRepository(db)
	bucket := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	projectB := projectA + "_b"
	userB := userA + "_b"
	if _, err := db.Exec(ctx, `INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1, $2, $3, 'developer', 'active')`, userB, tenantID, userB); err != nil {
		t.Fatalf("insert scoped user: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, owner_user_id, status) VALUES ($1, $2, $3, $4, 'active')`, projectB, tenantID, projectB, userB); err != nil {
		t.Fatalf("insert scoped project: %v", err)
	}

	if err := repo.UpsertUsageHourly(ctx, UsageRollupInput{TenantID: tenantID, BucketStart: bucket, ProjectID: projectA, UserID: userA, RequestCount: 5, InputTokens: 50}); err != nil {
		t.Fatalf("upsert project A: %v", err)
	}
	if err := repo.UpsertUsageHourly(ctx, UsageRollupInput{TenantID: tenantID, BucketStart: bucket, ProjectID: projectB, UserID: userB, RequestCount: 7, InputTokens: 70}); err != nil {
		t.Fatalf("upsert project B: %v", err)
	}

	projectSummary, err := repo.GetUsageSummaryScoped(ctx, UsageScope{TenantID: tenantID, ProjectIDs: []string{projectA}}, bucket, bucket.Add(time.Hour))
	if err != nil {
		t.Fatalf("project scoped summary: %v", err)
	}
	if projectSummary.Requests != 5 || projectSummary.InputTokens != 50 {
		t.Fatalf("unexpected project scoped summary: %+v", projectSummary)
	}

	userSummary, err := repo.GetUsageSummaryScoped(ctx, UsageScope{TenantID: tenantID, UserID: userB}, bucket, bucket.Add(time.Hour))
	if err != nil {
		t.Fatalf("user scoped summary: %v", err)
	}
	if userSummary.Requests != 7 || userSummary.InputTokens != 70 {
		t.Fatalf("unexpected user scoped summary: %+v", userSummary)
	}
}

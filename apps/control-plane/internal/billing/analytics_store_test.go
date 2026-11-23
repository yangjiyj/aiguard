package billing

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAnalyticsWhereRequiresAndAppliesScope(t *testing.T) {
	base := AnalyticsFilter{TenantID: "tenant-a", Start: time.Unix(100, 0), End: time.Unix(200, 0)}
	where, args, err := analyticsWhere(base)
	if err != nil || !strings.Contains(where, "AND FALSE") || len(args) != 3 {
		t.Fatalf("unscoped where=%q args=%v err=%v", where, args, err)
	}
	base.TeamIDs = []string{"team-a", "team-b"}
	where, args, err = analyticsWhere(base)
	if err != nil || !strings.Contains(where, "department_id = ANY($4)") || len(args) != 4 {
		t.Fatalf("team scope where=%q args=%v err=%v", where, args, err)
	}
	base.FullTenant = true
	where, args, err = analyticsWhere(base)
	if err != nil || strings.Contains(where, "department_id") || len(args) != 3 {
		t.Fatalf("full tenant where=%q args=%v err=%v", where, args, err)
	}
}

func TestAnalyticsDimensionAcceptsChannelAlias(t *testing.T) {
	providerID, _, _, providerOK := analyticsDimensionSQL("provider")
	channelID, _, _, channelOK := analyticsDimensionSQL("channel")
	if !providerOK || !channelOK || providerID != channelID {
		t.Fatalf("provider=%q/%v channel=%q/%v", providerID, providerOK, channelID, channelOK)
	}
}

func TestAnalyticsWhereAppliesReportFiltersInsideAuthorizedScope(t *testing.T) {
	filter := AnalyticsFilter{
		TenantID: "tenant-a", Start: time.Unix(100, 0), End: time.Unix(200, 0),
		TeamIDs:             []string{"authorized-team"},
		FilterDepartmentIDs: []string{"selected-team"},
		FilterProjectIDs:    []string{"project-a"},
		FilterUserIDs:       []string{"user-a"},
		FilterModelIDs:      []string{"model-a"},
		FilterProviderIDs:   []string{"provider-a"},
		FilterAgentTypes:    []string{"codex"},
	}
	where, args, err := analyticsWhere(filter)
	if err != nil {
		t.Fatalf("analyticsWhere: %v", err)
	}
	for _, expected := range []string{
		"department_id = ANY($4)",
		"department_id = ANY($5)",
		"project_id = ANY($6)",
		"user_id = ANY($7)",
		"model_id = ANY($8)",
		"provider_id = ANY($9)",
		"request_logs",
		"agent_type",
		"MIN(NULLIF",
		"ANY($10)",
	} {
		if !strings.Contains(where, expected) {
			t.Fatalf("where missing %q: %s", expected, where)
		}
	}
	if len(args) != 10 {
		t.Fatalf("args=%v", args)
	}
}

func TestAnalyticsDimensionAcceptsAgentType(t *testing.T) {
	id, name, _, ok := analyticsDimensionSQL("agent")
	if !ok || !strings.Contains(id, "agent_type") || !strings.Contains(name, "\u975e\u667a\u80fd\u4f53\u8c03\u7528") {
		t.Fatalf("agent dimension id=%q name=%q ok=%v", id, name, ok)
	}
}

func TestAnalyticsSummaryTreatsFailedFactsAsNonPricingFailures(t *testing.T) {
	store, db, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_usage_facts (
			id,tenant_id,request_id,billing_mode,user_name,department_name,project_name,
			provider_name,provider_type,model_name,prompt_tokens,output_tokens,currency,
			tariff_band,tariff_multiplier_ppm,billing_timezone,attribution_quality,status,occurred_at
		) VALUES ($1,$2,$3,'metering','','','','','','failed-model',0,0,'CNY','flat',1000000,'Asia/Shanghai','unknown','failed',$4)
	`, "usage_fact_failed_"+tenantID, tenantID, "req-failed", now); err != nil {
		t.Fatalf("insert failed fact: %v", err)
	}

	summary, err := store.GetAnalyticsSummary(ctx, AnalyticsFilter{
		TenantID: tenantID, Start: now.Add(-time.Hour), End: now.Add(time.Hour), FullTenant: true,
	})
	// Legacy priced definition stays compatible; the failed outcome is now
	// additionally visible as its own counter.
	if err != nil || summary.Requests != 1 || summary.PricedRequests != 1 ||
		summary.UnpricedRequests != 0 || summary.FailedRequests != 1 {
		t.Fatalf("failed request must not be diagnosed as missing price: summary=%+v err=%v", summary, err)
	}
}

func TestMeteringFactIsIdempotentImmutableAndQueryable(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	admittedAt := time.Now().UTC().Truncate(time.Second)
	input := MeteringInput{
		TenantID: tenantID, UserID: userID, RequestID: "req-metering-fact", ModelName: "unpriced-model",
		RequestStatus: "success", Usage: Usage{
			PromptTokens: 10, CachedInputTokens: 2, CacheWriteInputTokens: 1,
			OutputTokens: 2, ReasoningTokens: 1,
		}, AdmittedAt: admittedAt,
	}
	fact, err := store.RecordMeteringUsage(ctx, input)
	if err != nil || fact.Status != "unpriced" || fact.BillableAmountMicros != nil {
		t.Fatalf("fact=%+v err=%v", fact, err)
	}
	repeated, err := store.RecordMeteringUsage(ctx, input)
	if err != nil || repeated.ID != fact.ID {
		t.Fatalf("idempotent fact=%+v err=%v, first=%+v", repeated, err, fact)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_usage_facts WHERE tenant_id=$1 AND request_id=$2`, tenantID, input.RequestID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("fact count=%d err=%v", count, err)
	}
	summary, err := store.GetAnalyticsSummary(ctx, AnalyticsFilter{
		TenantID: tenantID, Start: admittedAt.Add(-time.Hour), End: admittedAt.Add(time.Hour), FullTenant: true,
	})
	if err != nil || summary.Requests != 1 || summary.UnpricedRequests != 1 ||
		summary.PromptTokens != 10 || summary.CachedInputTokens != 2 ||
		summary.CacheWriteInputTokens != 1 || summary.OutputTokens != 2 ||
		summary.ReasoningTokens != 1 || summary.TotalTokens != 12 ||
		summary.UpstreamCostKnownRequests != 0 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	filter := AnalyticsFilter{TenantID: tenantID, Start: admittedAt.Add(-time.Hour), End: admittedAt.Add(time.Hour), FullTenant: true}
	if rows, err := store.GetAnalyticsBreakdown(ctx, filter, "department", 10); err != nil || len(rows) != 1 ||
		rows[0].CachedInputTokens != 2 || rows[0].CacheWriteInputTokens != 1 ||
		rows[0].ReasoningTokens != 1 || rows[0].UpstreamCostKnownRequests != 0 {
		t.Fatalf("department breakdown=%+v err=%v", rows, err)
	}
	if rows, err := store.GetAnalyticsBreakdown(ctx, filter, "channel", 10); err != nil || len(rows) != 1 {
		t.Fatalf("channel breakdown=%+v err=%v", rows, err)
	}
	if rows, err := store.GetAnalyticsSeries(ctx, filter, "day"); err != nil || len(rows) != 1 {
		t.Fatalf("series=%+v err=%v", rows, err)
	}
	if rows, err := store.GetAnalyticsTimeProfile(ctx, filter, "Asia/Shanghai", 60); err != nil || len(rows) != 1 {
		t.Fatalf("time profile=%+v err=%v", rows, err)
	}
	if rows, err := store.GetAnalyticsDepartmentProviderMatrix(ctx, filter); err != nil || len(rows) != 1 {
		t.Fatalf("matrix=%+v err=%v", rows, err)
	}
	if _, err := db.Exec(ctx, `UPDATE billing_usage_facts SET status='settled' WHERE tenant_id=$1`, tenantID); err == nil {
		t.Fatal("append-only usage fact accepted an update")
	}
}

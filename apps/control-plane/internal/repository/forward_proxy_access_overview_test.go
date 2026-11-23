package repository

import (
	"strings"
	"testing"
	"time"
)

func TestForwardProxyTimelineGranularityFollowsWindow(t *testing.T) {
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		filter ForwardProxyAccessFilter
		want   string
	}{
		{name: "24 hours", filter: ForwardProxyAccessFilter{StartTime: start, EndTime: start.Add(24 * time.Hour)}, want: "hour"},
		{name: "48 hours", filter: ForwardProxyAccessFilter{StartTime: start, EndTime: start.Add(48 * time.Hour)}, want: "hour"},
		{name: "more than 48 hours", filter: ForwardProxyAccessFilter{StartTime: start, EndTime: start.Add(49 * time.Hour)}, want: "day"},
		{name: "unbounded", filter: ForwardProxyAccessFilter{}, want: "day"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := forwardProxyTimelineGranularity(tt.filter); got != tt.want {
				t.Fatalf("granularity=%q want %q", got, tt.want)
			}
		})
	}
}

func TestForwardProxyPublicTargetExpressionNeverFallsBackToInternalModelID(t *testing.T) {
	expr := forwardProxyPublicTargetExpr()
	for _, publicColumn := range []string{"rl.proxy_target_host", "m.model_label", "m.model_name"} {
		if !strings.Contains(expr, publicColumn) {
			t.Fatalf("target expression must include %s: %s", publicColumn, expr)
		}
	}
	for _, guard := range []string{"rl.proxy_target_host = COALESCE(rl.model_id", "rl.proxy_target_host ~ '^model_"} {
		if !strings.Contains(expr, guard) {
			t.Fatalf("customer-visible target expression must guard internal ids with %q: %s", guard, expr)
		}
	}
}

func TestForwardProxyOverviewQueriesStayTenantScopedAndUseBothContentStores(t *testing.T) {
	where := []string{"rl.tenant_id = $1", "rl.created_at >= $2"}
	evidence := forwardProxyEvidenceQualityQuery(where)
	for _, fragment := range []string{"FROM request_logs rl", "access_content_logs", "acl.request_id = rl.request_id", "content_logs", "cl.request_id = rl.id", "cl.tenant_id = rl.tenant_id", "rl.tenant_id = $1"} {
		if !strings.Contains(evidence, fragment) {
			t.Fatalf("evidence query missing %q:\n%s", fragment, evidence)
		}
	}

	dimension := forwardProxyTopDimensionQuery(forwardProxyPublicTargetExpr(), "COALESCE(rl.risk_state, 'normal')", where)
	for _, fragment := range []string{"LEFT JOIN models m ON m.id = rl.model_id", "m.model_label", "m.model_name", "rl.tenant_id = $1"} {
		if !strings.Contains(dimension, fragment) {
			t.Fatalf("target dimension query missing %q:\n%s", fragment, dimension)
		}
	}

	timeline := forwardProxyTimelineQuery(where, "hour", "COALESCE(rl.risk_state, 'normal')")
	for _, fragment := range []string{"date_trunc('hour', rl.created_at)", "COUNT(*) FILTER", "rl.tenant_id = $1", "LIMIT 31"} {
		if !strings.Contains(timeline, fragment) {
			t.Fatalf("timeline query missing %q:\n%s", fragment, timeline)
		}
	}

	risks := forwardProxyTopRiskCategoriesQuery(where)
	for _, fragment := range []string{"SELECT DISTINCT rl.request_id", "se.tenant_id = rl.tenant_id", "se.request_id = rl.request_id", "matched_summary->>'category'", "rl.tenant_id = $1", "LIMIT 8"} {
		if !strings.Contains(risks, fragment) {
			t.Fatalf("risk category query missing %q:\n%s", fragment, risks)
		}
	}
	if !strings.Contains(risks, "jsonb_array_elements") {
		t.Fatalf("risk category query must apply ignoredForwardProxySecurityEvent semantics:\n%s", risks)
	}
}

func TestForwardProxyAttentionRiskReasonsStayTenantScoped(t *testing.T) {
	reasons := forwardProxyAttentionRiskReasonsExpr()
	for _, want := range []string{
		"se_reason.request_id = rl.request_id",
		"se_reason.tenant_id = rl.tenant_id",
	} {
		if !strings.Contains(reasons, want) {
			t.Fatalf("attention reasons missing tenant-scoped event lookup %q:\n%s", want, reasons)
		}
	}
	memberReasons := forwardProxyMemberAliasedExpr(reasons)
	if !strings.Contains(memberReasons, "se_reason.tenant_id = rlm.tenant_id") {
		t.Fatalf("attention member reasons lost tenant scope:\n%s", memberReasons)
	}
}

func TestForwardProxyOverviewSlicesDefaultToEmpty(t *testing.T) {
	summary := newForwardProxyAccessSummary()
	if summary.Timeline == nil {
		t.Fatal("timeline must be an empty slice, not nil")
	}
	if summary.TopRiskCategories == nil {
		t.Fatal("top risk categories must be an empty slice, not nil")
	}
}

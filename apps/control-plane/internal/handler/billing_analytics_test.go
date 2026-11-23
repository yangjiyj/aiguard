package handler

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseBillingAnalyticsRangeDateEndIsInclusive(t *testing.T) {
	r := httptest.NewRequest("GET", "/?from=2026-08-01&to=2026-08-02", nil)
	start, end, ok := parseBillingAnalyticsRange(r)
	if !ok || !start.Equal(time.Date(2026, 7, 31, 16, 0, 0, 0, time.UTC)) ||
		!end.Equal(time.Date(2026, 8, 2, 16, 0, 0, 0, time.UTC)) {
		t.Fatalf("start=%s end=%s ok=%v", start, end, ok)
	}
}

func TestParseBillingAnalyticsRangeRejectsOverOneYear(t *testing.T) {
	r := httptest.NewRequest("GET", "/?from=2025-01-01&to=2026-08-01", nil)
	_, _, ok := parseBillingAnalyticsRange(r)
	if ok {
		t.Fatal("range over 366 days was accepted")
	}
}

func TestParseBillingAnalyticsDimensionFilters(t *testing.T) {
	r := httptest.NewRequest("GET", "/?department_ids=dept-a,dept-b&project_ids=project-a&user_ids=user-a&model_ids=model-a&provider_ids=provider-a&agent_types=codex,claude-code", nil)
	filters, ok := parseBillingAnalyticsDimensionFilters(r)
	if !ok {
		t.Fatal("valid report filters were rejected")
	}
	if len(filters.DepartmentIDs) != 2 || filters.DepartmentIDs[1] != "dept-b" ||
		len(filters.ProjectIDs) != 1 || filters.ProjectIDs[0] != "project-a" ||
		len(filters.UserIDs) != 1 || filters.UserIDs[0] != "user-a" ||
		len(filters.ModelIDs) != 1 || filters.ModelIDs[0] != "model-a" ||
		len(filters.ProviderIDs) != 1 || filters.ProviderIDs[0] != "provider-a" ||
		len(filters.AgentTypes) != 2 || filters.AgentTypes[1] != "claude-code" {
		t.Fatalf("filters=%+v", filters)
	}
}

func TestParseBillingAnalyticsDimensionFiltersRejectsOversizedValues(t *testing.T) {
	r := httptest.NewRequest("GET", "/?model_ids="+strings.Repeat("x", 129), nil)
	if _, ok := parseBillingAnalyticsDimensionFilters(r); ok {
		t.Fatal("oversized report filter was accepted")
	}
}

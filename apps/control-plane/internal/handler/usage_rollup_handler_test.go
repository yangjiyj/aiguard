package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

type fakeUsageRollupSummaryRepo struct {
	called bool
	scope  repository.UsageScope
	out    *repository.UsageRollupSummary
	err    error
}

func (f *fakeUsageRollupSummaryRepo) GetUsageSummaryScoped(ctx context.Context, scope repository.UsageScope, start, end time.Time) (*repository.UsageRollupSummary, error) {
	f.called = true
	f.scope = scope
	if f.out != nil || f.err != nil {
		return f.out, f.err
	}
	return &repository.UsageRollupSummary{}, nil
}

type fakeUsageSummaryRepo struct {
	called bool
	out    *repository.UsageSummary
	err    error
}

func (f *fakeUsageSummaryRepo) GetSummaryScoped(ctx context.Context, scope repository.UsageScope, startDate, endDate time.Time) (*repository.UsageSummary, error) {
	f.called = true
	if f.out != nil || f.err != nil {
		return f.out, f.err
	}
	return &repository.UsageSummary{TenantID: scope.TenantID}, nil
}

func usageRollupRequest(role string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/usage/summary?start_date=2026-06-18&end_date=2026-06-18", nil)
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_1",
		Role:     role,
		Status:   "active",
	}))
}

func TestGetUsageSummaryPrefersRollupWhenDataExists(t *testing.T) {
	freshUntil := time.Date(2026, 6, 18, 13, 0, 0, 0, time.UTC)
	rollup := &fakeUsageRollupSummaryRepo{out: &repository.UsageRollupSummary{Requests: 7, InputTokens: 100, OutputTokens: 50, TotalCost: 1.25, DataFreshUntil: &freshUntil}}
	legacy := &fakeUsageSummaryRepo{out: &repository.UsageSummary{TenantID: "tenant_1", Requests: 99}}
	deps := &Dependencies{UsageRollupRepo: rollup, UsageSummaryRepo: legacy}

	rr := httptest.NewRecorder()
	GetUsageSummary(deps).ServeHTTP(rr, usageRollupRequest("tenant_owner"))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !rollup.called {
		t.Fatal("expected rollup repo to be called")
	}
	if legacy.called {
		t.Fatal("legacy usage summary should not be called when rollup has data")
	}
	var resp types.UsageSummary
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Requests != 7 || resp.InputTokens != 100 || resp.OutputTokens != 50 || resp.TotalCost != 1.25 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.DataFreshUntil != "2026-06-18T13:00:00Z" {
		t.Fatalf("expected data_fresh_until to be forwarded, got %q", resp.DataFreshUntil)
	}
}

func TestGetUsageSummaryFallsBackWhenRollupIsEmpty(t *testing.T) {
	rollup := &fakeUsageRollupSummaryRepo{out: &repository.UsageRollupSummary{}}
	legacy := &fakeUsageSummaryRepo{out: &repository.UsageSummary{TenantID: "tenant_1", Requests: 3, InputTokens: 10, OutputTokens: 5, TotalCost: 0.5}}
	deps := &Dependencies{UsageRollupRepo: rollup, UsageSummaryRepo: legacy}

	rr := httptest.NewRecorder()
	GetUsageSummary(deps).ServeHTTP(rr, usageRollupRequest("tenant_owner"))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !legacy.called {
		t.Fatal("expected legacy summary fallback when rollup is empty")
	}
	var resp types.UsageSummary
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Requests != 3 || resp.InputTokens != 10 || resp.OutputTokens != 5 || resp.TotalCost != 0.5 {
		t.Fatalf("unexpected fallback response: %+v", resp)
	}
}

func TestGetUsageSummaryPassesUserScopeToRollup(t *testing.T) {
	rollup := &fakeUsageRollupSummaryRepo{out: &repository.UsageRollupSummary{Requests: 1}}
	deps := &Dependencies{UsageRollupRepo: rollup}

	rr := httptest.NewRecorder()
	GetUsageSummary(deps).ServeHTTP(rr, usageRollupRequest("developer"))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if rollup.scope.FullTenant || rollup.scope.UserID != "user_1" || rollup.scope.TenantID != "tenant_1" {
		t.Fatalf("rollup should receive user-scoped filter, got %+v", rollup.scope)
	}
}

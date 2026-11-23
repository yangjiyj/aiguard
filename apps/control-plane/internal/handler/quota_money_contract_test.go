package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestSetQuotaPolicyCanonicalMoneyStates(t *testing.T) {
	tests := []struct {
		name        string
		moneyJSON   string
		wantMicros  *int64
		wantBlocked bool
	}{
		{name: "inherit", moneyJSON: `"daily_budget_micros":null,"daily_budget_blocked":false`},
		{name: "unlimited", moneyJSON: `"daily_budget_micros":0,"daily_budget_blocked":false`, wantMicros: int64Pointer(0)},
		{name: "limit", moneyJSON: `"daily_budget_micros":12500001,"daily_budget_blocked":false`, wantMicros: int64Pointer(12500001)},
		{name: "blocked", moneyJSON: `"daily_budget_micros":null,"daily_budget_blocked":true`, wantBlocked: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeQuotaPolicyRepo{}
			deps := &Dependencies{SystemRepo: &quotaAuditSystemRepo{}, QuotaPolicyRepo: repo}
			body := []byte(`{"scope_type":"tenant",` + tc.moneyJSON + `}`)
			recorder := httptest.NewRecorder()

			SetQuotaPolicy(deps).ServeHTTP(recorder, adminCtx(httptest.NewRequest(
				http.MethodPut, "/admin/v1/policies/quota", bytes.NewReader(body),
			)))

			if recorder.Code != http.StatusOK || repo.saved == nil {
				t.Fatalf("status=%d policy=%+v body=%s", recorder.Code, repo.saved, recorder.Body.String())
			}
			if !equalOptionalInt64(repo.saved.DailyBudgetMicros, tc.wantMicros) ||
				repo.saved.DailyBudgetBlocked != tc.wantBlocked {
				t.Fatalf("saved money state=%+v", repo.saved)
			}
			var response map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response["daily_budget_blocked"] != tc.wantBlocked {
				t.Fatalf("blocked response=%#v", response)
			}
			if tc.wantMicros == nil {
				if response["daily_budget_micros"] != nil {
					t.Fatalf("inherit/blocked must return null micros: %#v", response)
				}
			} else if response["daily_budget_micros"] != float64(*tc.wantMicros) {
				t.Fatalf("micros response=%#v", response)
			}
			if response["budget_amount_basis"] != "billable_amount" {
				t.Fatalf("billable amount basis missing: %#v", response)
			}
		})
	}
}

func TestSetQuotaPolicyCanonicalMonthlyMoneyStates(t *testing.T) {
	tests := []struct {
		name        string
		moneyJSON   string
		wantMicros  *int64
		wantBlocked bool
	}{
		{name: "inherit", moneyJSON: `"monthly_budget_micros":null,"monthly_budget_blocked":false`},
		{name: "unlimited", moneyJSON: `"monthly_budget_micros":0,"monthly_budget_blocked":false`, wantMicros: int64Pointer(0)},
		{name: "limit", moneyJSON: `"monthly_budget_micros":12500001,"monthly_budget_blocked":false`, wantMicros: int64Pointer(12500001)},
		{name: "blocked", moneyJSON: `"monthly_budget_micros":null,"monthly_budget_blocked":true`, wantBlocked: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeQuotaPolicyRepo{}
			recorder := httptest.NewRecorder()
			SetQuotaPolicy(&Dependencies{SystemRepo: &quotaAuditSystemRepo{}, QuotaPolicyRepo: repo}).ServeHTTP(
				recorder,
				adminCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", bytes.NewBufferString(`{"scope_type":"tenant",`+tc.moneyJSON+`}`))),
			)

			if recorder.Code != http.StatusOK || repo.saved == nil {
				t.Fatalf("status=%d policy=%+v body=%s", recorder.Code, repo.saved, recorder.Body.String())
			}
			if !equalOptionalInt64(repo.saved.MonthlyBudgetMicros, tc.wantMicros) || repo.saved.MonthlyBudgetBlocked != tc.wantBlocked {
				t.Fatalf("saved money state=%+v", repo.saved)
			}
		})
	}
}

func TestSetQuotaPolicyCanonicalCountStates(t *testing.T) {
	dimensions := []struct {
		name       string
		limitField string
		blockField string
	}{
		{name: "daily token", limitField: "daily_token_limit", blockField: "daily_token_blocked"},
		{name: "monthly token", limitField: "monthly_token_limit", blockField: "monthly_token_blocked"},
		{name: "rpm", limitField: "rpm_limit", blockField: "rpm_blocked"},
		{name: "concurrency", limitField: "concurrency_limit", blockField: "concurrency_blocked"},
	}
	states := []struct {
		name        string
		limitJSON   string
		wantLimit   any
		wantBlocked bool
	}{
		{name: "inherit", limitJSON: "null"},
		{name: "unlimited", limitJSON: "0", wantLimit: float64(0)},
		{name: "limit", limitJSON: "17", wantLimit: float64(17)},
		{name: "blocked", limitJSON: "null", wantBlocked: true},
	}
	for _, dimension := range dimensions {
		for _, state := range states {
			t.Run(dimension.name+"/"+state.name, func(t *testing.T) {
				repo := &fakeQuotaPolicyRepo{}
				body := fmt.Sprintf(
					`{"scope_type":"tenant","%s":%s,"%s":%t}`,
					dimension.limitField,
					state.limitJSON,
					dimension.blockField,
					state.wantBlocked,
				)
				recorder := httptest.NewRecorder()
				SetQuotaPolicy(&Dependencies{SystemRepo: &quotaAuditSystemRepo{}, QuotaPolicyRepo: repo}).ServeHTTP(
					recorder,
					adminCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", bytes.NewBufferString(body))),
				)
				if recorder.Code != http.StatusOK || repo.saved == nil {
					t.Fatalf("status=%d policy=%+v body=%s", recorder.Code, repo.saved, recorder.Body.String())
				}
				var response map[string]any
				if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if response[dimension.limitField] != state.wantLimit || response[dimension.blockField] != state.wantBlocked {
					t.Fatalf("canonical state missing: %#v", response)
				}
			})
		}
	}
}

func TestSetQuotaPolicyValidatesAndEchoesTimezone(t *testing.T) {
	for _, tc := range []struct {
		name       string
		timezone   string
		wantStatus int
		want       string
	}{
		{name: "default", wantStatus: http.StatusOK, want: "Asia/Shanghai"},
		{name: "iana", timezone: `,"quota_timezone":"America/New_York"`, wantStatus: http.StatusOK, want: "America/New_York"},
		{name: "invalid", timezone: `,"quota_timezone":"Mars/Olympus"`, wantStatus: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeQuotaPolicyRepo{}
			recorder := httptest.NewRecorder()
			SetQuotaPolicy(&Dependencies{SystemRepo: &quotaAuditSystemRepo{}, QuotaPolicyRepo: repo}).ServeHTTP(
				recorder,
				adminCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", bytes.NewBufferString(`{"scope_type":"tenant"`+tc.timezone+`}`))),
			)
			if recorder.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, tc.wantStatus, recorder.Body.String())
			}
			if tc.wantStatus == http.StatusOK {
				if repo.saved == nil || repo.saved.QuotaTimezone != tc.want {
					t.Fatalf("timezone not saved: %+v", repo.saved)
				}
				var response map[string]any
				if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if response["quota_timezone"] != tc.want {
					t.Fatalf("timezone not echoed: %#v", response)
				}
			} else if repo.saved != nil {
				t.Fatalf("invalid timezone persisted: %+v", repo.saved)
			}
		})
	}
}

func TestSetQuotaPolicyLegacyCNYCompatibilityAndConflict(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantMicros int64
	}{
		{name: "legacy only", body: `{"scope_type":"tenant","daily_budget_limit":12.500001}`, wantStatus: http.StatusOK, wantMicros: 12500001},
		{name: "consistent dual", body: `{"scope_type":"tenant","daily_budget_micros":12500001,"daily_budget_limit":12.500001}`, wantStatus: http.StatusOK, wantMicros: 12500001},
		{name: "inconsistent dual", body: `{"scope_type":"tenant","daily_budget_micros":12500002,"daily_budget_limit":12.500001}`, wantStatus: http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeQuotaPolicyRepo{}
			deps := &Dependencies{SystemRepo: &quotaAuditSystemRepo{}, QuotaPolicyRepo: repo}
			recorder := httptest.NewRecorder()
			SetQuotaPolicy(deps).ServeHTTP(recorder, adminCtx(httptest.NewRequest(
				http.MethodPut, "/admin/v1/policies/quota", bytes.NewBufferString(tc.body),
			)))
			if recorder.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, tc.wantStatus, recorder.Body.String())
			}
			if tc.wantStatus == http.StatusOK {
				if repo.saved == nil || repo.saved.DailyBudgetMicros == nil || *repo.saved.DailyBudgetMicros != tc.wantMicros {
					t.Fatalf("legacy conversion failed: %+v", repo.saved)
				}
			} else if repo.saved != nil {
				t.Fatalf("conflicting money fields were persisted: %+v", repo.saved)
			}
		})
	}
}

func TestSetQuotaPolicyRejectsInvalidCanonicalMoneyAndUnknownFields(t *testing.T) {
	for _, body := range []string{
		`{"scope_type":"tenant","daily_budget_micros":-1}`,
		`{"scope_type":"tenant","daily_budget_micros":9007199254740992}`,
		`{"scope_type":"tenant","daily_budget_micros":1.5}`,
		`{"scope_type":"tenant","daily_budget_micros":1,"daily_budget_blocked":true}`,
		`{"scope_type":"tenant","daily_token_limit":1,"daily_token_blocked":true}`,
		`{"scope_type":"tenant","monthly_token_limit":-1}`,
		`{"scope_type":"tenant","rpm_limit":-1}`,
		`{"scope_type":"tenant","concurrency_limit":-1}`,
		`{"scope_type":"tenant","daily_budget_limit":NaN}`,
		`{"scope_type":"tenant","daily_budget_limit":1e999}`,
		`{"scope_type":"tenant","daily_budget_limit":0.0000001}`,
		`{"scope_type":"tenant"} {"scope_type":"tenant"}`,
		`{"scope_type":"tenant","unknown_money_mode":"free"}`,
	} {
		repo := &fakeQuotaPolicyRepo{}
		deps := &Dependencies{SystemRepo: &quotaAuditSystemRepo{}, QuotaPolicyRepo: repo}
		recorder := httptest.NewRecorder()
		SetQuotaPolicy(deps).ServeHTTP(recorder, adminCtx(httptest.NewRequest(
			http.MethodPut, "/admin/v1/policies/quota", bytes.NewBufferString(body),
		)))
		if recorder.Code != http.StatusBadRequest || repo.saved != nil {
			t.Fatalf("invalid amount accepted: body=%s status=%d saved=%+v response=%s", body, recorder.Code, repo.saved, recorder.Body.String())
		}
	}
}

func TestSetQuotaPolicyRejectsActionsWithoutCrossEntryRuntimeSupport(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{name: "pause key", body: `{"scope_type":"tenant","overage_action":"pause_key"}`, wantStatus: http.StatusBadRequest},
		{name: "downgrade model", body: `{"scope_type":"tenant","overage_action":"downgrade_model","downgrade_model_id":"model-ok"}`, wantStatus: http.StatusBadRequest},
		{name: "legacy target is read only", body: `{"scope_type":"tenant","overage_action":"notify","downgrade_model_id":"model-old"}`, wantStatus: http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeQuotaPolicyRepo{}
			deps := &Dependencies{SystemRepo: &quotaAuditSystemRepo{}, QuotaPolicyRepo: repo}
			recorder := httptest.NewRecorder()
			SetQuotaPolicy(deps).ServeHTTP(recorder, adminCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/policies/quota", bytes.NewBufferString(tc.body))))

			if recorder.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, tc.wantStatus, recorder.Body.String())
			}
			if repo.saved != nil {
				t.Fatalf("unsupported action persisted: %+v", repo.saved)
			}
		})
	}
}

func TestSetQuotaPolicyRejectsCrossTenantLegacyField(t *testing.T) {
	repo := &fakeQuotaPolicyRepo{}
	deps := &Dependencies{SystemRepo: &quotaAuditSystemRepo{}, QuotaPolicyRepo: repo}
	recorder := httptest.NewRecorder()
	SetQuotaPolicy(deps).ServeHTTP(recorder, adminCtx(httptest.NewRequest(
		http.MethodPut, "/admin/v1/policies/quota",
		bytes.NewBufferString(`{"tenant_id":"tenant-other","scope_type":"tenant","daily_budget_micros":1}`),
	)))
	if recorder.Code != http.StatusBadRequest || repo.saved != nil {
		t.Fatalf("cross-tenant request accepted: status=%d saved=%+v body=%s", recorder.Code, repo.saved, recorder.Body.String())
	}
}

func TestGetQuotaPolicyReturnsCanonicalMoneyState(t *testing.T) {
	daily := int64(1234567)
	repo := &fakeQuotaPolicyRepo{getByScopeResult: &repository.QuotaPolicy{
		ID: "qpol-money", TenantID: "tenant_default", ScopeType: "tenant",
		DailyBudgetMicros: &daily, MonthlyBudgetBlocked: true, Status: "active",
	}}
	recorder := httptest.NewRecorder()
	GetQuotaPolicy(&Dependencies{QuotaPolicyRepo: repo}).ServeHTTP(
		recorder,
		adminCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/policies/quota?scope_type=tenant", nil)),
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["daily_budget_micros"] != float64(daily) || response["monthly_budget_micros"] != nil ||
		response["monthly_budget_blocked"] != true {
		t.Fatalf("canonical state missing: %#v", response)
	}
}

func int64Pointer(value int64) *int64 { return &value }

func equalOptionalInt64(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

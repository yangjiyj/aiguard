package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
)

type cutoffRejectingAdmission struct{ err error }

func (a cutoffRejectingAdmission) Admit(context.Context, governor.AdmissionRequest) (*governor.AdmissionLease, error) {
	return nil, a.err
}
func (cutoffRejectingAdmission) Heartbeat(context.Context, *governor.AdmissionLease) error {
	return nil
}
func (cutoffRejectingAdmission) Settle(context.Context, *governor.AdmissionLease, int64, int64, bool) error {
	return nil
}
func (cutoffRejectingAdmission) Release(context.Context, *governor.AdmissionLease, int64, int64) error {
	return nil
}

// 五个模型入口在断流拒绝时必须一致：429 + budget_exhausted + 中文提示，并给 request_logs 打上
// billing_outcome=budget_exhausted（控制台据此显示“预算用尽被拒”）。
func TestBudgetCutoffRejectionIsConsistentAcrossFiveEntrypoints(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	for _, entrypoint := range quotaEntrypointCases() {
		t.Run(entrypoint.name, func(t *testing.T) {
			admission := cutoffRejectingAdmission{err: &governor.AdmissionLimitError{
				Metric: "month_cost_micros", Scope: "team", ScopeName: "研发部", Limit: 5_000_000_000, Used: 5_000_000_000,
				BudgetCutoff: true, RequestID: "req-cutoff", ResetAt: shanghaiTime(2026, 11, 1),
			}}
			audit := &MockAuditWriter{}
			h := buildQuotaEntrypointHandler(entrypoint.name, admission, audit, &MockProviderCaller{}, nil)
			request := httptest.NewRequest(http.MethodPost, entrypoint.path, bytes.NewBufferString(entrypoint.body))
			request = request.WithContext(setAuthInfo(request.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			if response.Code != http.StatusTooManyRequests {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var body struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Error.Code != budgetExhaustedCode || !strings.Contains(body.Error.Message, "研发部") || !strings.Contains(body.Error.Message, "11 月 1 日自动恢复") {
				t.Fatalf("body=%s", response.Body.String())
			}
			audit.mu.Lock()
			finalizes := audit.RequestLogFinalizes
			audit.mu.Unlock()
			if len(finalizes) != 1 {
				t.Fatalf("finalizes=%d", len(finalizes))
			}
			if finalizes[0].Status != budgetExhaustedCode || finalizes[0].StatusCode != http.StatusTooManyRequests || finalizes[0].Envelope.BillingOutcome != billingOutcomeBudgetExhausted {
				t.Fatalf("finalize = status %q code %d outcome %q", finalizes[0].Status, finalizes[0].StatusCode, finalizes[0].Envelope.BillingOutcome)
			}
		})
	}
}

// 断流关闭时的限额拒绝保持原有错误码 quota_exceeded，不打 billing_outcome。
func TestLegacyQuotaRejectionKeepsCodeAndDoesNotMarkBudgetOutcome(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	admission := cutoffRejectingAdmission{err: &governor.AdmissionLimitError{Metric: "month_cost_micros", Scope: "tenant", Limit: 1, Used: 1, RequestID: "r"}}
	audit := &MockAuditWriter{}
	h := buildQuotaEntrypointHandler("chat", admission, audit, &MockProviderCaller{}, nil)
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`))
	request = request.WithContext(setAuthInfo(request.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	var body struct {
		Error struct{ Code string } `json:"error"`
	}
	_ = json.Unmarshal(response.Body.Bytes(), &body)
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if response.Code != http.StatusTooManyRequests || body.Error.Code != "quota_exceeded" || len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Envelope.BillingOutcome != "" {
		t.Fatalf("status=%d body=%s finalizes=%+v", response.Code, response.Body.String(), audit.RequestLogFinalizes)
	}
}

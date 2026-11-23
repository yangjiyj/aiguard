package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

type failingQuotaProvider struct{}

func (failingQuotaProvider) GetEnforcementMode(context.Context, governor.ScopeRef) string {
	return "soft"
}
func (failingQuotaProvider) EffectiveQuota(context.Context, governor.ScopeRef) (governor.EffectiveQuotaInput, error) {
	return governor.EffectiveQuotaInput{}, context.DeadlineExceeded
}

type failingSnapshotProvider struct{}

func (failingSnapshotProvider) GetMulti(context.Context, governor.ScopeRef) (map[string]governor.Snapshot, error) {
	return nil, context.DeadlineExceeded
}

// 判定失败（配额读取超时）：断流关闭仍然放行；断流开启返回 503 中文，并给请求打上 budget_unavailable。
func TestGovernorFailureIsFailOpenWhenCutoffOffAndFailClosedWhenOn(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cutoffOn    bool
		wantBlocked bool
	}{{"default", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			decider := governor.New(failingSnapshotProvider{}, failingQuotaProvider{})
			envelope := &modelrouter.RequestEnvelope{RequestID: "req-gov", TenantID: "tenant-a", UserID: "user-a"}
			recorder := httptest.NewRecorder()
			blocked := applyGovernorDecision(context.Background(), recorder, envelope, "req-gov", decider, false, true, nil)
			if blocked != tc.wantBlocked {
				t.Fatalf("blocked=%v want %v (status=%d body=%s)", blocked, tc.wantBlocked, recorder.Code, recorder.Body.String())
			}
			if !tc.wantBlocked {
				if envelope.BillingOutcome != "" || recorder.Code != http.StatusOK {
					t.Fatalf("fail-open must leave the request untouched: outcome=%q status=%d", envelope.BillingOutcome, recorder.Code)
				}
				return
			}
			var body ErrorResponse
			_ = json.Unmarshal(recorder.Body.Bytes(), &body)
			if recorder.Code != http.StatusServiceUnavailable || body.Error.Code != "billing_unavailable" || body.Error.Message != "计费服务暂不可用，请稍后重试" {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if envelope.BillingOutcome != billingOutcomeBudgetUnavailable {
				t.Fatalf("billing outcome = %q", envelope.BillingOutcome)
			}
		})
	}
}

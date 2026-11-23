package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

func TestBillingRuntimeDescriptionUsesExplicitModeSemantics(t *testing.T) {
	cases := map[string]string{
		"prepaid":  "调用前冻结，完成后按实际用量扣款",
		"metering": "调用前冻结，完成后按实际用量扣款",
		"off":      "计费已关闭",
	}
	for mode, want := range cases {
		if got := billingRuntimeDescription(mode); got != want {
			t.Fatalf("billingRuntimeDescription(%q)=%q, want %q", mode, got, want)
		}
	}
}

func TestBillingHTTPErrorMapsCustomerRequestLimitsTo429(t *testing.T) {
	for _, item := range []struct {
		name string
		err  error
		code string
	}{
		{name: "rpm", err: billing.ErrCustomerRPMLimitExceeded, code: "rpm_limit_exceeded"},
		{name: "concurrency", err: billing.ErrCustomerConcurrencyLimitExceeded, code: "concurrency_limit_exceeded"},
	} {
		t.Run(item.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			billingHTTPError(w, errors.Join(errors.New("wrapped"), item.err))
			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want 429", w.Code)
			}
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body.Error.Code != item.code {
				t.Fatalf("error code = %q, want %q", body.Error.Code, item.code)
			}
		})
	}
}

func TestBillingHTTPErrorKeepsUnconfiguredPriceDistinctFromInsufficientBalance(t *testing.T) {
	cases := []struct {
		err     error
		status  int
		code    string
		message string
	}{
		// D6: an unpriced model is refused with a stable, non-retryable code.
		{billing.ErrPriceNotFound, http.StatusForbidden, "model_price_missing", "该模型未配置价格，请联系管理员"},
		// D5: an empty or overdrawn wallet is refused with a top-up hint.
		{billing.ErrInsufficientBalance, http.StatusTooManyRequests, "insufficient_balance", "余额不足，请充值"},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		billingHTTPError(w, tc.err)
		var body struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if w.Code != tc.status || body.Error.Code != tc.code || body.Error.Message != tc.message {
			t.Fatalf("%v -> status=%d code=%q message=%q, want %d %q %q", tc.err, w.Code, body.Error.Code, body.Error.Message, tc.status, tc.code, tc.message)
		}
	}
}

func TestBillingReserveRequestDecodesGatewayUsage(t *testing.T) {
	payload := []byte(`{
		"tenant_id":"tenant-a",
		"user_id":"user-a",
		"request_id":"request-a",
		"model_name":"model-a",
		"usage":{
			"prompt_tokens":101,
			"cached_input_tokens":11,
			"cache_write_input_tokens":7,
			"output_tokens":53,
			"reasoning_tokens":13
		}
	}`)

	var request BillingReserveRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatalf("decode billing reserve request: %v", err)
	}

	usage := request.Usage
	if usage.PromptTokens != 101 || usage.CachedInputTokens != 11 ||
		usage.CacheWriteInputTokens != 7 || usage.OutputTokens != 53 || usage.ReasoningTokens != 13 {
		t.Fatalf("decoded usage = %#v, want gateway snake_case token counts", usage)
	}
}

// 7.6: only an unbounded request (no max_tokens) has its output reservation
// narrowed; a client-supplied bound is never touched.
func TestBillingReserveRequestNarrowsOnlyUnboundedOutput(t *testing.T) {
	bounded := BillingReserveRequest{TenantID: "t", ModelName: "m", Usage: billing.Usage{OutputTokens: 9000}}
	if estimate, err := bounded.applyOutputEstimate(context.Background(), nil); err != nil || estimate != nil || bounded.Usage.OutputTokens != 9000 {
		t.Fatalf("bounded request changed: estimate=%v usage=%+v err=%v", estimate, bounded.Usage, err)
	}
	unbounded := BillingReserveRequest{TenantID: "t", ModelName: "m", Usage: billing.Usage{OutputTokens: 9000}, OutputTokensUnbounded: true}
	estimate, err := unbounded.applyOutputEstimate(context.Background(), nil)
	if err != nil || estimate == nil || *estimate != billing.DefaultOutputTokenCeiling || unbounded.Usage.OutputTokens != billing.DefaultOutputTokenCeiling {
		t.Fatalf("unbounded request: estimate=%v usage=%+v err=%v", estimate, unbounded.Usage, err)
	}
}

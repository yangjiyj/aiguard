package handler

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBillingDefaultMonetaryEnforcementAndUnpricedBypass(t *testing.T) {
	for _, mode := range []string{"metering", "prepaid"} {
		for _, limited := range []bool{false, true} {
			for _, tc := range []struct {
				name, body string
				status     int
				refused    bool
			}{
				{"unpriced", `{"unpriced":true}`, 200, false},
				{"legacy-unpriced", `{"error":{"code":"model_price_missing"}}`, 403, false},
				{"exhausted", `{"error":{"code":"monthly_allowance_exhausted"}}`, 429, true},
				{"outage", `{}`, 503, limited},
			} {
				t.Run(mode+"/"+tc.name+map[bool]string{false: "/unlimited", true: "/limited"}[limited], func(t *testing.T) {
					cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(tc.status)
						_, _ = w.Write([]byte(tc.body))
					}))
					defer cp.Close()
					c := NewBillingClientWithMode(cp.URL, "test-secret", "default", mode)
					c.AllowanceRequired = func(context.Context, string, string) (bool, error) { return limited, nil }
					e := &modelrouter.RequestEnvelope{TenantID: "t", UserID: "u", RequestID: "r", Model: "m"}
					err := c.ReserveUsage(context.Background(), e, BillingUsage{PromptTokens: 1})
					if (err != nil) != tc.refused {
						t.Fatalf("refused=%v want=%v err=%v", err != nil, tc.refused, err)
					}
					if !tc.refused && (tc.name == "unpriced" || tc.name == "legacy-unpriced") && !e.QuotaCostEstimateMissingPrice {
						t.Fatal("unpriced admission must skip monetary dimensions")
					}
				})
			}
		}
	}
}

func TestKnownUnpricedModelBypassesOutageWithExhaustedMonetaryAccount(t *testing.T) {
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer cp.Close()
	for _, mode := range []string{"metering", "prepaid"} {
		for _, priced := range []bool{false, true} {
			c := NewBillingClientWithMode(cp.URL, "test-secret", "default", mode)
			c.AllowanceRequired = func(context.Context, string, string) (bool, error) { return true, nil }
			c.ModelPriceConfigured = func(context.Context, string, string) (bool, error) { return priced, nil }
			e := &modelrouter.RequestEnvelope{TenantID: "t", UserID: "u", Model: "m", RequestID: "r"}
			err := c.ReserveUsage(context.Background(), e, BillingUsage{PromptTokens: 1})
			if (err != nil) != priced {
				t.Fatalf("mode=%s priced=%v err=%v", mode, priced, err)
			}
			if !priced {
				state, ok := c.trackingState("r")
				if !ok || !state.Unpriced || !e.QuotaCostEstimateMissingPrice {
					t.Fatalf("missing unpriced snapshot: %+v", state)
				}
			}
		}
	}
}

func TestIncompleteStreamWithoutMonetaryCapSettlesDeliveredEstimate(t *testing.T) {
	var measured struct {
		Estimated bool         `json:"estimated"`
		Usage     BillingUsage `json:"usage"`
	}
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&measured); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(`{"recorded":true,"billable_amount_micros":100}`))
	}))
	defer cp.Close()
	c := NewBillingClientWithMode(cp.URL, "test-secret", "default", "metering")
	e := &modelrouter.RequestEnvelope{TenantID: "t", UserID: "u", Model: "m", RequestID: "no-cap-stream"}
	c.reserved.Store(e.RequestID, billingTrackingState{Usage: BillingUsage{PromptTokens: 9, OutputTokens: 4096}, PriceID: "priced-quote", Admitted: true, AdmittedAt: time.Now().UTC()})
	outcome := c.Finalize(context.Background(), e, []byte(`{"choices":[{"message":{"content":"hello world"}}],"usage":{"prompt_tokens":0,"completion_tokens":0}}`), "incomplete")
	if outcome != "recorded" || !measured.Estimated || measured.Usage.PromptTokens != 9 || measured.Usage.OutputTokens != estimateTextTokens("hello world") {
		t.Fatalf("outcome=%s estimated=%v usage=%+v", outcome, measured.Estimated, measured.Usage)
	}
}

func TestCompletedStreamWithoutUpstreamUsageSettlesDeliveredEstimate(t *testing.T) {
	accumulator := newLiveStreamAccumulator()
	accumulator.observeEvent(relay.StreamEvent{Type: relay.EventTextDelta, Delta: "hello world"})
	accumulator.observeEvent(relay.StreamEvent{Type: relay.EventMessageEnd, FinishReason: "stop"})
	body, err := accumulator.responseBody("completed-no-usage")
	if err != nil {
		t.Fatal(err)
	}
	if state := canonicalizeResponseUsage(body).State; verifiedUsageState(state) {
		t.Fatalf("synthetic usage was treated as upstream: %s %s", state, body)
	}
	var measured struct {
		Estimated bool         `json:"estimated"`
		Usage     BillingUsage `json:"usage"`
	}
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&measured); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(`{"recorded":true,"billable_amount_micros":100}`))
	}))
	defer cp.Close()
	c := NewBillingClientWithMode(cp.URL, "test-secret", "default", "metering")
	e := &modelrouter.RequestEnvelope{TenantID: "t", UserID: "u", Model: "m", RequestID: "completed-no-usage"}
	c.reserved.Store(e.RequestID, billingTrackingState{Usage: BillingUsage{PromptTokens: 9, OutputTokens: 4096}, PriceID: "priced-quote", Admitted: true, AdmittedAt: time.Now().UTC()})
	if outcome := c.Finalize(context.Background(), e, body, "success"); outcome != "recorded" || !measured.Estimated || measured.Usage.OutputTokens != estimateTextTokens("hello world") {
		t.Fatalf("outcome=%s estimated=%v usage=%+v", outcome, measured.Estimated, measured.Usage)
	}
}

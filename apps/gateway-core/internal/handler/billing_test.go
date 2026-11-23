package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	billingstates "github.com/yangjiyj/aiguard/packages/shared-go/billingstates"
)

func TestNormalizeBillingUsagePreservesCacheAndReasoning(t *testing.T) {
	usage := normalizeBillingUsage([]byte(`{
        "usage": {
          "input_tokens": 100, "output_tokens": 30,
          "cache_read_input_tokens": 25, "cache_creation_input_tokens": 10,
          "output_tokens_details": {"reasoning_tokens": 12}
        }
    }`))
	if usage["prompt_tokens"] != 135 || usage["cached_input_tokens"] != 25 || usage["cache_write_input_tokens"] != 10 || usage["output_tokens"] != 30 || usage["reasoning_tokens"] != 12 {
		t.Fatalf("normalized usage = %#v", usage)
	}
	bounded := normalizeBillingUsage([]byte(`{"usage":{"prompt_tokens":5,"completion_tokens":2,"cache_read_input_tokens":9,"cache_creation_input_tokens":9,"completion_tokens_details":{"reasoning_tokens":9}}}`))
	if bounded["cached_input_tokens"] != 5 || bounded["cache_write_input_tokens"] != 0 || bounded["reasoning_tokens"] != 2 {
		t.Fatalf("bounded usage = %#v", bounded)
	}
}

func TestNormalizeBillingUsageProtocolFamilies(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     map[string]int64
	}{
		{
			name:     "openai chat and aliyun compatible",
			response: `{"usage":{"prompt_tokens":100,"completion_tokens":30,"prompt_tokens_details":{"cached_tokens":25,"cache_creation_input_tokens":10},"completion_tokens_details":{"reasoning_tokens":12}}}`,
			want:     map[string]int64{"prompt_tokens": 100, "cached_input_tokens": 25, "cache_write_input_tokens": 10, "output_tokens": 30, "reasoning_tokens": 12},
		},
		{
			name:     "openai responses",
			response: `{"usage":{"input_tokens":100,"output_tokens":30,"input_tokens_details":{"cached_tokens":25},"output_tokens_details":{"reasoning_tokens":12}}}`,
			want:     map[string]int64{"prompt_tokens": 100, "cached_input_tokens": 25, "cache_write_input_tokens": 0, "output_tokens": 30, "reasoning_tokens": 12},
		},
		{
			name:     "deepseek",
			response: `{"usage":{"prompt_tokens":100,"prompt_cache_hit_tokens":60,"prompt_cache_miss_tokens":40,"completion_tokens":30}}`,
			want:     map[string]int64{"prompt_tokens": 100, "cached_input_tokens": 60, "cache_write_input_tokens": 0, "output_tokens": 30, "reasoning_tokens": 0},
		},
		{
			name:     "deepseek totals from hit and miss fallback",
			response: `{"usage":{"prompt_cache_hit_tokens":60,"prompt_cache_miss_tokens":40,"completion_tokens":30}}`,
			want:     map[string]int64{"prompt_tokens": 100, "cached_input_tokens": 60, "cache_write_input_tokens": 0, "output_tokens": 30, "reasoning_tokens": 0},
		},
		{
			name:     "anthropic",
			response: `{"usage":{"input_tokens":15,"cache_read_input_tokens":60,"cache_creation_input_tokens":25,"output_tokens":30}}`,
			want:     map[string]int64{"prompt_tokens": 100, "cached_input_tokens": 60, "cache_write_input_tokens": 25, "output_tokens": 30, "reasoning_tokens": 0},
		},
		{
			name:     "dashscope top level cached tokens",
			response: `{"usage":{"input_tokens":100,"cached_tokens":25,"output_tokens":30}}`,
			want:     map[string]int64{"prompt_tokens": 100, "cached_input_tokens": 25, "cache_write_input_tokens": 0, "output_tokens": 30, "reasoning_tokens": 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeBillingUsage([]byte(tt.response))
			for key, want := range tt.want {
				if got[key] != want {
					t.Fatalf("%s = %d, want %d; normalized usage = %#v", key, got[key], want, got)
				}
			}
		})
	}
}

func TestBillingClientReservesThenSettles(t *testing.T) {
	var reserveSeen, settleSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(billingInternalTokenHeader) != "internal-secret" {
			t.Errorf("missing internal token")
		}
		switch r.URL.Path {
		case "/internal/v1/billing/reservations":
			reserveSeen = true
			var payload struct {
				Usage BillingUsage `json:"usage"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload.Usage.PromptTokens < 1 || payload.Usage.OutputTokens != 64 {
				t.Fatalf("reservation usage=%#v", payload.Usage)
			}
			_, _ = w.Write([]byte(`{"reserved":true,"price_id":"test-price","admitted_at":"2026-10-03T01:00:00Z"}`))
		case "/internal/v1/billing/settlements":
			settleSeen = true
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := NewBillingClient(server.URL, "internal-secret", "default")
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "user-a", RequestID: "req-a", Model: "model-a"}
	request := &ChatCompletionRequest{MaxCompletionTokens: 64, Messages: []Message{{Role: "user", Content: json.RawMessage(`"你好"`)}}}
	if err := client.Reserve(context.Background(), envelope, request); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	client.Finalize(context.Background(), envelope, []byte(`{"usage":{"prompt_tokens":2,"completion_tokens":3}}`), "success")
	if !reserveSeen || !settleSeen {
		t.Fatalf("reserve=%v settle=%v", reserveSeen, settleSeen)
	}
}

func TestBillingUsageEvidenceMarksFallbackSource(t *testing.T) {
	var evidence map[string]any
	if err := json.Unmarshal(billingUsageEvidence(nil, "estimated_reservation"), &evidence); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	if evidence["usage_source"] != "estimated_reservation" || evidence["upstream_usage_available"] != false {
		t.Fatalf("fallback evidence=%#v", evidence)
	}
	if err := json.Unmarshal(billingUsageEvidence([]byte(`{"usage":{"prompt_tokens":1},"choices":[{"message":{"content":"customer secret"}}]}`), "upstream"), &evidence); err != nil {
		t.Fatalf("decode upstream evidence: %v", err)
	}
	usage, usageOK := evidence["upstream_usage"].(map[string]any)
	if evidence["usage_source"] != "upstream" || !usageOK || usage["prompt_tokens"] != float64(1) {
		t.Fatalf("upstream evidence=%#v", evidence)
	}
	if encoded, _ := json.Marshal(evidence); bytes.Contains(encoded, []byte("customer secret")) || bytes.Contains(encoded, []byte("choices")) {
		t.Fatalf("billing evidence copied customer response content: %s", encoded)
	}
}

// A prepaid request that fails without usable usage evidence must NOT settle,
// and it must NOT release either: "failed" is not a definitive non-dispatch, so
// the only honest outcome is pending with the wallet freeze intact.
//
// This test previously asserted the opposite — that such a request releases —
// which is precisely the fund-safety hole the shared terminal table was
// corrected for: releasing on missing evidence refunds money the request may
// well have spent upstream, and the row then looks resolved to every later
// reader. The legitimate half of the original intent is kept below: a settle
// is never fabricated out of absent usage.
func TestBillingClientPrepaidHoldsFreezeWhenUsageIsUnavailable(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/internal/v1/billing/reservations":
			_, _ = w.Write([]byte(`{"reserved":true,"price_id":"test-price","admitted_at":"2026-10-03T01:00:00Z"}`))
		case "/internal/v1/billing/releases":
			_, _ = w.Write([]byte(`{}`))
		case "/internal/v1/billing/settlements":
			_, _ = w.Write([]byte(`{"amount_micros":1}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewBillingClient(server.URL, "internal-secret", "default")
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "user-a", RequestID: "req-no-usage", Model: "model-a"}
	if err := client.Reserve(context.Background(), envelope, &ChatCompletionRequest{MaxTokens: 1}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	outcome := client.Finalize(context.Background(), envelope, nil, "failed")
	if outcome != "pending" {
		t.Fatalf("outcome=%q want pending: a non-dispatch is unproven", outcome)
	}
	if envelope.BillingOutcome != "pending" {
		t.Fatalf("envelope.BillingOutcome=%q want pending so reconciliation finds the row",
			envelope.BillingOutcome)
	}
	if envelope.QuotaActualCostAvailable {
		t.Fatal("no usage evidence must not be turned into an actual cost")
	}
	for _, path := range paths {
		if path == "/internal/v1/billing/releases" {
			t.Fatalf("pending must not release the freeze, got calls %v", paths)
		}
		if path == "/internal/v1/billing/settlements" {
			t.Fatalf("pending must not settle without usage evidence, got calls %v", paths)
		}
	}
}

func TestBillingClientMeteringQuotesWithoutReservingAndReportsFailedMeasurement(t *testing.T) {
	var path string
	var payload struct {
		TenantID      string       `json:"tenant_id"`
		UserID        string       `json:"user_id"`
		ModelName     string       `json:"model_name"`
		RequestStatus string       `json:"request_status"`
		Usage         BillingUsage `json:"usage"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if r.URL.Path == "/internal/v1/billing/quotes" {
			_, _ = w.Write([]byte(`{"billable_amount_micros":25}`))
			return
		}
		_, _ = w.Write([]byte(`{"recorded":true,"billable_amount_micros":null}`))
	}))
	defer server.Close()

	client := NewBillingClientWithMode(server.URL, "internal-secret", "", "metering")
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "user-a", RequestID: "req-metering", Model: "model-a"}
	if err := client.ReserveUsage(context.Background(), envelope, BillingUsage{PromptTokens: 12, OutputTokens: 4}); err != nil {
		t.Fatalf("metering reserve blocked request: %v", err)
	}
	if path != "/internal/v1/billing/quotes" || !envelope.QuotaCostEstimateAvailable || envelope.QuotaEstimatedCostMicros != 25 {
		t.Fatalf("metering quote path=%q envelope=%+v", path, envelope)
	}
	client.Finalize(context.Background(), envelope, nil, "failed")
	if path != "/internal/v1/billing/measurements" || payload.TenantID != "tenant-a" || payload.UserID != "user-a" ||
		payload.ModelName != "model-a" || payload.RequestStatus != "failed" || payload.Usage.PromptTokens != 0 || payload.Usage.OutputTokens != 0 {
		t.Fatalf("measurement path=%q payload=%+v", path, payload)
	}
}

type billingOutcomeAuditWriter struct {
	MockAuditWriter
	outcome string
}

func (w *billingOutcomeAuditWriter) MarkBillingOutcome(_ context.Context, _ *modelrouter.RequestEnvelope, outcome string) {
	w.outcome = outcome
}

func TestBillingAuditWriterUsesAdmissionEstimateForAuditButNotSettlement(t *testing.T) {
	var settlementUsage BillingUsage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/v1/billing/reservations" {
			_, _ = w.Write([]byte(`{"reserved":true,"price_id":"test-price","admitted_at":"2026-10-03T01:00:00Z"}`))
			return
		}
		if r.URL.Path != "/internal/v1/billing/settlements" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var payload struct {
			Usage map[string]int64 `json:"usage"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		settlementUsage.PromptTokens = payload.Usage["prompt_tokens"]
		settlementUsage.OutputTokens = payload.Usage["output_tokens"]
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := NewBillingClient(server.URL, "internal-secret", "default")
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "user-a", RequestID: "req-estimated-audit", Model: "model-a"}
	if err := client.ReserveUsage(context.Background(), envelope, BillingUsage{PromptTokens: 12, OutputTokens: 4}); err != nil {
		t.Fatal(err)
	}
	inner := &billingOutcomeAuditWriter{}
	wrapper := NewBillingAuditWriter(inner, client)
	wrapper.FinalizeRequestLog(context.Background(), envelope, []byte(`{"id":"chatcmpl-no-usage"}`), "success", http.StatusOK, 10, nil)
	if len(inner.RequestLogFinalizes) != 1 {
		t.Fatalf("finalize calls=%d", len(inner.RequestLogFinalizes))
	}
	var audited struct {
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(inner.RequestLogFinalizes[0].RespBody, &audited); err != nil {
		t.Fatal(err)
	}
	if audited.Usage.PromptTokens != 12 || audited.Usage.CompletionTokens != 4 {
		t.Fatalf("audit usage=%+v, want admission estimate", audited.Usage)
	}
	if settlementUsage.PromptTokens != 12 || settlementUsage.OutputTokens != 4 {
		t.Fatalf("settlement usage=%+v, want original-response fallback", settlementUsage)
	}
	if inner.outcome != "settled" {
		t.Fatalf("billing outcome=%q, want settled", inner.outcome)
	}
}

// synthetic_no_upstream is a metering-only marker: the provider was never
// reached, so it must never be treated as verified provider usage. The shared
// Decide gate refuses to settle on it for every settle-family status.
func TestDecideRefusesSyntheticNoUpstreamAsVerifiedUsage(t *testing.T) {
	for _, status := range []string{"success", "incomplete", "client_canceled", "stream_aborted", "provider_timeout"} {
		if got := billingstates.Decide(status, billingstates.Evidence{
			UsageRecorded: true, UsageSource: "synthetic_no_upstream",
		}); got != billingstates.TerminalPending {
			t.Fatalf("Decide(%q, synthetic_no_upstream)=%q want pending", status, got)
		}
	}
	// The two verified provider sources still settle, and only those two.
	for _, source := range []string{"upstream", "upstream_total_adjusted"} {
		if got := billingstates.Decide("success", billingstates.Evidence{
			UsageRecorded: true, PromptTokens: 3, OutputTokens: 2, UsageSource: source,
		}); got != billingstates.TerminalSettle {
			t.Fatalf("Decide(success, %s)=%q want settle", source, got)
		}
	}
}

// usageSourceFromAuditArgs extracts the usage_source that RealAuditWriter would
// persist into request_logs.output_audit_result.response_metadata, read back
// out of the real INSERT arguments rather than from the envelope. Asserting on
// the envelope would pass even if the row lost the marker on the way to the DB,
// which is exactly the break this covers.
func usageSourceFromAuditArgs(t *testing.T, queries []string, args [][]interface{}) string {
	t.Helper()
	for i, query := range queries {
		if !strings.Contains(query, "INSERT INTO request_logs") {
			continue
		}
		row := args[i]
		// Locate output_audit_result by scanning the VALUES-free column list.
		cols := requestLogInsertColumns(query)
		idx := indexOf(cols, "output_audit_result")
		if idx < 0 || idx >= len(row) {
			continue
		}
		raw, ok := row[idx].([]byte)
		if !ok || len(raw) == 0 {
			// A nil or empty arg means no audit blob was written at all, which
			// is the honest representation of "no usage_source to record".
			return ""
		}
		var audit struct {
			ResponseMetadata struct {
				UsageSource string `json:"usage_source"`
			} `json:"response_metadata"`
		}
		if err := json.Unmarshal(raw, &audit); err != nil {
			t.Fatalf("decode output_audit_result %s: %v", raw, err)
		}
		return audit.ResponseMetadata.UsageSource
	}
	return ""
}

// requestLogInsertColumns extracts the column names of the request_logs INSERT
// so the test can index positionally against the real args.
func requestLogInsertColumns(query string) []string {
	open := strings.Index(query, "INSERT INTO request_logs")
	if open < 0 {
		return nil
	}
	rest := query[open:]
	lp := strings.Index(rest, "(")
	rp := strings.Index(rest, ")")
	if lp < 0 || rp < 0 || rp < lp {
		return nil
	}
	var cols []string
	for _, part := range strings.Split(rest[lp+1:rp], ",") {
		cols = append(cols, strings.TrimSpace(part))
	}
	return cols
}

func indexOf(items []string, want string) int {
	for i, item := range items {
		if item == want {
			return i
		}
	}
	return -1
}

// Billing and quota are independent feature switches, so usage_source must be
// persisted for a billing-only deployment. It used to be derived solely under
// e.QuotaAdmissionManaged, which left request_logs with no usage_source at all
// when the quota governor was off — and control-plane reconciliation reads that
// field, so none of those requests could ever be settled.
func TestBillingUsageSourcePersistedWithoutQuotaAdmission(t *testing.T) {
	cases := []struct {
		name       string
		mode       string
		status     string
		body       string
		admitted   bool
		wantSource string
	}{
		{
			name: "prepaid verified usage without quota", mode: "prepaid", status: "success",
			body:     `{"usage":{"prompt_tokens":2,"completion_tokens":3}}`,
			admitted: true, wantSource: "upstream",
		},
		{
			name: "prepaid total adjusted without quota", mode: "prepaid", status: "success",
			body:     `{"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":9}}`,
			admitted: true, wantSource: "upstream_total_adjusted",
		},
		{
			name: "prepaid estimated without quota", mode: "prepaid", status: "success",
			body:     `{"id":"no-usage"}`,
			admitted: true, wantSource: "estimated_reservation",
		},
		{
			name: "prepaid estimated incomplete without quota", mode: "prepaid", status: "client_canceled",
			body:     `{"id":"no-usage"}`,
			admitted: true, wantSource: "estimated_incomplete",
		},
		{
			name: "prepaid invalid usage without quota", mode: "prepaid", status: "success",
			body:     `{"usage":{"prompt_tokens":-5}}`,
			admitted: true, wantSource: "estimated_reservation_invalid_usage",
		},
		{
			name: "prepaid invalid incomplete without quota", mode: "prepaid", status: "stream_aborted",
			body:     `{"usage":{"prompt_tokens":-5}}`,
			admitted: true, wantSource: "estimated_incomplete_invalid_usage",
		},
		{
			// No admission: the marker must be the explicit unknown sentinel, NOT
			// the empty string. An empty usage_source is how a pre-942 row is
			// represented, and reconciliation would settle it as a legacy success
			// recovery — charging a request that never had an admission snapshot.
			name: "unadmitted estimate is explicit unknown", mode: "prepaid", status: "success",
			body: `{"id":"no-usage"}`, admitted: false, wantSource: "unknown_no_admission_evidence",
		},
		{
			name: "metering error retains admission estimate", mode: "metering", status: "error",
			body:     `{"id":"no-upstream"}`,
			admitted: true, wantSource: "estimated_reservation",
		},
		{
			name: "metering success is upstream", mode: "metering", status: "success",
			body:     `{"usage":{"prompt_tokens":1,"completion_tokens":1}}`,
			admitted: true, wantSource: "upstream",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var paths []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				switch r.URL.Path {
				case "/internal/v1/billing/reservations", "/internal/v1/billing/quotes":
					_, _ = w.Write([]byte(`{"reserved":true,"billable_amount_micros":10,"estimated_output_tokens":4}`))
				case "/internal/v1/billing/settlements":
					_, _ = w.Write([]byte(`{"amount_micros":10}`))
				default:
					_, _ = w.Write([]byte(`{}`))
				}
			}))
			defer server.Close()

			client := NewBillingClientWithMode(server.URL, "internal-secret", "default", tc.mode)
			envelope := &modelrouter.RequestEnvelope{
				TenantID: "tenant-a", UserID: "user-a",
				RequestID: "req-src-" + tc.name, Model: "model-a",
				// QuotaAdmissionManaged is deliberately FALSE: this is the
				// billing-only deployment that used to lose the marker.
				QuotaAdmissionManaged: false,
			}
			// Seed the real tracking state the derivation reads.
			client.reserved.Store(envelope.RequestID, billingTrackingState{
				Usage: BillingUsage{PromptTokens: 12, OutputTokens: 4}, Admitted: tc.admitted, PriceID: "test-price", AdmittedAt: time.Now().UTC(),
			})

			db := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
			inner := &RealAuditWriter{db: db}
			NewBillingAuditWriter(inner, client).FinalizeRequestLog(
				context.Background(), envelope, []byte(tc.body), tc.status, http.StatusOK, 1, nil,
			)

			got := usageSourceFromAuditArgs(t, db.queries, db.args)
			if got != tc.wantSource {
				t.Fatalf("persisted usage_source=%q want %q (billing-only path)", got, tc.wantSource)
			}
			// The envelope and the persisted row must agree, or the log lies
			// about how the charge was derived.
			if got != "" && envelope.BillingUsageSource != got {
				t.Fatalf("envelope source %q != persisted %q", envelope.BillingUsageSource, got)
			}
		})
	}
}

// The marker must be written even when the finalize decision is PENDING and no
// control-plane call is made at all. That is the case where the wallet stays
// frozen and reconciliation has to pick the row up later from durable evidence
// — exactly when a missing usage_source would strand it forever.
func TestBillingUsageSourcePersistedOnPendingWithoutControlPlaneCall(t *testing.T) {
	// A server that fails every call: pending must not contact it, and the log
	// row must still carry the source.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("pending must not call the control plane, got %s", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewBillingClientWithMode(server.URL, "internal-secret", "default", "prepaid")
	envelope := &modelrouter.RequestEnvelope{
		TenantID: "tenant-a", UserID: "user-a", RequestID: "req-pending-src", Model: "model-a",
	}
	// No admitted estimate and a generic failure status: pending.
	client.reserved.Store(envelope.RequestID, billingTrackingState{
		Usage: BillingUsage{PromptTokens: 5, OutputTokens: 2}, Admitted: false,
	})
	db := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	NewBillingAuditWriter(&RealAuditWriter{db: db}, client).FinalizeRequestLog(
		context.Background(), envelope, []byte(`{"id":"no-usage"}`), "provider_result_unknown", http.StatusOK, 1, nil,
	)
	if envelope.BillingOutcome != "pending" {
		t.Fatalf("outcome=%q want pending", envelope.BillingOutcome)
	}
	// No admission means no estimated marker may be claimed. The row carries the
	// explicit unknown sentinel rather than an empty marker, because empty means
	// "pre-942 legacy row" to reconciliation and would earn a compatibility
	// settle for a request that never had an admission.
	if got := usageSourceFromAuditArgs(t, db.queries, db.args); got != "unknown_no_admission_evidence" {
		t.Fatalf("usage_source=%q want the unknown sentinel for an unadmitted pending request", got)
	}

	// With an admission granted the same pending-by-status row carries the
	// estimated marker, so reconciliation can still attribute it.
	admittedEnvelope := &modelrouter.RequestEnvelope{
		TenantID: "tenant-a", UserID: "user-a", RequestID: "req-pending-src-2", Model: "model-a",
	}
	client.reserved.Store(admittedEnvelope.RequestID, billingTrackingState{
		Usage: BillingUsage{PromptTokens: 5, OutputTokens: 2}, Admitted: true, PriceID: "test-price", AdmittedAt: time.Now().UTC(),
	})
	db2 := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	NewBillingAuditWriter(&RealAuditWriter{db: db2}, client).FinalizeRequestLog(
		context.Background(), admittedEnvelope, []byte(`{"id":"no-usage"}`), "provider_result_unknown", http.StatusOK, 1, nil,
	)
	if got := usageSourceFromAuditArgs(t, db2.queries, db2.args); got != "estimated_reservation" {
		t.Fatalf("usage_source=%q want estimated_reservation for an admitted pending request", got)
	}
}

// Quota-only accounting must be unchanged: with no billing marker the quota
// marker is still persisted, so a deployment that runs quota without billing
// keeps its existing behaviour.
func TestQuotaUsageSourceStillPersistedWithoutBilling(t *testing.T) {
	envelope := &modelrouter.RequestEnvelope{
		TenantID: "tenant-a", UserID: "user-a", RequestID: "req-quota-only", Model: "model-a",
		QuotaAdmissionManaged: true,
		QuotaUsageSource:      "estimated_reservation",
		QuotaEstimatedTokens:  16,
		QuotaFinalize:         func(context.Context, int64, int64, bool, bool) error { return nil },
	}
	db := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	(&RealAuditWriter{db: db}).FinalizeRequestLog(
		context.Background(), envelope, []byte(`{"id":"no-usage"}`), "success", http.StatusOK, 1, nil,
	)
	if got := usageSourceFromAuditArgs(t, db.queries, db.args); got != "estimated_reservation" {
		t.Fatalf("quota-only usage_source=%q want estimated_reservation", got)
	}
}

// The estimated_* sources are honored only when the admission snapshot was
// really granted. HasApprovedEstimate reflects the admission response, not a
// hardcoded true.
//
// Without admission the decision is PENDING, and pending must leave the wallet
// alone: Finalize must not post to /settlements (no unadmitted estimate may be
// charged) and must not post to /releases either (pending means "evidence
// insufficient", NOT "provably never dispatched"). The test asserts the HTTP
// behavior directly — zero requests reach the control plane — because the
// damage from getting this wrong is a silent refund, which no assertion on the
// returned string alone would catch.
//
// A granted admission settles the very same source, so the gate is the evidence
// and not the source name.
func TestFinalizeHoldsEstimatedSettlePendingWithoutAdmission(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/internal/v1/billing/settlements":
			_, _ = w.Write([]byte(`{"amount_micros":40}`))
		case "/internal/v1/billing/releases":
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewBillingClient(server.URL, "internal-secret", "default")
	unadmitted := &modelrouter.RequestEnvelope{
		TenantID: "tenant-a", UserID: "user-a", RequestID: "req-no-admission", Model: "model-a",
	}
	// A tracking snapshot without a priced admission: the estimate in it was
	// never approved by the control plane.
	client.reserved.Store(unadmitted.RequestID, billingTrackingState{
		Usage: BillingUsage{PromptTokens: 12, OutputTokens: 4}, Admitted: false,
	})
	outcome := client.Finalize(context.Background(), unadmitted, []byte(`{"id":"no-usage"}`), "success")
	if outcome != "pending" {
		t.Fatalf("outcome=%q want pending (no admission evidence)", outcome)
	}
	if unadmitted.BillingOutcome != "pending" {
		t.Fatalf("envelope.BillingOutcome=%q want pending so reconciliation can find the row",
			unadmitted.BillingOutcome)
	}
	if len(paths) != 0 {
		t.Fatalf("pending must not contact the control plane, got %v", paths)
	}
	// The freeze must survive: no cost is booked either way.
	if unadmitted.QuotaActualCostAvailable {
		t.Fatal("pending must not book an actual cost")
	}

	// With the admission actually granted, the same source settles.
	admitted := &modelrouter.RequestEnvelope{
		TenantID: "tenant-a", UserID: "user-a", RequestID: "req-admitted", Model: "model-a",
	}
	client.reserved.Store(admitted.RequestID, billingTrackingState{
		Usage: BillingUsage{PromptTokens: 12, OutputTokens: 4}, Admitted: true, PriceID: "test-price", AdmittedAt: time.Now().UTC(),
	})
	if outcome := client.Finalize(context.Background(), admitted, []byte(`{"id":"no-usage"}`), "success"); outcome != "settled" {
		t.Fatalf("outcome=%q want settled (admission granted)", outcome)
	}
	if len(paths) != 1 || paths[0] != "/internal/v1/billing/settlements" {
		t.Fatalf("paths=%v want exactly one settlements call", paths)
	}
}

// The three terminal kinds must stay distinct all the way through Finalize.
// Only a definitive non-dispatch may refund; generic failures and unknown
// statuses do not prove the request never reached a provider, so they hold the
// freeze instead of releasing it.
func TestFinalizeReleasesOnlyDefinitiveNonDispatch(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	client := NewBillingClient(server.URL, "internal-secret", "default")

	cases := []struct {
		status  string
		want    string
		release bool
	}{
		// Definitive non-dispatch: provably never sent upstream.
		{status: "provider_unavailable", want: "released", release: true},
		{status: "model_route_unavailable", want: "released", release: true},
		{status: "security_blocked", want: "released", release: true},
		// Generic failures may happen AFTER dispatch: hold the freeze.
		{status: "error", want: "released", release: true},
		{status: "provider_error", want: "released", release: true},
		{status: "some_future_status", want: "pending", release: false},
		{status: "", want: "pending", release: false},
		{status: "received", want: "pending", release: false},
	}
	for i, tc := range cases {
		paths = nil
		requestID := "req-terminal-" + tc.status + "-" + string(rune('a'+i))
		envelope := &modelrouter.RequestEnvelope{
			TenantID: "tenant-a", UserID: "user-a", RequestID: requestID, Model: "model-a",
		}
		client.reserved.Store(requestID, billingTrackingState{
			Usage: BillingUsage{PromptTokens: 3, OutputTokens: 2}, Admitted: true, PriceID: "test-price", AdmittedAt: time.Now().UTC(),
		})
		outcome := client.Finalize(context.Background(), envelope, nil, tc.status)
		if outcome != tc.want {
			t.Fatalf("status=%q outcome=%q want %q", tc.status, outcome, tc.want)
		}
		wantCalls := 1
		if !tc.release {
			wantCalls = 0
		}
		if len(paths) != wantCalls {
			t.Fatalf("status=%q paths=%v want %d call(s)", tc.status, paths, wantCalls)
		}
		if tc.release && paths[0] != "/internal/v1/billing/releases" {
			t.Fatalf("status=%q path=%q want the releases endpoint", tc.status, paths[0])
		}
	}
}

func TestBillingAuditWriterPassesEstimatedUsageToQuotaFinalizer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/billing/reservations":
			_, _ = w.Write([]byte(`{"reserved":true,"reserved_micros":100,"price_id":"test-price","admitted_at":"2026-10-03T01:00:00Z"}`))
		case "/internal/v1/billing/settlements":
			_, _ = w.Write([]byte(`{"amount_micros":40}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewBillingClient(server.URL, "internal-secret", "default")
	var finalizedTokens, finalizedCost int64
	var finalizedCostActual bool
	envelope := &modelrouter.RequestEnvelope{
		TenantID: "tenant-a", UserID: "user-a", ProjectID: "project-a", RequestID: "req-quota-estimate", Model: "model-a",
		QuotaAdmissionManaged: true, QuotaEstimatedTokens: 16,
		QuotaFinalize: func(_ context.Context, actualTokens, actualCost int64, costActual, success bool) error {
			if !success {
				t.Fatal("successful billing wrapper response released quota lease")
			}
			finalizedTokens, finalizedCost, finalizedCostActual = actualTokens, actualCost, costActual
			return nil
		},
	}
	if err := client.ReserveUsage(context.Background(), envelope, BillingUsage{PromptTokens: 12, OutputTokens: 4}); err != nil {
		t.Fatal(err)
	}
	if !envelope.QuotaCostEstimateAvailable || envelope.QuotaEstimatedCostMicros != 100 {
		t.Fatalf("reservation did not expose billable estimate: %+v", envelope)
	}
	inner := &RealAuditWriter{db: &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}}
	NewBillingAuditWriter(inner, client).FinalizeRequestLog(context.Background(), envelope, []byte(`{"id":"no-usage"}`), "success", http.StatusOK, 1, nil)
	if finalizedTokens != 16 || finalizedCost != 40 || !finalizedCostActual || envelope.QuotaUsageSource != "estimated_reservation" {
		t.Fatalf("quota tokens=%d cost=%d actual=%v source=%q", finalizedTokens, finalizedCost, finalizedCostActual, envelope.QuotaUsageSource)
	}
}

func TestBillingAuditWriterPassesMeteringAmountToQuotaFinalizer(t *testing.T) {
	var measurementRaw json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/billing/quotes":
			_, _ = w.Write([]byte(`{"billable_amount_micros":100}`))
		case "/internal/v1/billing/measurements":
			var payload struct {
				RawUsage json.RawMessage `json:"raw_usage"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			measurementRaw = append(json.RawMessage(nil), payload.RawUsage...)
			_, _ = w.Write([]byte(`{"recorded":true,"billable_amount_micros":40}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewBillingClientWithMode(server.URL, "internal-secret", "", "metering")
	var finalizedTokens, finalizedCost int64
	var finalizedCostActual bool
	envelope := &modelrouter.RequestEnvelope{
		TenantID: "tenant-a", UserID: "user-a", ProjectID: "project-a", RequestID: "req-metering-quota", Model: "model-a",
		QuotaAdmissionManaged: true, QuotaEstimatedTokens: 16,
		QuotaFinalize: func(_ context.Context, actualTokens, actualCost int64, costActual, success bool) error {
			if !success {
				t.Fatal("successful metering response released quota lease")
			}
			finalizedTokens, finalizedCost, finalizedCostActual = actualTokens, actualCost, costActual
			return nil
		},
	}
	if err := client.ReserveUsage(context.Background(), envelope, BillingUsage{PromptTokens: 12, OutputTokens: 4}); err != nil {
		t.Fatal(err)
	}
	inner := &RealAuditWriter{db: &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}}
	response := []byte(`{"usage":{"prompt_tokens":7,"completion_tokens":3},"choices":[{"message":{"content":"customer response body"}}]}`)
	NewBillingAuditWriter(inner, client).FinalizeRequestLog(context.Background(), envelope, response, "success", http.StatusOK, 1, nil)
	if finalizedTokens != 10 || finalizedCost != 40 || !finalizedCostActual {
		t.Fatalf("quota tokens=%d cost=%d actual=%v", finalizedTokens, finalizedCost, finalizedCostActual)
	}
	if bytes.Contains(measurementRaw, []byte("customer response body")) || bytes.Contains(measurementRaw, []byte("choices")) {
		t.Fatalf("measurement raw_usage copied customer response body: %s", measurementRaw)
	}
}

func TestBillingFinalizeFailureUsesExplicitQuotaCostQuality(t *testing.T) {
	tests := []struct {
		name         string
		mode         string
		wantCost     int64
		wantEstimate bool
	}{
		{name: "estimated", mode: "prepaid", wantCost: 100, wantEstimate: true},
		{name: "unpriced", mode: "metering"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/internal/v1/billing/reservations":
					_, _ = w.Write([]byte(`{"reserved":true,"reserved_micros":100,"price_id":"test-price","admitted_at":"2026-10-03T01:00:00Z"}`))
				case "/internal/v1/billing/quotes":
					w.WriteHeader(http.StatusServiceUnavailable)
				default:
					w.WriteHeader(http.StatusServiceUnavailable)
				}
			}))
			defer server.Close()

			client := NewBillingClientWithMode(server.URL, "internal-secret", "", tc.mode)
			envelope := &modelrouter.RequestEnvelope{
				TenantID: "tenant-a", UserID: "user-a", RequestID: "req-" + tc.name, Model: "model-a",
				QuotaAdmissionManaged: true, QuotaEstimatedTokens: 16,
			}
			var gotCost int64
			var gotActual, gotSuccess bool
			envelope.QuotaFinalize = func(_ context.Context, _ int64, cost int64, actual, success bool) error {
				gotCost, gotActual, gotSuccess = cost, actual, success
				return nil
			}
			if err := client.ReserveUsage(context.Background(), envelope, BillingUsage{PromptTokens: 12, OutputTokens: 4}); err != nil {
				t.Fatal(err)
			}
			if envelope.QuotaCostEstimateAvailable != tc.wantEstimate {
				t.Fatalf("estimate available=%v, want %v", envelope.QuotaCostEstimateAvailable, tc.wantEstimate)
			}
			inner := &RealAuditWriter{db: &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}}
			NewBillingAuditWriter(inner, client).FinalizeRequestLog(context.Background(), envelope, nil, "success", http.StatusOK, 1, nil)
			if gotCost != tc.wantCost || gotActual || !gotSuccess {
				t.Fatalf("quota cost=%d actual=%v success=%v", gotCost, gotActual, gotSuccess)
			}
		})
	}
}

func TestVerifiedResponseUsageTokensAcceptsExplicitZero(t *testing.T) {
	prompt, completion, ok := verifiedResponseUsageTokens([]byte(`{"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}`))
	if !ok || prompt != 0 || completion != 0 {
		t.Fatalf("explicit zero usage prompt=%d completion=%d present=%v", prompt, completion, ok)
	}
	if _, _, ok := verifiedResponseUsageTokens([]byte(`{"usage":{}}`)); ok {
		t.Fatal("empty usage object must not be treated as verified zero")
	}
	if _, _, ok := verifiedResponseUsageTokens([]byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":3}}`)); ok {
		t.Fatal("conflicting total must not be treated as verified upstream usage")
	}
	if prompt, completion, ok := verifiedResponseUsageTokens([]byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":30}}`)); !ok || prompt+completion != 30 {
		t.Fatalf("inflated total was undercounted: prompt=%d completion=%d present=%v", prompt, completion, ok)
	}
	if _, _, ok := verifiedResponseUsageTokens([]byte(`{"usage":{"prompt_tokens":-1,"completion_tokens":0,"total_tokens":0}}`)); ok {
		t.Fatal("negative usage must not be treated as verified upstream usage")
	}
	if _, _, ok := verifiedResponseUsageTokens([]byte(`{"usage":{"prompt_tokens":9223372036854775807,"completion_tokens":1}}`)); ok {
		t.Fatal("overflowing usage components must not be trusted")
	}
}

func TestCanonicalUsageUsesConservativeAliasMaximums(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantPrompt int64
		wantOutput int64
		wantState  string
	}{
		{
			name:       "prompt input conflict",
			body:       `{"usage":{"prompt_tokens":10,"input_tokens":100,"completion_tokens":2}}`,
			wantPrompt: 100, wantOutput: 2, wantState: "upstream",
		},
		{
			name:       "completion output conflict",
			body:       `{"usage":{"prompt_tokens":10,"completion_tokens":3,"output_tokens":30}}`,
			wantPrompt: 10, wantOutput: 30, wantState: "upstream",
		},
		{
			name:       "anthropic candidate beats prompt alias",
			body:       `{"usage":{"prompt_tokens":20,"input_tokens":15,"cache_read_input_tokens":60,"cache_creation_input_tokens":25,"output_tokens":30}}`,
			wantPrompt: 100, wantOutput: 30, wantState: "upstream",
		},
		{
			name:       "total remains final lower bound",
			body:       `{"usage":{"prompt_tokens":10,"input_tokens":100,"completion_tokens":2,"output_tokens":30,"total_tokens":150}}`,
			wantPrompt: 120, wantOutput: 30, wantState: "upstream_total_adjusted",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prompt, output, state := responseUsageTokenState([]byte(tc.body))
			billing := normalizeBillingUsage([]byte(tc.body))
			if prompt != tc.wantPrompt || output != tc.wantOutput || state != tc.wantState {
				t.Fatalf("canonical prompt=%d output=%d state=%q", prompt, output, state)
			}
			if billing["prompt_tokens"] != prompt || billing["output_tokens"] != output {
				t.Fatalf("billing diverged from quota/audit canonical usage: %#v", billing)
			}
		})
	}
}

func TestCanonicalUsageRejectsValuesOutsideExactAccountingRange(t *testing.T) {
	_, _, state := responseUsageTokenState([]byte(`{"usage":{"prompt_tokens":9007199254740992,"completion_tokens":1}}`))
	if state != "invalid" {
		t.Fatalf("usage state=%q, want invalid for an inexact Redis/JSON integer", state)
	}
}

func TestBillingAuditWriterSettlesPartialLiveStreamUsage(t *testing.T) {
	var settlementUsage BillingUsage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/billing/reservations":
			_, _ = w.Write([]byte("{\"reserved\":true}"))
		case "/internal/v1/billing/settlements":
			var payload struct {
				Usage map[string]int64 `json:"usage"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			settlementUsage.PromptTokens = payload.Usage["prompt_tokens"]
			settlementUsage.CachedInputTokens = payload.Usage["cached_input_tokens"]
			settlementUsage.CacheWriteTokens = payload.Usage["cache_write_input_tokens"]
			settlementUsage.OutputTokens = payload.Usage["output_tokens"]
			_, _ = w.Write([]byte("{}"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewBillingClient(server.URL, "internal-secret", "default")
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "user-a", RequestID: "req-live-billing", Model: "model-a"}
	if err := client.ReserveUsage(context.Background(), envelope, BillingUsage{PromptTokens: 200, OutputTokens: 100}); err != nil {
		t.Fatal(err)
	}
	inner := &MockAuditWriter{}
	wrapper := NewBillingAuditWriter(inner, client)
	wrapper.FinalizeRequestLog(context.Background(), envelope,
		[]byte("{\"usage\":{\"prompt_tokens\":100,\"prompt_cache_hit_tokens\":60,\"prompt_cache_miss_tokens\":40,\"completion_tokens\":30}}"),
		"client_canceled", http.StatusRequestTimeout, 1, nil)
	if settlementUsage.PromptTokens != 100 || settlementUsage.CachedInputTokens != 60 ||
		settlementUsage.OutputTokens != 30 {
		t.Fatalf("partial live settlement usage=%#v", settlementUsage)
	}
}

// 7.6: CJK text must not be reserved at its UTF-8 byte length (3 tokens per
// character); the estimate stays above the rune count as a safety margin.
func TestEstimateChatPromptTokensDoesNotBillCJKAtByteLength(t *testing.T) {
	text := strings.Repeat("你好", 500)
	request := &ChatCompletionRequest{Messages: []Message{{Role: "user", Content: json.RawMessage(strconv.Quote(text))}}}
	estimate := estimateChatPromptTokens(request)
	runes := int64(utf8.RuneCountInString(text))
	if estimate < runes || estimate >= int64(len(text)) {
		t.Fatalf("CJK estimate=%d want within [%d, %d)", estimate, runes, len(text))
	}
	ascii := strings.Repeat("hello world ", 100)
	request = &ChatCompletionRequest{Messages: []Message{{Role: "user", Content: json.RawMessage(strconv.Quote(ascii))}}}
	if estimate := estimateChatPromptTokens(request); estimate < int64(len(ascii))/4 || estimate >= int64(len(ascii)) {
		t.Fatalf("ASCII estimate=%d for %d bytes", estimate, len(ascii))
	}
}

func TestEstimateEmbeddingInputTokensDoesNotBillCJKAtByteLength(t *testing.T) {
	text := strings.Repeat("你好", 500)
	estimate := estimateEmbeddingInputTokens(text)
	if estimate < int64(utf8.RuneCountInString(text)) || estimate >= int64(len(text)) {
		t.Fatalf("embedding estimate=%d for %d runes / %d bytes", estimate, utf8.RuneCountInString(text), len(text))
	}
}

// 7.6: without max_tokens the gateway reserves only a ceiling, flags it as
// unbounded, and adopts the control plane's historical estimate so an
// estimated settlement matches the reservation.
func TestBillingClientUnboundedOutputAdoptsControlPlaneEstimate(t *testing.T) {
	var reserved struct {
		Usage     BillingUsage `json:"usage"`
		Unbounded bool         `json:"output_tokens_unbounded"`
	}
	var settled struct {
		Usage BillingUsage `json:"usage"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/billing/reservations":
			if err := json.NewDecoder(r.Body).Decode(&reserved); err != nil {
				t.Error(err)
			}
			_, _ = w.Write([]byte(`{"reserved":true,"estimated_output_tokens":240,"price_id":"test-price","admitted_at":"2026-10-03T01:00:00Z"}`))
		case "/internal/v1/billing/settlements":
			if err := json.NewDecoder(r.Body).Decode(&settled); err != nil {
				t.Error(err)
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := NewBillingClient(server.URL, "internal-secret", "default")
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "user-a", RequestID: "req-unbounded", Model: "model-a"}
	request := &ChatCompletionRequest{Messages: []Message{{Role: "user", Content: json.RawMessage(`"hi"`)}}}
	if err := client.Reserve(context.Background(), envelope, request); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if !reserved.Unbounded || reserved.Usage.OutputTokens != defaultOutputTokenCeiling {
		t.Fatalf("reservation payload=%+v", reserved)
	}
	// Provider omitted usage: settle from the reservation estimate.
	client.Finalize(context.Background(), envelope, []byte(`{}`), "success")
	if settled.Usage.OutputTokens != 240 {
		t.Fatalf("estimated settlement output=%d want 240", settled.Usage.OutputTokens)
	}

	bounded := &ChatCompletionRequest{MaxTokens: 64, Messages: request.Messages}
	envelope.RequestID = "req-bounded"
	reserved.Unbounded = false
	if err := client.Reserve(context.Background(), envelope, bounded); err != nil {
		t.Fatalf("reserve bounded: %v", err)
	}
	if reserved.Unbounded || reserved.Usage.OutputTokens != 64 {
		t.Fatalf("bounded reservation payload=%+v", reserved)
	}
}

func TestBillingFinalizeIgnoresCanceledRequestContext(t *testing.T) {
	settled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/billing/reservations":
			_, _ = w.Write([]byte(`{"reserved":true,"price_id":"test-price","admitted_at":"2026-10-03T01:00:00Z"}`))
		case "/internal/v1/billing/settlements":
			settled = true
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := NewBillingClient(server.URL, "internal-secret", "default")
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "user-a", RequestID: "req-canceled", Model: "model-a"}
	if err := client.Reserve(context.Background(), envelope, &ChatCompletionRequest{MaxTokens: 1}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client.Finalize(ctx, envelope, []byte(`{"usage":{"prompt_tokens":1,"completion_tokens":1}}`), "success")
	if !settled {
		t.Fatal("canceled request context canceled billing settlement")
	}
}

func TestBillingClientPreservesNestedLimitErrorAndRetryAfter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":"rpm_limit_exceeded","message":"customer requests per minute limit exceeded"}}`))
	}))
	defer server.Close()

	client := NewBillingClient(server.URL, "internal-secret", "default")
	err := client.ReserveUsage(context.Background(), &modelrouter.RequestEnvelope{
		TenantID: "tenant-a", UserID: "user-a", RequestID: "req-rate-limit", Model: "model-a",
	}, BillingUsage{PromptTokens: 1})
	var admission *BillingAdmissionError
	if !errors.As(err, &admission) {
		t.Fatalf("error=%v, want BillingAdmissionError", err)
	}
	if admission.Code != "rpm_limit_exceeded" || admission.HTTPStatus != http.StatusTooManyRequests ||
		admission.Message != "customer requests per minute limit exceeded" {
		t.Fatalf("admission=%#v", admission)
	}
	retryable, ok := err.(interface{ RetryAfterValue() string })
	if !ok || retryable.RetryAfterValue() != "60" {
		value := ""
		if ok {
			value = retryable.RetryAfterValue()
		}
		t.Fatalf("retry-after carrier=%T value=%q, want 60", err, value)
	}
}

func TestBillingClientMeteringFlagsMissingModelPrice(t *testing.T) {
	cases := []struct {
		body        string
		status      int
		wantMissing bool
	}{
		{`{"error":{"code":"model_price_missing","message":"x"}}`, http.StatusForbidden, true},
		{`{"error":{"code":"billing_internal_error","message":"x"}}`, http.StatusInternalServerError, false},
	}
	for _, tc := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		client := NewBillingClientWithMode(server.URL, "internal-secret", "", "metering")
		envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "user-a", RequestID: "req-quote", Model: "model-a"}
		if err := client.ReserveUsage(context.Background(), envelope, BillingUsage{PromptTokens: 1}); err != nil {
			t.Fatalf("metering quote must not block: %v", err)
		}
		server.Close()
		if envelope.QuotaCostEstimateAvailable || envelope.QuotaCostEstimateMissingPrice != tc.wantMissing {
			t.Fatalf("%s: available=%v missing=%v, want missing=%v", tc.body, envelope.QuotaCostEstimateAvailable, envelope.QuotaCostEstimateMissingPrice, tc.wantMissing)
		}
	}
}

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestBillingSourceDoesNotInferNonDispatchFromMeteringStatus(t *testing.T) {
	client := NewBillingClientWithMode("", "", "", "metering")
	e := &modelrouter.RequestEnvelope{RequestID: "source-proof"}
	client.reserved.Store(e.RequestID, billingTrackingState{Admitted: true, PriceID: "frozen-price", AdmittedAt: time.Now().UTC()})
	if got := client.deriveUsageSource(e, []byte(`{"usage":{"prompt_tokens":2,"completion_tokens":3}}`), "provider_error"); got != "upstream" {
		t.Fatalf("dispatched provider_error source=%q", got)
	}
	if got := client.deriveUsageSource(e, []byte(`{"id":"missing-usage"}`), "provider_error"); got != "estimated_reservation" {
		t.Fatalf("admitted provider_error source=%q", got)
	}
	client.reserved.Delete(e.RequestID)
	if got := client.deriveUsageSource(e, nil, "success"); got != unknownUsageSource {
		t.Fatalf("live unadmitted source=%q", got)
	}
}

func TestBillingFrozenUnknownSourceSurvivesFinalizeAndQuota(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; _, _ = w.Write([]byte(`{}`)) }))
	defer server.Close()
	client := NewBillingClient(server.URL, "token", "default")
	e := &modelrouter.RequestEnvelope{TenantID: "t", RequestID: "r", Model: "m", BillingUsageSource: unknownUsageSource, QuotaUsageSource: "upstream", QuotaAdmissionManaged: true}
	client.reserved.Store(e.RequestID, billingTrackingState{Admitted: true, PriceID: "p", AdmittedAt: time.Now().UTC()})
	db := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	NewBillingAuditWriter(&RealAuditWriter{db: db}, client).FinalizeRequestLog(context.Background(), e, []byte(`{"usage":{"prompt_tokens":2,"completion_tokens":3}}`), "success", 200, 1, nil)
	if calls != 0 || e.BillingOutcome != "pending" || usageSourceFromAuditArgs(t, db.queries, db.args) != unknownUsageSource {
		t.Fatalf("calls=%d outcome=%q source=%q", calls, e.BillingOutcome, e.BillingUsageSource)
	}
}

func TestBillingCompensationGatewayBridge(t *testing.T) {
	endpoint := os.Getenv("BILLING_BRIDGE_ENDPOINT")
	if endpoint == "" {
		t.Skip("BILLING_BRIDGE_ENDPOINT not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	client := NewBillingClient(endpoint, "bridge-secret", "default")
	e := &modelrouter.RequestEnvelope{TenantID: os.Getenv("BILLING_BRIDGE_TENANT"), UserID: os.Getenv("BILLING_BRIDGE_USER"), ProjectID: os.Getenv("BILLING_BRIDGE_PROJECT"), RequestID: os.Getenv("BILLING_BRIDGE_REQUEST"), Model: os.Getenv("BILLING_BRIDGE_MODEL")}
	if err := client.ReserveUsage(ctx, e, BillingUsage{PromptTokens: 12, OutputTokens: 4}); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("BILLING_BRIDGE_KIND") == "no_log" {
		return
	}
	if os.Getenv("BILLING_BRIDGE_KIND") == "lost_tracking" {
		client = NewBillingClient(endpoint, "bridge-secret", "default")
	}
	writer := NewBillingAuditWriter(&RealAuditWriter{db: &poolDBExecutor{Pool: db}}, client)
	writer.EnsureRequestLog(ctx, e)
	writer.FinalizeRequestLog(ctx, e, []byte(os.Getenv("BILLING_BRIDGE_BODY")), os.Getenv("BILLING_BRIDGE_STATUS"), 200, 1, nil)
	source := readPersistedUsageSource(t, db, ctx, e.TenantID, e.RequestID)
	if source != os.Getenv("BILLING_BRIDGE_SOURCE") {
		t.Fatalf("source=%q want=%q", source, os.Getenv("BILLING_BRIDGE_SOURCE"))
	}
	if e.BillingOutcome != os.Getenv("BILLING_BRIDGE_OUTCOME") {
		t.Fatalf("outcome=%q want=%q", e.BillingOutcome, os.Getenv("BILLING_BRIDGE_OUTCOME"))
	}
}

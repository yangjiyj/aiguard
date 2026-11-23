package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestImageAccountingFailureKeepsActualSpecsInDurableAudit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer server.Close()
	c := NewBillingClient(server.URL, "test-secret", "default")
	env := &modelrouter.RequestEnvelope{TenantID: "t", UserID: "u", RequestID: "recover-image", Model: "image", EndpointType: "images"}
	c.reserved.Store(env.RequestID, billingTrackingState{Admitted: true, PriceID: "p", AdmittedAt: time.Now(), Usage: BillingUsage{ImageRequest: true, ImageCount: 3, ImageSize: "1024x1024", ImageQuality: "standard"}})
	inner := &MockAuditWriter{}
	w := NewBillingAuditWriter(inner, c)
	body := imageUsageEvidence([]byte(`{"size":"1792x1024","quality":"hd","data":[{"url":"private-image"}],"usage":{"input_tokens":10,"output_tokens":20,"output_tokens_details":{"image_tokens":15,"reasoning_tokens":2}}}`))
	w.FinalizeRequestLog(context.Background(), env, body, "success", 200, 1, nil)
	if len(inner.RequestLogFinalizes) != 1 {
		t.Fatal("missing audit despite accounting failure")
	}
	result := inner.RequestLogFinalizes[0].AuditResult
	if result == nil {
		t.Fatal("billing evidence not attached to audit")
	}
	encoded, err := json.Marshal(result.ResponseMetadata["billing_usage"])
	if err != nil {
		t.Fatal(err)
	}
	var usage BillingUsage
	if json.Unmarshal(encoded, &usage) != nil || !usage.ImageRequest || usage.ImageCount != 1 || usage.ImageSize != "1792x1024" || usage.ImageQuality != "hd" || usage.ImageOutputTokens != 15 || usage.ReasoningTokens != 2 {
		t.Fatalf("durable recovery usage lost actual specs: %s", encoded)
	}
}

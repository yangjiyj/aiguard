package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

func TestImageAdmissionAndSettlementUseActualSpecsAndQuantity(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	response := `{"size":"1792x1024","quality":"hd","data":[{"b64_json":"secret","size":"1024x1024"},{"url":"https://private/image"}],"usage":{"input_tokens":50,"output_tokens":120,"input_tokens_details":{"image_tokens":20},"output_tokens_details":{"image_tokens":100,"reasoning_tokens":10}}}`
	var admitted, settled BillingUsage
	var settledPrice string
	var settledRatio int64
	var settledTariff json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/billing/quotes":
			var p struct {
				Usage BillingUsage `json:"usage"`
			}
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				t.Error(err)
			}
			admitted = p.Usage
			_, _ = w.Write([]byte(`{"price_id":"frozen-image","admitted_at":"2026-10-09T01:00:00Z","customer_group_ratio_ppm":800000,"tariff_quote":{"multiplier_ppm":500000}}`))
		case "/internal/v1/billing/measurements":
			var p struct {
				Usage  BillingUsage    `json:"usage"`
				Price  string          `json:"price_id"`
				Ratio  int64           `json:"customer_group_ratio_ppm"`
				Tariff json.RawMessage `json:"tariff_quote"`
				Raw    json.RawMessage `json:"raw_usage"`
			}
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				t.Error(err)
			}
			settled, settledPrice, settledRatio, settledTariff = p.Usage, p.Price, p.Ratio, p.Tariff
			if bytes.Contains(p.Raw, []byte("secret")) || bytes.Contains(p.Raw, []byte("private/image")) {
				t.Errorf("image data retained: %s", p.Raw)
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := NewBillingClientWithMode(server.URL, "test-secret", "default", "metering")
	audit := &MockAuditWriter{}
	h := NewImagesHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, NewBillingAuditWriter(audit, client), &MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{CallResponse: []byte(response)}}, nil)
	h.SetBillingPreflight(client)
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, newImagesTestRequest(`{"model":"dall-e-3","prompt":"bridge","n":3,"size":"1024x1024","quality":"standard"}`))
	if w.Code != 200 {
		t.Fatalf("image failed: %d %s", w.Code, w.Body.String())
	}
	if !admitted.ImageRequest || admitted.ImageCount != 3 || admitted.ImageSize != "1024x1024" || admitted.ImageQuality != "standard" {
		t.Fatalf("admission lost requested specification: %+v", admitted)
	}
	if !settled.ImageRequest || settled.ImageCount != 2 || settled.ImageSize != "1792x1024" || settled.ImageQuality != "hd" || settled.ImageOutputTokens != 100 || settled.ReasoningTokens != 10 || settled.ImageInputTokens != 20 || settled.OutputTokens != 120 {
		t.Fatalf("settlement lost actual specifications/token tiers: %+v", settled)
	}
	if len(settled.ImageVariants) != 2 || settled.ImageVariants[0].Size != "1024x1024" || settled.ImageVariants[0].Quality != "hd" || settled.ImageVariants[1].Size != "1792x1024" {
		t.Fatalf("actual per-image specs: %+v", settled.ImageVariants)
	}
	if settledPrice != "frozen-image" || settledRatio != 800000 || !bytes.Contains(settledTariff, []byte("500000")) {
		t.Fatalf("metering lost quote snapshot: %s/%d/%s", settledPrice, settledRatio, settledTariff)
	}
}

func TestImagesMeasuredZeroReplacesRequestedQuantity(t *testing.T) {
	zero := imageUsageEvidence([]byte(`{"data":[]}`))
	usage := responseUsageExtensions(zero)
	if !usage.ImageCountMeasured || usage.ImageCount != 0 {
		t.Fatalf("zero outputs lost measurement evidence: %s %+v", zero, usage)
	}
	for _, raw := range []string{`{"model":"image","prompt":"test","stream":true}`, `--multipart\nContent-Disposition: form-data; name="size"\n1792x1024`} {
		if _, err := parseImagesRequest([]byte(raw)); err == nil {
			t.Fatalf("unsupported format accepted: %s", raw)
		}
	}
}

func TestAzureBingCounterSuppressesSearchAliasesAcrossNestedAndStream(t *testing.T) {
	for _, raw := range []string{
		`{"usage":{"tool_calls":{"web_search":4,"web_search_preview":2,"file_search":1}},"tool_usage":{"web_search":{"num_requests":3}},"output":[{"id":"s","type":"web_search_call"}]}`,
		`{"usage":{"tool_calls":{"web_search":4}},"output":[{"id":"s","type":"web_search_call"}],"response":{"tool_usage":{"web_search":{"num_requests":3}},"usage":{"input_tokens_details":{"image_tokens":40,"cached_tokens_details":{"image_tokens":5}},"output_tokens_details":{"image_tokens":60}}}}`,
	} {
		u, bad := parseResponseUsageExtensions([]byte(raw))
		if bad || u.ToolCalls["bing_web_search"] != 3 {
			t.Fatalf("Bing transaction evidence: %+v invalid=%v", u, bad)
		}
		if _, ok := u.ToolCalls["web_search"]; ok {
			t.Fatalf("search alias double billed: %+v", u.ToolCalls)
		}
		if _, ok := u.ToolCalls["web_search_preview"]; ok {
			t.Fatalf("preview alias double billed: %+v", u.ToolCalls)
		}
	}
	nested := responseUsageExtensions([]byte(`{"response":{"usage":{"input_tokens_details":{"image_tokens":40,"cached_tokens_details":{"image_tokens":5}},"output_tokens_details":{"image_tokens":60}}}}`))
	if nested.ImageInputTokens != 40 || nested.CachedImageInputTokens != 5 || nested.ImageOutputTokens != 60 {
		t.Fatalf("nested image tiers lost: %+v", nested)
	}
	for _, counter := range []string{"3", "0"} {
		a := newLiveStreamAccumulator()
		for _, raw := range []string{`{"item":{"id":"s1","type":"web_search_call","status":"completed"}}`, `{"response":{"tool_usage":{"web_search":{"num_requests":` + counter + `}},"usage":{"input_tokens":10,"output_tokens":10}}}`, `{"item":{"id":"s2","type":"web_search_preview_call","status":"completed"}}`, `{"item":{"id":"f1","type":"file_search_call","status":"completed"}}`} {
			a.observeBillingTools(relay.StreamEvent{Raw: []byte(raw)})
		}
		body, err := a.responseBody("azure")
		if err != nil {
			t.Fatal(err)
		}
		tools := responseUsageExtensions(body).ToolCalls
		if _, ok := tools["web_search"]; ok {
			t.Fatalf("stream search duplicate: %+v", tools)
		}
		if _, ok := tools["web_search_preview"]; ok {
			t.Fatalf("stream preview duplicate: %+v", tools)
		}
		if tools["file_search"] != 1 {
			t.Fatalf("unrelated tool silenced: %+v", tools)
		}
		if _, ok := tools["bing_web_search"]; !ok {
			t.Fatalf("explicit Bing zero lost: %+v", tools)
		}
	}
}

func TestImageMissingSpecificationAllowsWithoutMonetaryCharge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"image_price_missing","message":"missing spec"}}`))
	}))
	defer server.Close()
	c := NewBillingClientWithMode(server.URL, "secret", "", "metering")
	for _, required := range []bool{false, true} {
		c.AllowanceRequired = func(context.Context, string, string) (bool, error) { return required, nil }
		env := &modelrouter.RequestEnvelope{TenantID: "t", UserID: "u", RequestID: "image", Model: "image"}
		if err := c.ReserveUsage(context.Background(), env, BillingUsage{ImageRequest: true, ImageCount: 1, ImageSize: "auto"}); err != nil || !env.QuotaCostEstimateMissingPrice {
			t.Fatalf("missing spec admitted/obscured (required=%v): %v", required, err)
		}
	}
}

func TestImageExplicitZeroOutputTokensRemainZero(t *testing.T) {
	var settled BillingUsage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Usage BillingUsage `json:"usage"`
		}
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Error(err)
		}
		settled = p.Usage
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	c := NewBillingClient(server.URL, "test-secret", "default")
	for _, cse := range []struct {
		response string
		want     int64
	}{
		{`{"usage":{"input_tokens":1,"output_tokens":10,"output_tokens_details":{"image_tokens":0}}}`, 0},
		{`{"usage":{"input_tokens":1,"output_tokens":10}}`, 10},
	} {
		env := &modelrouter.RequestEnvelope{TenantID: "t", UserID: "u", RequestID: "zero-image", Model: "image", EndpointType: "images"}
		c.reserved.Store(env.RequestID, billingTrackingState{Admitted: true, PriceID: "p", Usage: BillingUsage{ImageRequest: true, ImageCount: 1}})
		c.Finalize(context.Background(), env, []byte(cse.response), "success")
		if settled.ImageOutputTokens != cse.want {
			t.Fatalf("image output measured/fallback=%d, want %d", settled.ImageOutputTokens, cse.want)
		}
	}
}

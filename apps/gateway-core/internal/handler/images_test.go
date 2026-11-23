package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

const testImageResponse = `{"created":1716399600,"data":[{"b64_json":"aW1hZ2U="}]}`

func newImagesTestRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(body))
	return req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
}

func TestImagesSuccessPreservesResponseAndAuditsMetadataWithoutPayload(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	caller := &MockProviderCaller{CallResponse: []byte(testImageResponse)}
	audit := &MockAuditWriter{}
	h := NewImagesHandler(
		&config.Config{},
		&MockModelResolver{},
		&MockRateLimitChecker{},
		&MockSecurityChecker{},
		audit,
		&MockProviderAdapterFactory{MockProviderCaller: caller},
		nil,
	)

	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, newImagesTestRequest(`{"model":"gpt-image-2","prompt":"draw a red bridge","n":1}`))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Body.String() != testImageResponse {
		t.Fatalf("response body changed: %s", response.Body.String())
	}
	if len(caller.CallEnvelopes) != 1 || caller.CallEnvelopes[0].EndpointType != "images" {
		t.Fatalf("unexpected provider envelopes: %+v", caller.CallEnvelopes)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "success" {
		t.Fatalf("unexpected audit finalizes: %+v", audit.RequestLogFinalizes)
	}
	auditResult := audit.RequestLogFinalizes[0].AuditResult
	if auditResult == nil || auditResult.ResponseMetadata["image_count"] != 1 {
		t.Fatalf("image metadata missing: %+v", auditResult)
	}
	if body := audit.RequestLogFinalizes[0].RespBody; bytes.Contains(body, []byte("b64_json")) || bytes.Contains(body, []byte("aW1hZ2U=")) || responseUsageExtensions(body).ImageCount != 1 {
		t.Fatalf("audit must retain only measured image count, not the image payload: %s", body)
	}
	encodedAudit, err := json.Marshal(auditResult)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encodedAudit, []byte("aW1hZ2U=")) {
		t.Fatal("base64 image data leaked into audit metadata")
	}
}

func TestImagesReservesBillingBeforeProviderCall(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	caller := &MockProviderCaller{CallResponse: []byte(testImageResponse)}
	billing := &recordingBillingPreflight{}
	h := NewImagesHandler(
		&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{},
		&MockAuditWriter{}, &MockProviderAdapterFactory{MockProviderCaller: caller}, nil,
	)
	h.SetBillingPreflight(billing)

	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, newImagesTestRequest(`{"model":"gpt-image-2","prompt":"draw a red bridge"}`))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if billing.reserveUsageCalls != 1 || billing.reserveUsageEnvelope == nil ||
		billing.reserveUsageEnvelope.EndpointType != "images" || billing.reserveUsage.PromptTokens < 1 {
		t.Fatalf("billing calls=%d envelope=%+v usage=%+v", billing.reserveUsageCalls, billing.reserveUsageEnvelope, billing.reserveUsage)
	}
	if len(caller.CallCalls) != 1 {
		t.Fatalf("provider calls=%d, want 1", len(caller.CallCalls))
	}
}

func TestImagesSuccessfulBillingSettlementKeepsReservedPromptUsage(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	settlements := make(chan BillingUsage, 1)
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/billing/reservations":
			_, _ = w.Write([]byte(`{"reserved":true,"price_id":"image-price","admitted_at":"2026-10-03T01:00:00Z"}`))
		case "/internal/v1/billing/settlements":
			var payload struct {
				Usage BillingUsage `json:"usage"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode image settlement: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			settlements <- payload.Usage
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer controlPlane.Close()

	client := NewBillingClient(controlPlane.URL, "internal-secret", "default")
	audit := NewBillingAuditWriter(&MockAuditWriter{}, client)
	h := NewImagesHandler(
		&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{},
		audit, &MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{CallResponse: []byte(testImageResponse)}}, nil,
	)
	h.SetBillingPreflight(client)

	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, newImagesTestRequest(`{"model":"gpt-image-2","prompt":"draw a red bridge"}`))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	select {
	case usage := <-settlements:
		if usage.PromptTokens < 1 || usage.OutputTokens != 0 {
			t.Fatalf("image settlement usage=%+v, want reserved prompt tokens", usage)
		}
	case <-context.Background().Done():
		t.Fatal("image settlement was not sent")
	default:
		t.Fatal("image settlement was not sent")
	}
}

func TestImagesStopsBeforeProviderWhenBillingLimitRejects(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	caller := &MockProviderCaller{CallResponse: []byte(testImageResponse)}
	billing := &recordingBillingPreflight{reserveUsageErr: &BillingAdmissionError{
		Code: "concurrency_limit_exceeded", HTTPStatus: http.StatusTooManyRequests,
		Message: "customer concurrent request limit exceeded",
	}}
	h := NewImagesHandler(
		&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{},
		&MockAuditWriter{}, &MockProviderAdapterFactory{MockProviderCaller: caller}, nil,
	)
	h.SetBillingPreflight(billing)

	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, newImagesTestRequest(`{"model":"gpt-image-2","prompt":"draw a red bridge"}`))

	if response.Code != http.StatusTooManyRequests || !strings.Contains(response.Body.String(), "concurrency_limit_exceeded") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(caller.CallCalls) != 0 {
		t.Fatalf("provider calls=%d, want 0", len(caller.CallCalls))
	}
}

func TestImagesBlocksUnsafePromptBeforeProviderCall(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	caller := &MockProviderCaller{CallResponse: []byte(testImageResponse)}
	audit := &MockAuditWriter{}
	h := NewImagesHandler(
		&config.Config{},
		&MockModelResolver{},
		&MockRateLimitChecker{},
		&MockSecurityChecker{
			InputAction:   "block",
			InputFindings: []SecurityFinding{{Type: "unsafe_content", Severity: "high"}},
		},
		audit,
		&MockProviderAdapterFactory{MockProviderCaller: caller},
		nil,
	)

	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, newImagesTestRequest(`{"model":"gpt-image-2","prompt":"unsafe prompt"}`))

	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(caller.CallCalls) != 0 {
		t.Fatal("provider was called after prompt block")
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "security_blocked" {
		t.Fatalf("unexpected audit status: %+v", audit.RequestLogFinalizes)
	}
}

func TestImagesMasksPromptBeforeProviderCall(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	caller := &MockProviderCaller{CallResponse: []byte(testImageResponse)}
	audit := &MockAuditWriter{}
	h := NewImagesHandler(
		&config.Config{},
		&MockModelResolver{},
		&MockRateLimitChecker{},
		&MockSecurityChecker{
			InputAction:   "mask",
			InputMasked:   "redacted prompt",
			InputFindings: []SecurityFinding{{Type: "secret", Severity: "high"}},
		},
		audit,
		&MockProviderAdapterFactory{MockProviderCaller: caller},
		nil,
	)

	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, newImagesTestRequest(`{"model":"gpt-image-1","prompt":"original secret","size":"1024x1024"}`))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(caller.TransformRequestCalls) != 1 {
		t.Fatalf("transform calls=%d, want 1", len(caller.TransformRequestCalls))
	}
	var providerBody map[string]interface{}
	if err := json.Unmarshal(caller.TransformRequestCalls[0].RawBody, &providerBody); err != nil {
		t.Fatal(err)
	}
	if providerBody["prompt"] != "redacted prompt" {
		t.Fatalf("provider prompt=%v, want masked prompt", providerBody["prompt"])
	}
	if len(audit.SecurityEventWrites) != 1 || audit.SecurityEventWrites[0].ActionTaken != "security_masked" {
		t.Fatalf("unexpected security events: %+v", audit.SecurityEventWrites)
	}
}

func TestImagesRejectsProviderWithoutImageEndpoint(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	audit := &MockAuditWriter{}
	h := NewImagesHandler(
		&config.Config{},
		&MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
			ID:              "model-anthropic",
			ModelName:       "gpt-image-2",
			ProviderID:      "provider-anthropic",
			ProviderType:    "anthropic",
			ProviderBaseURL: "http://127.0.0.1:1",
			UpstreamModelID: "gpt-image-2",
		}},
		&MockRateLimitChecker{},
		&MockSecurityChecker{},
		audit,
		&RealProviderAdapterFactory{},
		nil,
	)

	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, newImagesTestRequest(`{"model":"gpt-image-2","prompt":"draw a bridge"}`))

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "provider_unsupported") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "provider_unsupported" {
		t.Fatalf("unexpected audit finalizes: %+v", audit.RequestLogFinalizes)
	}
}

func TestImagesUsesNextCapableModelRoute(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "false")
	chatOnly := modelrouter.ModelRecord{
		ID:                   "model-chat",
		ModelName:            "logical/image",
		ProviderID:           "chat-only",
		ProviderType:         "anthropic",
		Status:               "active",
		ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true},
		ProviderName:         "Anthropic",
	}
	imageCapable := modelrouter.ModelRecord{
		ID:                   "model-image",
		ModelName:            "logical/image",
		ProviderID:           "image-provider",
		ProviderType:         "openai",
		Status:               "active",
		ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, Images: true},
		ProviderName:         "OpenAI",
	}
	decision := &modelrouter.RoutingDecision{
		ModelRouteV2: &modelrouter.ModelRouteDecisionV2{
			SchemaVersion:  2,
			RequestedModel: "logical/image",
			PlannedRoute: modelrouter.RouteIdentity{
				ProviderName: "Anthropic",
				RouteRef:     "线路 1",
			},
			Candidates: []modelrouter.RouteCandidateDecision{
				{ProviderName: "Anthropic", RouteRef: "线路 1", ExclusionReason: "selected_primary"},
				{ProviderName: "OpenAI", RouteRef: "线路 2"},
			},
		},
	}
	engine := &executionTestEngine{
		hasPolicy: true,
		applied:   true,
		plan: modelrouter.RoutePlan{
			Primary:   chatOnly,
			Fallbacks: []modelrouter.ModelRecord{imageCapable},
			Decision:  decision,
		},
	}
	unsupported := &MockProviderCaller{
		TransformRequestError: fmt.Errorf("%w: images", provider.ErrEndpointNotSupported),
	}
	supported := &MockProviderCaller{CallResponse: []byte(testImageResponse)}
	factory := &MockProviderAdapterFactory{
		CallersByProviderID: map[string]ProviderCaller{
			"chat-only":      unsupported,
			"image-provider": supported,
		},
	}
	h := NewImagesHandler(
		&config.Config{},
		&MockModelResolver{},
		&MockRateLimitChecker{},
		&MockSecurityChecker{},
		&MockAuditWriter{},
		factory,
		nil,
	)
	h.SetModelRoutingEngine(engine)

	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, newImagesTestRequest(`{"model":"logical/image","prompt":"draw a bridge"}`))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(unsupported.CallCalls) != 0 || len(supported.CallCalls) != 1 {
		t.Fatalf("calls unsupported=%d supported=%d", len(unsupported.CallCalls), len(supported.CallCalls))
	}
	if len(supported.CallEnvelopes) != 1 || supported.CallEnvelopes[0].EndpointType != "images" || supported.CallEnvelopes[0].ProviderID != "image-provider" {
		t.Fatalf("unexpected selected route: %+v", supported.CallEnvelopes)
	}
	if decision.ModelRouteV2.Candidates[0].ExclusionReason != "endpoint_not_supported" {
		t.Fatalf("unsupported route was not explained: %#v", decision.ModelRouteV2)
	}
}

func TestImagesUsesActualUpstreamUsageForAuditAndBillingWithoutRetainingImage(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	imageResponse := `{"data":[{"b64_json":"aW1hZ2U="}],"usage":{"input_tokens":29,"output_tokens":343,"total_tokens":372}}`
	settlements := make(chan BillingUsage, 1)
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/billing/reservations":
			_, _ = w.Write([]byte(`{"reserved":true,"price_id":"image-price","admitted_at":"2026-10-09T01:00:00Z"}`))
		case "/internal/v1/billing/settlements":
			var payload struct {
				Usage    BillingUsage    `json:"usage"`
				RawUsage json.RawMessage `json:"raw_usage"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
				return
			}
			if !bytes.Contains(payload.RawUsage, []byte(`"usage_source":"upstream"`)) {
				t.Errorf("missing verified upstream usage evidence: %s", payload.RawUsage)
			}
			settlements <- payload.Usage
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer controlPlane.Close()
	client := NewBillingClient(controlPlane.URL, "internal-secret", "default")
	recorded := &MockAuditWriter{}
	h := NewImagesHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{},
		NewBillingAuditWriter(recorded, client), &MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{CallResponse: []byte(imageResponse)}}, nil)
	h.SetBillingPreflight(client)
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, newImagesTestRequest(`{"model":"gpt-image-2","prompt":"blue circle"}`))
	if w.Code != 200 || w.Body.String() != imageResponse {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	select {
	case usage := <-settlements:
		if usage.PromptTokens != 29 || usage.OutputTokens != 343 {
			t.Fatalf("settled usage=%+v", usage)
		}
	default:
		t.Fatal("missing settlement")
	}
	if len(recorded.RequestLogFinalizes) != 1 {
		t.Fatal("missing audit")
	}
	evidence := recorded.RequestLogFinalizes[0].RespBody
	if bytes.Contains(evidence, []byte("aW1hZ2U=")) || bytes.Contains(evidence, []byte("data")) {
		t.Fatal("image leaked into audit")
	}
	prompt, output, valid := verifiedResponseUsageTokens(evidence)
	if !valid || prompt != 29 || output != 343 {
		t.Fatalf("audit usage=%d/%d valid=%v", prompt, output, valid)
	}
}

func TestImageUsageEvidenceOmitsAbsentAndOversizedUsage(t *testing.T) {
	for _, body := range []string{`{"usage":null}`, `invalid`, `{"usage":{"blob":"` + strings.Repeat("x", 64<<10) + `"}}`} {
		if got := imageUsageEvidence([]byte(body)); got != nil {
			t.Fatal("invalid or unbounded usage retained")
		}
	}
}

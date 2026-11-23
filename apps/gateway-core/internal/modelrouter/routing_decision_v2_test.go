package modelrouter

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestLegacyDecisionStillDeserializes(t *testing.T) {
	var decision RoutingDecision
	if err := json.Unmarshal([]byte(`{"provider_layer":{"selected_provider":"legacy-provider","strategy":"priority"},"fallback_retries":1}`), &decision); err != nil {
		t.Fatal(err)
	}
	if decision.ProviderLayer == nil || decision.ProviderLayer.ProviderID != "legacy-provider" || decision.FallbackRetries != 1 {
		t.Fatalf("legacy decision changed: %#v", decision)
	}
}

func TestLegacyDecisionDeepSanitizesContainersAndDropsUnsupportedValues(t *testing.T) {
	long := strings.Repeat("x", 300) + " api_key=tail-token"
	decision := &RoutingDecision{GovernorOverride: map[string]any{
		"nested":      map[string]any{"safe": "Bearer nested-token", "strings": []string{"gpt-5.4", "sk-arraytoken"}, "typed": map[string]string{"route": "https://x.example/v1?q=url-token", "state": "secret=state-token"}},
		"items":       []any{map[string]any{"value": "Authorization: Bearer item-token"}, []string{"credential_id=cred-token"}, long},
		"unsupported": make(chan int), "nan": math.NaN(), "inf": math.Inf(1), "ok": true,
	}, ModelRouteV2: &ModelRouteDecisionV2{SchemaVersion: 2, RequestedModel: "gpt-5.4", Candidates: []RouteCandidateDecision{{NormalizedScores: map[string]float64{"latency": math.NaN(), "stability": 0.9}}}}}
	safe := SanitizeRoutingDecision(decision)
	raw, err := json.Marshal(safe)
	if err != nil {
		t.Fatalf("sanitized decision must marshal: %v", err)
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{"nested-token", "arraytoken", "url-token", "state-token", "item-token", "cred-token", "tail-token", "unsupported", "\"nan\"", "\"inf\""} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("legacy nested value leaked %q: %s", forbidden, raw)
		}
	}
	if !strings.Contains(string(raw), "gpt-5.4") || !strings.Contains(string(raw), "stability") {
		t.Fatalf("normal typed values removed: %s", raw)
	}
}

func TestV2DecisionSanitizesSecretsAndRequestContent(t *testing.T) {
	decision := &RoutingDecision{
		GovernorOverride: map[string]any{"prompt": "customer secret", "authorization": "Bearer key", "safe": "kept"},
		ProviderLayer:    &ProviderDecision{Reason: map[string]any{"api_key": "sk-secret", "upstream_url": "https://upstream.example/v1?q=secret"}},
		ModelRouteV2:     &ModelRouteDecisionV2{SchemaVersion: 2, RequestedModel: "logical-model"},
	}
	safe := SanitizeRoutingDecision(decision)
	raw, err := json.Marshal(safe)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{"customer secret", "bearer key", "sk-secret", "q=secret", "\"prompt\"", "\"authorization\"", "\"api_key\""} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("sensitive material persisted: %s", raw)
		}
	}
	if !strings.Contains(text, "kept") {
		t.Fatalf("safe explanation removed: %s", raw)
	}
}

func TestV2DecisionDeepSanitizesEveryTypedString(t *testing.T) {
	secretURL := "https://upstream.example/v1?api_key=top-secret#raw"
	decision := &RoutingDecision{ModelRouteV2: &ModelRouteDecisionV2{
		SchemaVersion: 2, RequestedModel: "gpt-5.4", PolicySource: "Authorization: Bearer policy-token", Strategy: "smart\x00secret=route-token",
		PlannedRoute:   RouteIdentity{ProviderName: "供应商 Bearer provider-token", RouteRef: secretURL},
		ActualRoute:    RouteIdentity{ProviderName: "正常供应商", RouteRef: "credential_id=cred-123"},
		Candidates:     []RouteCandidateDecision{{ProviderName: "api_key=sk-candidate", RouteRef: secretURL, SampleState: "secret: candidate-token", DimensionState: map[string]string{"latency": "Bearer dimension-token"}, ExclusionReason: "failed at " + secretURL}},
		Attempts:       []RouteAttemptDecision{{Route: RouteIdentity{ProviderName: "Authorization=attempt-token", RouteRef: secretURL}, Result: "secret=result-token", StatusCodeCategory: "5xx\x01", FailureCategory: "api-key: attempt-secret"}},
		FallbackReason: "Bearer fallback-token",
	}}
	raw, err := json.Marshal(SanitizeRoutingDecision(decision))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{"policy-token", "route-token", "provider-token", "top-secret", "cred-123", "sk-candidate", "candidate-token", "dimension-token", "attempt-token", "result-token", "attempt-secret", "fallback-token", "?api_key=", "#raw", "\\u0000", "\\u0001"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("typed v2 value leaked %q: %s", forbidden, raw)
		}
	}
	if !strings.Contains(string(raw), "gpt-5.4") || !strings.Contains(string(raw), "正常供应商") {
		t.Fatalf("normal business values were over-redacted: %s", raw)
	}
}

func TestRoutingDecisionPersistsContentFreeProtocolFingerprint(t *testing.T) {
	decision := &RoutingDecision{
		IngressProtocol:  "chat",
		UpstreamProtocol: "responses",
		RequestFeatures:  []string{"tools", "tool_results", "vision"},
	}
	raw, err := json.Marshal(SanitizeRoutingDecision(decision))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{`"ingress_protocol":"chat"`, `"upstream_protocol":"responses"`, `"tool_results"`, `"vision"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing protocol audit field %s in %s", want, text)
		}
	}
}

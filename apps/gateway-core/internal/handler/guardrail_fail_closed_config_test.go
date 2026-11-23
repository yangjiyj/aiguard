package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func fetchGatewayPayload(t *testing.T, payload map[string]any) (semanticRuntimeConfig, error) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	return client.fetchSemanticRuntimeConfig(context.Background())
}

func resignGatewayPayload(t *testing.T, payload map[string]any) {
	t.Helper()
	revision, err := semanticGatewayConfigRevision(payload, gatewaySemanticTestKey)
	if err != nil {
		t.Fatal(err)
	}
	payload["revision"] = revision
}

// An older control plane does not send guardrail_fail_closed_enabled: the
// payload must still verify and the option must resolve to false.
func TestGatewayConfigWithoutFailClosedKeyResolvesFalse(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	payload := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, false, false)
	config, err := fetchGatewayPayload(t, payload)
	if err != nil {
		t.Fatalf("legacy payload rejected: %v", err)
	}
	if config.GuardrailFailClosedEnabled {
		t.Fatal("missing key must resolve to false")
	}
}

func TestGatewayConfigFailClosedKeyIsSignedAndDecoded(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	for _, value := range []bool{true, false} {
		payload := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, false, false)
		payload["guardrail_fail_closed_enabled"] = value
		resignGatewayPayload(t, payload)
		config, err := fetchGatewayPayload(t, payload)
		if err != nil {
			t.Fatalf("value=%v rejected: %v", value, err)
		}
		if config.GuardrailFailClosedEnabled != value {
			t.Fatalf("decoded %v want %v", config.GuardrailFailClosedEnabled, value)
		}
	}
}

func TestGatewayConfigRejectsUnsignedOrNonBooleanFailClosedKey(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	// Added after signing: the attestation must fail.
	unsigned := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, false, false)
	unsigned["guardrail_fail_closed_enabled"] = true
	if _, err := fetchGatewayPayload(t, unsigned); err == nil {
		t.Fatal("unsigned fail-closed option was accepted")
	}
	nonBool := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, false, false)
	nonBool["guardrail_fail_closed_enabled"] = "true"
	if _, err := fetchGatewayPayload(t, nonBool); err == nil {
		t.Fatal("non-boolean fail-closed option was accepted")
	}
}

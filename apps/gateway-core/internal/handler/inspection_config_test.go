package handler

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInspectionConfigUsesFiveSignedFlagsAcrossGatewayAndProxy(t *testing.T) {
	payload := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, true, false)
	for key, value := range map[string]bool{"inspect_user_input": false, "inspect_model_output": true, "inspect_builtin_context": true, "inspect_history": true, "inspect_tool_results": false} {
		payload[key] = value
	}
	revision, err := semanticGatewayConfigRevision(payload, gatewaySemanticTestKey)
	if err != nil {
		t.Fatal(err)
	}
	payload["revision"] = revision
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(payload) }))
	defer server.Close()
	gateway := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	config, err := gateway.fetchSemanticRuntimeConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	proxy := inspectionscope.NewGatewayReader(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	if err := proxy.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := inspectionscope.Policy{InspectModelOutput: true, InspectBuiltinContext: true, InspectHistory: true}
	if config.InspectionPolicy == nil || *config.InspectionPolicy != want || proxy.InspectionPolicy(context.Background()) != want {
		t.Fatalf("signed scope differs: %+v", config)
	}
	payload["inspect_tool_results"] = true
	if _, err := gateway.fetchSemanticRuntimeConfig(context.Background()); err == nil {
		t.Fatal("gateway accepted unsigned scope change")
	}
	if err := proxy.Refresh(context.Background()); err == nil {
		t.Fatal("proxy accepted unsigned scope change")
	}
	if proxy.InspectionPolicy(context.Background()) != want {
		t.Fatal("failed refresh discarded last good policy")
	}
}

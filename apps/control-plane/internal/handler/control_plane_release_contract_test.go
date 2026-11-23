package handler

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestControlPlaneReleaseContractKeepsRoutingAndAssuranceFields(t *testing.T) {
	routingPayload, err := json.Marshal(modelRoutingOverviewDTO{OutboundRouteAvailable: false})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(routingPayload, []byte(`"outbound_route_available":false`)) {
		t.Fatalf("model routing response lost outbound availability: %s", routingPayload)
	}

	foundHardcodedCredential := false
	for _, policy := range evalAssurancePolicyContracts() {
		if policy["policy_id"] == "code.hardcoded_credential" {
			foundHardcodedCredential = true
		}
		if policy["rule_id"] == nil || policy["target_category"] == nil {
			t.Fatalf("assurance policy lost exact rule mapping: %#v", policy)
		}
		if policy["supported_stages"] == nil || policy["sample_transport"] == nil {
			t.Fatalf("assurance policy lost execution coverage: %#v", policy)
		}
	}
	if !foundHardcodedCredential {
		t.Fatal("hardcoded credential assurance policy is missing")
	}
}

package repository

import (
	"strings"
	"testing"
)

func TestEndpointToolLifecycleIdentityUsesFullScope(t *testing.T) {
	base := endpointToolLifecycleIdentity("tenant-a", "endpoint-a", "session-a", "tool-a")
	for name, other := range map[string]string{
		"tenant":   endpointToolLifecycleIdentity("tenant-b", "endpoint-a", "session-a", "tool-a"),
		"endpoint": endpointToolLifecycleIdentity("tenant-a", "endpoint-b", "session-a", "tool-a"),
		"session":  endpointToolLifecycleIdentity("tenant-a", "endpoint-a", "session-b", "tool-a"),
		"tool":     endpointToolLifecycleIdentity("tenant-a", "endpoint-a", "session-a", "tool-b"),
	} {
		if other == base {
			t.Errorf("%s did not change lifecycle lock identity", name)
		}
	}
}

func TestEndpointProposalInsertCarriesEndpointAndEmptyRequestID(t *testing.T) {
	entry := &ToolCallLog{
		ID: "tc-proposal-test", RequestID: "", SessionID: "session-test", TenantID: "tenant-test",
		EndpointID: "endpoint-test", ToolName: "read_file", ToolType: "filesystem", RiskLevel: "low",
		Status: "audited", EventKind: "invocation_proposed", AttributionMode: "endpoint_hook",
		AttributionConfidence: 1, Provenance: "agent_endpoint", Parameters: map[string]interface{}{},
	}
	query, args, err := buildToolCallLogInsert(entry)
	if err != nil {
		t.Fatalf("build proposal insert: %v", err)
	}
	if len(args) != 57 || args[1] != "" || args[56] != "endpoint-test" {
		t.Fatalf("unexpected request_id/endpoint args: len=%d request_id=%v endpoint_id=%v", len(args), args[1], args[56])
	}
	if !strings.Contains(query, "public_event_id, endpoint_id") || !strings.Contains(query, "$57") {
		t.Fatalf("proposal insert does not bind endpoint_id: %s", query)
	}
}

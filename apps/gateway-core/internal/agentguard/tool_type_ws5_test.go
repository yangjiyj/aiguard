package agentguard

import (
	"context"
	"encoding/json"
	"testing"
)

// W5 5.9: explicit console mapping and schema inference classify custom tools.
func TestWS5ResolveToolTypePrecedence(t *testing.T) {
	cases := []struct {
		name, configured, inferred, want string
	}{
		{"acme_sync", "", "", ToolTypeUnknown},
		{"acme_sync", "", ToolTypeNetwork, ToolTypeNetwork},
		{"acme_sync", "database", ToolTypeNetwork, ToolTypeDatabase},
		{"read_file", "network", "", ToolTypeNetwork},
		{"read_file", "", ToolTypeNetwork, ToolTypeFile},
		{"read_file", "bogus", "", ToolTypeFile},
		{"use_skill", "system", "", ToolTypeSkill},
		{"mcp__srv__x", "file", "", ToolTypeMCP},
	}
	for _, tc := range cases {
		if got := ResolveToolType(tc.name, tc.configured, tc.inferred); got != tc.want {
			t.Fatalf("ResolveToolType(%q,%q,%q) = %q, want %q", tc.name, tc.configured, tc.inferred, got, tc.want)
		}
	}
}

func TestWS5InferToolTypeFromSchema(t *testing.T) {
	cases := map[string]string{
		`{"type":"object","properties":{"command":{"type":"string"}}}`:                                                 ToolTypeSystem,
		`{"type":"object","properties":{"sql":{"type":"string"}}}`:                                                     ToolTypeDatabase,
		`{"type":"object","properties":{"target":{"type":"object","properties":{"url":{"type":"string"}}}}}`:           ToolTypeNetwork,
		`{"type":"object","properties":{"files":{"type":"array","items":{"type":"object","properties":{"path":{}}}}}}`: ToolTypeFile,
		`{"type":"object","properties":{"message":{"type":"string"}}}`:                                                 "",
		`not json`: "",
	}
	for schema, want := range cases {
		if got := InferToolTypeFromSchema(json.RawMessage(schema)); got != want {
			t.Fatalf("InferToolTypeFromSchema(%s) = %q, want %q", schema, got, want)
		}
	}
}

func TestWS5CustomToolTypedBySchemaGetsAnalyzed(t *testing.T) {
	toolType := ResolveToolType("acme_sync", "", InferToolTypeFromSchema(json.RawMessage(`{"properties":{"endpoint":{}}}`)))
	decision := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
		ToolName: "acme_sync", ToolType: toolType,
		Arguments: map[string]any{"endpoint": "http://169.254.169.254/latest/meta-data"},
		Mode:      ModeAudit, Policy: blockingProtectionsPolicy(),
	})
	// 2.9.22：云元数据是防护项命中，配成阻断时判为阻断。
	if decision.RawDecision != DecisionBlock || decision.ProtectionItem != "agent.cloud_metadata" {
		t.Fatalf("schema-typed custom tool must reach the network analyzer, got %#v", decision)
	}
}

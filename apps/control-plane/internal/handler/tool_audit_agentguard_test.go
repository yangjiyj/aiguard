package handler

import (
	"encoding/json"
	"testing"
)

func TestInternalToolLogRequestDecodesAgentGuardFields(t *testing.T) {
	var req InternalToolLogRequest
	err := json.Unmarshal([]byte(`{
		"tool_name":"network.upload",
		"tool_type":"network",
		"raw_decision":"confirm",
		"effective_decision":"block",
		"mode":"strict",
		"effective_reason":"confirm_without_channel_fail_closed",
		"policy_version":"policy-v1",
		"trace_id":"trace-1",
		"endpoint_id":"ep-authenticated",
		"confidence":0.91,
		"evidence_json":[{"rule_id":"argument_tainted"}],
		"normalized_target":"https://evil.example/upload",
		"provenance":"tainted",
		"tainted_arguments":["url"],
		"event_kind":"invocation_proposed",
		"execution_observed":false,
		"result_observed":false,
		"tool_call_id":"call-1",
		"asset_id":"asset-1",
		"skill_invocation_id":"skill-1",
		"mcp_server_id":"server-1",
		"mcp_tool_id":"tool-1",
		"definition_hash":"sha256:def",
		"attribution_mode":"explicit",
		"attribution_confidence":0.99
	}`), &req)
	if err != nil {
		t.Fatalf("decode request: %v", err)
	}

	if req.RawDecision != "confirm" || req.EffectiveDecision != "block" || req.Mode != "strict" {
		t.Fatalf("decision fields were not decoded: %#v", req)
	}
	if req.PolicyVersion != "policy-v1" || req.TraceID != "trace-1" || req.EndpointID != "ep-authenticated" {
		t.Fatalf("policy or endpoint metadata was not decoded: %#v", req)
	}
	if req.Confidence != 0.91 {
		t.Fatalf("confidence = %v, want 0.91", req.Confidence)
	}
	if string(req.EvidenceJSON) != `[{"rule_id":"argument_tainted"}]` {
		t.Fatalf("unexpected evidence json: %s", string(req.EvidenceJSON))
	}
	if string(req.TaintedArguments) != `["url"]` {
		t.Fatalf("unexpected tainted args json: %s", string(req.TaintedArguments))
	}
	if req.EventKind != "invocation_proposed" || req.ExecutionObserved {
		t.Fatalf("runtime truth fields were not decoded: %#v", req)
	}
	if req.ToolCallID != "call-1" || req.AssetID != "asset-1" || req.SkillInvocationID != "skill-1" {
		t.Fatalf("correlation fields were not decoded: %#v", req)
	}
	if req.MCPServerID != "server-1" || req.MCPToolID != "tool-1" || req.DefinitionHash != "sha256:def" || req.AttributionMode != "explicit" || req.AttributionConfidence != 0.99 {
		t.Fatalf("asset attribution fields were not decoded: %#v", req)
	}
}

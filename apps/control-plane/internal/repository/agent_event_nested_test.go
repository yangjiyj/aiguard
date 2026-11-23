package repository

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func nestedFixture(typ string) json.RawMessage {
	return json.RawMessage(strings.ReplaceAll(strings.ReplaceAll(`{"event_id":"11111111-1111-7111-8111-111111111111","event_type":"TYPE","occurred_at":"TIME","agent":{"product":"claude-code","runtime":"cli"},"session":{"session_id":"session-1"},"turn":{"prompt_id":"prompt-1"},"context":{"machine_id":"m","hostname":"h","os_user":"u"},"tool":{"tool_use_id":"tool-1","name":"Bash","type":"system"},"local_decision":{"raw":"block","effective":"block","mode":"block","latency_ms":0,"source":"local","policy_version":1}}`, "TYPE", typ), "TIME", time.Now().UTC().Format(time.RFC3339Nano)))
}
func TestHookdNestedProjectionRetainsRawAndIndexes(t *testing.T) {
	raw := nestedFixture("tool.pre")
	r, err := decodeAgentEvent(raw, "ep_fixture")
	if err != nil {
		t.Fatal(err)
	}
	if r.SessionID != "session-1" || r.PromptID != "prompt-1" || r.ToolUseID != "tool-1" || r.ToolName != "Bash" || r.EndpointID != "ep_fixture" || r.Decision != "block" || r.Status != "blocked" {
		t.Fatalf("projection=%+v", r)
	}
	if !strings.Contains(string(r.Payload), `"session":{"session_id":"session-1"}`) || strings.Contains(string(r.Payload), "effective_decision") {
		t.Fatal("raw canonical event was rewritten")
	}
	if !strings.Contains(string(r.LocalDecision), `"effective_decision":"block"`) {
		t.Fatal("decision index absent")
	}
	_, action, alert := agentEventSecurityEventDecision(r)
	if !alert || action != "block" {
		t.Fatal("blocked nested event not projected to alert")
	}
}
func TestHookdNestedMultiAssetAndWouldBlock(t *testing.T) {
	var value map[string]any
	if err := json.Unmarshal(nestedFixture("asset.snapshot"), &value); err != nil {
		t.Fatal(err)
	}
	value["assets"] = []any{map[string]any{"asset_type": "skill", "name": "one", "present": true}, map[string]any{"asset_type": "plugin", "name": "two", "present": false}}
	local := value["local_decision"].(map[string]any)
	local["effective"] = "audit"
	local["mode"] = "would_block"
	raw, _ := json.Marshal(value)
	r, err := decodeAgentEvent(raw, "ep_fixture")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Assets) != 2 || r.Assets[0].Name != "one" || r.Assets[1].Present || r.Assets[0].Hash != "" {
		t.Fatalf("lost asset or invented hash: %+v", r.Assets)
	}
	if r.Decision != "would_block" {
		t.Fatal("would block mode lost")
	}
	if _, _, alert := agentEventSecurityEventDecision(r); alert {
		t.Fatal("would-block became real blocked alert")
	}
}
func TestHookdNestedRejectsMixedFlatAndNested(t *testing.T) {
	var value map[string]any
	_ = json.Unmarshal(nestedFixture("tool.post"), &value)
	value["session_id"] = "foreign"
	raw, _ := json.Marshal(value)
	if _, err := decodeAgentEvent(raw, "ep_fixture"); err == nil {
		t.Fatal("mixed identity accepted")
	}
}

func TestHookdNestedToolLifecycleFacts(t *testing.T) {
	for _, typ := range []string{"tool.pre", "tool.denied", "tool.post", "tool.failure"} {
		for _, hasResult := range []bool{false, true} {
			r, err := decodeAgentEvent(nestedFixture(typ), "ep_fixture")
			if err != nil {
				t.Fatal(err)
			}
			r.HasResult = hasResult
			kind, execution, result := agentToolLifecycleFacts(r)
			completed := typ == "tool.post" || typ == "tool.failure"
			if execution != completed || result != (completed && hasResult) {
				t.Fatalf("%s/%v: %s %v %v", typ, hasResult, kind, execution, result)
			}
			if (kind == "result_observed") != result {
				t.Fatalf("result fact constraint: %s/%v", typ, hasResult)
			}
			if completed && !hasResult && kind != "execution_forwarded" {
				t.Fatalf("missing execution fact: %s", kind)
			}
		}
	}
}

func TestHookdNestedTerminalMetadataUsesV1HashAndJSONNumberFields(t *testing.T) {
	var event map[string]any
	if err := json.Unmarshal(nestedFixture("tool.post"), &event); err != nil {
		t.Fatal(err)
	}
	tool := event["tool"].(map[string]any)
	tool["args_hash"] = "sha256:" + strings.Repeat("a", 64)
	tool["result"] = map[string]any{
		"hash": "sha256:" + strings.Repeat("b", 64), "len": json.Number("19"), "success": true,
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeAgentEvent(raw, "ep_fixture")
	if err != nil {
		t.Fatal(err)
	}
	if record.ArgumentsHash != "sha256:"+strings.Repeat("a", 64) || record.ResultHash != "sha256:"+strings.Repeat("b", 64) ||
		record.ResultLength != 19 || !record.HasResultLength || !record.HasResult || !record.HasResultSuccess || !record.ResultSuccess || record.ToolCallID != record.ToolUseID {
		t.Fatalf("nested terminal metadata projection=%+v", record)
	}
}
func TestHookdNestedLongToolName(t *testing.T) {
	raw := strings.Replace(string(nestedFixture("tool.post")), "\"name\":\"Bash\"", "\"name\":\""+strings.Repeat("x", 255)+"\"", 1)
	r, err := decodeAgentEvent([]byte(raw), "ep_fixture")
	if err != nil || len(r.ToolName) != 255 {
		t.Fatalf("max wire tool name: %v", err)
	}
}

func TestHookdNestedUUIDIdentityCanonical(t *testing.T) {
	raw := strings.Replace(string(nestedFixture("tool.pre")), "11111111-1111-7111-8111-111111111111", "AAAAAAAA-AAAA-7AAA-8AAA-AAAAAAAAAAAA", 1)
	r, err := decodeAgentEvent([]byte(raw), "ep_fixture")
	if err != nil {
		t.Fatal(err)
	}
	if agentEventAckID(r) != "AAAAAAAA-AAAA-7AAA-8AAA-AAAAAAAAAAAA" || r.ID != "aaaaaaaa-aaaa-7aaa-8aaa-aaaaaaaaaaaa" || !strings.Contains(string(r.Payload), "AAAAAAAA") {
		t.Fatal("identity or raw claim lost")
	}
}

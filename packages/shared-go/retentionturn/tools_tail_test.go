package retentionturn

import (
	"encoding/json"
	"testing"
)

func decodeObject(t *testing.T, body string) map[string]interface{} {
	t.Helper()
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestTailAfterLastUserTextAnthropicToolRound(t *testing.T) {
	decoded := decodeObject(t, `{"messages":[
		{"role":"user","content":"first"},
		{"role":"assistant","content":"a"},
		{"role":"user","content":"帮我看下 deploy.sh"},
		{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Read","input":{"file_path":"/etc/hosts"}}]},
		{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"127.0.0.1 localhost"}]}
	]}`)

	tail := TailAfterLastUserText(decoded)["messages"]
	if len(tail) != 3 {
		t.Fatalf("tail len = %d, want 3 (last user turn + tool_use + tool_result)", len(tail))
	}
	first, _ := tail[0].(map[string]interface{})
	if first["content"] != "帮我看下 deploy.sh" {
		t.Fatalf("tail must start at the last human turn, got %v", first["content"])
	}
}

func TestTailAfterLastUserTextResponsesInput(t *testing.T) {
	decoded := decodeObject(t, `{"input":[
		{"role":"user","content":"第一轮"},
		{"role":"assistant","content":"ok"},
		{"role":"user","content":"查一下"},
		{"type":"function_call","call_id":"call_a","name":"shell","arguments":"{\"cmd\":\"ls\"}"},
		{"type":"function_call_output","call_id":"call_a","output":"file1"}
	]}`)

	tail := TailAfterLastUserText(decoded)["input"]
	if len(tail) != 3 {
		t.Fatalf("tail len = %d, want 3", len(tail))
	}
}

func TestTailAfterLastUserTextWithoutHumanTurnKeepsEverything(t *testing.T) {
	decoded := decodeObject(t, `{"messages":[{"role":"tool","tool_call_id":"call_1","content":"result"}]}`)
	tail := TailAfterLastUserText(decoded)["messages"]
	if len(tail) != 1 {
		t.Fatalf("incremental tool-result-only request must keep its evidence, got %d", len(tail))
	}
	if _, present := TailAfterLastUserText(decodeObject(t, `{"model":"m"}`))["messages"]; present {
		t.Fatal("missing field must not be reported as present")
	}
}

func TestToolObservationsUnchangedByTailExtraction(t *testing.T) {
	raw := []byte(`{"messages":[
		{"role":"user","content":"first"},
		{"role":"assistant","content":[{"type":"tool_use","id":"toolu_old","name":"Old","input":{}}]},
		{"role":"user","content":"再来一轮"},
		{"role":"assistant","content":[{"type":"tool_use","id":"toolu_new","name":"Read","input":{}}]},
		{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_new","content":"ok"}]}
	]}`)
	observed := toolObservations(raw, true)
	current := false
	for _, observation := range observed {
		if observation.ID == Digest("tool-id\x00toolu_old") {
			t.Fatal("observation must not include tool calls from turns before the last human message")
		}
		if observation.ID == Digest("tool-id\x00toolu_new") && observation.Name == "Read" {
			current = true
		}
	}
	if !current {
		t.Fatalf("current turn tool call missing: %+v", observed)
	}
}

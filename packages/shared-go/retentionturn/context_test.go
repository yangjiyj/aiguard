package retentionturn

import (
	"encoding/json"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"strings"
	"testing"
)

func TestThreeProtocolToolLoopsAndRepeatedHumanOccurrences(t *testing.T) {
	cases := []struct{ name, path, request, response, next string }{
		{"chat", "/v1/chat/completions", `{"messages":[{"role":"user","content":"检查"}]}`, `{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":"read","arguments":"{}"}}]}}]}`, `{"messages":[{"role":"user","content":"检查"},{"role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":"read","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call-1","content":"result"}]}`},
		{"anthropic", "/v1/messages", `{"messages":[{"role":"user","content":"检查"}]}`, `{"content":[{"type":"tool_use","id":"call-1","name":"read","input":{}}]}`, `{"messages":[{"role":"user","content":"检查"},{"role":"assistant","content":[{"type":"tool_use","id":"call-1","name":"read","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"call-1","content":"result"}]}]}`},
		{"responses", "/v1/responses", `{"input":[{"role":"user","content":"检查"}]}`, `{"output":[{"type":"function_call","call_id":"call-1","name":"read","arguments":"{}"}]}`, `{"input":[{"role":"user","content":"检查"},{"type":"function_call","call_id":"call-1","name":"read","arguments":"{}"},{"type":"function_call_output","call_id":"call-1","output":"result"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, ok := aimsg.ParseChatRequest(tc.path, []byte(tc.request))
			if !ok {
				t.Fatal("first parse")
			}
			next, ok := aimsg.ParseChatRequest(tc.path, []byte(tc.next))
			if !ok {
				t.Fatal("next parse")
			}
			a := BuildRequest(first.Messages, []byte(tc.request), "identity")
			b := BuildRequest(next.Messages, []byte(tc.next), "identity")
			response := BuildResponse([]byte(tc.response), "")
			if a == nil || b == nil || a.HistoryKey != b.HistoryKey || b.UserCount != 1 || len(response.Links) != 1 {
				t.Fatalf("contexts=%+v %+v %+v", a, b, response)
			}
			found := false
			for _, link := range b.Links {
				found = found || link == response.Links[0]
			}
			if !found {
				t.Fatal("tool replay not correlated")
			}
			next.Messages = append(next.Messages, aimsg.ConvMessage{Role: "user", Source: aimsg.SourceUser, Content: "检查"})
			c := BuildRequest(next.Messages, nil, "identity")
			if c.UserCount != 2 || c.HistoryKey == a.HistoryKey {
				t.Fatal("repeated human submission merged")
			}
			raw := string(Patch(a, response))
			if strings.Contains(raw, "检查") || strings.Contains(raw, "call-1") || strings.Contains(raw, "identity") && strings.Contains(raw, "\"identity\"") {
				t.Fatal("raw context leaked")
			}
		})
	}
}
func TestSSEAndUnknownTextDoNotInventCompletion(t *testing.T) {
	response := BuildResponse([]byte("data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"id\":\"call-1\"}]}}]}\n\ndata: [DONE]\n"), "")
	if len(response.Links) != 1 {
		t.Fatalf("SSE links=%+v", response)
	}
	var patch map[string]interface{}
	if err := json.Unmarshal(Patch(nil, response), &patch); err != nil {
		t.Fatal(err)
	}
	if _, ok := patch["request"]; ok {
		t.Fatal("response patch overwrote request")
	}
	if _, ok := patch["status"]; ok {
		t.Fatal("wire completion claimed task status")
	}
	if got := BuildRequest([]aimsg.ConvMessage{{Role: "user", Source: aimsg.SourceToolResult, Content: "tool output"}}, nil, ""); got != nil {
		t.Fatal("tool result treated as question")
	}
}

func TestIncrementalToolResultCarriesLinksWithoutInventingUser(t *testing.T) {
	raw := []byte(`{"input":[{"type":"function_call_output","call_id":"call-1","output":"done"}]}`)
	parsed, ok := aimsg.ParseChatRequest("/v1/responses", raw)
	if !ok {
		t.Fatal("parse")
	}
	request := BuildRequest(parsed.Messages, raw, "caller")
	if request == nil || request.UserCount != 0 || request.HistoryKey != "" || len(request.Links) != 1 {
		t.Fatalf("incremental=%+v", request)
	}
	if got := BuildRequest([]aimsg.ConvMessage{{Role: "assistant", Source: aimsg.SourceAssistantHistory, Content: "old answer"}}, nil, "caller"); got != nil {
		t.Fatal("assistant-only background work treated as tool continuation")
	}
}

func TestClientMetadataDoesNotSplitHumanHistory(t *testing.T) {
	for _, client := range []string{"claude-code", "openai-codex", "workbuddy", "cline"} {
		t.Run(client, func(t *testing.T) {
			metadata := "# AGENTS.md instructions\n<INSTRUCTIONS>context</INSTRUCTIONS>\n<environment_context>host</environment_context>"
			if client == "claude-code" {
				metadata = "<system-reminder>Current workspace context</system-reminder>"
			}
			if client == "cline" {
				metadata = "<environment_details>\n# VSCode Visible Files\nmain.go\n</environment_details>"
			}
			if client == "workbuddy" {
				metadata = `<system-reminder data-role="user-context">workspace</system-reminder>`
			}
			question := "请修复问题"
			if client == "cline" {
				question = "<task>请修复问题</task>\n# task_progress RECOMMENDED\n<environment_details>workspace</environment_details>"
			}
			messages := []aimsg.ConvMessage{{Source: aimsg.SourceUser, Content: metadata}, {Source: aimsg.SourceUser, Content: question}}
			first := BuildRequest(messages, nil, client)
			if first == nil || first.Partial || first.UserCount != 1 {
				t.Fatalf("first=%+v", first)
			}
			messages = append(messages, aimsg.ConvMessage{Source: aimsg.SourceAssistantHistory, Content: "检查中"}, aimsg.ConvMessage{Source: aimsg.SourceToolResult, Content: "工具结果"})
			next := BuildRequest(messages, nil, client)
			if next.HistoryKey != first.HistoryKey || next.Partial {
				t.Fatalf("next=%+v", next)
			}
			messages = append(messages, aimsg.ConvMessage{Source: aimsg.SourceUser, Content: "继续"})
			final := BuildRequest(messages, nil, client)
			if final.HistoryKey == first.HistoryKey || final.UserCount != 2 {
				t.Fatal("new user input not separated")
			}
		})
	}
	ambiguous := BuildRequest([]aimsg.ConvMessage{{Source: aimsg.SourceUser, Content: "<system-reminder>unfinished"}, {Source: aimsg.SourceUser, Content: "text"}}, nil, "id")
	if ambiguous == nil || !ambiguous.Partial {
		t.Fatal("unknown/truncated envelope treated as complete")
	}
}

func TestToolsPreserveNamesAcrossProtocolsWithoutArgumentsOrOldTurns(t *testing.T) {
	for _, raw := range []string{
		`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call1","function":{"name":"read_file","arguments":"secret"}}]}}]}`,
		`{"content":[{"type":"tool_use","id":"call1","name":"read_file","input":{"secret":"value"}}]}`,
		`{"output":[{"type":"function_call","call_id":"call1","name":"read_file","arguments":"secret"}]}`,
		"data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"call1\",\"name\":\"read_file\",\"arguments\":\"secret\"}}\n\n",
	} {
		tools := BuildResponse([]byte(raw), "").Tools
		if len(tools) != 1 || tools[0].Name != "read_file" || tools[0].Kind != "invocation_proposed" {
			t.Fatalf("tools=%+v", tools)
		}
		body, _ := json.Marshal(tools)
		if strings.Contains(string(body), "secret") || strings.Contains(string(body), "call1") {
			t.Fatal("private payload retained")
		}
	}
	raw := []byte(`{"messages":[{"role":"user","content":"old"},{"role":"assistant","tool_calls":[{"id":"old","function":{"name":"old_tool"}}]},{"role":"user","content":"new"},{"role":"assistant","tool_calls":[{"id":"new","function":{"name":"new_tool"}}]},{"role":"tool","tool_call_id":"new","content":"result"}]}`)
	parsed, _ := aimsg.ParseChatRequest("/v1/chat/completions", raw)
	tools := BuildRequest(parsed.Messages, raw, "i").Tools
	if len(tools) != 2 || tools[0].Name != "new_tool" || tools[1].Kind != "result_observed" {
		t.Fatalf("old turn tools leaked: %+v", tools)
	}
	if tools := BuildResponse([]byte(`{"messages":[{"role":"user","content":[{"type":"tool_use","id":"fake","name":"fake"}]}],"tools":[{"type":"function","function":{"name":"definition"}}]}`), "").Tools; len(tools) != 0 {
		t.Fatalf("human text or definitions became calls: %+v", tools)
	}
}

func TestSSEToolNameCanArriveInFinalItem(t *testing.T) {
	raw := []byte("data: {\"item\":{\"type\":\"function_call\",\"call_id\":\"call1\",\"name\":\"\"}}\n\ndata: {\"item\":{\"type\":\"function_call\",\"call_id\":\"call1\",\"name\":\"read_file\"}}\n")
	tools := BuildResponse(raw, "").Tools
	if len(tools) != 1 || tools[0].Name != "read_file" {
		t.Fatalf("stream completion lost tool name: %+v", tools)
	}
}

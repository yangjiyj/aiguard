package handler

import (
	"encoding/json"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionturn"
	"net/http/httptest"
	"testing"
)

func TestForwardProxyTurnContextPreservesOccurrencesAndToolOnlyReply(t *testing.T) {
	record := ProxyAuditRecord{RequestID: "r1", TenantID: "tenant", ContentRetained: true, RetentionLevel: "content", SourceIP: "192.0.2.1", TargetHost: "api.example.com", AgentType: "custom"}
	request := httptest.NewRequest("POST", "https://api.example.com/v1/chat/completions", nil)
	request.Header.Set("Content-Type", "application/json")
	body := []byte(`{"messages":[{"role":"user","content":"检查"}]}`)
	response := []byte(`{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"read","arguments":"{}"}}]}}]}`)
	input := extractRequestContentWithDecoder(request, body, "openai_compatible")
	output := extractResponseContent(response, "application/json")
	var first retentionturn.Context
	if err := json.Unmarshal(forwardProxyTurnPatch(record, input, output, ""), &first); err != nil {
		t.Fatal(err)
	}
	if first.Request == nil || first.Response == nil || len(first.Response.Links) != 1 || len(first.Response.Tools) != 1 || first.Response.Tools[0].Name != "read" {
		t.Fatalf("context=%+v", first)
	}
	followup := extractRequestContentWithDecoder(request, []byte(`{"messages":[{"role":"user","content":"检查"},{"role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":"read","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call-1","content":"result"}]}`), "openai_compatible")
	var next retentionturn.Context
	if err := json.Unmarshal(forwardProxyTurnPatch(record, followup, ExtractedContent{}, "结果"), &next); err != nil {
		t.Fatal(err)
	}
	if first.Request.HistoryKey != next.Request.HistoryKey || next.Request.UserCount != 1 {
		t.Fatal("tool loop changed human occurrence")
	}
	found := false
	for _, link := range next.Request.Links {
		found = found || link == first.Response.Links[0]
	}
	if !found {
		t.Fatal("tool link lost")
	}
	incremental := extractRequestContentWithDecoder(request, []byte(`{"messages":[{"role":"tool","tool_call_id":"call-1","content":"result"}]}`), "openai_compatible")
	if incremental.TurnRequest == nil || incremental.TurnRequest.UserCount != 0 {
		t.Fatal("incremental tool result lost")
	}
	if _, ok := buildAccessContentLogPayload(record, incremental, ExtractedContent{}); !ok {
		t.Fatal("context-only continuation discarded")
	}
	record.ContentRetained = false
	if forwardProxyTurnPatch(record, input, output, "") != nil {
		t.Fatal("retention disabled but correlation retained")
	}
}

func TestForwardProxyRetainsProtocolToolsForAllAgentClients(t *testing.T) {
	for _, client := range []string{"claude-code", "openai-codex", "workbuddy", "cline"} {
		t.Run(client, func(t *testing.T) {
			request := httptest.NewRequest("POST", "https://api.example.com/v1/chat/completions", nil)
			request.Header.Set("Content-Type", "application/json")
			input := extractRequestContentWithDecoder(request, []byte(`{"messages":[{"role":"user","content":"检查"}]}`), "openai_compatible")
			output := extractResponseContent([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call1","function":{"name":"execute_command","arguments":"{}"}}]}}]}`), "application/json")
			record := ProxyAuditRecord{RequestID: "r", TenantID: "t", ContentRetained: true, RetentionLevel: "content", AgentType: client, SourceIP: "192.0.2.1", TargetHost: "api.example.com"}
			var c retentionturn.Context
			if err := json.Unmarshal(forwardProxyTurnPatch(record, input, output, ""), &c); err != nil {
				t.Fatal(err)
			}
			if c.Request == nil || c.Request.UserCount != 1 || c.Response == nil || len(c.Response.Tools) != 1 || c.Response.Tools[0].Name != "execute_command" {
				t.Fatalf("context=%+v", c)
			}
		})
	}
}

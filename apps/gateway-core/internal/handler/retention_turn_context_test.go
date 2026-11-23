package handler

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionturn"
	"testing"
)

type turnRecordingAudit struct {
	MockAuditWriter
	patches [][]byte
}

func (a *turnRecordingAudit) WriteRetentionTurnContext(_ context.Context, _ *modelrouter.RequestEnvelope, patch []byte) {
	a.patches = append(a.patches, patch)
}
func TestAPITurnContextWritesRequestAndToolOnlyResponse(t *testing.T) {
	audit := &turnRecordingAudit{}
	h := &ChatCompletionsHandler{auditWriter: NewBillingAuditWriter(NewAsyncAuditWriter(audit, nil), nil)}
	envelope := &modelrouter.RequestEnvelope{RequestID: "r1", TenantID: "tenant", ClientID: "client", EnvironmentScope: "customer"}
	h.writeRequestContentLogs(context.Background(), envelope, []Message{{Role: "user", Content: json.RawMessage(`"检查"`)}})
	h.writeResponseContentLogs(context.Background(), envelope, []byte(`{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"read","arguments":"{}"}}]}}]}`))
	if len(audit.patches) != 2 {
		t.Fatalf("patches=%d", len(audit.patches))
	}
	var input, output retentionturn.Context
	_ = json.Unmarshal(audit.patches[0], &input)
	_ = json.Unmarshal(audit.patches[1], &output)
	if input.Request == nil || input.Request.UserCount != 1 || output.Request != nil || output.Response == nil || len(output.Response.Links) != 1 || len(output.Response.Tools) != 1 || output.Response.Tools[0].Name != "read" {
		t.Fatalf("contexts=%+v %+v", input, output)
	}
	h.writeRequestContentLogs(context.Background(), envelope, []Message{{Role: "tool", ToolCallID: "call-1", Content: json.RawMessage(`"result"`)}})
	var continuation retentionturn.Context
	_ = json.Unmarshal(audit.patches[2], &continuation)
	if continuation.Request == nil || continuation.Request.UserCount != 0 || len(continuation.Request.Links) != 1 {
		t.Fatal("incremental request correlation lost")
	}

}
func TestReverseProxyTurnContextUsesFullHistoryAndCallerIdentity(t *testing.T) {
	raw := []byte(`{"messages":[{"role":"user","content":"继续"},{"role":"assistant","content":"第一个答复"},{"role":"user","content":"继续"}]}`)
	parsed, ok := aimsg.ParseChatRequest("/v1/messages", raw)
	if !ok {
		t.Fatal("parse")
	}
	record := reverseProxyAuditRecord{ContentRetained: true, ClientID: "caller-a", TargetHost: "api.example.com"}
	var a, b retentionturn.Context
	if err := json.Unmarshal(reverseProxyTurnPatch(record, parsed, true, raw, nil, "第二个答复"), &a); err != nil {
		t.Fatal(err)
	}
	record.ClientID = "caller-b"
	_ = json.Unmarshal(reverseProxyTurnPatch(record, parsed, true, raw, nil, "第二个答复"), &b)
	if a.Request == nil || a.Request.UserCount != 2 || a.Request.IdentityKey == b.Request.IdentityKey {
		t.Fatalf("contexts=%+v %+v", a, b)
	}
	record.ContentRetained = false
	if reverseProxyTurnPatch(record, parsed, true, raw, nil, "") != nil {
		t.Fatal("disabled retention")
	}
}

func TestAPITurnContextWriterBindsTenantAndTrustedScope(t *testing.T) {
	db := &mockDBExecutor{}
	writer := &RealAuditWriter{db: db}
	writer.WriteRetentionTurnContext(context.Background(), &modelrouter.RequestEnvelope{RequestID: "r1", TenantID: "tenant-a", EnvironmentScope: "customer"}, retentionturn.Patch(nil, retentionturn.BuildResponse(nil, "answer")))
	if db.execCalls != 1 || db.queries[0] != retentionturn.UpdateSQL || db.args[0][0] != "tenant-a" || db.args[0][1] != "r1" || db.args[0][2] != "customer" {
		t.Fatalf("unscoped write: %+v", db.args)
	}
	writer.WriteRetentionTurnContext(context.Background(), &modelrouter.RequestEnvelope{RequestID: "r1"}, []byte("{}"))
	if db.execCalls != 1 {
		t.Fatal("missing tenant permitted")
	}
}

func TestReverseProxyRetainsToolNamesForAllAgentClients(t *testing.T) {
	for _, client := range []string{"claude-code", "openai-codex", "workbuddy", "cline"} {
		t.Run(client, func(t *testing.T) {
			raw := []byte(`{"messages":[{"role":"user","content":"检查"}]}`)
			parsed, _ := aimsg.ParseChatRequest("/v1/messages", raw)
			record := reverseProxyAuditRecord{ContentRetained: true, ClientID: "caller", AgentType: client, TargetHost: "api.example.com"}
			response := []byte(`{"content":[{"type":"tool_use","id":"call1","name":"read_file","input":{"path":"private-file"}}]}`)
			var c retentionturn.Context
			if err := json.Unmarshal(reverseProxyTurnPatch(record, parsed, true, raw, response, ""), &c); err != nil {
				t.Fatal(err)
			}
			if c.Request == nil || c.Request.UserCount != 1 || c.Response == nil || len(c.Response.Tools) != 1 || c.Response.Tools[0].Name != "read_file" {
				t.Fatalf("context=%+v", c)
			}
		})
	}
}

func TestAPIClientsKeepOneHumanAcrossToolLoop(t *testing.T) {
	for _, client := range []string{"claude-code", "openai-codex", "workbuddy", "cline"} {
		t.Run(client, func(t *testing.T) {
			audit := &turnRecordingAudit{}
			h := &ChatCompletionsHandler{auditWriter: audit}
			envelope := &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t", ClientID: "c", AgentType: client, EnvironmentScope: "customer"}
			metadata := `"# AGENTS.md instructions\n<INSTRUCTIONS>context</INSTRUCTIONS>\n<environment_context>host</environment_context>"`
			if client == "workbuddy" {
				metadata = `"<system-reminder data-role=\"user-context\">workspace</system-reminder>"`
			}
			messages := []Message{{Role: "user", Content: json.RawMessage(metadata)}, {Role: "user", Content: json.RawMessage(`"检查"`)}}
			h.writeRequestContentLogs(context.Background(), envelope, messages)
			messages = append(messages, Message{Role: "assistant", ToolCalls: []ToolCall{{ID: "call1", Type: "function", Function: ToolCallFunc{Name: "read_file", Arguments: "{}"}}}}, Message{Role: "tool", ToolCallID: "call1", Content: json.RawMessage(`"result"`)})
			h.writeRequestContentLogs(context.Background(), envelope, messages)
			var a, b retentionturn.Context
			_ = json.Unmarshal(audit.patches[0], &a)
			_ = json.Unmarshal(audit.patches[1], &b)
			if a.Request == nil || b.Request == nil || a.Request.Partial || b.Request.Partial || a.Request.HistoryKey != b.Request.HistoryKey || b.Request.UserCount != 1 || len(b.Request.Tools) != 2 {
				t.Fatalf("API client context failed: %+v %+v", a, b)
			}
		})
	}
}

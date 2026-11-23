package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

// ---------- 上游成因（记录在案；这些输入今天就能产生空名工具） ----------

// 流式：上游只发参数增量、没有带名字的 start，累积器会凭空建出无名工具。
func TestUpstreamCause_StreamArgumentsWithoutStartYieldNamelessToolCall(t *testing.T) {
	acc := newLiveStreamAccumulator()
	acc.observeEvent(relay.StreamEvent{Type: relay.EventToolArgumentsDelta, Index: 0,
		ToolCall: &relay.ToolCall{ID: "call_1", Index: 0}, Delta: `{"path":"/tmp/a"}`})
	body, err := acc.responseBody("req-1")
	if err != nil {
		t.Fatal(err)
	}
	var resp ChatCompletionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Choices) == 0 || len(resp.Choices[0].Message.ToolCalls) != 1 || resp.Choices[0].Message.ToolCalls[0].Function.Name != "" {
		t.Fatalf("nameless tool did not reproduce: %s", body)
	}
}

// 原生 Messages：tool_use 块缺 name，审计载荷的 ToolName 为空（只标记 ProtocolIdentityRejected）。
func TestUpstreamCause_NativeToolUseWithoutNameBuildsEmptyAuditToolName(t *testing.T) {
	call := ToolCall{ID: "toolu_1", Type: "function", ProtocolIdentityRejected: true, Function: ToolCallFunc{Arguments: `{}`}}
	if payload := buildAgentGuardToolAuditPayload(call, agentguard.Decision{}, nil); payload.ToolName != "" {
		t.Fatalf("expected empty ToolName, got %q", payload.ToolName)
	}
}

// ---------- 修复：唯一出口 LogToolCallWithID 补默认值并保留标记 ----------

type capturedToolLog struct {
	mu     sync.Mutex
	bodies []map[string]any
}

func (c *capturedToolLog) last() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.bodies) == 0 {
		return nil
	}
	return c.bodies[len(c.bodies)-1]
}

// strictControlPlane 与控制面 tool_audit.go:94 的校验一致：tool_name/tool_type 为空返回 400。
func strictControlPlane(t *testing.T) (*httptest.Server, *capturedToolLog) {
	t.Helper()
	captured := &capturedToolLog{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		captured.mu.Lock()
		captured.bodies = append(captured.bodies, m)
		captured.mu.Unlock()
		if m["tool_name"] == "" || m["tool_type"] == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"tc_1"}`))
	}))
	t.Cleanup(server.Close)
	return server, captured
}

func notesOf(t *testing.T, body map[string]any) []string {
	t.Helper()
	params, _ := body["parameters"].(map[string]any)
	raw, _ := params[toolAuditNotesKey].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, v.(string))
	}
	return out
}

func TestLogToolCallFillsUnknownForBlankToolNameAndKeepsMarker(t *testing.T) {
	server, captured := strictControlPlane(t)
	client := NewToolRiskClient(server.URL, "secret")
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-1", TenantID: "tenant-1"}
	for _, blank := range []string{"", "   ", "\t\n"} {
		err := client.LogToolCall(context.Background(), envelope, ToolAuditLogPayload{
			ToolName: blank, ToolType: "unknown", ToolCallID: "call_9", EventKind: "invocation_proposed",
			Parameters: map[string]any{"path": "/etc/hosts"},
		})
		if err != nil {
			t.Fatalf("blank=%q: %v", blank, err)
		}
		body := captured.last()
		if body["tool_name"] != "unknown" {
			t.Fatalf("blank=%q tool_name=%v", blank, body["tool_name"])
		}
		if body["tool_call_id"] != "call_9" || body["event_kind"] != "invocation_proposed" {
			t.Fatalf("identity fields lost: %v", body)
		}
		if got := notesOf(t, body); len(got) != 1 || got[0] != "tool_name_missing" {
			t.Fatalf("notes=%v", got)
		}
		if params := body["parameters"].(map[string]any); params["path"] != "/etc/hosts" {
			t.Fatalf("original parameters lost: %v", params)
		}
	}
}

func TestLogToolCallInfersToolTypeWhenBlank(t *testing.T) {
	server, captured := strictControlPlane(t)
	client := NewToolRiskClient(server.URL, "secret")
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-1", TenantID: "tenant-1"}
	cases := []struct{ name, wantType string }{{"read_file", "file"}, {"bash", "system"}, {"acme_sync", "unknown"}, {"", "unknown"}}
	for _, tc := range cases {
		if err := client.LogToolCall(context.Background(), envelope, ToolAuditLogPayload{ToolName: tc.name, ToolType: ""}); err != nil {
			t.Fatalf("name=%q: %v", tc.name, err)
		}
		body := captured.last()
		if body["tool_type"] != tc.wantType {
			t.Fatalf("name=%q tool_type=%v want %s", tc.name, body["tool_type"], tc.wantType)
		}
		if notes := notesOf(t, body); !contains(notes, "tool_type_missing") {
			t.Fatalf("name=%q notes=%v missing tool_type_missing", tc.name, notes)
		}
	}
}

func TestLogToolCallLeavesValidPayloadUntouched(t *testing.T) {
	server, captured := strictControlPlane(t)
	client := NewToolRiskClient(server.URL, "secret")
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-1", TenantID: "tenant-1"}
	params := map[string]any{"url": "https://example.test"}
	if err := client.LogToolCall(context.Background(), envelope, ToolAuditLogPayload{ToolName: " web_fetch ", ToolType: "network", Parameters: params}); err != nil {
		t.Fatal(err)
	}
	body := captured.last()
	if body["tool_name"] != " web_fetch " || body["tool_type"] != "network" {
		t.Fatalf("valid fields rewritten: %v", body)
	}
	if got := notesOf(t, body); len(got) != 0 {
		t.Fatalf("unexpected notes %v", got)
	}
	if _, polluted := params[toolAuditNotesKey]; polluted {
		t.Fatal("caller's parameters map was mutated")
	}
}

func TestLogToolCallDoesNotMutateCallersParametersWhenNormalizing(t *testing.T) {
	server, _ := strictControlPlane(t)
	client := NewToolRiskClient(server.URL, "secret")
	params := map[string]any{"k": "v"}
	_ = client.LogToolCall(context.Background(), &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t"},
		ToolAuditLogPayload{ToolName: "", Parameters: params})
	if _, polluted := params[toolAuditNotesKey]; polluted || len(params) != 1 {
		t.Fatalf("caller map mutated: %v", params)
	}
}

func TestLogToolCallWithIDStillReturnsStoredIDAfterNormalizing(t *testing.T) {
	server, _ := strictControlPlane(t)
	client := NewToolRiskClient(server.URL, "secret")
	id, err := client.LogToolCallWithID(context.Background(), &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t"}, ToolAuditLogPayload{ToolName: ""})
	if err != nil || id != "tc_1" {
		t.Fatalf("id=%q err=%v", id, err)
	}
}

// 非 2xx 的错误仍然要返回给调用方（不能吞），且文本里只有状态码。
func TestLogToolCallStillReportsServerRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("password=hunter2 body detail"))
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, "secret")
	err := client.LogToolCall(context.Background(), &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t"}, ToolAuditLogPayload{ToolName: "x", ToolType: "file"})
	if err == nil || !strings.Contains(err.Error(), "status 500") || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("err=%v", err)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

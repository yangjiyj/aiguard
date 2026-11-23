package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionturn"
)

const (
	toolTurnUserText   = "帮我看下 deploy.sh"
	toolTurnUseLine    = `[tool_use:Read] {"file_path":"/tmp/deploy.sh"}`
	toolTurnResultBody = "#!/bin/bash\n\n\necho hi"
	toolTurnWantSect1  = "【工具】[tool_use:Read] {\"file_path\":\"/tmp/deploy.sh\"}"
	toolTurnWantSect2  = "【工具】#!/bin/bash\necho hi"
)

func toolTurnMessages() []ConvMessage {
	return []ConvMessage{
		{Role: "system", Source: aimsg.SourceSystemPrompt, Content: "You are Claude Code."},
		{Role: "user", Source: aimsg.SourceUser, Content: "第一轮问题"},
		{Role: "assistant", Source: aimsg.SourceAssistantHistory, Content: "好的"},
		{Role: "user", Source: aimsg.SourceUser, Content: toolTurnUserText},
		{Role: "assistant", Source: aimsg.SourceAssistantHistory, Content: toolTurnUseLine},
		{Role: "user", Source: aimsg.SourceToolResult, Content: toolTurnResultBody},
	}
}

func TestRetainedRequestTextKeepsHumanTurnAndToolTail(t *testing.T) {
	userText, sections := retainedRequestText(toolTurnMessages())
	if userText != toolTurnUserText {
		t.Fatalf("userText = %q, want %q", userText, toolTurnUserText)
	}
	if len(sections) != 2 || sections[0] != toolTurnWantSect1 || sections[1] != toolTurnWantSect2 {
		t.Fatalf("tool sections = %#v", sections)
	}
}

func TestRetainedRequestTextPlainTurnMatchesLegacyByteForByte(t *testing.T) {
	messages := []ConvMessage{
		{Role: "system", Source: aimsg.SourceSystemPrompt, Content: "You are WorkBuddy agent big prompt"},
		{Role: "user", Source: aimsg.SourceUser, Content: "真的吗"},
		{Role: "assistant", Source: aimsg.SourceAssistantHistory, Content: "是啊"},
	}
	userText, sections := retainedRequestText(messages)
	if len(sections) != 0 {
		t.Fatalf("plain turn must not produce tool sections: %#v", sections)
	}
	if userText != retainedUserTurnText(messages) {
		t.Fatalf("userText drifted from retainedUserTurnText: %q vs %q", userText, retainedUserTurnText(messages))
	}
}

func TestRetainedRequestTextWithoutHumanTurnIsEmpty(t *testing.T) {
	messages := []ConvMessage{{Role: "user", Source: aimsg.SourceToolResult, Content: "orphan tool output"}}
	userText, sections := retainedRequestText(messages)
	if userText != "" || len(sections) != 0 {
		t.Fatalf("incremental tool-only request must not invent a human turn: %q %#v", userText, sections)
	}
}

func TestRetainedResponseToolSections(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []string
	}{
		{"pure tool_use", `[tool_use:Bash] {"command":"ls"}`, []string{`【工具】[tool_use:Bash] {"command":"ls"}`}},
		{"ssE reassembled", "[tool] [tool_use:Bash] {\"command\":\"ls\"}", []string{`【工具】[tool_use:Bash] {"command":"ls"}`}},
		{"reasoning dropped", "[reasoning] 想一下\n[tool_use:Bash] {\"command\":\"ls\"}", []string{`【工具】[tool_use:Bash] {"command":"ls"}`}},
		{"no tools", "[reasoning] 想一下\n好的", nil},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := retainedResponseToolSections(testCase.text)
			if strings.Join(got, "|") != strings.Join(testCase.want, "|") {
				t.Fatalf("sections = %#v, want %#v", got, testCase.want)
			}
		})
	}
}

func TestBuildAccessContentLogRetainsToolTurnEvidence(t *testing.T) {
	record := ProxyAuditRecord{RequestID: "req_tool", TenantID: "tenant_default", Provider: "anthropic", Product: "anthropic_messages", RetentionLevel: "content", ContentRetained: true}
	request := ExtractedContent{Messages: toolTurnMessages()}
	response := ExtractedContent{Text: `[tool_use:Bash] {"command":"ls"}`, VisibleTextKnown: true}

	payload, ok := buildAccessContentLogPayload(record, request, response)
	if !ok {
		t.Fatal("tool turn must still build a retained payload")
	}
	wantRequest := toolTurnUserText + "\n\n" + toolTurnWantSect1 + "\n\n" + toolTurnWantSect2
	if payload.RequestContentRedacted != wantRequest {
		t.Fatalf("request retention = %q, want %q", payload.RequestContentRedacted, wantRequest)
	}
	if payload.ResponseContentRedacted != "【工具】[tool_use:Bash] {\"command\":\"ls\"}" {
		t.Fatalf("a tool-only reply must retain its tool call, got %q", payload.ResponseContentRedacted)
	}
	if payload.DecoderVersion != "v3" {
		t.Fatalf("decoder version = %q, want v3", payload.DecoderVersion)
	}
}

func TestBuildAccessContentLogKeepsVisibleTextBeforeToolSections(t *testing.T) {
	record := ProxyAuditRecord{RequestID: "req_tool2", TenantID: "tenant_default", Provider: "anthropic", Product: "anthropic_messages", RetentionLevel: "content", ContentRetained: true}
	response := ExtractedContent{
		Text:             "好的\n[tool_use:Bash] {\"command\":\"ls\"}",
		VisibleText:      "好的",
		VisibleTextKnown: true,
	}
	payload, ok := buildAccessContentLogPayload(record, ExtractedContent{Messages: toolTurnMessages()}, response)
	if !ok {
		t.Fatal("expected payload")
	}
	want := "好的\n\n【工具】[tool_use:Bash] {\"command\":\"ls\"}"
	if payload.ResponseContentRedacted != want {
		t.Fatalf("response retention = %q, want %q", payload.ResponseContentRedacted, want)
	}
}

func TestBuildAccessContentLogVisibleOnlyResponseIsUnchanged(t *testing.T) {
	record := ProxyAuditRecord{RequestID: "req_plain", TenantID: "tenant_default", Provider: "anthropic", Product: "anthropic_messages", RetentionLevel: "content", ContentRetained: true}
	response := ExtractedContent{Text: "好的", VisibleText: "[reasoning] 想一下\n好的", VisibleTextKnown: true}
	payload, ok := buildAccessContentLogPayload(record, ExtractedContent{}, response)
	if !ok {
		t.Fatal("expected payload")
	}
	if payload.ResponseContentRedacted != "好的" {
		t.Fatalf("visible-only response drifted: %q", payload.ResponseContentRedacted)
	}
}

func TestBuildAccessContentLogTruncatesToolTailButKeepsHumanTurn(t *testing.T) {
	record := ProxyAuditRecord{RequestID: "req_big", TenantID: "tenant_default", Provider: "anthropic", Product: "anthropic_messages", RetentionLevel: "content", ContentRetained: true}
	head := "看下这个文件"
	var body strings.Builder
	for body.Len() < 100*1024 {
		body.WriteString("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n")
	}
	request := ExtractedContent{Messages: []ConvMessage{
		{Role: "user", Source: aimsg.SourceUser, Content: head},
		{Role: "user", Source: aimsg.SourceToolResult, Content: body.String()},
	}}

	payload, ok := buildAccessContentLogPayload(record, request, ExtractedContent{})
	if !ok {
		t.Fatal("expected payload")
	}
	got := payload.RequestContentRedacted
	if !strings.HasPrefix(got, head) {
		t.Fatalf("human turn must survive truncation, got prefix %q", got[:min(60, len(got))])
	}
	if !strings.HasSuffix(got, "...[truncated]") {
		t.Fatalf("oversized tool tail must carry a truncation marker, got suffix %q", got[len(got)-40:])
	}
	if len(got) > maxAccessRetentionTextBytes {
		t.Fatalf("retained request text exceeds budget: %d", len(got))
	}
}

func TestBuildAccessContentLogEmptyToolCallsIsEmptyArray(t *testing.T) {
	record := ProxyAuditRecord{RequestID: "req_none", TenantID: "tenant_default", Provider: "deepseek", Product: "deepseek_chat", RetentionLevel: "content", ContentRetained: true}
	payload, ok := buildAccessContentLogPayload(record, ExtractedContent{Text: "你好"}, ExtractedContent{Text: "你好"})
	if !ok {
		t.Fatal("expected payload")
	}
	if payload.ToolCallMetadataJSON != "[]" {
		t.Fatalf("empty tool calls must serialize as [], got %q", payload.ToolCallMetadataJSON)
	}
}

func TestAccessContentLogSQLPersistsToolCallMetadata(t *testing.T) {
	statement := accessContentLogUpsertSQL()
	for _, fragment := range []string{"tool_call_metadata_json", "$16::jsonb", "tool_call_metadata_json = EXCLUDED.tool_call_metadata_json"} {
		if !strings.Contains(statement, fragment) {
			t.Fatalf("upsert statement missing %q:\n%s", fragment, statement)
		}
	}
}

func TestRetainedRequestToolCallsAnthropicToolRound(t *testing.T) {
	raw := []byte(`{"model":"claude","messages":[
		{"role":"user","content":"第一轮"},
		{"role":"assistant","content":[{"type":"tool_use","id":"toolu_old","name":"Old","input":{}}]},
		{"role":"user","content":"帮我看下 hosts"},
		{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Read","input":{"file_path":"/etc/hosts"}}]},
		{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"127.0.0.1 localhost"}]}
	]}`)

	calls := retainedRequestToolCalls(raw)
	if len(calls) != 2 {
		t.Fatalf("calls = %+v", calls)
	}
	digest := retentionturn.Digest("tool-id\x00toolu_1")
	if calls[0].ID != digest || calls[0].Name != "Read" || calls[0].Kind != "invocation_proposed" || calls[0].Stage != "request" {
		t.Fatalf("invocation call = %+v", calls[0])
	}
	if calls[0].ArgumentsPreview != `{"file_path":"/etc/hosts"}` {
		t.Fatalf("arguments preview = %q", calls[0].ArgumentsPreview)
	}
	if calls[1].ID != digest || calls[1].Kind != "result_observed" || calls[1].ResultPreview != "127.0.0.1 localhost" {
		t.Fatalf("result call = %+v", calls[1])
	}
	if calls[1].Name != "" || calls[1].ArgumentsPreview != "" {
		t.Fatalf("result call must not invent a name or arguments: %+v", calls[1])
	}
}

func TestRetainedRequestToolCallsOpenAIResponses(t *testing.T) {
	raw := []byte(`{"input":[
		{"role":"user","content":"查一下"},
		{"type":"function_call","call_id":"call_a","name":"shell","arguments":"{\"cmd\":\"ls\"}"},
		{"type":"function_call_output","call_id":"call_a","output":"file1"}
	]}`)

	calls := retainedRequestToolCalls(raw)
	if len(calls) != 2 {
		t.Fatalf("calls = %+v", calls)
	}
	if calls[0].Name != "shell" || calls[0].ArgumentsPreview != `{"cmd":"ls"}` || calls[0].Kind != "invocation_proposed" {
		t.Fatalf("function_call = %+v", calls[0])
	}
	if calls[1].Kind != "result_observed" || calls[1].ResultPreview != "file1" {
		t.Fatalf("function_call_output = %+v", calls[1])
	}
}

func TestRetainedRequestToolCallsOpenAIChat(t *testing.T) {
	raw := []byte(`{"messages":[
		{"role":"user","content":"查一下"},
		{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"shell","arguments":"{\"cmd\":\"ls\"}"}}]},
		{"role":"tool","tool_call_id":"call_1","name":"shell","content":"file1"}
	]}`)

	calls := retainedRequestToolCalls(raw)
	if len(calls) != 2 {
		t.Fatalf("calls = %+v", calls)
	}
	if calls[0].Name != "shell" || calls[0].ArgumentsPreview != `{"cmd":"ls"}` {
		t.Fatalf("tool_calls = %+v", calls[0])
	}
	if calls[1].Kind != "result_observed" || calls[1].ResultPreview != "file1" {
		t.Fatalf("role=tool = %+v", calls[1])
	}
}

func TestRetainedToolCallPreviewsRedactSecrets(t *testing.T) {
	const secret = "sk-abcdefghijklmnopqrstuvwxyz0123456789"
	calls := retainedRequestToolCalls([]byte(`{"messages":[
		{"role":"user","content":"看看这个"},
		{"role":"assistant","content":[{"type":"tool_use","id":"toolu_k","name":"Bash","input":{"api_key":"` + secret + `"}}]},
		{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_k","content":"OPENAI_API_KEY=` + secret + `"}]}
	]}`))
	if len(calls) != 2 {
		t.Fatalf("calls = %+v", calls)
	}
	for _, call := range calls {
		if strings.Contains(call.ArgumentsPreview, secret) || strings.Contains(call.ResultPreview, secret) {
			t.Fatalf("tool preview leaked the raw credential: %+v", call)
		}
	}
	if !strings.Contains(calls[0].ArgumentsPreview, "<redacted:secret>") {
		t.Fatalf("expected redaction marker in %q", calls[0].ArgumentsPreview)
	}
}

func TestRetainedToolCallPreviewsAreTruncated(t *testing.T) {
	long := strings.Repeat("a", 4000)
	calls := retainedRequestToolCalls([]byte(`{"messages":[
		{"role":"user","content":"看看"},
		{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_l","content":"` + long + `"}]}
	]}`))
	if len(calls) != 1 {
		t.Fatalf("calls = %+v", calls)
	}
	if runes := []rune(calls[0].ResultPreview); len(runes) != maxRetainedToolPreviewRunes {
		t.Fatalf("preview runes = %d, want %d", len(runes), maxRetainedToolPreviewRunes)
	}
}

func TestRetainedResponseToolCallsPairsIDsByOrder(t *testing.T) {
	observations := []retentionturn.ToolObservation{
		{ID: retentionturn.Digest("tool-id\x00b1"), Name: "Bash", Kind: "invocation_proposed"},
		{ID: retentionturn.Digest("tool-id\x00b2"), Name: "Read", Kind: "invocation_proposed"},
		{ID: retentionturn.Digest("tool-id\x00other"), Name: "", Kind: "result_observed"},
	}

	calls := retainedResponseToolCalls("[tool] [tool_use:Bash] {\"command\":\"ls\"}\n[tool_use:Read] {\"file_path\":\"/tmp/a\"}", observations)
	if len(calls) != 2 {
		t.Fatalf("calls = %+v", calls)
	}
	if calls[0].ID != observations[0].ID || calls[0].Stage != "response" || calls[0].Kind != "invocation_proposed" {
		t.Fatalf("first call = %+v", calls[0])
	}
	if calls[1].ID != observations[1].ID {
		t.Fatalf("second call must pair with the second invocation: %+v", calls[1])
	}
	if calls[1].ArgumentsPreview != `{"file_path":"/tmp/a"}` {
		t.Fatalf("arguments preview = %q", calls[1].ArgumentsPreview)
	}

	// 名字对不上时宁可没有 id，也不给错误关联。
	mismatched := retainedResponseToolCalls("[tool_use:Unknown] {}", observations[:1])
	if len(mismatched) != 1 || mismatched[0].ID != "" {
		t.Fatalf("mismatched name must leave the correlation empty: %+v", mismatched)
	}
}

func TestRetainedRequestToolCallsSerializesAsJSONArray(t *testing.T) {
	calls := retainedRequestToolCalls([]byte(`{"messages":[{"role":"tool","tool_call_id":"call_1","content":"x"}]}`))
	raw, err := json.Marshal(calls)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == "null" {
		t.Fatal("request tool calls must serialize as a JSON array")
	}
}

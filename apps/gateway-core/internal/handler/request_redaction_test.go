package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

const redactionTestToken = "<JJD_phone_0123456789abcdef0123456789abcdef_0>"

func redactionTestContext() (context.Context, *modelrouter.RequestEnvelope) {
	ctx := withBlockLedger(context.Background())
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-private", TenantID: "tenant-private", ProjectID: "project", Model: "gpt-4"}
	addRequestRedaction(ctx, envelope, redactionTestToken, map[string]string{redactionTestToken: "13800138000"})
	return ctx, envelope
}

func TestRequestRedactionIsolationAndUnregisteredValues(t *testing.T) {
	ctx, envelope := redactionTestContext()
	raw := []byte(fmt.Sprintf(`{"id":%q,"choices":[{"message":{"content":%q}}]}`, redactionTestToken, "电话 "+redactionTestToken+" xxx <MASKED>"))
	restored := restoreRedactionBody(ctx, envelope, raw)
	var parsed map[string]any
	_ = json.Unmarshal(restored, &parsed)
	if parsed["id"] != redactionTestToken {
		t.Fatal("metadata must not be restored")
	}
	if !strings.Contains(string(restored), "13800138000 xxx") {
		t.Fatalf("wrong restoration: %s", restored)
	}
	for _, other := range []*modelrouter.RequestEnvelope{{RequestID: "other", TenantID: envelope.TenantID}, {RequestID: envelope.RequestID, TenantID: "other"}} {
		if string(restoreRedactionBody(ctx, other, raw)) != string(raw) {
			t.Fatal("cross-request/tenant restoration")
		}
	}
	fresh := withBlockLedger(context.Background())
	if hasRequestRedaction(fresh, envelope) {
		t.Fatal("map leaked to fresh request")
	}
	addRequestRedaction(ctx, envelope, "xxx", map[string]string{"xxx": "must-never-restore"})
	if len(requestRedactionValues(ctx, envelope)) != 1 {
		t.Fatal("non-issued placeholder accepted")
	}
}

func TestRequestRedactionSSESplitTokensAndCompletionChoices(t *testing.T) {
	ctx, envelope := redactionTestContext()
	half := len(redactionTestToken) / 2
	frames := []string{}
	for _, part := range []string{redactionTestToken[:half], redactionTestToken[half:]} {
		// Both choices are represented at position zero in separate provider frames.
		for _, choice := range []int{0, 1} {
			text := part
			if choice == 1 {
				text = "other-" + part
			}
			raw := fmt.Sprintf(`{"object":"chat.completion.chunk","choices":[{"index":%d,"delta":{"content":%q}}]}`, choice, text)
			frames = append(frames, "data: "+raw+"\n\n")
		}
	}
	body := []byte(strings.Join(frames, "") + "data: [DONE]\n\n")
	restored := restoreRedactionBody(ctx, envelope, body)
	got := map[int]string{}
	for _, line := range strings.Split(string(restored), "\n") {
		if !strings.HasPrefix(line, "data: {") {
			continue
		}
		var payload struct {
			Choices []struct {
				Index int
				Delta struct{ Content string }
			}
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &payload); err != nil {
			t.Fatal(err)
		}
		for _, choice := range payload.Choices {
			got[choice.Index] += choice.Delta.Content
		}
	}
	if got[0] != "13800138000" {
		t.Fatalf("split token failed: %q", got[0])
	}
	if got[1] != "other-"+redactionTestToken[:half]+"other-"+redactionTestToken[half:] {
		t.Fatalf("cross-choice merge: %q", got[1])
	}
	if !strings.HasSuffix(string(restored), "data: [DONE]\n\n") {
		t.Fatal("SSE terminator changed")
	}
}

func TestRequestRedactionNativeSSEAndJSONToolArguments(t *testing.T) {
	ctx, envelope := redactionTestContext()
	for _, kind := range []string{"response.output_text.delta", "content_block_delta"} {
		var frames []string
		for _, part := range []string{redactionTestToken[:20], redactionTestToken[20:]} {
			var raw string
			if kind == "content_block_delta" {
				raw = fmt.Sprintf(`{"type":%q,"index":0,"delta":{"type":"text_delta","text":%q}}`, kind, part)
			} else {
				raw = fmt.Sprintf(`{"type":%q,"output_index":0,"content_index":0,"delta":%q}`, kind, part)
			}
			frames = append(frames, "event: "+kind+"\ndata: "+raw+"\n\n")
		}
		restored := string(restoreRedactionBody(ctx, envelope, []byte(strings.Join(frames, ""))))
		if strings.Contains(restored, "JJD_") || !strings.Contains(restored, "13800138000") {
			t.Fatalf("native restoration failed: %s", restored)
		}
	}
	quotedToken := "<JJD_name_0123456789abcdef0123456789abcdef_1>"
	original := "客户\"名\\称"
	addRequestRedaction(ctx, envelope, quotedToken, map[string]string{quotedToken: original})
	args, _ := json.Marshal(map[string]any{"name": quotedToken})
	body, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"tool_calls": []any{map[string]any{"function": map[string]any{"arguments": string(args)}}}}}}})
	restored := restoreRedactionBody(ctx, envelope, body)
	var response ChatCompletionResponse
	if err := json.Unmarshal(restored, &response); err != nil {
		t.Fatal(err)
	}
	var argument map[string]any
	if err := json.Unmarshal([]byte(response.Choices[0].Message.ToolCalls[0].Function.Arguments), &argument); err != nil {
		t.Fatal("invalid restored JSON arguments", err)
	}
	if argument["name"] != original {
		t.Fatalf("quoted original corrupted: %#v", argument)
	}
}

func TestRequestRedactionRestoresOnlyDeliveryAfterAudit(t *testing.T) {
	ctx, envelope := redactionTestContext()
	audit := &MockAuditWriter{}
	handler := &ChatCompletionsHandler{auditWriter: audit}
	raw := []byte(fmt.Sprintf(`{"choices":[{"message":{"role":"assistant","content":%q}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`, redactionTestToken))
	writer := httptest.NewRecorder()
	handler.finalizeChatJSONSuccess(ctx, writer, chatJSONSuccessFinalizerInput{envelope: envelope, respBody: raw, startedAt: time.Now()})
	if !strings.Contains(writer.Body.String(), "13800138000") {
		t.Fatalf("delivery did not restore: %s", writer.Body.String())
	}
	for _, entry := range audit.ContentLogWrites {
		if strings.Contains(entry.Content, "13800138000") {
			t.Fatal("restored original entered retention")
		}
	}
	if len(audit.RequestLogFinalizes) != 1 {
		t.Fatal("response was not audited")
	}
}

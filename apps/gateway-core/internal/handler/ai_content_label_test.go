package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/aicontentlabel"
)

const labelTestSecret = "synthetic-label-secret"
const labelTestRequestID = "req_6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"

func labelTestClient(t *testing.T, settings aicontentlabel.Settings) *ToolRiskClient {
	t.Helper()
	client := NewToolRiskClient("http://127.0.0.1:1", labelTestSecret)
	client.setAIContentLabelSettings(settings)
	return client
}

func labelOnSettings() aicontentlabel.Settings {
	s := aicontentlabel.DefaultSettings()
	s.ExplicitEnabled = true
	s.WatermarkEnabled = true
	return s
}

func portalEnvelope() *modelrouter.RequestEnvelope {
	return &modelrouter.RequestEnvelope{RequestID: labelTestRequestID, TenantID: "t_1", AgentType: aicontentlabel.PortalAgentType}
}

// requireWatermark 断言文本里恰好有一个能校验通过的水印，且指向测试请求号。
func requireWatermark(t *testing.T, text string) {
	t.Helper()
	frames := aicontentlabel.Find(text)
	if len(frames) != 1 {
		t.Fatalf("want exactly one watermark frame, got %d in %q", len(frames), text)
	}
	got, ok := aicontentlabel.Verify(frames[0], aicontentlabel.DeriveKey(labelTestSecret))
	if !ok || got != labelTestRequestID {
		t.Fatalf("watermark verify = %q, %v", got, ok)
	}
}

func decodeJSONMap(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("invalid JSON %q: %v", raw, err)
	}
	return m
}

func TestDeliverResponseBodyDisabledOrNonPortalIsByteIdentical(t *testing.T) {
	body := []byte(`{"id":"c1","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"你好 <b>"}}]}`)
	cases := map[string]struct {
		client   *ToolRiskClient
		envelope *modelrouter.RequestEnvelope
	}{
		"出厂默认":      {labelTestClient(t, aicontentlabel.DefaultSettings()), portalEnvelope()},
		"编码助手":      {labelTestClient(t, labelOnSettings()), &modelrouter.RequestEnvelope{RequestID: labelTestRequestID, AgentType: "claude-code"}},
		"没有客户端类型":   {labelTestClient(t, labelOnSettings()), &modelrouter.RequestEnvelope{RequestID: labelTestRequestID}},
		"没有 client": {nil, portalEnvelope()},
	}
	for name, c := range cases {
		if got := deliverResponseBody(context.Background(), c.client, c.envelope, body); string(got) != string(body) {
			t.Fatalf("%s: body changed: %s", name, got)
		}
		if needsAIContentLabel(c.client, c.envelope) {
			t.Fatalf("%s: needsAIContentLabel should be false", name)
		}
	}
}

func TestDeliverResponseBodyLabelsChatJSON(t *testing.T) {
	client := labelTestClient(t, labelOnSettings())
	body := []byte(`{"id":"c1","choices":[
		{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"第一段。\n\n第二段。\n","reasoning_content":"思考过程"}},
		{"index":1,"finish_reason":"length","message":{"role":"assistant","content":"被截断的回答"}},
		{"index":2,"finish_reason":"tool_calls","message":{"role":"assistant","content":"","tool_calls":[{"id":"call_1","type":"function","function":{"name":"write","arguments":"{\"text\":\"文件内容\"}"}}]}}
	],"usage":{"prompt_tokens":3,"completion_tokens":5}}`)
	if !needsAIContentLabel(client, portalEnvelope()) {
		t.Fatal("portal request should need a label")
	}
	got := decodeJSONMap(t, deliverResponseBody(context.Background(), client, portalEnvelope(), body))
	choices := got["choices"].([]any)

	stop := choices[0].(map[string]any)["message"].(map[string]any)
	content := stop["content"].(string)
	requireWatermark(t, content)
	if aicontentlabel.Strip(content) != "第一段。\n\n第二段。\n\n（以上内容由 AI 生成）\n" {
		t.Fatalf("labeled content = %q", aicontentlabel.Strip(content))
	}
	if !strings.Contains(content, "第二段。"+string([]rune(content)[len([]rune("第一段。\n\n第二段。"))])) {
		t.Fatalf("watermark should follow the last paragraph: %q", content)
	}
	if stop["reasoning_content"] != "思考过程" {
		t.Fatalf("reasoning_content changed: %v", stop["reasoning_content"])
	}
	if c := choices[1].(map[string]any)["message"].(map[string]any)["content"]; c != "被截断的回答" {
		t.Fatalf("length-truncated choice was labeled: %v", c)
	}
	call := choices[2].(map[string]any)["message"].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)
	if call["function"].(map[string]any)["arguments"] != `{"text":"文件内容"}` {
		t.Fatalf("tool arguments changed: %v", call["function"])
	}
}

func TestLabelTextKeepsWatermarkOutOfCodeBlocks(t *testing.T) {
	plan := aiContentLabelPlan{explicit: "（以上内容由 AI 生成）", watermark: "WM"}
	got := labelText("说明如下：\n\n```go\nfmt.Println(1)\n```\n", plan)
	want := "说明如下：WM\n\n```go\nfmt.Println(1)\n```\n\n（以上内容由 AI 生成）\n"
	if got != want {
		t.Fatalf("labelText = %q, want %q", got, want)
	}
	onlyCode := labelText("```\ncode\n```", plan)
	if strings.Contains(onlyCode, "WM") || !strings.HasSuffix(onlyCode, "（以上内容由 AI 生成）") {
		t.Fatalf("all-code answer = %q", onlyCode)
	}
	if labelText("   ", plan) != "   " {
		t.Fatal("blank text must stay blank")
	}
}

func TestDeliverResponseBodyRestoresBeforeLabelling(t *testing.T) {
	client := labelTestClient(t, labelOnSettings())
	envelope := portalEnvelope()
	ctx := withRequestRedaction(context.Background())
	placeholder := "<JJD_手机号_0123456789abcdef0123456789abcdef_1>"
	addRequestRedaction(ctx, envelope, "请联系 "+placeholder, map[string]string{placeholder: "13800138000"})
	body := []byte(`{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"已记录 ` + placeholder + `"}}]}`)

	got := decodeJSONMap(t, deliverResponseBody(ctx, client, envelope, body))
	content := got["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["content"].(string)
	requireWatermark(t, content)
	if aicontentlabel.Strip(content) != "已记录 13800138000\n\n（以上内容由 AI 生成）" {
		t.Fatalf("content = %q", aicontentlabel.Strip(content))
	}
}

func TestDeliverResponseBodyExplicitOnlyWithoutSecret(t *testing.T) {
	client := NewToolRiskClient("http://127.0.0.1:1", "")
	client.setAIContentLabelSettings(labelOnSettings())
	body := []byte(`{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"回答"}}]}`)
	got := decodeJSONMap(t, deliverResponseBody(context.Background(), client, portalEnvelope(), body))
	content := got["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["content"].(string)
	if content != "回答\n\n（以上内容由 AI 生成）" || len(aicontentlabel.Find(content)) != 0 {
		t.Fatalf("content = %q", content)
	}
}

func TestDeliverResponseBodyLabelsMessagesJSON(t *testing.T) {
	client := labelTestClient(t, labelOnSettings())
	body := []byte(`{"id":"msg_1","type":"message","role":"assistant","stop_reason":"end_turn","content":[
		{"type":"thinking","thinking":"先想一想","signature":"sig"},
		{"type":"text","text":"前一段"},
		{"type":"tool_use","id":"tu_1","name":"write","input":{"text":"不要改"}},
		{"type":"text","text":"最后一段"}
	]}`)
	got := decodeJSONMap(t, deliverResponseBody(context.Background(), client, portalEnvelope(), body))
	blocks := got["content"].([]any)
	if blocks[0].(map[string]any)["thinking"] != "先想一想" {
		t.Fatal("thinking changed")
	}
	if blocks[1].(map[string]any)["text"] != "前一段" {
		t.Fatal("non-final text block changed")
	}
	if blocks[2].(map[string]any)["input"].(map[string]any)["text"] != "不要改" {
		t.Fatal("tool_use input changed")
	}
	last := blocks[3].(map[string]any)["text"].(string)
	requireWatermark(t, last)
	if aicontentlabel.Strip(last) != "最后一段\n\n（以上内容由 AI 生成）" {
		t.Fatalf("last text = %q", last)
	}

	toolStop := []byte(`{"type":"message","role":"assistant","stop_reason":"tool_use","content":[{"type":"text","text":"调用工具"}]}`)
	if out := deliverResponseBody(context.Background(), client, portalEnvelope(), toolStop); string(out) != string(toolStop) {
		t.Fatalf("tool_use stop should not be labeled: %s", out)
	}
}

func TestDeliverResponseBodyLabelsResponsesJSON(t *testing.T) {
	client := labelTestClient(t, labelOnSettings())
	body := []byte(`{"id":"resp_1","object":"response","status":"completed","output_text":"答案","output":[
		{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"摘要"}]},
		{"type":"function_call","id":"fc_1","arguments":"{\"a\":1}"},
		{"type":"message","id":"msg_1","role":"assistant","content":[{"type":"output_text","text":"答案"}]}
	]}`)
	got := decodeJSONMap(t, deliverResponseBody(context.Background(), client, portalEnvelope(), body))
	output := got["output"].([]any)
	text := output[2].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	requireWatermark(t, text)
	if got["output_text"] != text {
		t.Fatalf("output_text not kept in sync: %v", got["output_text"])
	}
	if output[1].(map[string]any)["arguments"] != `{"a":1}` {
		t.Fatal("function_call arguments changed")
	}
	if output[0].(map[string]any)["summary"].([]any)[0].(map[string]any)["text"] != "摘要" {
		t.Fatal("reasoning summary changed")
	}

	incomplete := []byte(`{"object":"response","status":"incomplete","output":[{"type":"message","content":[{"type":"output_text","text":"半截"}]}]}`)
	if out := deliverResponseBody(context.Background(), client, portalEnvelope(), incomplete); string(out) != string(incomplete) {
		t.Fatalf("incomplete response should not be labeled: %s", out)
	}
}

func sseBody(frames ...string) []byte {
	var b strings.Builder
	for _, f := range frames {
		if strings.HasPrefix(f, "event:") {
			b.WriteString(f + "\n")
			continue
		}
		b.WriteString("data: " + f + "\n\n")
	}
	return []byte(b.String())
}

func sseFrames(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		raw := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if raw == "[DONE]" {
			continue
		}
		out = append(out, decodeJSONMap(t, []byte(raw)))
	}
	return out
}

func TestDeliverResponseBodyLabelsMessagesSSE(t *testing.T) {
	client := labelTestClient(t, labelOnSettings())
	body := sseBody(
		"event: message_start",
		`{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[]}}`,
		`{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"想"}}`,
		`{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`,
		`{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"你好，"}}`,
		`{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"世界"}}`,
		`{"type":"content_block_stop","index":1}`,
		`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":4}}`,
		`{"type":"message_stop"}`,
	)
	out := deliverResponseBody(context.Background(), client, portalEnvelope(), body)
	before, after := sseFrames(t, body), sseFrames(t, out)
	if len(before) != len(after) || !strings.Contains(string(out), "event: message_start") {
		t.Fatalf("frame layout changed: %d -> %d", len(before), len(after))
	}
	if after[2]["delta"].(map[string]any)["thinking"] != "想" {
		t.Fatal("thinking delta changed")
	}
	if after[4]["delta"].(map[string]any)["text"] != "你好，" {
		t.Fatal("earlier text delta should keep its length")
	}
	var full strings.Builder
	for _, f := range after {
		if d, _ := f["delta"].(map[string]any); d != nil && d["type"] == "text_delta" {
			full.WriteString(d["text"].(string))
		}
	}
	requireWatermark(t, full.String())
	if aicontentlabel.Strip(full.String()) != "你好，世界\n\n（以上内容由 AI 生成）" {
		t.Fatalf("streamed text = %q", aicontentlabel.Strip(full.String()))
	}
}

func TestDeliverResponseBodyLabelsResponsesSSEConsistently(t *testing.T) {
	client := labelTestClient(t, labelOnSettings())
	body := sseBody(
		`{"type":"response.created","response":{"id":"resp_1","status":"in_progress"}}`,
		`{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"答"}`,
		`{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"案"}`,
		`{"type":"response.output_text.done","item_id":"msg_1","output_index":0,"content_index":0,"text":"答案"}`,
		`{"type":"response.content_part.done","item_id":"msg_1","output_index":0,"content_index":0,"part":{"type":"output_text","text":"答案"}}`,
		`{"type":"response.output_item.done","output_index":0,"item":{"id":"msg_1","type":"message","content":[{"type":"output_text","text":"答案"}]}}`,
		`{"type":"response.completed","response":{"id":"resp_1","status":"completed","output_text":"答案","output":[{"id":"msg_1","type":"message","content":[{"type":"output_text","text":"答案"}]}]}}`,
	)
	after := sseFrames(t, deliverResponseBody(context.Background(), client, portalEnvelope(), body))
	streamed := after[1]["delta"].(string) + after[2]["delta"].(string)
	requireWatermark(t, streamed)
	if after[1]["delta"] != "答" {
		t.Fatal("earlier delta should keep its length")
	}
	snapshots := []string{
		after[3]["text"].(string),
		after[4]["part"].(map[string]any)["text"].(string),
		after[5]["item"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string),
		after[6]["response"].(map[string]any)["output"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string),
		after[6]["response"].(map[string]any)["output_text"].(string),
	}
	for i, s := range snapshots {
		if s != streamed {
			t.Fatalf("snapshot %d = %q, want streamed text %q", i, s, streamed)
		}
	}
}

func TestDeliverResponseBodyLeavesUnfinishedSSEAlone(t *testing.T) {
	client := labelTestClient(t, labelOnSettings())
	body := sseBody(
		`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"半截"}}`,
		`{"type":"message_delta","delta":{"stop_reason":"max_tokens"}}`,
	)
	if out := deliverResponseBody(context.Background(), client, portalEnvelope(), body); string(out) != string(body) {
		t.Fatalf("max_tokens stream was labeled: %s", out)
	}
}

func TestSystemSettingsRefreshLoadsAIContentLabel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			aicontentlabel.KeyExplicitEnabled:  "true",
			aicontentlabel.KeyWatermarkEnabled: "false",
			aicontentlabel.KeyExplicitText:     "本回答由人工智能生成",
			aicontentlabel.KeyAgentTypes:       `["enterprise-portal","customer-desk"]`,
		})
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, labelTestSecret)
	if err := client.refreshBlockNoticeSettings(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := client.AIContentLabelSettings()
	if !s.ExplicitEnabled || s.WatermarkEnabled || s.ExplicitText != "本回答由人工智能生成" || !s.AppliesTo("customer-desk") {
		t.Fatalf("settings = %+v", s)
	}

	server.Close()
	if err := client.refreshBlockNoticeSettings(context.Background()); err == nil {
		t.Fatal("refresh against a closed server should fail")
	}
	if !client.AIContentLabelSettings().ExplicitEnabled {
		t.Fatal("failed refresh must keep the last good settings")
	}
}

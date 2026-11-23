package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

const (
	tolNonce = "0123456789abcdef0123456789abcdef"
	tolTok0  = "<JJD_phone_" + tolNonce + "_0>"
	tolTok1  = "<JJD_phone_" + tolNonce + "_1>"
	tolTok10 = "<JJD_phone_" + tolNonce + "_10>"
)

func tolContext() (context.Context, *modelrouter.RequestEnvelope) {
	ctx := withBlockLedger(context.Background())
	env := &modelrouter.RequestEnvelope{RequestID: "req-tol", TenantID: "tenant-tol"}
	masked := tolTok0 + tolTok1 + tolTok10
	addRequestRedaction(ctx, env, masked, map[string]string{tolTok0: "13800138000", tolTok1: "13900139000", tolTok10: "13700137000"})
	return ctx, env
}

func TestRestoreToleratesPlaceholderVariants(t *testing.T) {
	bs := string(rune(92))
	spaced := func(s string) string { return strings.Join(strings.Split(s, ""), " ") }
	cases := map[string]string{
		"strict":            tolTok0,
		"lowercase":         strings.ToLower(tolTok0),
		"uppercase":         strings.ToUpper(tolTok0),
		"no brackets":       "JJD_phone_" + tolNonce + "_0",
		"html escaped":      "&lt;JJD_phone_" + tolNonce + "_0&gt;",
		"double escaped":    "&amp;lt;JJD_phone_" + tolNonce + "_0&amp;gt;",
		"inner spaces":      "< JJD_phone_ " + tolNonce + " _0 >",
		"every char spaced": spaced(tolTok0),
		"newline inside":    "<JJD_phone_" + tolNonce + "\n_0>",
		"md backslash":      "<JJD" + bs + "_phone" + bs + "_" + tolNonce + bs + "_0>",
		"zero width":        "<JJD_phone_" + tolNonce[:10] + "​" + tolNonce[10:] + "_0>",
		"fullwidth":         "＜JJD_phone_" + tolNonce + "_0＞",
	}
	for name, variant := range cases {
		for _, wrap := range [][2]string{{"", ""}, {"`", "`"}, {"**", "**"}, {"\"", "\""}} {
			ctx, env := tolContext()
			raw, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": "电话是 " + wrap[0] + variant + wrap[1] + "。"}}}})
			var out ChatCompletionResponse
			if err := json.Unmarshal(restoreRedactionBody(ctx, env, raw), &out); err != nil {
				t.Fatal(err)
			}
			want := "电话是 " + wrap[0] + "13800138000" + wrap[1] + "。"
			if got := out.Choices[0].Message.Content; got != want {
				t.Fatalf("%s wrap=%q: got %q want %q", name, wrap[0], got, want)
			}
		}
	}
}

func TestRestoreSequenceBoundaryAndForeignNonce(t *testing.T) {
	ctx, env := tolContext()
	foreign := "<JJD_phone_ffffffffffffffffffffffffffffffff_0>"
	text := "a " + tolTok1 + " b JJD_phone_" + tolNonce + "_10 c " + tolTok0 + " d " + foreign + " e JJD_phone_" + tolNonce + "_1"
	raw, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": text}}}})
	var out ChatCompletionResponse
	_ = json.Unmarshal(restoreRedactionBody(ctx, env, raw), &out)
	want := "a 13900139000 b 13700137000 c 13800138000 d " + foreign + " e 13900139000"
	if out.Choices[0].Message.Content != want {
		t.Fatalf("got %q want %q", out.Choices[0].Message.Content, want)
	}
}

func TestRestoreSingleFrameCrossFrameVariantsChatSSE(t *testing.T) {
	ctx, env := tolContext()
	variant := "&lt;jjd_PHONE_ " + tolNonce[:7] + " " + tolNonce[7:] + "_0&gt;"
	cut := []int{3, 15, 30, len(variant) - 2}
	prev := 0
	var frames []string
	for _, c := range append(cut, len(variant)) {
		raw := fmt.Sprintf(`{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":%q}}]}`, variant[prev:c])
		frames = append(frames, "data: "+raw+"\n\n")
		prev = c
	}
	body := strings.Join(frames, "") + "data: [DONE]\n\n"
	restored := string(restoreRedactionBody(ctx, env, []byte(body)))
	got := ""
	for _, line := range strings.Split(restored, "\n") {
		if strings.HasPrefix(line, "data: {") {
			var p struct {
				Choices []struct{ Delta struct{ Content string } }
			}
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &p); err != nil {
				t.Fatal(err)
			}
			got += p.Choices[0].Delta.Content
		}
	}
	if got != "13800138000" || strings.Count(restored, "data: {") != len(frames) {
		t.Fatalf("got %q frames=%d\n%s", got, strings.Count(restored, "data: {"), restored)
	}
}

func TestRestoreAnthropicMessagesJSONAndSSE(t *testing.T) {
	ctx, env := tolContext()
	variant := "`" + strings.ToLower(tolTok0) + "`"
	raw, _ := json.Marshal(map[string]any{"type": "message", "content": []any{map[string]any{"type": "text", "text": "号码 " + variant}}})
	if !strings.Contains(string(restoreRedactionBody(ctx, env, raw)), "号码 `13800138000`") {
		t.Fatal("native JSON not restored")
	}
	var frames []string
	half := len(variant) / 2
	for _, part := range []string{variant[:half], variant[half:]} {
		frames = append(frames, "event: content_block_delta\ndata: "+fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%q}}`, part)+"\n\n")
	}
	restored := string(restoreRedactionBody(ctx, env, []byte(strings.Join(frames, ""))))
	if strings.Contains(strings.ToLower(restored), "jjd_") || !strings.Contains(restored, "13800138000") {
		t.Fatalf("native SSE not restored: %s", restored)
	}
	// tool_use 参数在流里以 partial_json 分片出现。
	args := fmt.Sprintf(`{"phone":%q}`, strings.ToUpper(tolTok0))
	frames = nil
	for _, part := range []string{args[:9], args[9:20], args[20:]} {
		frames = append(frames, "event: content_block_delta\ndata: "+fmt.Sprintf(`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":%q}}`, part)+"\n\n")
	}
	restored = string(restoreRedactionBody(ctx, env, []byte(strings.Join(frames, ""))))
	joined := ""
	for _, line := range strings.Split(restored, "\n") {
		if strings.HasPrefix(line, "data: {") {
			var p struct {
				Delta struct {
					PartialJSON string `json:"partial_json"`
				}
			}
			_ = json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &p)
			joined += p.Delta.PartialJSON
		}
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(joined), &parsed); err != nil || parsed["phone"] != "13800138000" {
		t.Fatalf("partial_json not restored: %q %v", joined, err)
	}
}

func TestRestoreGapRaisesOneAlert(t *testing.T) {
	ctx, env := tolContext()
	alerts := 0
	setRedactionGapSink(ctx, func(context.Context, *modelrouter.RequestEnvelope) { alerts++ })
	// 改写得无法识别：序号被替换成字母，nonce 仍残留。
	raw, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": "x JJD_phone_" + tolNonce + "_zero y " + tolTok0}}}})
	var out ChatCompletionResponse
	_ = json.Unmarshal(restoreRedactionBody(ctx, env, raw), &out)
	_ = restoreRedactionBody(ctx, env, raw)
	if alerts != 1 {
		t.Fatalf("alerts=%d want 1", alerts)
	}
	if !strings.Contains(out.Choices[0].Message.Content, "13800138000") {
		t.Fatal("restorable part lost")
	}
	// 全部还原成功不告警。
	ctx2, env2 := tolContext()
	alerts = 0
	setRedactionGapSink(ctx2, func(context.Context, *modelrouter.RequestEnvelope) { alerts++ })
	ok, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": tolTok0}}}})
	restoreRedactionBody(ctx2, env2, ok)
	if alerts != 0 {
		t.Fatal("unexpected alert")
	}
}

package provider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

func readAllStreamEvents(t *testing.T, reader relay.StreamReader) ([]relay.StreamEvent, error) {
	t.Helper()
	var events []relay.StreamEvent
	for {
		event, err := reader.Next(context.Background())
		if err != nil {
			if errors.Is(err, io.EOF) {
				return events, nil
			}
			return events, err
		}
		events = append(events, event)
	}
}

// OpenAI 官方顺序：finish_reason 块 → include_usage 的 usage 块（choices 为空）→ [DONE]。
// 读到 finish_reason 后不能立即结束，否则权威 usage 丢失，计费只能按 0 或估算入账。
func TestOpenAIChatLiveStreamKeepsUsageChunkAfterFinishReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"length\"}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"id\":\"x\",\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":60,\"total_tokens\":69}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()
	env := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "gpt-4"}
	reader, _, err := (&OpenAIAdapter{BaseURL: srv.URL, APIKey: "test"}).OpenStream(context.Background(), env, []byte(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	events, err := readAllStreamEvents(t, reader)
	if err != nil {
		t.Fatalf("stream error: %v", err)
	}
	var usage *relay.Usage
	finishSeen := false
	for _, event := range events {
		if event.Type == relay.EventMessageEnd && event.FinishReason == "length" {
			finishSeen = true
		}
		if event.Usage != nil {
			usage = event.Usage
		}
	}
	if !finishSeen || usage == nil || usage.InputTokens != 9 || usage.OutputTokens != 60 {
		t.Fatalf("finish=%v usage=%+v events=%+v", finishSeen, usage, events)
	}
}

// 没有 usage 块、直接 [DONE] 的上游照常结束；结束在 finish 后直接断开连接也照常结束，不报截断错误。
func TestOpenAIChatLiveStreamEndsWithoutUsageChunk(t *testing.T) {
	for name, tail := range map[string]string{
		"done":   "data: [DONE]\n\n",
		"closed": "",
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":\"stop\"}]}\n\n"+tail)
			}))
			defer srv.Close()
			env := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "gpt-4"}
			reader, _, err := (&OpenAIAdapter{BaseURL: srv.URL, APIKey: "test"}).OpenStream(context.Background(), env, []byte(`{"model":"gpt-4","messages":[]}`))
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			events, err := readAllStreamEvents(t, reader)
			if err != nil || len(events) == 0 || events[len(events)-1].Type != relay.EventMessageEnd {
				t.Fatalf("err=%v events=%+v", err, events)
			}
		})
	}
}

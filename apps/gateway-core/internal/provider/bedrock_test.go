package provider

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	modelrouter "github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestBedrockAdapterTransformsRequestAndResponse(t *testing.T) {
	adapter := &BedrockAdapter{}
	envelope := &modelrouter.RequestEnvelope{
		EndpointType:    "chat",
		Model:           "claude-prod",
		UpstreamModelID: "anthropic.claude-3-5-sonnet-20241022-v2:0",
	}
	raw := []byte(`{"model":"claude-prod","messages":[{"role":"system","content":"Be concise."},{"role":"user","content":"Hello"}],"temperature":0.2,"max_tokens":128}`)
	transformed, err := adapter.TransformRequest(envelope, raw)
	if err != nil {
		t.Fatal(err)
	}
	var request bedrockConverseRequest
	if err := json.Unmarshal(transformed, &request); err != nil {
		t.Fatal(err)
	}
	if len(request.System) != 1 || request.System[0].Text != "Be concise." {
		t.Fatalf("system=%+v", request.System)
	}
	if len(request.Messages) != 1 || request.Messages[0].Content[0].Text != "Hello" {
		t.Fatalf("messages=%+v", request.Messages)
	}
	if request.InferenceConfig == nil || request.InferenceConfig.MaxTokens == nil || *request.InferenceConfig.MaxTokens != 128 {
		t.Fatalf("inferenceConfig=%+v", request.InferenceConfig)
	}
	native := []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"Hi"}]}},"stopReason":"end_turn","usage":{"inputTokens":3,"outputTokens":2,"totalTokens":5}}`)
	result, err := adapter.TransformResponse(native)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(result, []byte(`"claude-prod"`)) || !bytes.Contains(result, []byte(`"Hi"`)) || !bytes.Contains(result, []byte(`"prompt_tokens"`)) {
		t.Fatalf("result=%s", result)
	}
}

func TestBedrockAdapterCallSignsConverseRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/model/anthropic.claude-3-5-sonnet-20241022-v2:0/converse" {
			t.Errorf("path=%s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKID/") {
			t.Errorf("authorization=%q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Amz-Date") == "" || r.Header.Get("X-Amz-Content-Sha256") == "" {
			t.Error("missing SigV4 headers")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"output":{"message":{"role":"assistant","content":[{"text":"ok"}]}},"stopReason":"end_turn"}`)
	}))
	defer server.Close()

	adapter := &BedrockAdapter{
		BaseURL: server.URL,
		APIKey:  `{"access_key_id":"AKID","secret_access_key":"SECRET","region":"us-east-1"}`,
	}
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "logical", UpstreamModelID: "anthropic.claude-3-5-sonnet-20241022-v2:0"}
	payload, err := adapter.TransformRequest(envelope, []byte(`{"messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := adapter.Call(context.Background(), envelope, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(resp, []byte(`"stopReason"`)) {
		t.Fatalf("response=%s", resp)
	}
}

func TestBedrockAdapterCallStreamingAggregatesEventStream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		events := [][]byte{
			bedrockTestEvent("messageStart", []byte(`{}`)),
			bedrockTestEvent("contentBlockStart", []byte(`{"contentBlockIndex":0}`)),
			bedrockTestEvent("contentBlockDelta", []byte(`{"contentBlockIndex":0,"delta":{"text":"hel"}}`)),
			bedrockTestEvent("contentBlockDelta", []byte(`{"contentBlockIndex":0,"delta":{"text":"lo"}}`)),
			bedrockTestEvent("messageStop", []byte(`{"stopReason":"end_turn"}`)),
			bedrockTestEvent("metadata", []byte(`{"usage":{"inputTokens":4,"outputTokens":2,"totalTokens":6}}`)),
		}
		for _, event := range events {
			_, _ = w.Write(event)
		}
	}))
	defer server.Close()

	adapter := &BedrockAdapter{BaseURL: server.URL, APIKey: `{"access_key_id":"AKID","secret_access_key":"SECRET","region":"us-east-1"}`}
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "logical", UpstreamModelID: "model"}
	payload, err := adapter.TransformRequest(envelope, []byte(`{"messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	native, err := adapter.CallStreaming(context.Background(), envelope, payload)
	if err != nil {
		t.Fatal(err)
	}
	result, err := adapter.TransformResponse(native)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(result, []byte(`"hello"`)) || envelope.UpstreamTTFTMs == nil {
		t.Fatalf("result=%s ttft=%v", result, envelope.UpstreamTTFTMs)
	}
}

func bedrockTestEvent(eventType string, payload []byte) []byte {
	headerName := []byte(`:event-type`)
	headers := []byte{byte(len(headerName))}
	headers = append(headers, headerName...)
	headers = append(headers, 7, byte(len(eventType)>>8), byte(len(eventType)))
	headers = append(headers, []byte(eventType)...)
	totalLength := 12 + len(headers) + len(payload) + 4
	frame := make([]byte, 12)
	binary.BigEndian.PutUint32(frame[0:4], uint32(totalLength))
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(headers)))
	binary.BigEndian.PutUint32(frame[8:12], crc32.ChecksumIEEE(frame[:8]))
	frame = append(frame, headers...)
	frame = append(frame, payload...)
	checksum := crc32.ChecksumIEEE(frame)
	var checksumBytes [4]byte
	binary.BigEndian.PutUint32(checksumBytes[:], checksum)
	return append(frame, checksumBytes[:]...)
}

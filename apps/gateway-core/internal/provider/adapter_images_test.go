package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	modelrouter "github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestOpenAIAdapterImagesUsesResponsesImageGenerationTool(t *testing.T) {
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Fatalf("path=%s want=/v1/responses", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatalf("authorization header missing")
		}
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_1","object":"response","created_at":1716399600,"status":"completed","output":[{"type":"image_generation_call","id":"ig_1","status":"completed","result":"aW1hZ2U="}]}`))
	}))
	defer server.Close()

	original := []byte(`{"model":"customer-image-prod","prompt":"draw a red bridge","n":1,"size":"1024x1024","quality":"high","background":"transparent","output_format":"png","output_compression":80,"moderation":"low","input_fidelity":"high","unknown_extension":{"keep":true}}`)
	adapter := &OpenAIAdapter{BaseURL: server.URL + "/v1", APIKey: "test-key"}
	env := &modelrouter.RequestEnvelope{EndpointType: "images", Model: "customer-image-prod", UpstreamModelID: "vendor-image-2", ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, Images: true, ImagesResponsesBridge: true}}

	transformed, err := adapter.TransformRequest(env, original)
	if err != nil {
		t.Fatal(err)
	}
	upstreamResponse, err := adapter.Call(context.Background(), env, transformed)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(gotBody, &got); err != nil {
		t.Fatalf("upstream body invalid: %v", err)
	}
	if got["model"] != "vendor-image-2" || got["input"] != "draw a red bridge" {
		t.Fatalf("unexpected model/input: %#v", got)
	}
	tools, ok := got["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("unexpected tools: %#v", got["tools"])
	}
	imageTool, ok := tools[0].(map[string]any)
	if !ok || imageTool["type"] != "image_generation" {
		t.Fatalf("unexpected image tool: %#v", tools[0])
	}
	if imageTool["size"] != "1024x1024" || imageTool["quality"] != "high" ||
		imageTool["background"] != "transparent" || imageTool["output_format"] != "png" ||
		imageTool["output_compression"] != float64(80) || imageTool["moderation"] != "low" ||
		imageTool["input_fidelity"] != "high" {
		t.Fatalf("image options were not mapped: %#v", imageTool)
	}
	if _, exists := got["unknown_extension"]; exists {
		t.Fatalf("unknown Images API field leaked into Responses request: %#v", got)
	}

	imagesResponse, err := adapter.TransformImageResponse(upstreamResponse)
	if err != nil {
		t.Fatal(err)
	}
	var images map[string]any
	if err := json.Unmarshal(imagesResponse, &images); err != nil {
		t.Fatalf("Images response invalid: %v", err)
	}
	if images["created"] != float64(1716399600) {
		t.Fatalf("created=%v", images["created"])
	}
	data, ok := images["data"].([]any)
	if !ok || len(data) != 1 || data[0].(map[string]any)["b64_json"] != "aW1hZ2U=" {
		t.Fatalf("unexpected Images response: %#v", images)
	}
}

func TestOpenAIAdapterImagesRejectsMultipleImagesForResponsesBridge(t *testing.T) {
	adapter := &OpenAIAdapter{}
	env := &modelrouter.RequestEnvelope{EndpointType: "images", Model: "customer-image-prod", ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, Images: true, ImagesResponsesBridge: true}}
	_, err := adapter.TransformRequest(env, []byte(`{"model":"gpt-image-2","prompt":"draw","n":2}`))
	if err == nil || !strings.Contains(err.Error(), "n") {
		t.Fatalf("expected explicit n>1 rejection, got %v", err)
	}
}

func TestOpenAIAdapterTransformImageResponseRejectsMissingResult(t *testing.T) {
	adapter := &OpenAIAdapter{}
	_, err := adapter.TransformImageResponse([]byte(`{"status":"completed","output":[{"type":"message","content":[]}]}`))
	if err == nil || !strings.Contains(err.Error(), "image_generation_call") {
		t.Fatalf("expected missing image result error, got %v", err)
	}
}

func TestOpenAIAdapterImagesDoNotInferResponsesBridgeFromModelName(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":1716399600,"data":[{"b64_json":"aW1hZ2U="}]}`))
	}))
	defer server.Close()

	adapter := &OpenAIAdapter{BaseURL: server.URL + "/v1", APIKey: "test-key"}
	env := &modelrouter.RequestEnvelope{EndpointType: "images", Model: "gpt-image-2"}
	payload, err := adapter.TransformRequest(env, []byte(`{"model":"legacy-image","prompt":"draw"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Call(context.Background(), env, payload); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/images/generations" {
		t.Fatalf("path=%s want=/v1/images/generations", gotPath)
	}
}

func TestOpenAIAdapterTransformImageResponsePreservesBase64Bytes(t *testing.T) {
	adapter := &OpenAIAdapter{}
	input := []byte(`{"created_at":1716399600,"output":[{"type":"image_generation_call","result":"aW1hZ2U="},{"type":"image_generation_call","result":"c2Vjb25k"}]}`)
	output, err := adapter.TransformImageResponse(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output, []byte("aW1hZ2U=")) || !bytes.Contains(output, []byte("c2Vjb25k")) {
		t.Fatalf("converted response lost image results: %s", output)
	}
}

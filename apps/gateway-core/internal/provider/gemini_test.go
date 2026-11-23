package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	modelrouter "github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestGeminiAdapterTransformsOpenAIRequestAndResponse(t *testing.T) {
	adapter := &GeminiAdapter{}
	envelope := &modelrouter.RequestEnvelope{
		EndpointType:    "chat",
		Model:           "gemini-logical",
		UpstreamModelID: "gemini-2.5-flash",
	}
	raw := []byte(`{"model":"gemini-logical","messages":[{"role":"system","content":"You are concise."},{"role":"user","content":[{"type":"text","text":"hello"}]}],"temperature":0.2,"max_tokens":32}`)
	transformed, err := adapter.TransformRequest(envelope, raw)
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]interface{}
	if err := json.Unmarshal(transformed, &request); err != nil {
		t.Fatal(err)
	}
	if request["contents"] == nil || request["system_instruction"] == nil {
		t.Fatalf("request was not translated to Gemini: %s", transformed)
	}
	if got := adapter.model; got != "gemini-2.5-flash" {
		t.Fatalf("adapter model = %q", got)
	}

	response, err := adapter.TransformResponse([]byte(`{"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"Hello"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":2,"totalTokenCount":5}}`))
	if err != nil {
		t.Fatal(err)
	}
	var openAI map[string]interface{}
	if err := json.Unmarshal(response, &openAI); err != nil {
		t.Fatal(err)
	}
	if openAI["object"] != "chat.completion" || openAI["model"] != "gemini-2.5-flash" {
		t.Fatalf("unexpected OpenAI response: %s", response)
	}
	choices := openAI["choices"].([]interface{})
	message := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	if message["content"] != "Hello" {
		t.Fatalf("response content = %#v", message["content"])
	}
	usage := openAI["usage"].(map[string]interface{})
	if usage["total_tokens"] != float64(5) {
		t.Fatalf("response usage = %#v", usage)
	}
}

func TestGeminiAdapterCallsVertexWithServiceAccountOAuth(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, privateKey)})

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Fatalf("unexpected token request: %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		values, _ := url.ParseQuery(string(body))
		assertion := values.Get("assertion")
		if values.Get("grant_type") == "" || len(strings.Split(assertion, ".")) != 3 {
			t.Fatalf("invalid OAuth JWT exchange: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"vertex-token","expires_in":3600}`)
	}))
	defer tokenServer.Close()

	vertexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/v1/projects/demo-project/locations/global/publishers/google/models/gemini-2.5-flash:generateContent"
		if r.URL.Path != wantPath {
			t.Fatalf("Vertex path = %q, want %q", r.URL.Path, wantPath)
		}
		if r.Header.Get("Authorization") != "Bearer vertex-token" {
			t.Fatalf("Vertex authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"from vertex"}]},"finishReason":"STOP"}]}`)
	}))
	defer vertexServer.Close()

	credential := serviceAccountJSON(t, "demo-project", "gemini-test@example.iam.gserviceaccount.com", string(privateKeyPEM), tokenServer.URL)
	adapter := &GeminiAdapter{BaseURL: vertexServer.URL, APIKey: credential}
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "gemini-2.5-flash", UpstreamModelID: "gemini-2.5-flash"}
	payload, err := adapter.TransformRequest(envelope, []byte(`{"model":"gemini-2.5-flash","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	response, err := adapter.Call(context.Background(), envelope, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(response), "from vertex") {
		t.Fatalf("unexpected Vertex response: %s", response)
	}
}

func TestGeminiAdapterAccumulatesStreamingSSE(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"stream-token","expires_in":3600}`)
	}))
	defer tokenServer.Close()
	vertexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("alt") != "sse" || !strings.HasSuffix(r.URL.Path, ":streamGenerateContent") {
			t.Fatalf("unexpected stream endpoint: %s", r.URL.String())
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hel\"}]}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"candidates\":[{\"index\":0,\"content\":{\"parts\":[{\"text\":\"lo\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"totalTokenCount\":4}}\n\n")
	}))
	defer vertexServer.Close()
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, privateKey)})
	credential := serviceAccountJSON(t, "stream-project", "stream@example.iam.gserviceaccount.com", string(privateKeyPEM), tokenServer.URL)
	adapter := &GeminiAdapter{BaseURL: vertexServer.URL, APIKey: credential}
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "gemini-2.5-flash"}
	payload, err := adapter.TransformRequest(envelope, []byte(`{"model":"gemini-2.5-flash","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	native, err := adapter.CallStreaming(context.Background(), envelope, payload)
	if err != nil {
		t.Fatal(err)
	}
	openAI, err := adapter.TransformResponse(native)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(openAI), `"content":"Hello"`) {
		t.Fatalf("stream was not accumulated: %s", openAI)
	}
}

func mustPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func serviceAccountJSON(t *testing.T, project, email, privateKey, tokenURI string) string {
	t.Helper()
	value, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"project_id":   project,
		"client_email": email,
		"private_key":  privateKey,
		"token_uri":    tokenURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s", value)
}

func TestGeminiAdapterMapsReasoningEffortToThinkingConfig(t *testing.T) {
	adapter := &GeminiAdapter{}
	envelope := &modelrouter.RequestEnvelope{
		EndpointType:    "chat",
		Model:           "gemini-logical",
		UpstreamModelID: "gemini-3.1-pro-preview",
	}
	cases := map[string]map[string]interface{}{
		`{"model":"m","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"high"}`:    {"thinkingLevel": "HIGH"},
		`{"model":"m","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"low"}`:     {"thinkingLevel": "LOW"},
		`{"model":"m","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"minimal"}`: {"thinkingBudget": float64(0)},
	}
	for raw, want := range cases {
		transformed, err := adapter.TransformRequest(envelope, []byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		var request map[string]interface{}
		if err := json.Unmarshal(transformed, &request); err != nil {
			t.Fatal(err)
		}
		generation, ok := request["generation_config"].(map[string]interface{})
		if !ok {
			t.Fatalf("missing generation_config for %s: %s", raw, transformed)
		}
		if !reflect.DeepEqual(generation["thinkingConfig"], want) {
			t.Fatalf("thinkingConfig = %#v, want %#v for %s", generation["thinkingConfig"], want, raw)
		}
	}
	transformed, err := adapter.TransformRequest(envelope, []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]interface{}
	if err := json.Unmarshal(transformed, &request); err != nil {
		t.Fatal(err)
	}
	if generation, ok := request["generation_config"].(map[string]interface{}); ok {
		if _, exists := generation["thinkingConfig"]; exists {
			t.Fatal("thinkingConfig synthesized without reasoning_effort")
		}
	}
}

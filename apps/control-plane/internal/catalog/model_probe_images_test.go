package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPModelProberImagesUsesGenerationContract(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/images/generations" || r.Header.Get("Authorization") != "Bearer probe-secret" {
			t.Errorf("wrong image endpoint/auth: %s", r.URL.Path)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		if body["model"] != "gpt-image-2" || body["prompt"] == nil || body["n"] != float64(1) || body["size"] != "1024x1024" {
			t.Errorf("invalid generation request: %#v", body)
		}
		for _, field := range []string{"messages", "input", "stream", "max_completion_tokens", "max_output_tokens"} {
			if _, ok := body[field]; ok {
				t.Errorf("text field sent to image endpoint: %s", field)
			}
		}
		io.WriteString(w, `{"created":1,"data":[{"url":"https://images.example.test/probe.png"}]}`)
	}))
	defer server.Close()
	req := validProbeRequest(server.URL+"/v1", "bearer")
	req.Protocol = "images"
	req.DeploymentName = "gpt-image-2"
	result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), req)
	if calls != 1 || !result.OK || !result.PayloadValidated || result.HTTPStatus != 200 {
		t.Fatalf("image evidence missing: %+v calls=%d", result, calls)
	}
}

func TestImageProbeRequiresImagePayloadAndLargerBound(t *testing.T) {
	png := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jwZ8AAAAASUVORK5CYII="
	for _, item := range []struct {
		name, body string
		valid      bool
	}{
		{"base64", fmt.Sprintf(`{"data":[{"b64_json":%q}]}`, png), true},
		{"large-image-envelope", `{"data":[{"url":"https://images.example.test/image.png"}],"padding":"` + strings.Repeat("x", 300<<10) + `"}`, true},
		{"empty", `{"data":[]}`, false},
		{"text", `{"choices":[{"message":{"content":"OK"}}]}`, false},
		{"error", `{"error":{"message":"probe-secret"},"data":[{"url":"https://images.example.test/image.png"}]}`, false},
		{"bad-base64", `{"data":[{"b64_json":"bm90IGFuIGltYWdl"}]}`, false},
		{"unsafe-url", `{"data":[{"url":"file:///etc/passwd"}]}`, false},
		{"oversized", `{"data":[{"url":"https://images.example.test/image.png"}],"padding":"` + strings.Repeat("x", 17<<20) + `"}`, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			if got := validModelProbeSuccessBody(strings.NewReader(item.body), "images"); got != item.valid {
				t.Fatalf("validated=%v want=%v", got, item.valid)
			}
		})
	}
}

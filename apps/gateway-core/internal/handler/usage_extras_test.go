package handler

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMeasuredToolsDoNotCountDeclarationsOrDuplicateSnapshots(t *testing.T) {
	response := []byte(`{"usage":{"input_tokens":100,"output_tokens":20,"tool_calls":{"web_search":2}},"tools":[{"type":"web_search"}],"output":[{"id":"s1","type":"web_search_call","status":"completed"},{"id":"s1","type":"web_search_call","status":"completed"},{"id":"s2","type":"web_search_call","status":"completed"},{"id":"f1","type":"file_search_call","status":"failed"}]}`)
	usage := canonicalizeResponseUsage(response)
	if usage.ToolCalls["web_search"] != 2 || usage.ToolCalls["file_search"] != 0 || usage.PromptTokens != 100 {
		t.Fatalf("usage: %+v", usage)
	}
	declarations := responseUsageExtensions([]byte(`{"tools":[{"type":"web_search"}],"choices":[{"message":{"tool_calls":[{"type":"function","function":{"name":"web_search"}}]}}]}`))
	if len(declarations.ToolCalls) != 0 {
		t.Fatalf("declarations are not execution evidence: %+v", declarations)
	}
	invalid := canonicalizeResponseUsage([]byte(`{"usage":{"input_tokens":100,"output_tokens":20,"server_tool_use":{"web_search_requests":-1}}}`))
	if invalid.State != "invalid" {
		t.Fatalf("negative count accepted: %+v", invalid)
	}
}

func TestImageUsageEvidenceRetainsCountWithoutImages(t *testing.T) {
	evidence := imageUsageEvidence([]byte(`{"data":[{"b64_json":"secret-image"},{"url":"https://private-image"}]}`))
	var decoded map[string]any
	if json.Unmarshal(evidence, &decoded) != nil || decoded["image_count"] != float64(2) || decoded["data"] != nil {
		t.Fatalf("image evidence: %s", evidence)
	}
	if responseUsageExtensions(evidence).ImageCount != 2 {
		t.Fatal("lost measured image count")
	}
	duplicate := responseUsageExtensions([]byte(`{"usage":{"image_count":2},"data":[{"url":"1"},{"url":"2"}]}`))
	if duplicate.ImageCount != 2 {
		t.Fatalf("double counted images: %+v", duplicate)
	}
}

func TestStreamingBuiltInToolsCountStableIDsOnce(t *testing.T) {
	accumulator := newLiveStreamAccumulator()
	for _, raw := range []string{`{"type":"response.output_item.added","item":{"id":"s1","type":"web_search_call","status":"in_progress"}}`, `{"type":"response.output_item.done","item":{"id":"s1","type":"web_search_call","status":"completed"}}`, `{"type":"response.output_item.done","item":{"id":"s2","type":"web_search_call","status":"completed"}}`, `{"type":"response.completed","response":{"usage":{"input_tokens":100,"output_tokens":20},"output":[{"id":"s1","type":"web_search_call"},{"id":"s2","type":"web_search_call"}]}}`} {
		accumulator.observeBillingTools(relay.StreamEvent{Raw: []byte(raw)})
	}
	body, err := accumulator.responseBody("request-tools")
	if err != nil {
		t.Fatal(err)
	}
	if tools := responseUsageExtensions(body).ToolCalls; tools["web_search"] != 2 {
		t.Fatalf("stream tool evidence: %s %+v", body, tools)
	}
}

func TestAllowanceRequiredFailsClosedAndShowbackRetainsTolerance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"code":"billing_unavailable"}}`))
	}))
	defer server.Close()
	client := NewBillingClientWithMode(server.URL, "test-secret", "", "metering")
	env := &modelrouter.RequestEnvelope{TenantID: "t", UserID: "u", RequestID: "required"}
	client.AllowanceRequired = func(context.Context, string, string) (bool, error) { return true, nil }
	var admission *BillingAdmissionError
	if err := client.ReserveUsage(context.Background(), env, BillingUsage{PromptTokens: 1}); !errors.As(err, &admission) || admission.Code != "billing_unavailable" {
		t.Fatalf("required budget admitted: %v", err)
	}
	client.AllowanceRequired = func(context.Context, string, string) (bool, error) { return false, nil }
	env.RequestID = "showback"
	if err := client.ReserveUsage(context.Background(), env, BillingUsage{PromptTokens: 1}); err != nil {
		t.Fatalf("ordinary showback rejected: %v", err)
	}
}

func TestNewAPIUsageKeepsImageTokenCacheAndCacheWriteAliases(t *testing.T) {
	body := []byte(`{"usage":{"input_tokens":100,"output_tokens":20,"input_tokens_details":{"image_tokens":40,"cached_tokens":10,"cache_write_tokens":20,"cached_tokens_details":{"image_tokens":5}},"prompt_tokens_details":{"cached_creation_tokens":20}}}`)
	usage := canonicalizeResponseUsage(body)
	if usage.PromptTokens != 100 || usage.CachedInputTokens != 10 || usage.CacheWriteTokens != 20 || usage.ImageInputTokens != 40 || usage.CachedImageInputTokens != 5 {
		t.Fatalf("New API usage lost dimensions or counted aliases twice: %+v", usage)
	}
	extended := extendedBillingUsage(body)
	if extended["image_input_tokens"] != int64(40) || extended["cached_image_input_tokens"] != int64(5) {
		t.Fatalf("settlement lost image token details: %+v", extended)
	}
	zero := responseUsageExtensions([]byte(`{"image_count":0}`))
	if !zero.ImageCountMeasured || zero.ImageCount != 0 {
		t.Fatal("measured zero images must replace an admission estimate")
	}
}

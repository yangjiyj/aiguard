package handler

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fixedInspectionPolicy struct{ policy inspectionscope.Policy }

func (f fixedInspectionPolicy) InspectionPolicy(context.Context) inspectionscope.Policy {
	return f.policy
}
func fullInspectionPolicy() fixedInspectionPolicy {
	p := inspectionscope.Default()
	p.InspectBuiltinContext = true
	p.InspectHistory = true
	return fixedInspectionPolicy{p}
}

func TestProxyScopePreservesCurrentCredentialsContextAndIncomplete(t *testing.T) {
	body := `{"messages":[{"role":"system","content":"builtin"},{"role":"user","content":"old"},{"role":"tool","content":"old result"},{"role":"user","content":"latest task"},{"role":"tool","content":"credential"}]}`
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	extracted := extractRequestContentWithDecoder(req, []byte(body), "openai_compatible")
	extracted = selectExtractedInspection(extracted, inspectionscope.Default())
	plan, err := buildInspectionPlan(map[string]interface{}{"request_id": "r", "context": map[string]interface{}{}}, extracted)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 2 {
		t.Fatalf("targets=%+v", plan)
	}
	for i, p := range plan {
		c := p["context"].(map[string]interface{})
		if c["message_index"] != i+3 || c["user_task"] != "latest task" || len(c["judgment_context"].([]map[string]any)) != 3 {
			t.Fatalf("provenance=%+v", c)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		json.NewDecoder(r.Body).Decode(&p)
		if p["content"] == "credential" {
			w.Write([]byte(`{"action":"block","findings":[{"type":"secret","content_source":"tool_result"}],"semantic_status":"incomplete","semantic_reason":"judge_timeout"}`))
			return
		}
		w.Write([]byte(`{"action":"allow","findings":[],"semantic_status":"completed"}`))
	}))
	defer server.Close()
	req = httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	action, findings, meta := NewSecurityClient(server.URL).CheckInput(context.Background(), "t", "r", req)
	if action != "block" || len(findings) != 1 || meta == nil || meta.SemanticStatus != "incomplete" {
		t.Fatalf("credential/incomplete lost: %s %+v %+v", action, findings, meta)
	}
}

func TestProxyTelemetryIsExactAndCannotBeSpoofedByBody(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"action":"audit","findings":[]}`))
	}))
	defer server.Close()
	for _, url := range []string{"https://ab.chatgpt.com/v1/rgstr", "https://api.openai.com/v1/chat/completions"} {
		req := httptest.NewRequest("POST", url, strings.NewReader(`{"messages":[{"role":"user","content":"histogram telemetry credential"}]}`))
		req.Header.Set("Content-Type", "application/json")
		NewSecurityClient(server.URL).CheckInput(context.Background(), "t", "r", req)
	}
	if calls != 1 {
		t.Fatalf("telemetry classification calls=%d", calls)
	}
}

func TestProxyHistoricalAttachmentDoesNotReenterAsUnknown(t *testing.T) {
	body := `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,aGVsbG8="}}]},{"role":"user","content":"latest"}]}`
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", nil)
	e := extractRequestContentWithDecoder(req, []byte(body), "openai_compatible")
	e = selectExtractedInspection(e, inspectionscope.Default())
	if len(e.Attachments) != 0 || len(e.Messages) != 1 {
		t.Fatalf("historical file reentered: %+v", e)
	}
}

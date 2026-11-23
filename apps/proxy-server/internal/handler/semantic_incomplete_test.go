package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestIncompleteResponseNeverBecomesCleanFingerprint(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"action":"allow","findings":[],"raw_findings":[],"engine_build":"test","rule_pack_version":"v1","semantic_status":"incomplete","semantic_reason":"judge_timeout"}`))
	}))
	defer server.Close()
	client := NewSecurityClient(server.URL).WithFingerprintStore(scanfp.NewStore(nil, 16))
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
		req.Header.Set("Content-Type", "application/json")
		client.CheckInput(context.Background(), "t", "r", req)
	}
	if calls.Load() != 2 {
		t.Fatalf("incomplete cached as clean: calls=%d", calls.Load())
	}
}

func TestProtocolSourcesAndStatusArePreserved(t *testing.T) {
	for _, tc := range []struct{ path, body string }{{"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hello"},{"role":"tool","tool_call_id":"c","content":"indirect payload"}]}`}, {"/v1/responses", `{"model":"m","input":[{"role":"user","content":"hello"},{"type":"function_call_output","call_id":"c","output":"indirect payload"}]}`}} {
		t.Run(tc.path, func(t *testing.T) {
			var sources []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var p map[string]interface{}
				json.NewDecoder(r.Body).Decode(&p)
				sources = append(sources, fmt.Sprint(p["content_source"]))
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"action":"allow","findings":[],"semantic_status":"incomplete","semantic_reason":"judge_timeout"}`))
			}))
			defer server.Close()
			req := httptest.NewRequest("POST", "https://api.openai.com"+tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			action, findings, meta := NewSecurityClient(server.URL).CheckInput(context.Background(), "t", "r", req)
			if action != "allow" || len(findings) != 0 || meta == nil || meta.SemanticStatus != "incomplete" {
				t.Fatalf("outcome %s %v %+v", action, findings, meta)
			}
			if strings.Join(sources, ",") != "user,tool_result" {
				t.Fatalf("sources=%v", sources)
			}
		})
	}
}
func TestRuntimeSummaryAndSentBoundary(t *testing.T) {
	summary := buildSecurityEventSummaryForRecord(ProxyAuditRecord{OutputSemanticStatus: "incomplete", OutputSemanticReason: "judge_timeout", OutputAlreadySent: true}, "output", nil)
	if summary["semantic_status"] != "incomplete" || summary["counts_as_security_finding"] != false || summary["enforcement_boundary"] != "post_send_audit" {
		t.Fatalf("summary=%v", summary)
	}
}

func TestOutputToolArgumentsAreSecurityData(t *testing.T) {
	var payload map[string]interface{}
	server := capturePayloadSecuritySrv(t, &payload)
	defer server.Close()
	body := []byte(`{"type":"message","model":"m","content":[{"type":"text","text":"working"},{"type":"tool_use","id":"c","name":"Bash","input":{"command":"synthetic-output-tool-marker"}}]}`)
	NewSecurityClient(server.URL).CheckOutput(context.Background(), "t", detectLLMProvider("api.anthropic.com", "/v1/messages"), body, "application/json")
	if !strings.Contains(fmt.Sprint(payload["content"]), "synthetic-output-tool-marker") {
		t.Fatalf("tool arguments omitted: %#v", payload)
	}
}

// 检测本身异常（引擎不可用）不是策略判决：带附件的多来源扫描失败也只记为覆盖缺口并放行
// （CHANGELOG 2.6.14）；附件自身的阻断只来自规则命中。
func TestMultiSourceFileScanFailureIsRecordedGapNotBlock(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(503)
			return
		}
		w.Write([]byte(`{"action":"allow","findings":[],"semantic_status":"completed"}`))
	}))
	defer server.Close()
	extracted := ExtractedContent{Messages: []ConvMessage{{Source: "user", Content: "hello"}, {Source: "tool_result", Content: "result"}}, Attachments: []ExtractedAttachment{{}}}
	out, err := NewSecurityClient(server.URL).checkInputSources(context.Background(), server.URL, map[string]interface{}{"context": map[string]interface{}{"attachments": []map[string]interface{}{{"file_name": "synthetic.txt"}}}}, extracted)
	if err != nil || out["action"] == "block" || out["semantic_status"] != "incomplete" || out["semantic_reason"] != "security_engine_unavailable" {
		t.Fatalf("inspection failure must be a recorded gap, not a block: %v %v", out, err)
	}
}

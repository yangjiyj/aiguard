package security

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckInputDecodesVersionAndRawFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{
			"request_id": "r1", "action": "audit",
			"findings": [{"rule_id":"pi-1","severity":"high","type":"prompt_injection"}],
			"engine_build": "build-abc", "rule_pack_version": "rp-7",
			"semantic_status": "incomplete", "semantic_reason": "breaker_open",
			"raw_findings": [{"rule_id":"pi-1","severity":"critical","type":"prompt_injection"}],
			"latency_ms": 3
		}`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.CheckInput(context.Background(), &CheckInputRequest{RequestID: "r1", Content: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.EngineBuild != "build-abc" || resp.RulePackVersion != "rp-7" {
		t.Fatalf("版本回带解码失败: %+v", resp)
	}
	if resp.SemanticStatus != "incomplete" || resp.SemanticReason != "breaker_open" {
		t.Fatalf("语义裁判状态回带解码失败: %+v", resp)
	}
	var raw []map[string]any
	if err := json.Unmarshal(resp.RawFindings, &raw); err != nil || len(raw) != 1 || raw[0]["severity"] != "critical" {
		t.Fatalf("raw_findings 必须原样保留(含降档前 severity): %s", resp.RawFindings)
	}
}

func TestApplyContextPostsContractShape(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apply-context/" {
			t.Errorf("path = %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"action":"audit","findings":[{"rule_id":"pi-1","severity":"high"}]}`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.ApplyContext(context.Background(), &ApplyContextRequest{
		TenantID:    "t1",
		RawFindings: json.RawMessage(`[{"rule_id":"pi-1"}]`),
		Context: ApplyContextContext{
			AgentType: "claude-code", ProjectID: "p1", UserID: "u1",
			ContentSource: "system_prompt", AccessType: "api",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Action != "audit" || len(resp.Findings) != 1 || resp.Findings[0].RuleID != "pi-1" {
		t.Fatalf("resp = %+v", resp)
	}
	// 契约 2 入参形状
	if gotBody["tenant_id"] != "t1" {
		t.Fatalf("tenant_id 缺失: %v", gotBody)
	}
	ctxMap := gotBody["context"].(map[string]any)
	for _, k := range []string{"agent_type", "project_id", "user_id", "content_source", "access_type"} {
		if _, ok := ctxMap[k]; !ok {
			t.Fatalf("context.%s 缺失: %v", k, ctxMap)
		}
	}
	if _, ok := gotBody["raw_findings"].([]any); !ok {
		t.Fatalf("raw_findings 必须是数组: %v", gotBody)
	}
}

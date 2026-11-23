package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 构造带受限文件策略的 ProxyHandler；auditOnly 控制 securityClient 审计模式。
func newRFProxyHandler(t *testing.T, auditOnly bool, policy RestrictedFilePolicy) *ProxyHandler {
	t.Helper()
	// securityClient 仅用于 SecurityAuditOnly 判定：用 env 无法控制，改注入 reader。
	sec := NewSecurityClient("http://127.0.0.1:0")
	sec.auditOnlySettings = staticBooleanSettingReader(auditOnly)
	h := NewProxyHandler(nil, nil, sec, nil, nil)
	h.restrictedFilePolicy = staticRFPolicyReader{policy: policy}
	return h
}

type staticRFPolicyReader struct{ policy RestrictedFilePolicy }

func (s staticRFPolicyReader) Get(context.Context, string, string) RestrictedFilePolicy {
	return s.policy
}

var codexPDFResponsesSSE = "event: response.output_item.done\n" +
	"data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"id\":\"i1\",\"type\":\"custom_tool_call\",\"call_id\":\"c1\",\"name\":\"exec\",\"input\":\"const r = await tools.exec_command({cmd:\\\"pdftotext 合同.pdf -\\\",workdir:\\\"/w\\\"})\"}}\n\n" +
	"event: response.completed\n" +
	"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"status\":\"completed\",\"output\":[]}}\n\n"

// 四象限：{审计,非审计}×{block,record}。
func TestMergeRestrictedFileOutputQuadrants(t *testing.T) {
	quadrants := []struct {
		name       string
		auditOnly  bool
		action     string
		wantAction string
	}{
		{"非审计+block → block", false, "block", "block"},
		{"非审计+record → audit", false, "record", "audit"},
		{"审计+block → audit（审计模式最高优先级）", true, "block", "audit"},
		{"审计+record → audit", true, "record", "audit"},
	}
	for _, q := range quadrants {
		t.Run(q.name, func(t *testing.T) {
			h := newRFProxyHandler(t, q.auditOnly, RestrictedFilePolicy{Patterns: []string{"*.pdf"}, Action: q.action})
			rec := ProxyAuditRecord{AgentType: "openai-codex"}
			action, findings := h.mergeRestrictedFileOutput("tenant_default", rec, []byte(codexPDFResponsesSSE), "text/event-stream", "allow", nil)
			if action != q.wantAction {
				t.Fatalf("action=%q, want %q (findings=%v)", action, q.wantAction, findings)
			}
			if len(findings) == 0 {
				t.Fatalf("no finding merged")
			}
			f := findings[0]
			if f["rule_id"] != "agentguard-restricted-file-pattern" {
				t.Fatalf("rule_id=%v", f["rule_id"])
			}
			if f["action"] != q.wantAction {
				t.Fatalf("finding action=%v, want %q", f["action"], q.wantAction)
			}
		})
	}
}

// 无策略 → 原样透传。
func TestMergeRestrictedFileOutputNoPolicy(t *testing.T) {
	h := newRFProxyHandler(t, false, RestrictedFilePolicy{})
	rec := ProxyAuditRecord{AgentType: "openai-codex"}
	action, findings := h.mergeRestrictedFileOutput("tenant_default", rec, []byte(codexPDFResponsesSSE), "text/event-stream", "allow", nil)
	if action != "allow" || len(findings) != 0 {
		t.Fatalf("no-policy should pass through, action=%q findings=%v", action, findings)
	}
}

// 无 reader → 原样透传。
func TestMergeRestrictedFileOutputNilReader(t *testing.T) {
	h := NewProxyHandler(nil, nil, NewSecurityClient("http://127.0.0.1:0"), nil, nil)
	rec := ProxyAuditRecord{AgentType: "openai-codex"}
	action, findings := h.mergeRestrictedFileOutput("tenant_default", rec, []byte(codexPDFResponsesSSE), "text/event-stream", "allow", nil)
	if action != "allow" || len(findings) != 0 {
		t.Fatalf("nil reader should pass through, action=%q findings=%v", action, findings)
	}
}

// 与既有 SE action 取强者：SE 已 block 时保持 block。
func TestMergeRestrictedFileOutputKeepsStrongerAction(t *testing.T) {
	h := newRFProxyHandler(t, false, RestrictedFilePolicy{Patterns: []string{"*.pdf"}, Action: "record"})
	rec := ProxyAuditRecord{AgentType: "openai-codex"}
	action, _ := h.mergeRestrictedFileOutput("tenant_default", rec, []byte(codexPDFResponsesSSE), "text/event-stream", "block", nil)
	if action != "block" {
		t.Fatalf("should keep stronger SE action block, got %q", action)
	}
}

// 端到端：假控制面 + 假上游 SSE，经 reader 拉策略后评估。
func TestRestrictedFileEndToEndPolicyFetch(t *testing.T) {
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/v1/internal/agentguard/effective-policy" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"restricted_file_patterns": []string{"*.pdf"}, "restricted_file_action": "block",
			}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer cp.Close()

	sec := NewSecurityClient("http://127.0.0.1:0")
	sec.auditOnlySettings = staticBooleanSettingReader(false)
	h := NewProxyHandler(nil, nil, sec, nil, nil)
	h.restrictedFilePolicy = NewHTTPRestrictedFilePolicyReader(cp.URL, "secret")

	rec := ProxyAuditRecord{AgentType: "openai-codex"}
	action, findings := h.mergeRestrictedFileOutput("tenant_default", rec, []byte(codexPDFResponsesSSE), "text/event-stream", "allow", nil)
	if action != "block" || len(findings) == 0 {
		t.Fatalf("end-to-end fetch+block failed, action=%q findings=%v", action, findings)
	}
}

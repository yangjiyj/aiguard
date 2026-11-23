package handler

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func codexResponsesRequest(path string) string {
	return `{"model":"gpt-5","input":[{"role":"user","content":"# Files mentioned by the user:\n## 合同.pdf: ` + path + `\n## My request:\n请分析这个文件"}]}`
}

func newRFInputProxyHandler(auditOnly bool, policy RestrictedFilePolicy) *ProxyHandler {
	sec := NewSecurityClient("http://127.0.0.1:0")
	sec.auditOnlySettings = staticBooleanSettingReader(auditOnly)
	h := NewProxyHandler(nil, nil, sec, nil, nil)
	h.restrictedFilePolicy = staticRFPolicyReader{policy: policy}
	return h
}

func callInput(h *ProxyHandler, body string) (string, []map[string]interface{}, bool) {
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := ProxyAuditRecord{AgentType: "openai-codex"}
	// 用真实生产解码器名（openai_compatible 经 /responses 分发到 Responses 解码）。
	return h.checkCodexMentionedFilesRestrictedInput("tenant_default", rec, req, []byte(body), "openai_compatible")
}

// Codex 信封 + 受限文件 → block + stage=input finding。
func TestProxyCodexMentionedFileBlocked(t *testing.T) {
	h := newRFInputProxyHandler(false, RestrictedFilePolicy{Patterns: []string{"*.pdf"}, Action: "block"})
	action, findings, blocked := callInput(h, codexResponsesRequest("/home/u/合同.pdf"))
	if !blocked || action != "block" {
		t.Fatalf("want block, action=%q blocked=%v", action, blocked)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %+v", findings)
	}
	f := findings[0]
	if f["stage"] != "input" || f["rule_id"] != "agentguard-restricted-file-pattern" {
		t.Fatalf("finding=%+v", f)
	}
	if f["counts_as_security_finding"] != true {
		t.Fatalf("counts_as_security_finding != true")
	}
}

// 审计模式 + block → 只记录（执行模式以控制台为准，审计模式最高优先级）。
func TestProxyCodexAuditModeBlockOnlyRecords(t *testing.T) {
	h := newRFInputProxyHandler(true, RestrictedFilePolicy{Patterns: []string{"*.pdf"}, Action: "block"})
	action, _, blocked := callInput(h, codexResponsesRequest("/home/u/合同.pdf"))
	if blocked || action != "audit" {
		t.Fatalf("audit mode + block must only record, action=%q blocked=%v", action, blocked)
	}
}

// 审计模式 + record → 放行 + finding action=audit。
func TestProxyCodexAuditModeRecordAllows(t *testing.T) {
	h := newRFInputProxyHandler(true, RestrictedFilePolicy{Patterns: []string{"*.pdf"}, Action: "record"})
	action, findings, blocked := callInput(h, codexResponsesRequest("/home/u/合同.pdf"))
	if blocked || action != "audit" {
		t.Fatalf("record should allow, action=%q blocked=%v", action, blocked)
	}
	if findings[0]["action"] != "audit" {
		t.Fatalf("finding action=%v", findings[0]["action"])
	}
}

// 无策略 → 放行。
func TestProxyCodexNoPolicyAllows(t *testing.T) {
	h := newRFInputProxyHandler(false, RestrictedFilePolicy{})
	_, findings, blocked := callInput(h, codexResponsesRequest("/home/u/合同.pdf"))
	if blocked || len(findings) != 0 {
		t.Fatalf("no policy should allow, findings=%v blocked=%v", findings, blocked)
	}
}

// 非 Codex 信封 → 放行。
func TestProxyNonCodexAllows(t *testing.T) {
	h := newRFInputProxyHandler(false, RestrictedFilePolicy{Patterns: []string{"*.pdf"}, Action: "block"})
	_, findings, blocked := callInput(h, `{"model":"gpt-5","input":[{"role":"user","content":"请分析 合同.pdf"}]}`)
	if blocked || len(findings) != 0 {
		t.Fatalf("non-Codex should allow, findings=%v blocked=%v", findings, blocked)
	}
}

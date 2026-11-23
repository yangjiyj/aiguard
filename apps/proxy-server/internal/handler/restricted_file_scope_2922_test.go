package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// 批次 2B：独立代理的受限文件——文件类工具按路径精确匹配（修老漏检：目录型、带路径通配的模式
// 对 Read 的 file_path 认不出）、作用范围、例外（与网关同一来源、同一路径口径）。

func readInvocation(path string) []ToolInvocation {
	raw, _ := json.Marshal(map[string]any{"file_path": path})
	return []ToolInvocation{{Name: "Read", Arguments: string(raw)}}
}

func TestEvaluateRestrictedFileToolCalls2922FileToolPaths(t *testing.T) {
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{
		{"/vault/", "/vault/x.txt", true},
		{"/vault/", "/srv/vault-notes.txt", false},
		{"docs/**/*.docx", "docs/a/b/plan.docx", true},
		{"*.pdf", "/home/u/合同.pdf", true},
		{"/vault/", "https://example.com/vault/x.txt", false},
	} {
		findings := evaluateRestrictedFileToolCalls(RestrictedFilePolicy{Patterns: []string{tc.pattern}, Action: "block"}, readInvocation(tc.path))
		if (len(findings) == 1 && findings[0]["action"] == "block") != tc.want {
			t.Errorf("pattern=%q path=%q findings=%+v want block=%v", tc.pattern, tc.path, findings, tc.want)
		}
	}
	nested := []ToolInvocation{{Name: "MultiRead", Arguments: `{"options":{"paths":["/tmp/a.txt","/vault/b.txt"]}}`}}
	if findings := evaluateRestrictedFileToolCalls(RestrictedFilePolicy{Patterns: []string{"/vault/"}, Action: "block"}, nested); len(findings) != 1 {
		t.Fatalf("nested path arrays are path arguments too: %+v", findings)
	}
}

func TestEvaluateRestrictedFileToolCalls2922ScopeAndExceptions(t *testing.T) {
	future := time.Now().Add(time.Hour)
	base := RestrictedFilePolicy{Patterns: []string{"/vault/"}, Action: "block"}

	scoped := base
	scoped.ScopesConfigured, scoped.Scopes = true, []string{"tool_call", "user_mention"}
	if findings := evaluateRestrictedFileToolCalls(scoped, readInvocation("/vault/x.txt")); len(findings) != 0 {
		t.Fatalf("proxy_output not selected: %+v", findings)
	}
	scoped.Scopes = []string{"proxy_output"}
	if findings := evaluateRestrictedFileToolCalls(scoped, readInvocation("/vault/x.txt")); len(findings) != 1 {
		t.Fatalf("proxy_output selected: %+v", findings)
	}

	excepted := base
	excepted.Exceptions = []RestrictedFileException{{ID: "e-x", TargetPattern: "/vault/x.txt", ExpiresAt: future}}
	findings := evaluateRestrictedFileToolCalls(excepted, readInvocation("/vault/x.txt"))
	if len(findings) != 1 || findings[0]["action"] != "audit" || findings[0]["exception_id"] != "e-x" {
		t.Fatalf("an exception naming the file only records: %+v", findings)
	}
	if findings := evaluateRestrictedFileToolCalls(excepted, readInvocation("/vault/y.txt")); len(findings) != 1 || findings[0]["action"] != "block" {
		t.Fatalf("other files stay restricted: %+v", findings)
	}
	expired := base
	expired.Exceptions = []RestrictedFileException{{ID: "e-old", ExpiresAt: time.Now().Add(-time.Hour)}}
	if findings := evaluateRestrictedFileToolCalls(expired, readInvocation("/vault/x.txt")); findings[0]["action"] != "block" {
		t.Fatalf("expired exceptions do not apply: %+v", findings)
	}

	h := newRFProxyHandler(t, false, excepted)
	if action, _ := h.mergeRestrictedFileOutput("tenant_default", ProxyAuditRecord{AgentType: "openai-codex"},
		[]byte(codexPDFResponsesSSE), "text/event-stream", "allow", nil); action != "allow" {
		t.Fatalf("no restricted hit in the stream, action=%q", action)
	}
}

func TestProxyCodexMentionedFile2922ScopeAndExceptions(t *testing.T) {
	future := time.Now().Add(time.Hour)
	scoped := RestrictedFilePolicy{Patterns: []string{"*.pdf"}, Action: "block", ScopesConfigured: true, Scopes: []string{"tool_call"}}
	if _, findings, blocked := callInput(newRFInputProxyHandler(false, scoped), codexResponsesRequest("/home/u/合同.pdf")); blocked || len(findings) != 0 {
		t.Fatalf("user_mention not selected: blocked=%v findings=%+v", blocked, findings)
	}
	excepted := RestrictedFilePolicy{Patterns: []string{"*.pdf"}, Action: "block",
		Exceptions: []RestrictedFileException{{ID: "e-contract", TargetPattern: "合同.pdf", ExpiresAt: future}}}
	action, findings, blocked := callInput(newRFInputProxyHandler(false, excepted), codexResponsesRequest("/home/u/合同.pdf"))
	if blocked || action != "audit" || findings[0]["exception_id"] != "e-contract" {
		t.Fatalf("an exception naming the file only records: action=%q blocked=%v findings=%+v", action, blocked, findings)
	}
	if _, _, blocked := callInput(newRFInputProxyHandler(false, excepted), codexResponsesRequest("/home/u/报价.pdf")); !blocked {
		t.Fatal("other files stay blocked")
	}
}

func TestRestrictedFilePolicyFetch2922ScopesAndExceptions(t *testing.T) {
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"restricted_file_patterns": []string{"/vault/"}, "restricted_file_action": "block",
			"restricted_file_scopes": []string{"proxy_output"},
			"exceptions": []map[string]any{
				{"id": "e-file", "rule_id": "agent.restricted_file", "target_pattern": "/vault/x.txt", "expires_at": time.Now().Add(time.Hour)},
				{"id": "e-other", "rule_id": "agent.ssh_private_key", "target_pattern": "", "expires_at": time.Now().Add(time.Hour)},
			},
		}})
	}))
	defer cp.Close()
	policy := NewHTTPRestrictedFilePolicyReader(cp.URL, "secret").Get(context.Background(), "tenant", "openai-codex")
	if !policy.ScopesConfigured || len(policy.Scopes) != 1 || policy.Scopes[0] != "proxy_output" {
		t.Fatalf("scopes=%+v", policy)
	}
	if len(policy.Exceptions) != 1 || policy.Exceptions[0].ID != "e-file" {
		t.Fatalf("only exceptions naming restricted files are kept: %+v", policy.Exceptions)
	}
	if findings := evaluateRestrictedFileToolCalls(policy, readInvocation("/vault/x.txt")); findings[0]["action"] != "audit" {
		t.Fatalf("fetched exception applies: %+v", findings)
	}
}

// 合流后代理与网关共用 filerestrict 的例外口径（2A 收尾）：目录例外含目录本身；只有开头的 ~/ 是家目录。
func TestRestrictedFileExceptionSharesGatewayPathRules(t *testing.T) {
	policy := RestrictedFilePolicy{Exceptions: []RestrictedFileException{
		{ID: "e-dir", TargetPattern: "~/.ssh/", ExpiresAt: time.Now().Add(time.Hour)},
	}}
	now := time.Now()
	for target, want := range map[string]string{
		"~/.ssh":             "e-dir",
		"~/.ssh/id_rsa":      "e-dir",
		"~/../~/.ssh/id_rsa": "",
		"x/../~/.ssh/id_rsa": "",
		"~/.sshx":            "",
	} {
		if got := policy.exceptionFor(target, now); got != want {
			t.Errorf("exceptionFor(%q) = %q, want %q", target, got, want)
		}
	}
}

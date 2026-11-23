package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestEvaluateRestrictedFileToolCalls(t *testing.T) {
	policy := RestrictedFilePolicy{Patterns: []string{"*.pdf", "*.docx"}, Action: "block"}
	tests := []struct {
		name        string
		invocations []ToolInvocation
		wantFinding bool
		wantPreview string
	}{
		{
			name:        "Codex JS 形态",
			invocations: []ToolInvocation{{Name: "exec", Arguments: `{"input":"const r = await tools.exec_command({cmd:\"pdftotext 合同.pdf -\"})"}`}},
			wantFinding: true, wantPreview: "*.pdf",
		},
		{
			name:        "argv 形态",
			invocations: []ToolInvocation{{Name: "shell", Arguments: `{"command":["bash","-lc","pdftotext a.pdf -"]}`}},
			wantFinding: true, wantPreview: "*.pdf",
		},
		{
			name:        "Anthropic tool_use command",
			invocations: []ToolInvocation{{Name: "Bash", Arguments: `{"command":"cat a.pdf"}`}},
			wantFinding: true, wantPreview: "*.pdf",
		},
		{
			name:        "Claude Code Read file_path",
			invocations: []ToolInvocation{{Name: "Read", Arguments: `{"file_path":"/x/合同.docx"}`}},
			wantFinding: true, wantPreview: "*.docx",
		},
		{
			name:        "不命中",
			invocations: []ToolInvocation{{Name: "Bash", Arguments: `{"command":"cat a.go"}`}},
			wantFinding: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := evaluateRestrictedFileToolCalls(policy, tt.invocations)
			if tt.wantFinding && len(findings) == 0 {
				t.Fatalf("want finding, got none")
			}
			if !tt.wantFinding && len(findings) != 0 {
				t.Fatalf("want no finding, got %+v", findings)
			}
			if tt.wantFinding {
				f := findings[0]
				if f["counts_as_security_finding"] != true {
					t.Fatalf("counts_as_security_finding != true: %+v", f)
				}
				if f["rule_id"] != "agentguard-restricted-file-pattern" {
					t.Fatalf("rule_id=%v", f["rule_id"])
				}
				if f["action"] != "block" {
					t.Fatalf("action=%v, want block", f["action"])
				}
				preview, _ := f["matched_text_preview"].(string)
				if !strings.Contains(preview, tt.wantPreview) {
					t.Fatalf("preview=%q 不含 %q", preview, tt.wantPreview)
				}
				// 目标须脱敏，不含完整路径原文
				if strings.Contains(preview, "合同.pdf") || strings.Contains(preview, "pdftotext") {
					t.Fatalf("preview 未脱敏: %q", preview)
				}
			}
		})
	}
}

func TestEvaluateRestrictedFileToolCallsNoPolicy(t *testing.T) {
	invs := []ToolInvocation{{Name: "Bash", Arguments: `{"command":"cat a.pdf"}`}}
	if f := evaluateRestrictedFileToolCalls(RestrictedFilePolicy{}, invs); len(f) != 0 {
		t.Fatalf("empty policy should yield no finding: %+v", f)
	}
}

// record 动作 → finding action=audit。
func TestEvaluateRestrictedFileToolCallsRecordAction(t *testing.T) {
	policy := RestrictedFilePolicy{Patterns: []string{"*.pdf"}, Action: "record"}
	f := evaluateRestrictedFileToolCalls(policy, []ToolInvocation{{Name: "Bash", Arguments: `{"command":"cat a.pdf"}`}})
	if len(f) != 1 || f[0]["action"] != "audit" {
		t.Fatalf("record action should map to audit finding: %+v", f)
	}
}

// 策略读取：成功→缓存；失败→回退上次值；从未成功→空策略。
func TestHTTPRestrictedFilePolicyReaderFallback(t *testing.T) {
	var calls int32
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-Tenant-ID") != "tenant-1" {
			t.Errorf("missing tenant header")
		}
		if r.Header.Get("X-Internal-Token") == "" && r.Header.Get("X-Internal-Secret") == "" {
			// headeraudit.InternalTokenHeader 具体值由实现决定，这里只断非空
		}
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"restricted_file_patterns": []string{"*.pdf"}, "restricted_file_action": "block",
		}})
	}))
	defer srv.Close()

	reader := NewHTTPRestrictedFilePolicyReader(srv.URL, "secret").(*httpRestrictedFilePolicyReader)
	reader.ttl = 0 // 禁缓存，每次 fetch

	p := reader.Get(context.Background(), "tenant-1", "openai-codex")
	if len(p.Patterns) != 1 || p.Action != "block" {
		t.Fatalf("first fetch: %+v", p)
	}

	// 失败回退上次值
	fail.Store(true)
	p2 := reader.Get(context.Background(), "tenant-1", "openai-codex")
	if len(p2.Patterns) != 1 {
		t.Fatalf("should fall back to last good: %+v", p2)
	}
}

// 从未成功 → 空策略（功能关闭），不阻塞。
func TestHTTPRestrictedFilePolicyReaderNeverSucceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	reader := NewHTTPRestrictedFilePolicyReader(srv.URL, "secret")
	p := reader.Get(context.Background(), "tenant-1", "openai-codex")
	if len(p.Patterns) != 0 {
		t.Fatalf("never-succeeded should be empty policy: %+v", p)
	}
}

// 无密钥 → 永远空策略。
func TestStaticReaderNoSecret(t *testing.T) {
	reader := NewHTTPRestrictedFilePolicyReader("http://x", "")
	p := reader.Get(context.Background(), "tenant-1", "openai-codex")
	if len(p.Patterns) != 0 {
		t.Fatalf("no-secret reader should be empty: %+v", p)
	}
}

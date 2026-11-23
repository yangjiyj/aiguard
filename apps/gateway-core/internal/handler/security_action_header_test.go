package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

func TestStrongerSecurityAction(t *testing.T) {
	tests := []struct{ a, b, want string }{
		{"", "audit", "audit"}, {"audit", "mask", "mask"}, {"mask", "reply", "reply"},
		{"reply", "block", "block"}, {"block", "audit", "block"}, {"", "", ""},
	}
	for _, tt := range tests {
		if got := strongerSecurityAction(tt.a, tt.b); got != tt.want {
			t.Errorf("strongerSecurityAction(%q,%q) = %q, want %q", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestSetSecurityActionHeaderSkipsAllowAndEmpty(t *testing.T) {
	for _, action := range []string{"", "allow"} {
		w := httptest.NewRecorder()
		setSecurityActionHeader(w, action, true)
		if got := w.Header().Get("X-Security-Action"); got != "" {
			t.Errorf("action %q should not set header, got %q", action, got)
		}
	}
	w := httptest.NewRecorder()
	setSecurityActionHeader(w, "block", true)
	if w.Header().Get("X-Security-Action") != "block" {
		t.Error("block should set header when enabled")
	}
}

func TestSetSecurityActionHeaderGatedOffByDefault(t *testing.T) {
	// SECURITY_ACTION_HEADER_ENABLED=false 时绝不设头（env 默认 true，config 零值仍为关）：
	// audit_only 下该头等于检测预言机，对外暴露数据面的部署可显式关闭
	w := httptest.NewRecorder()
	setSecurityActionHeader(w, "block", false)
	if got := w.Header().Get("X-Security-Action"); got != "" {
		t.Fatalf("header must not be set when gate is off, got %q", got)
	}

	if securityActionHeaderEnabled(nil) {
		t.Fatal("nil config must mean disabled")
	}
	if securityActionHeaderEnabled(&config.Config{}) {
		t.Fatal("zero-value config must mean disabled (default off)")
	}
	if !securityActionHeaderEnabled(&config.Config{SecurityActionHeader: true}) {
		t.Fatal("explicitly enabled config must mean enabled")
	}
}

func TestOutputActionOf(t *testing.T) {
	tests := []struct {
		name  string
		audit *AuditResult
		want  string
	}{
		{"nil audit result", nil, ""},
		{"allow", &AuditResult{OutputAction: "allow"}, ""},
		{"empty action", &AuditResult{}, ""},
		{"audit", &AuditResult{OutputAction: "audit"}, "audit"},
		{"mask", &AuditResult{OutputAction: "mask"}, "mask"},
		{"block", &AuditResult{OutputAction: "block"}, "block"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := outputActionOf(tt.audit); got != tt.want {
				t.Errorf("outputActionOf = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetStatusCodeToolBlocked(t *testing.T) {
	if got := getStatusCode("tool_blocked"); got != http.StatusForbidden {
		t.Fatalf("tool_blocked = %d, want 403 (审计侧记 403，响应必须一致)", got)
	}
}

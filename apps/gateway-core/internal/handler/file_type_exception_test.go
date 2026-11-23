package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// r2922 对抗复核：文件类型“禁止”命中被内容例外放开后（引擎把动作降成 audit/allow 并标上例外编号），
// 网关不能再只凭类别拦。无例外时照拦。
func blockedTypeFinding(action, exceptionID string) SecurityFinding {
	return SecurityFinding{
		Type: "file", Category: "file_policy_blocked_type", RuleID: "file-policy-blocked-type:pdf",
		Severity: "high", Action: action, ExceptionID: exceptionID,
	}
}

func TestExplicitFileTypePolicyBlocksOnlyUnexemptedBlockingHits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		finding SecurityFinding
		want    bool
	}{
		{"block", blockedTypeFinding("block", ""), true},
		{"quarantine", blockedTypeFinding("quarantine", ""), true},
		{"exception audit", blockedTypeFinding("audit", "exc-pdf"), false},
		{"exception allow", blockedTypeFinding("allow", "exc-pdf"), false},
		{"block with exception id", blockedTypeFinding("block", "exc-pdf"), false},
		{"legacy rule id", SecurityFinding{Category: "file_policy_blocked_type", RuleID: "file-policy-blocked-type", Action: "block"}, true},
		{"typed rule id without category", SecurityFinding{RuleID: "file-policy-blocked-type:exe", Action: "block"}, true},
		{"audit without exception", blockedTypeFinding("audit", ""), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := explicitFileTypePolicyBlocks([]SecurityFinding{tc.finding}); got != tc.want {
				t.Fatalf("explicitFileTypePolicyBlocks = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestApplyInputSecurity_BlockedFileTypeReleasedByContentException(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	for _, tc := range []struct {
		name      string
		finding   SecurityFinding
		wantBlock bool
	}{
		{"exception", blockedTypeFinding("audit", "exc-pdf"), false},
		{"no exception", blockedTypeFinding("block", ""), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			audit := &MockAuditWriter{}
			h := &ChatCompletionsHandler{
				cfg:            &config.Config{},
				securityClient: &spySecurityChecker{action: "audit", findings: []SecurityFinding{tc.finding}},
				auditWriter:    audit,
			}
			envelope := &modelrouter.RequestEnvelope{RequestID: "r-file-type-exception", TenantID: "tenant_default", ProjectID: "project_default", Model: "m"}
			req := &ChatCompletionRequest{Model: "m", Messages: []Message{{Role: "user", Content: docxAttachmentMessage(t)}}}
			_, err := h.applyInputSecurity(context.Background(), envelope, req)
			if (err != nil) != tc.wantBlock {
				t.Fatalf("blocked=%v want %v (err=%v)", err != nil, tc.wantBlock, err)
			}
			if tc.wantBlock != hasSecurityEvent(audit, "security_blocked") {
				t.Fatalf("security_blocked event = %v, want %v: %+v", hasSecurityEvent(audit, "security_blocked"), tc.wantBlock, audit.SecurityEventWrites)
			}
		})
	}
}

func TestFileUploadHandlerBlockedTypeReleasedByContentException(t *testing.T) {
	for _, tc := range []struct {
		name      string
		finding   SecurityFinding
		wantBlock bool
	}{
		{"exception", blockedTypeFinding("audit", "exc-pdf"), false},
		{"no exception", blockedTypeFinding("block", ""), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			security := &fileUploadSecurityStub{action: "audit", findings: []SecurityFinding{tc.finding}}
			caller := &fileUploadCallerStub{body: []byte(`{"id":"file_upstream","object":"file"}`)}
			h := newFileUploadHandlerForTest(&config.Config{}, security, caller)
			response := httptest.NewRecorder()
			h.Handler().ServeHTTP(response, newFileUploadRequest(t, []byte("%PDF-safe-sample")))
			if blocked := response.Code == http.StatusForbidden; blocked != tc.wantBlock {
				t.Fatalf("status=%d want block=%v body=%s", response.Code, tc.wantBlock, response.Body.String())
			}
			if wantCalls := map[bool]int{true: 0, false: 1}[tc.wantBlock]; caller.calls != wantCalls {
				t.Fatalf("upstream calls = %d, want %d", caller.calls, wantCalls)
			}
		})
	}
}

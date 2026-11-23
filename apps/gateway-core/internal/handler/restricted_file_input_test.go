package handler

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func codexEnvelopeMsg(path string) string {
	var sb strings.Builder
	sb.WriteString("# Files mentioned by the user:\n")
	sb.WriteString("## 合同.pdf: " + path + "\n")
	sb.WriteString("## My request:\n请分析这个文件")
	return sb.String()
}

func newRFInputHandler(t *testing.T, auditOnly bool, action, patternsJSON string) (*ChatCompletionsHandler, *MockAuditWriter) {
	t.Helper()
	client := newRestrictedFileToolRiskClient(t, auditOnly, action, patternsJSON, nil)
	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{
		cfg:            &config.Config{SecurityAuditOnly: auditOnly},
		securityClient: &MockSecurityChecker{},
		auditWriter:    audit,
		toolRiskClient: client,
	}
	return h, audit
}

func userMessage(content string) Message {
	raw, _ := json.Marshal(content)
	return Message{Role: "user", Content: raw}
}

// Codex 信封 + 受限文件 → block（403 error + security_blocked 事件）。
func TestCodexMentionedFileRestrictedBlocked(t *testing.T) {
	h, audit := newRFInputHandler(t, false, "block", `["*.pdf"]`)
	env := &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t", UserID: "u", AgentType: "openai-codex"}
	msgs := []Message{userMessage(codexEnvelopeMsg("/home/u/合同.pdf"))}
	blocked, err := h.checkCodexMentionedFilesRestricted(context.Background(), env, msgs)
	if !blocked || err == nil {
		t.Fatalf("want block, blocked=%v err=%v", blocked, err)
	}
	if !strings.Contains(err.Error(), "受限文件类型不允许交给模型") || !strings.Contains(err.Error(), "*.pdf") {
		t.Fatalf("error message=%q", err.Error())
	}
	found := false
	for _, ev := range audit.SecurityEventWrites {
		if ev.ActionTaken == "security_blocked" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing security_blocked event: %+v", audit.SecurityEventWrites)
	}
}

// 审计模式 + block → 只记录（执行模式以控制台为准，审计模式最高优先级）。
func TestCodexMentionedFileAuditModeBlockOnlyRecords(t *testing.T) {
	h, audit := newRFInputHandler(t, true, "block", `["*.pdf"]`)
	env := &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t", UserID: "u", AgentType: "openai-codex"}
	msgs := []Message{userMessage(codexEnvelopeMsg("/home/u/合同.pdf"))}
	blocked, err := h.checkCodexMentionedFilesRestricted(context.Background(), env, msgs)
	if blocked || err != nil {
		t.Fatalf("audit mode + block must only record, blocked=%v err=%v", blocked, err)
	}
	for _, ev := range audit.SecurityEventWrites {
		if ev.ActionTaken == "security_blocked" {
			t.Fatalf("audit mode must not write security_blocked: %+v", audit.SecurityEventWrites)
		}
	}
	if len(audit.SecurityEventWrites) == 0 {
		t.Fatal("audit mode must keep restricted-file evidence")
	}
}

// 审计模式 + record → 放行 + security_audit 事件。
func TestCodexMentionedFileAuditModeRecordAllows(t *testing.T) {
	h, audit := newRFInputHandler(t, true, "record", `["*.pdf"]`)
	env := &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t", UserID: "u", AgentType: "openai-codex"}
	msgs := []Message{userMessage(codexEnvelopeMsg("/home/u/合同.pdf"))}
	blocked, err := h.checkCodexMentionedFilesRestricted(context.Background(), env, msgs)
	if blocked || err != nil {
		t.Fatalf("record should allow, blocked=%v err=%v", blocked, err)
	}
	found := false
	for _, ev := range audit.SecurityEventWrites {
		if ev.ActionTaken == "security_audit" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing security_audit event: %+v", audit.SecurityEventWrites)
	}
}

// 同信封策略为空 → 放行。
func TestCodexMentionedFileNoPolicyAllows(t *testing.T) {
	h, _ := newRFInputHandler(t, false, "block", "")
	env := &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t", UserID: "u", AgentType: "openai-codex"}
	msgs := []Message{userMessage(codexEnvelopeMsg("/home/u/合同.pdf"))}
	blocked, err := h.checkCodexMentionedFilesRestricted(context.Background(), env, msgs)
	if blocked || err != nil {
		t.Fatalf("no policy should allow, blocked=%v err=%v", blocked, err)
	}
}

// 非 Codex 信封（无清单）→ 放行。
func TestNonCodexMessageAllows(t *testing.T) {
	h, _ := newRFInputHandler(t, false, "block", `["*.pdf"]`)
	env := &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t", UserID: "u"}
	msgs := []Message{userMessage("请分析 合同.pdf 这个文件")}
	blocked, err := h.checkCodexMentionedFilesRestricted(context.Background(), env, msgs)
	if blocked || err != nil {
		t.Fatalf("non-Codex message should allow, blocked=%v err=%v", blocked, err)
	}
}

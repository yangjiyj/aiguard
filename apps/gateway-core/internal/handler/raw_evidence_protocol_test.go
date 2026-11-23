package handler

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// needleChecker 只在内容含 needle 时命中（action 为 block 或 mask），命中带回网关传入的
// 协议消息序号（与真实引擎回带 message_index 一致）。
type needleChecker struct {
	*MockSecurityChecker
	needle string
	action string
}

func (c *needleChecker) CheckInput(_ context.Context, _ *modelrouter.RequestEnvelope, content string, messageIndex int, messageRole string, _ string) (string, string, []SecurityFinding, error) {
	if !strings.Contains(content, c.needle) {
		return "allow", "", nil, nil
	}
	idx := messageIndex
	if c.action == "mask" {
		return "mask", strings.ReplaceAll(content, c.needle, "<PHONE>"), []SecurityFinding{{Type: "pii", Category: "phone", Severity: "medium", Action: "mask",
			RuleID: "r-phone", RuleName: "手机号", MessageIndex: &idx, MessageRole: messageRole}}, nil
	}
	return "block", "", []SecurityFinding{{Type: "secret", Category: "api_key", Severity: "critical", Action: "block",
		RuleID: "r-key", RuleName: "密钥", MessageIndex: &idx, MessageRole: messageRole}}, nil
}

func (c *needleChecker) CheckInputDetailed(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, messageIndex int, messageRole string, contentSource string) (*InputCheckOutcome, error) {
	action, masked, findings, err := c.CheckInput(ctx, envelope, content, messageIndex, messageRole, contentSource)
	if err != nil {
		return nil, err
	}
	return &InputCheckOutcome{Action: action, MaskedContent: masked, Findings: findings}, nil
}

func evidenceFor(t *testing.T, req *ChatCompletionRequest, needle, action string, wantBlocked bool) []RawEvidenceRecord {
	t.Helper()
	audit := &rawEvidenceAudit{MockAuditWriter: &MockAuditWriter{}}
	h := &ChatCompletionsHandler{securityClient: &needleChecker{MockSecurityChecker: &MockSecurityChecker{}, needle: needle, action: action}, auditWriter: audit}
	ctx := withBlockLedger(context.Background())
	r := h.applyChatInputSecurity(ctx, rawEvidenceEnvelope(), req)
	if wantBlocked != (r.err != nil) {
		t.Fatalf("blocked=%v want %v (err=%v)", r.err != nil, wantBlocked, r.err)
	}
	return append([]RawEvidenceRecord(nil), audit.records...)
}

func assertSingleEvidence(t *testing.T, recs []RawEvidenceRecord, disposition, wantText, wantRole string, wantIndex int, wantRule, wantRuleName string) {
	t.Helper()
	if len(recs) != 1 {
		t.Fatalf("records=%d want 1: %+v", len(recs), recs)
	}
	rec := recs[0]
	if rec.Disposition != disposition || !strings.Contains(rec.Text, wantText) || rec.Role != wantRole || rec.Index != wantIndex {
		t.Fatalf("stored wrong message: %+v (want %s text~%q role=%s index=%d)", rec, disposition, wantText, wantRole, wantIndex)
	}
	if strings.Contains(rec.Text, "系统提示词") || strings.Contains(rec.Text, "好的助手回复") {
		t.Fatalf("stored unrelated message text: %+v", rec)
	}
	if len(rec.RuleIDs) != 1 || rec.RuleIDs[0] != wantRule || len(rec.RuleNames) != 1 || rec.RuleNames[0] != wantRuleName {
		t.Fatalf("rule attribution must be the hit rule only: %+v", rec)
	}
}

func anthropicChatRequest(t *testing.T, body string) *ChatCompletionRequest {
	t.Helper()
	var req AnthropicMessagesRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	chat, err := (&MessagesHandler{}).convertToChatRequest(&req)
	if err != nil {
		t.Fatal(err)
	}
	return chat
}

func responsesChatRequest(t *testing.T, body string) *ChatCompletionRequest {
	t.Helper()
	var req ResponsesRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	chat, err := (&ResponsesHandler{}).convertToChatRequest(&req)
	if err != nil {
		t.Fatal(err)
	}
	return chat
}

// B-1：Anthropic Messages 前面多一条 system，协议序号与网关数组位置错开。
func TestRawEvidenceBlockedAnthropicStoresHitMessage(t *testing.T) {
	req := anthropicChatRequest(t, `{"model":"m","max_tokens":10,"system":"系统提示词","messages":[
		{"role":"user","content":"你好"},
		{"role":"assistant","content":"好的助手回复"},
		{"role":"user","content":"我的密钥 sk-SECRET-1"}]}`)
	assertSingleEvidence(t, evidenceFor(t, req, "sk-SECRET-1", "block", true), rawEvidenceBlocked, "我的密钥 sk-SECRET-1", "user", 2, "r-key", "密钥")
}

// k=0：不能把系统提示词当阻断原文存下。
func TestRawEvidenceBlockedAnthropicFirstMessageNotSystem(t *testing.T) {
	req := anthropicChatRequest(t, `{"model":"m","max_tokens":10,"system":"系统提示词","messages":[
		{"role":"user","content":"密钥 sk-SECRET-0"}]}`)
	assertSingleEvidence(t, evidenceFor(t, req, "sk-SECRET-0", "block", true), rawEvidenceBlocked, "密钥 sk-SECRET-0", "user", 0, "r-key", "密钥")
}

// tool_result 块被拆成多条网关消息：仍按协议序号取回命中的那条协议消息原文。
func TestRawEvidenceBlockedAnthropicToolResultSplit(t *testing.T) {
	req := anthropicChatRequest(t, `{"model":"m","max_tokens":10,"system":"系统提示词","messages":[
		{"role":"user","content":"读取配置"},
		{"role":"assistant","content":[{"type":"text","text":"好的助手回复"},{"type":"tool_use","id":"tu_1","name":"read","input":{}}]},
		{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu_1","content":"配置内容 sk-SECRET-T"},{"type":"text","text":"继续"}]}]}`)
	assertSingleEvidence(t, evidenceFor(t, req, "sk-SECRET-T", "block", true), rawEvidenceBlocked, "配置内容 sk-SECRET-T", "user", 2, "r-key", "密钥")
}

func TestRawEvidenceBlockedResponsesStoresHitMessage(t *testing.T) {
	req := responsesChatRequest(t, `{"model":"m","instructions":"系统提示词","input":[
		{"role":"user","content":"你好"},
		{"role":"assistant","content":"好的助手回复"},
		{"role":"user","content":"我的密钥 sk-SECRET-R"}]}`)
	assertSingleEvidence(t, evidenceFor(t, req, "sk-SECRET-R", "block", true), rawEvidenceBlocked, "我的密钥 sk-SECRET-R", "user", 2, "r-key", "密钥")
}

func TestRawEvidenceBlockedChatStoresHitMessage(t *testing.T) {
	req := &ChatCompletionRequest{Model: "m", Messages: []Message{
		{Role: "system", Content: jsonQuote("系统提示词")},
		{Role: "user", Content: jsonQuote("你好")},
		{Role: "assistant", Content: jsonQuote("好的助手回复")},
		{Role: "user", Content: jsonQuote("我的密钥 sk-SECRET-C")},
	}}
	assertSingleEvidence(t, evidenceFor(t, req, "sk-SECRET-C", "block", true), rawEvidenceBlocked, "我的密钥 sk-SECRET-C", "user", 3, "r-key", "密钥")
}

// 脱敏改写同样按协议序号记录与归属规则。
func TestRawEvidenceMaskedAnthropicUsesProtocolIndex(t *testing.T) {
	req := anthropicChatRequest(t, `{"model":"m","max_tokens":10,"system":"系统提示词","messages":[
		{"role":"user","content":"你好"},
		{"role":"assistant","content":"好的助手回复"},
		{"role":"user","content":"电话 13800138000"}]}`)
	assertSingleEvidence(t, evidenceFor(t, req, "13800138000", "mask", false), rawEvidenceMasked, "电话 13800138000", "user", 2, "r-phone", "手机号")
}

func TestRawEvidenceMaskedResponsesUsesProtocolIndex(t *testing.T) {
	req := responsesChatRequest(t, `{"model":"m","instructions":"系统提示词","input":[
		{"role":"user","content":"电话 13800138000"}]}`)
	assertSingleEvidence(t, evidenceFor(t, req, "13800138000", "mask", false), rawEvidenceMasked, "电话 13800138000", "user", 0, "r-phone", "手机号")
}

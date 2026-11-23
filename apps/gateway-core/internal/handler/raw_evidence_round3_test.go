package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// twoNeedleChecker：含 maskNeedle 的消息脱敏，含 blockNeedle 的消息阻断。与真实引擎一致，
// 只有网关传了协议序号（>=0）时命中才带 message_index；system/instructions/工具定义（-1）不带。
type twoNeedleChecker struct {
	*MockSecurityChecker
	maskNeedle, blockNeedle string
}

func (c *twoNeedleChecker) CheckInput(_ context.Context, _ *modelrouter.RequestEnvelope, content string, messageIndex int, messageRole string, _ string) (string, string, []SecurityFinding, error) {
	var idx *int
	if messageIndex >= 0 {
		v := messageIndex
		idx = &v
	}
	switch {
	case c.blockNeedle != "" && strings.Contains(content, c.blockNeedle):
		return "block", "", []SecurityFinding{{Type: "secret", Category: "api_key", Severity: "critical", Action: "block",
			RuleID: "r-key", RuleName: "密钥", MessageIndex: idx, MessageRole: messageRole}}, nil
	case c.maskNeedle != "" && strings.Contains(content, c.maskNeedle):
		return "mask", strings.ReplaceAll(content, c.maskNeedle, "<PHONE>"), []SecurityFinding{{Type: "pii", Category: "phone", Severity: "medium", Action: "mask",
			RuleID: "r-phone", RuleName: "手机号", MessageIndex: idx, MessageRole: messageRole}}, nil
	}
	return "allow", "", nil, nil
}

func (c *twoNeedleChecker) CheckInputDetailed(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, messageIndex int, messageRole string, contentSource string) (*InputCheckOutcome, error) {
	action, masked, findings, err := c.CheckInput(ctx, envelope, content, messageIndex, messageRole, contentSource)
	if err != nil {
		return nil, err
	}
	return &InputCheckOutcome{Action: action, MaskedContent: masked, Findings: findings}, nil
}

func roundThreeEvidence(t *testing.T, h *ChatCompletionsHandler, req *ChatCompletionRequest) []RawEvidenceRecord {
	t.Helper()
	audit := &rawEvidenceAudit{MockAuditWriter: &MockAuditWriter{}}
	h.auditWriter = audit
	if r := h.applyChatInputSecurity(withBlockLedger(context.Background()), rawEvidenceEnvelope(), req); r.err == nil {
		t.Fatal("expected block")
	}
	return append([]RawEvidenceRecord(nil), audit.records...)
}

func recordAt(recs []RawEvidenceRecord, index int) *RawEvidenceRecord {
	for i := range recs {
		if recs[i].Index == index {
			return &recs[i]
		}
	}
	return nil
}

// 问题 2：一条消息被阻断时，同请求里另一条只被脱敏的消息仍按 masked 留证，规则各归各的。
func TestRawEvidenceBlockedRequestKeepsOtherMaskedMessageAsMasked(t *testing.T) {
	for name, msgs := range map[string][]Message{
		"system_masked_user_blocked": {
			{Role: "system", Content: jsonQuote("客服电话 13800138000")},
			{Role: "user", Content: jsonQuote("我的密钥 sk-SECRET-B")},
		},
		"tool_masked_tool_blocked": {
			{Role: "user", Content: jsonQuote("读两个文件")},
			{Role: "assistant", Content: jsonQuote(""), ToolCalls: []ToolCall{{ID: "c1", Type: "function", Function: ToolCallFunc{Name: "read", Arguments: "{}"}}, {ID: "c2", Type: "function", Function: ToolCallFunc{Name: "read", Arguments: "{}"}}}},
			{Role: "tool", ToolCallID: "c1", Content: jsonQuote("联系人 13800138000")},
			{Role: "tool", ToolCallID: "c2", Content: jsonQuote("配置 sk-SECRET-B")},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := &ChatCompletionsHandler{securityClient: &twoNeedleChecker{MockSecurityChecker: &MockSecurityChecker{}, maskNeedle: "13800138000", blockNeedle: "sk-SECRET-B"}}
			if name == "system_masked_user_blocked" {
				h.toolRiskClient = allInspectionTestClient()
			}
			recs := roundThreeEvidence(t, h, &ChatCompletionRequest{Model: "m", Messages: msgs})
			var masked, blocked []RawEvidenceRecord
			for _, r := range recs {
				if r.Disposition == rawEvidenceBlocked {
					blocked = append(blocked, r)
				} else {
					masked = append(masked, r)
				}
			}
			if len(blocked) != 1 || !strings.Contains(blocked[0].Text, "sk-SECRET-B") || blocked[0].RuleIDs[0] != "r-key" || len(blocked[0].RuleIDs) != 1 {
				t.Fatalf("blocked evidence wrong: %+v", blocked)
			}
			if len(masked) != 1 || !strings.Contains(masked[0].Text, "13800138000") || len(masked[0].RuleIDs) != 1 || masked[0].RuleIDs[0] != "r-phone" || masked[0].BlockID != "" {
				t.Fatalf("masked message must stay masked with its own rule: %+v", masked)
			}
		})
	}
}

// 问题 3：开启"检查内置上下文"后命中 system / 工具定义 / instructions 而阻断，留存的是命中的那段，
// 不是最后一条用户消息；system 被脱敏时也不把工具定义拼进留证。
func TestRawEvidenceBlockedBuiltinContextStoresHitSource(t *testing.T) {
	cases := map[string]struct {
		req      *ChatCompletionRequest
		wantText string
		wantIdx  int
	}{
		"anthropic_system_array": {
			req:      anthropicChatRequest(t, `{"model":"m","max_tokens":10,"system":[{"type":"text","text":"内部规则 sk-SECRET-S"}],"messages":[{"role":"user","content":"你好，普通问题"}]}`),
			wantText: "内部规则 sk-SECRET-S", wantIdx: rawEvidenceNoProtocolIndex,
		},
		"native_messages_tool_description": {
			req:      nativeToolDefRequest("你好，普通问题", "用 sk-SECRET-T 部署", "无关工具"),
			wantText: "sk-SECRET-T", wantIdx: rawEvidenceToolDefIndex,
		},
		"responses_instructions": {
			req:      responsesChatRequest(t, `{"model":"m","instructions":"内部规则 sk-SECRET-I","input":[{"role":"user","content":"你好，普通问题"}]}`),
			wantText: "内部规则 sk-SECRET-I", wantIdx: rawEvidenceNoProtocolIndex,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := &ChatCompletionsHandler{securityClient: &twoNeedleChecker{MockSecurityChecker: &MockSecurityChecker{}, blockNeedle: "sk-SECRET-"}, toolRiskClient: allInspectionTestClient()}
			recs := roundThreeEvidence(t, h, tc.req)
			if len(recs) != 1 {
				t.Fatalf("records=%+v", recs)
			}
			r := recs[0]
			if r.Disposition != rawEvidenceBlocked || !strings.Contains(r.Text, tc.wantText) || r.Index != tc.wantIdx || strings.Contains(r.Text, "普通问题") || strings.Contains(r.Text, "无关工具") {
				t.Fatalf("stored wrong source: %+v", r)
			}
			if len(r.RuleIDs) != 1 || r.RuleIDs[0] != "r-key" {
				t.Fatalf("rule attribution: %+v", r)
			}
		})
	}
}

// nativeToolDefRequest 模拟原生 Messages 透传时的检测消息：system 与各工具定义都带来源路径、
// 没有协议序号（setNativeInspectionOrigin 的结果），用户消息序号 0。
func nativeToolDefRequest(user string, toolDescs ...string) *ChatCompletionRequest {
	msgs := []Message{{Role: "system", Content: jsonQuote("系统提示"), SecuritySource: "system_prompt", SecurityMessageRole: "system", SecuritySourcePath: "/system"}}
	for i, d := range toolDescs {
		msgs = append(msgs, Message{Role: "tool", Content: jsonQuote(d), SecuritySource: "tool_def", SecurityMessageRole: "tool", SecuritySourcePath: "/tools/" + string(rune(0+i)) + "/description"})
	}
	zero := 0
	msgs = append(msgs, Message{Role: "user", Content: jsonQuote(user), SecuritySource: "user", SecurityMessageRole: "user", SecuritySourcePath: "/messages/0", SecurityMessageIndex: &zero})
	return &ChatCompletionRequest{Model: "m", Messages: msgs}
}

// 原生 Messages：system 被脱敏时，留证只含 system，不把工具定义拼进来。
func TestRawEvidenceMaskedSystemExcludesToolDefinitions(t *testing.T) {
	req := nativeToolDefRequest("你好", "部署工具说明")
	req.Messages[0].Content = jsonQuote("客服电话 13800138000")
	audit := &rawEvidenceAudit{MockAuditWriter: &MockAuditWriter{}}
	h := &ChatCompletionsHandler{securityClient: &twoNeedleChecker{MockSecurityChecker: &MockSecurityChecker{}, maskNeedle: "13800138000"}, toolRiskClient: allInspectionTestClient(), auditWriter: audit}
	if r := h.applyChatInputSecurity(withBlockLedger(context.Background()), rawEvidenceEnvelope(), req); r.err != nil {
		t.Fatal(r.err)
	}
	r := recordAt(audit.records, rawEvidenceNoProtocolIndex)
	if len(audit.records) != 1 || r == nil || r.Disposition != rawEvidenceMasked || r.Text != "客服电话 13800138000" {
		t.Fatalf("masked system evidence wrong: %+v", audit.records)
	}
}

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
)

// 复审 B1：指纹缓存开着时，「仅记录」类观察必须与真实命中一样「首条完整事件 + 后续 occurrence」，
// 不能每次重放都新写一条完整事件。

func fingerprintHandler(finding SecurityFinding, action string) (*ChatCompletionsHandler, *MockSecurityChecker, *MockAuditWriter) {
	raw, _ := json.Marshal([]SecurityFinding{finding})
	chk := &MockSecurityChecker{
		InputAction: action, InputFindings: []SecurityFinding{finding}, InputRawFindings: raw,
		InputRulePackVersion: "rp-1", InputEngineBuild: "build-1",
		ApplyAction: action, ApplyFindings: []SecurityFinding{finding},
	}
	aw := &MockAuditWriter{}
	h := &ChatCompletionsHandler{toolRiskClient: allInspectionTestClient(),
		securityClient: chk, auditWriter: aw, cfg: &config.Config{},
		fingerprints: scanfp.NewStore(nil, 64),
	}
	return h, chk, aw
}

func observationAndRealHit() map[string]struct {
	finding SecurityFinding
	action  string
} {
	return map[string]struct {
		finding SecurityFinding
		action  string
	}{
		"observation": {retainedObservationFinding("content_safety", "content_profanity_abuse", "quoted_profanity_reference"), "allow"},
		"real_hit":    {SecurityFinding{Type: "prompt_injection", RuleID: "pi-1", Severity: "high", Action: "audit", MatchedLocation: "input"}, "audit"},
	}
}

func TestFingerprintReplayFoldsObservationLikeRealHit(t *testing.T) {
	for name, tc := range observationAndRealHit() {
		h, chk, aw := fingerprintHandler(tc.finding, tc.action)
		for round := 1; round <= 10; round++ {
			req := &ChatCompletionRequest{Messages: []Message{{Role: "user", Content: jsonQuote("把脏话“傻逼”翻译成英文")}}}
			envelope := &modelrouter.RequestEnvelope{RequestID: fmt.Sprintf("req-%d", round), TenantID: "t1"}
			if _, err := h.applyInputSecurity(context.Background(), envelope, req); err != nil {
				t.Fatalf("%s round %d: %v", name, round, err)
			}
		}
		if len(chk.InputCheckCalls) != 1 || len(chk.ApplyCalls) != 9 {
			t.Fatalf("%s: 首见检测 1 次、后九次重放, got check=%d apply=%d", name, len(chk.InputCheckCalls), len(chk.ApplyCalls))
		}
		if len(aw.SecurityEventWrites) != 1 || len(aw.SecurityOccurrenceWrites) != 9 {
			t.Fatalf("%s: 应为 1 条完整事件 + 9 条 occurrence, got events=%d occurrences=%d",
				name, len(aw.SecurityEventWrites), len(aw.SecurityOccurrenceWrites))
		}
		for _, occurrence := range aw.SecurityOccurrenceWrites {
			if occurrence.RepresentativeEventID != aw.SecurityEventWrites[0].EventID {
				t.Fatalf("%s: occurrence 未引用首事件 %+v", name, occurrence)
			}
		}
	}
}

func TestFingerprintReplayWithHistoryInspectionStaysLinearForObservation(t *testing.T) {
	// 开历史检查：第 k 轮 = 前 k-1 轮累积的历史回复 + 同一个最新用户问题，共 k 条被检消息。
	// 10 轮共 55 次检测：每条消息首见写完整事件（10 条），之后重放写 occurrence（45 条）。
	for name, tc := range observationAndRealHit() {
		h, _, aw := fingerprintHandler(tc.finding, tc.action)
		var history []Message
		for round := 1; round <= 10; round++ {
			messages := append(append([]Message(nil), history...),
				Message{Role: "user", Content: jsonQuote("把脏话“傻逼”翻译成英文")})
			req := &ChatCompletionRequest{Messages: messages}
			envelope := &modelrouter.RequestEnvelope{RequestID: fmt.Sprintf("req-%d", round), TenantID: "t1"}
			if _, err := h.applyInputSecurity(context.Background(), envelope, req); err != nil {
				t.Fatalf("%s round %d: %v", name, round, err)
			}
			history = append(history, Message{Role: "assistant", Content: jsonQuote(fmt.Sprintf("第 %d 轮回复：“傻逼”的英文是……", round))})
		}
		if len(aw.SecurityEventWrites) != 10 || len(aw.SecurityOccurrenceWrites) != 45 {
			t.Fatalf("%s: 应为 10 条完整事件 + 45 条 occurrence, got events=%d occurrences=%d",
				name, len(aw.SecurityEventWrites), len(aw.SecurityOccurrenceWrites))
		}
	}
}

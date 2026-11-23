package agentguard

import (
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 2.9.22 起没有内置安全底线：这些用例原来锁定“底线不被显式放行/托管记录规则放开”，
// 现在锁定“管理员配成阻断/确认的防护项与 Skill 隔离不被更宽的规则放开”，
// 并补上默认配置（告警放行）下同一输入不拦。

func hardeningExplicitAllowPolicy(settings protection.Settings) *EffectivePolicy {
	return &EffectivePolicy{
		Mode: ModeStrict, RuleMode: ModeStrict, DefaultAction: DecisionAudit, ConfirmChannelEnabled: true,
		Rules:           []PolicyRule{{ID: "allow-system", ToolPattern: "system.*", Action: DecisionAllow, Enabled: true}},
		RestrictedFiles: &RestrictedFilePolicy{Patterns: []string{"*.pem"}, Action: "block"},
		Protections:     settings,
	}
}

func TestConfiguredProtectionExplicitAllowCannotBypass(t *testing.T) {
	restricted := protectionFinding(restrictedFileReason, "/srv/key.pem", "high", nil)
	restricted.RestrictedFileMatched = true
	tests := []struct {
		name     string
		raw      Decision
		settings protection.Settings
		want     DecisionAction
		// configuredOnly: 不是防护项（管理员的 Skill 隔离）或其动作另有配置（受限文件），没有“默认不拦”的对照。
		configuredOnly bool
	}{
		{name: "skill quarantine", raw: Decision{RawDecision: DecisionBlock, Reason: reasonSkillVersionQuarantined, ConfiguredEnforcement: true}, want: DecisionBlock, configuredOnly: true},
		{name: "skill admission unavailable", raw: protectionFinding(reasonSkillAdmissionUnavail, "", "high", nil), settings: protection.Settings{"skill.admission_unavailable": {Action: protection.ActionConfirm}}, want: DecisionConfirm},
		{name: "restricted file", raw: restricted, want: DecisionBlock, configuredOnly: true},
		{name: "secret egress", raw: protectionFinding(reasonHighConfidenceSecretOut, "", "critical", nil), settings: protection.Settings{"agent.secret_egress": {Action: protection.ActionBlock}}, want: DecisionBlock},
		{name: "private target", raw: protectionFinding(targetReasonLoopbackOrPrivate, "", "high", nil), settings: protection.Settings{"agent.private_network": {Action: protection.ActionBlock}}, want: DecisionBlock},
		{name: "metadata target", raw: protectionFinding(targetReasonCloudMetadata, "", "critical", nil), settings: protection.Settings{"agent.cloud_metadata": {Action: protection.ActionBlock}}, want: DecisionBlock},
		{name: "metadata hostname", raw: protectionFinding(targetReasonMetadataHostname, "", "critical", nil), settings: protection.Settings{"agent.cloud_metadata": {Action: protection.ActionBlock}}, want: DecisionBlock},
		{name: "credential file", raw: protectionFinding(targetReasonCloudCredential, "", "critical", nil), settings: protection.Settings{"agent.cloud_credential": {Action: protection.ActionBlock}}, want: DecisionBlock},
		{name: "private key", raw: protectionFinding(targetReasonSSHPrivateKey, "", "critical", nil), settings: protection.Settings{"agent.ssh_private_key": {Action: protection.ActionBlock}}, want: DecisionBlock},
		{name: "sensitive file", raw: protectionFinding(targetReasonSensitiveName, "", "critical", nil), settings: protection.Settings{"agent.sensitive_name": {Action: protection.ActionBlock}}, want: DecisionBlock},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluate := func(settings protection.Settings, caller Mode) Decision {
				return ApplyEffectivePolicy(tt.raw, PolicyEvaluationInput{ToolName: "Bash", ToolType: "system", Policy: hardeningExplicitAllowPolicy(settings), CallerMode: caller})
			}
			if got := evaluate(tt.settings, ModeStrict); got.EffectiveDecision != tt.want {
				t.Fatalf("explicit allow bypassed configured protection: got %q want %q (%+v)", got.EffectiveDecision, tt.want, got)
			}
			for _, mode := range []Mode{ModeAudit, ModeObserve, ModeLight} {
				if got := evaluate(tt.settings, mode); got.EffectiveDecision != DecisionAudit {
					t.Fatalf("record mode %q exceeded its ceiling: %+v", mode, got)
				}
			}
			if !tt.configuredOnly {
				if got := evaluate(nil, ModeStrict); got.EffectiveDecision == DecisionBlock || got.EffectiveDecision == DecisionConfirm {
					t.Fatalf("default settings must not interrupt: %+v", got)
				}
			}
		})
	}
}

func TestConfiguredProtectionManagedRecordCannotDisableNetworkBlock(t *testing.T) {
	blocking := protection.Settings{
		"agent.private_network": {Action: protection.ActionBlock},
		"agent.cloud_metadata":  {Action: protection.ActionBlock},
	}
	for _, reason := range []string{targetReasonLoopbackOrPrivate, targetReasonCloudMetadata, targetReasonMetadataHostname} {
		for _, action := range []string{"record", "alert_allow"} {
			raw := protectionFinding(reason, "", "critical", nil)
			policy := governanceManagedPolicy(action)
			policy.Protections = blocking
			got := ApplyEffectivePolicy(raw, PolicyEvaluationInput{
				ToolName: "Bash", ToolType: "system", Policy: policy, CallerMode: ModeStrict,
			})
			if got.EffectiveDecision != DecisionBlock {
				t.Fatalf("managed %s disabled configured network protection %s: %+v", action, reason, got)
			}
			got = ApplyEffectivePolicy(raw, PolicyEvaluationInput{
				ToolName: "Bash", ToolType: "system", Policy: governanceManagedPolicy(action), CallerMode: ModeStrict,
			})
			if got.EffectiveDecision != DecisionAudit || !got.NotificationRequired {
				t.Fatalf("managed %s with default protection must alert and allow %s: %+v", action, reason, got)
			}
		}
	}
}

func TestConfiguredProtectionRecordKeepsAdministratorAction(t *testing.T) {
	restricted := protectionFinding(restrictedFileReason, "/srv/key.pem", "high", nil)
	restricted.RestrictedFileMatched = true
	for _, tc := range []struct {
		raw    Decision
		policy *EffectivePolicy
	}{
		{restricted, &EffectivePolicy{Mode: ModeStrict, RestrictedFiles: &RestrictedFilePolicy{Patterns: []string{"*.pem"}, Action: "record"}}},
		{protectionFinding(reasonHighConfidenceSecretOut, "", "critical", nil), &EffectivePolicy{Mode: ModeStrict, Protections: protection.Settings{"agent.secret_egress": {Action: protection.ActionRecord}}}},
	} {
		got := ApplyEffectivePolicy(tc.raw, PolicyEvaluationInput{ToolName: "Bash", ToolType: "system", Policy: tc.policy, CallerMode: ModeStrict})
		if got.EffectiveDecision != DecisionAudit || got.NotificationRequired {
			t.Fatalf("configured record was escalated: %+v", got)
		}
	}
}

func TestExplicitEnforcementHasTrustedMarker(t *testing.T) {
	for _, ctx := range []PolicyContext{{Mode: ModeStrict, ExplicitBlock: true}, {Mode: ModeStrict, ExplicitConfirm: true, ConfirmChannelEnabled: true}} {
		got := ApplyPolicy(Decision{RawDecision: DecisionAllow}, ctx)
		if !got.ConfiguredEnforcement {
			t.Fatalf("explicit enforcement lost its trusted marker: %+v", got)
		}
	}
	if got := ApplyPolicy(Decision{RawDecision: DecisionBlock, MatchedRuleID: "metadata_only"}, PolicyContext{Mode: ModeStrict}); got.ConfiguredEnforcement {
		t.Fatalf("rule-match metadata alone granted configured enforcement: %+v", got)
	}
}

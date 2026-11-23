package agentguard

import "testing"

func TestResolveDestructivePolicyPriority(t *testing.T) {
	tests := []struct {
		name       string
		input      DestructivePolicyResolutionInput
		wantAction DestructiveAction
		wantSource ConfigSource
	}{
		{
			name: "application or agent overrides tenant",
			input: DestructivePolicyResolutionInput{
				Mode:         ModeLight,
				ScopePolicy:  &DestructivePolicy{Action: DestructiveActionBlock, ScopeType: "application", ScopeRef: "app-public"},
				TenantPolicy: &DestructivePolicy{Action: DestructiveActionRecord, ScopeType: "tenant"},
			},
			wantAction: DestructiveActionBlock,
			wantSource: ConfigSourceApplicationPolicy,
		},
		{
			name: "agent overrides tenant",
			input: DestructivePolicyResolutionInput{
				Mode:         ModeAudit,
				ScopePolicy:  &DestructivePolicy{Action: DestructiveActionConfirm, ScopeType: "agent", ScopeRef: "agent-public"},
				TenantPolicy: &DestructivePolicy{Action: DestructiveActionRecord, ScopeType: "tenant"},
			},
			wantAction: DestructiveActionConfirm,
			wantSource: ConfigSourceAgentPolicy,
		},
		{
			name: "tenant overrides mode",
			input: DestructivePolicyResolutionInput{
				Mode:         ModeStrict,
				TenantPolicy: &DestructivePolicy{Action: DestructiveActionAlertAllow, ScopeType: "tenant"},
			},
			wantAction: DestructiveActionAlertAllow,
			wantSource: ConfigSourceTenantPolicy,
		},
		{
			name: "mode overrides system",
			input: DestructivePolicyResolutionInput{
				Mode:          ModeLight,
				SystemDefault: DestructiveActionRecord,
			},
			wantAction: DestructiveActionAlertAllow,
			wantSource: ConfigSourceModePreset,
		},
		{
			name: "system default is last fallback",
			input: DestructivePolicyResolutionInput{
				SystemDefault: DestructiveActionBlock,
			},
			wantAction: DestructiveActionBlock,
			wantSource: ConfigSourceSystemDefault,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, source := ResolveDestructivePolicy(tt.input)
			if got == nil || got.Action != tt.wantAction || source != tt.wantSource {
				t.Fatalf("ResolveDestructivePolicy() = (%#v, %q), want action=%q source=%q", got, source, tt.wantAction, tt.wantSource)
			}
		})
	}
}

func TestDestructiveModePresetsAndObserveCompatibility(t *testing.T) {
	tests := []struct {
		mode Mode
		want DestructiveAction
	}{
		{ModeObserve, DestructiveActionRecord},
		{ModeAudit, DestructiveActionRecord},
		{ModeLight, DestructiveActionAlertAllow},
		{ModeStrict, DestructiveActionBlock},
	}
	for _, tt := range tests {
		got, source := ResolveDestructivePolicy(DestructivePolicyResolutionInput{Mode: tt.mode})
		if got.Action != tt.want || source != ConfigSourceModePreset {
			t.Fatalf("mode %q = (%#v,%q), want %q/mode preset", tt.mode, got, source, tt.want)
		}
		if tt.mode == ModeObserve && got.Mode != ModeAudit {
			t.Fatalf("observe must normalize to audit, got %q", got.Mode)
		}
	}
}

func TestDestructiveActionExecutionAndNotificationAreOrthogonal(t *testing.T) {
	tests := []struct {
		action DestructiveAction
		exec   DecisionAction
		notify bool
	}{
		{DestructiveActionRecord, DecisionAudit, false},
		{DestructiveActionAlertAllow, DecisionAudit, true},
		{DestructiveActionConfirm, DecisionConfirm, true},
		{DestructiveActionBlock, DecisionBlock, true},
	}
	for _, tt := range tests {
		exec, notify := DestructiveActionSemantics(tt.action)
		if exec != tt.exec || notify != tt.notify {
			t.Fatalf("action %q = (%q,%t), want (%q,%t)", tt.action, exec, notify, tt.exec, tt.notify)
		}
	}
}

func TestDestructivePolicyAllowsReverseModeOverrides(t *testing.T) {
	tests := []struct {
		name   string
		mode   Mode
		action DestructiveAction
		want   DecisionAction
		notify bool
	}{
		{"light can block", ModeLight, DestructiveActionBlock, DecisionBlock, true},
		{"strict can alert and allow", ModeStrict, DestructiveActionAlertAllow, DecisionAudit, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := ApplyEffectivePolicy(
				Decision{RawDecision: DecisionConfirm},
				PolicyEvaluationInput{
					RiskCategory:   "destructive_change",
					HighConfidence: true,
					Policy: &EffectivePolicy{
						Mode:         tt.mode,
						Destructive:  &DestructivePolicy{Action: tt.action},
						ConfigSource: ConfigSourceTenantPolicy,
					},
					CallerMode: ModeStrict,
				},
			)
			if decision.EffectiveDecision != tt.want || decision.NotificationRequired != tt.notify {
				t.Fatalf("decision = %#v, want execution=%q notify=%t", decision, tt.want, tt.notify)
			}
		})
	}
}

func TestDestructivePolicyCarriesSelectedNotificationChannels(t *testing.T) {
	decision := ApplyEffectivePolicy(Decision{RawDecision: DecisionBlock}, PolicyEvaluationInput{
		HighConfidence: true,
		RiskCategory:   DestructiveRiskCategory,
		Policy: &EffectivePolicy{Mode: ModeLight, Destructive: &DestructivePolicy{
			Action: DestructiveActionAlertAllow, NotifyChannelIDs: []string{"channel-a"},
		}},
	})
	if len(decision.NotifyChannelIDs) != 1 || decision.NotifyChannelIDs[0] != "channel-a" {
		t.Fatalf("notification channels = %#v", decision.NotifyChannelIDs)
	}
}

func TestDestructivePolicyOnlyEnforcesHighConfidence(t *testing.T) {
	for _, action := range []DestructiveAction{DestructiveActionAlertAllow, DestructiveActionConfirm, DestructiveActionBlock} {
		decision := ApplyEffectivePolicy(
			Decision{RawDecision: DecisionConfirm},
			PolicyEvaluationInput{
				RiskCategory:   "destructive_change",
				HighConfidence: false,
				Policy:         &EffectivePolicy{Mode: ModeStrict, Destructive: &DestructivePolicy{Action: action}},
			},
		)
		if decision.EffectiveDecision != DecisionAudit || decision.NotificationRequired {
			t.Fatalf("medium/low confidence action %q must only record, got %#v", action, decision)
		}
	}
}

func TestLegacyRiskCategoryStillRespectsCallerModeCeiling(t *testing.T) {
	decision := ApplyEffectivePolicy(
		Decision{RawDecision: DecisionBlock},
		PolicyEvaluationInput{
			RiskCategory: "data_egress",
			Policy:       &EffectivePolicy{Mode: ModeStrict, DefaultAction: DecisionBlock},
			CallerMode:   ModeAudit,
		},
	)
	if decision.EffectiveDecision != DecisionAudit {
		t.Fatalf("legacy category must retain audit ceiling, got %#v", decision)
	}
}
func TestLegacyRiskCategoryTreatsLightCallerModeAsAudit(t *testing.T) {
	decision := ApplyEffectivePolicy(
		Decision{RawDecision: DecisionBlock},
		PolicyEvaluationInput{
			RiskCategory: "data_egress",
			Policy:       &EffectivePolicy{Mode: ModeStrict, DefaultAction: DecisionBlock},
			CallerMode:   ModeLight,
		},
	)
	if decision.EffectiveDecision != DecisionAudit {
		t.Fatalf("light mode must preserve audit behavior for legacy categories, got %#v", decision)
	}
}
func TestResolveDestructivePolicyRejectsUnknownScope(t *testing.T) {
	got, source := ResolveDestructivePolicy(DestructivePolicyResolutionInput{
		Mode:         ModeStrict,
		ScopePolicy:  &DestructivePolicy{Action: DestructiveActionBlock, ScopeType: "unknown", ScopeRef: "foreign"},
		TenantPolicy: &DestructivePolicy{Action: DestructiveActionRecord, ScopeType: "tenant"},
	})
	if got.Action != DestructiveActionRecord || source != ConfigSourceTenantPolicy {
		t.Fatalf("unknown scope must not override tenant policy, got (%#v,%q)", got, source)
	}
}
func TestDestructiveCategorySynthesizesSystemRecordWithoutPolicy(t *testing.T) {
	tests := []struct {
		name           string
		raw            DecisionAction
		highConfidence bool
	}{
		{"high block", DecisionBlock, true},
		{"high confirm", DecisionConfirm, true},
		{"low block", DecisionBlock, false},
		{"low confirm", DecisionConfirm, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ApplyEffectivePolicy(
				Decision{RawDecision: tt.raw},
				PolicyEvaluationInput{
					RiskCategory:   DestructiveRiskCategory,
					HighConfidence: tt.highConfidence,
					CallerMode:     ModeStrict,
				},
			)
			if got.EffectiveDecision != DecisionAudit || got.FinalAction != DestructiveActionRecord {
				t.Fatalf("nil policy must synthesize system record, got %#v", got)
			}
			if got.ConfigSource != ConfigSourceSystemDefault || got.Mode != ModeAudit || got.NotificationRequired {
				t.Fatalf("nil policy facts mismatch: %#v", got)
			}
		})
	}
}

func TestDestructiveCategorySynthesizesModePresetForLegacyPolicyJSON(t *testing.T) {
	tests := []struct {
		mode       Mode
		high       bool
		wantAction DestructiveAction
		wantExec   DecisionAction
		wantNotify bool
	}{
		{ModeObserve, true, DestructiveActionRecord, DecisionAudit, false},
		{ModeAudit, true, DestructiveActionRecord, DecisionAudit, false},
		{ModeLight, true, DestructiveActionAlertAllow, DecisionAudit, true},
		{ModeStrict, true, DestructiveActionBlock, DecisionBlock, true},
		{ModeStrict, false, DestructiveActionRecord, DecisionAudit, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			got := ApplyEffectivePolicy(
				Decision{RawDecision: DecisionBlock},
				PolicyEvaluationInput{
					RiskCategory:   DestructiveRiskCategory,
					HighConfidence: tt.high,
					Policy:         &EffectivePolicy{Mode: tt.mode, PolicyVersion: "legacy-json"},
					CallerMode:     ModeStrict,
				},
			)
			if got.FinalAction != tt.wantAction || got.EffectiveDecision != tt.wantExec || got.NotificationRequired != tt.wantNotify {
				t.Fatalf("legacy policy mode %q = %#v", tt.mode, got)
			}
			if got.ConfigSource != ConfigSourceModePreset {
				t.Fatalf("legacy policy must report mode preset source, got %#v", got)
			}
		})
	}
}

// The global "record" (观察留痕) posture is documented in the policy center as
// the ceiling for every policy. A tenant destructive policy saved as block must
// therefore only record while it is on, and say why.
func TestDestructivePolicyHonoursGlobalAuditOnlyCeiling(t *testing.T) {
	for _, caller := range []Mode{ModeAudit, ModeObserve} {
		for _, action := range []DestructiveAction{DestructiveActionAlertAllow, DestructiveActionConfirm, DestructiveActionBlock} {
			decision := ApplyEffectivePolicy(Decision{RawDecision: DecisionBlock}, PolicyEvaluationInput{
				RiskCategory:   DestructiveRiskCategory,
				HighConfidence: true,
				CallerMode:     caller,
				Policy: &EffectivePolicy{
					Mode:         ModeAudit,
					Destructive:  &DestructivePolicy{Mode: ModeAudit, Action: action, ScopeType: "tenant"},
					ConfigSource: ConfigSourceTenantPolicy,
				},
			})
			if decision.EffectiveDecision != DecisionAudit || decision.FinalAction != DestructiveActionRecord || decision.NotificationRequired {
				t.Fatalf("caller %q action %q must only record under global audit-only, got %#v", caller, action, decision)
			}
			if decision.EffectiveReason != DestructiveEffectiveReasonGlobalAuditOnly {
				t.Fatalf("caller %q action %q reason = %q", caller, action, decision.EffectiveReason)
			}
			if decision.CustomAction != action {
				t.Fatalf("configured action must stay visible for the audit record, got %q", decision.CustomAction)
			}
			if decision.Mode != ModeAudit {
				t.Fatalf("recorded mode must match the applied enforcement, got %q", decision.Mode)
			}
		}
	}
}

func TestDestructivePolicyBlocksInProtectModeAndReportsStrictExecution(t *testing.T) {
	decision := ApplyEffectivePolicy(Decision{RawDecision: DecisionBlock}, PolicyEvaluationInput{
		RiskCategory:   DestructiveRiskCategory,
		HighConfidence: true,
		CallerMode:     ModeStrict,
		Policy: &EffectivePolicy{
			Mode:         ModeAudit,
			Destructive:  &DestructivePolicy{Mode: ModeAudit, Action: DestructiveActionBlock, ScopeType: "tenant"},
			ConfigSource: ConfigSourceTenantPolicy,
		},
	})
	if decision.EffectiveDecision != DecisionBlock || decision.FinalAction != DestructiveActionBlock {
		t.Fatalf("protect mode must enforce the configured block, got %#v", decision)
	}
	if decision.Mode != ModeStrict {
		t.Fatalf("a blocked operation must not be recorded as mode=audit, got %q", decision.Mode)
	}
}

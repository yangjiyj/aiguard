package agentguard

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

func TestDisabledRuleNeverMatches(t *testing.T) {
	policy := &EffectivePolicy{
		ID:            "agp_disabled",
		Mode:          ModeStrict,
		DefaultAction: DecisionAllow,
		Rules: []PolicyRule{{
			ID:          "disabled-block",
			ToolPattern: "Bash",
			Action:      DecisionBlock,
			Enabled:     false,
		}},
	}

	decision := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
		ToolName: "Bash",
		ToolType: "system",
		Arguments: map[string]any{
			"executable": "go",
			"args":       []any{"test", "./..."},
		},
		Mode:   ModeStrict,
		Policy: policy,
		CommandAllowlist: []CommandAllowRule{{
			Executable: "go",
			ArgsPrefix: []string{"test"},
		}},
	})

	if decision.EffectiveDecision != DecisionAllow {
		t.Fatalf("disabled rule must never match, got %#v", decision)
	}
}

func TestPolicyRuntimeMatchCandidates(t *testing.T) {
	tests := []struct {
		name        string
		toolName    string
		toolType    string
		toolPattern string
	}{
		{name: "web search", toolName: "WebSearch", toolType: "network", toolPattern: "network.*"},
		{name: "bash", toolName: "Bash", toolType: "system", toolPattern: "system.*"},
		{name: "read", toolName: "Read", toolType: "file", toolPattern: "file.*"},
		{name: "skill", toolName: "Skill", toolType: "skill", toolPattern: "skill.*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &EffectivePolicy{
				ID:            "agp_" + tt.toolType,
				Mode:          ModeStrict,
				DefaultAction: DecisionAllow,
				Rules: []PolicyRule{{
					ID:          "block-" + tt.toolType,
					ToolPattern: tt.toolPattern,
					Action:      DecisionBlock,
					Enabled:     true,
				}},
			}

			decision := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
				ToolName:  tt.toolName,
				ToolType:  tt.toolType,
				Arguments: map[string]any{},
				Mode:      ModeStrict,
				Policy:    policy,
			})

			if decision.EffectiveDecision != DecisionBlock {
				t.Fatalf("%s should match %s through normalized type path, got %#v", tt.toolName, tt.toolPattern, decision)
			}
			if decision.MatchedRuleID != "block-"+tt.toolType {
				t.Fatalf("matched rule id = %q, want %q", decision.MatchedRuleID, "block-"+tt.toolType)
			}
		})
	}
}

func TestPolicyRuleSelectionUsesSharedPrecedence(t *testing.T) {
	tests := []struct {
		name           string
		rules          []PolicyRule
		mode           Mode
		channelEnabled bool
		protections    protection.Settings
		wantAction     DecisionAction
		wantReason     string
		wantRuleID     string
	}{
		{
			name: "specific block beats earlier wide allow",
			rules: []PolicyRule{
				{ID: "allow-wide", ToolPattern: "network.*", Action: DecisionAllow, Enabled: true},
				{ID: "block-specific", ToolPattern: "network.websearch", Action: DecisionBlock, Enabled: true},
			},
			mode:       ModeStrict,
			wantAction: DecisionBlock,
			wantReason: effectiveReasonExplicitBlock,
			wantRuleID: "block-specific",
		},
		{
			name: "confirm beats audit and allow",
			rules: []PolicyRule{
				{ID: "allow-wide", ToolPattern: "network.*", Action: DecisionAllow, Enabled: true},
				{ID: "audit-specific", ToolPattern: "network.websearch", Action: DecisionAudit, Enabled: true},
				{ID: "confirm-specific", ToolPattern: "network.websearch", Action: DecisionConfirm, Enabled: true},
			},
			mode:           ModeStrict,
			channelEnabled: true,
			wantAction:     DecisionConfirm,
			wantReason:     effectiveReasonStrictConfirm,
			wantRuleID:     "confirm-specific",
		},
		{
			name: "same strength keeps first rule",
			rules: []PolicyRule{
				{ID: "block-first", ToolPattern: "network.*", Action: DecisionBlock, Enabled: true},
				{ID: "block-second", ToolPattern: "network.websearch", Action: DecisionBlock, Enabled: true},
			},
			mode:       ModeStrict,
			wantAction: DecisionBlock,
			wantReason: effectiveReasonExplicitBlock,
			wantRuleID: "block-first",
		},
		{
			// 2.9.22：无确认通道按 agent.confirm_without_channel，配成阻断时 fail-closed。
			name: "confirm without channel fails closed",
			rules: []PolicyRule{
				{ID: "confirm-specific", ToolPattern: "network.websearch", Action: DecisionConfirm, Enabled: true},
			},
			mode:        ModeStrict,
			protections: protection.Settings{"agent.confirm_without_channel": {Action: protection.ActionBlock}},
			wantAction:  DecisionBlock,
			wantReason:  effectiveReasonConfirmFailClosed,
			wantRuleID:  "confirm-specific",
		},
		{
			name: "confirm without channel alerts and allows by default",
			rules: []PolicyRule{
				{ID: "confirm-specific", ToolPattern: "network.websearch", Action: DecisionConfirm, Enabled: true},
			},
			mode:       ModeStrict,
			wantAction: DecisionAudit,
			wantReason: effectiveReasonConfirmFallbackAudit,
			wantRuleID: "confirm-specific",
		},
		{
			name: "audit ceiling records would confirm",
			rules: []PolicyRule{
				{ID: "confirm-specific", ToolPattern: "network.websearch", Action: DecisionConfirm, Enabled: true},
			},
			mode:           ModeAudit,
			channelEnabled: true,
			wantAction:     DecisionAudit,
			wantReason:     effectiveReasonWouldConfirm,
			wantRuleID:     "confirm-specific",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := ApplyEffectivePolicy(Decision{RawDecision: DecisionAllow}, PolicyEvaluationInput{
				ToolName: "WebSearch",
				ToolType: "network",
				Policy: &EffectivePolicy{
					ID:                    "agp_shared_precedence",
					Mode:                  tt.mode,
					DefaultAction:         DecisionAllow,
					ConfirmChannelEnabled: tt.channelEnabled,
					Rules:                 tt.rules,
					Protections:           tt.protections,
				},
			})
			if decision.EffectiveDecision != tt.wantAction || decision.EffectiveReason != tt.wantReason || decision.MatchedRuleID != tt.wantRuleID {
				t.Fatalf("decision = %#v, want action=%q reason=%q rule=%q", decision, tt.wantAction, tt.wantReason, tt.wantRuleID)
			}
		})
	}
}

func TestPolicyRuleEnabledJSONCompatibility(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "legacy missing field defaults true", raw: `{"id":"legacy","tool_pattern":"file.*","action":"audit"}`, want: true},
		{name: "explicit false stays false", raw: `{"id":"disabled","tool_pattern":"file.*","action":"audit","enabled":false}`, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rule PolicyRule
			if err := json.Unmarshal([]byte(tt.raw), &rule); err != nil {
				t.Fatalf("unmarshal policy rule: %v", err)
			}
			if rule.Enabled != tt.want {
				t.Fatalf("enabled = %v, want %v", rule.Enabled, tt.want)
			}
		})
	}
}

func TestLegacyRuleWithoutIDStillEvaluatesSafely(t *testing.T) {
	var rule PolicyRule
	if err := json.Unmarshal([]byte(`{"tool_pattern":"network.*","action":"audit"}`), &rule); err != nil {
		t.Fatalf("unmarshal legacy rule: %v", err)
	}
	decision := ApplyEffectivePolicy(Decision{RawDecision: DecisionAllow}, PolicyEvaluationInput{
		ToolName: "WebSearch",
		ToolType: "network",
		Policy: &EffectivePolicy{
			ID:            "legacy-policy",
			Mode:          ModeStrict,
			DefaultAction: DecisionAllow,
			Rules:         []PolicyRule{rule},
		},
	})
	if decision.EffectiveDecision != DecisionAudit {
		t.Fatalf("legacy rule should still evaluate, got %#v", decision)
	}
	if decision.MatchedRuleID != "" {
		t.Fatalf("legacy empty rule id must stay empty, got %q", decision.MatchedRuleID)
	}
	if len(decision.Evidence) != 0 {
		t.Fatalf("legacy empty rule id must not create invalid evidence: %#v", decision.Evidence)
	}
}

func TestEffectivePolicyPersistsMatchedRuleEvidenceWithoutDuplicates(t *testing.T) {
	policy := &EffectivePolicy{
		ID:            "agp_audit_evidence",
		Mode:          ModeStrict,
		DefaultAction: DecisionAllow,
		Rules: []PolicyRule{{
			ID:          "block-network",
			ToolPattern: "network.*",
			Action:      DecisionBlock,
			Enabled:     true,
		}},
	}
	apply := func(evidence []Evidence) Decision {
		return ApplyEffectivePolicy(Decision{RawDecision: DecisionAllow, Evidence: evidence}, PolicyEvaluationInput{
			ToolName:   "WebSearch",
			ToolType:   "network",
			Policy:     policy,
			CallerMode: ModeStrict,
		})
	}

	t.Run("preserves analyzer evidence", func(t *testing.T) {
		decision := apply([]Evidence{{RuleID: "argument_tainted", Category: "provenance"}})
		seen := map[string]string{}
		for _, item := range decision.Evidence {
			seen[item.RuleID] = item.Category
		}
		if seen["argument_tainted"] != "provenance" {
			t.Fatalf("analyzer evidence was not preserved: %#v", decision.Evidence)
		}
		if seen["block-network"] != "policy_rule_match" {
			t.Fatalf("matched policy rule evidence missing: %#v", decision.Evidence)
		}
	})

	t.Run("does not duplicate existing rule id", func(t *testing.T) {
		decision := apply([]Evidence{{RuleID: "block-network", Category: "existing"}})
		count := 0
		for _, item := range decision.Evidence {
			if item.RuleID == "block-network" {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("matched policy rule evidence count = %d, want 1: %#v", count, decision.Evidence)
		}
	})
}

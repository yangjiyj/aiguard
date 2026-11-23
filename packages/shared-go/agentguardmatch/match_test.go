package agentguardmatch

import "testing"

func TestMatchesUsesRealCandidatesAndExplicitTypeWildcard(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		toolName string
		toolType string
		want     bool
	}{
		{name: "explicit type wildcard", pattern: "network.*", toolName: "WebSearch", toolType: "network", want: true},
		{name: "question does not match synthetic wildcard", pattern: "network.?", toolName: "WebSearch", toolType: "network", want: false},
		{name: "character class matches real normalized path", pattern: "network.[w]ebsearch", toolName: "WebSearch", toolType: "network", want: true},
		{name: "escaped wildcard does not match synthetic candidate", pattern: `network.\*`, toolName: "WebSearch", toolType: "network", want: false},
		{name: "invalid glob", pattern: "network.[", toolName: "WebSearch", toolType: "network", want: false},
		{name: "empty name and type", pattern: "*", toolName: "", toolType: "", want: false},
		{name: "type-only explicit wildcard", pattern: "network.*", toolName: "", toolType: "network", want: true},
		{name: "type-only question", pattern: "network.?", toolName: "", toolType: "network", want: false},
		{name: "name-only glob", pattern: "web*", toolName: "WebSearch", toolType: "", want: true},
		{name: "empty name with generic wildcard", pattern: "*", toolName: "", toolType: "network", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Matches(tt.pattern, tt.toolName, tt.toolType); got != tt.want {
				t.Fatalf("Matches(%q, %q, %q) = %v, want %v", tt.pattern, tt.toolName, tt.toolType, got, tt.want)
			}
		})
	}
}

func TestEvaluateRulesUsesStableActionPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		rules      []Rule
		wantAction string
		wantRuleID string
		wantMatch  bool
	}{
		{
			name: "specific block beats earlier wide allow",
			rules: []Rule{
				{ID: "allow-wide", Pattern: "network.*", Action: ActionAllow, Enabled: true},
				{ID: "block-specific", Pattern: "network.websearch", Action: ActionBlock, Enabled: true},
			},
			wantAction: ActionBlock,
			wantRuleID: "block-specific",
			wantMatch:  true,
		},
		{
			name: "confirm beats audit and allow",
			rules: []Rule{
				{ID: "allow-wide", Pattern: "network.*", Action: ActionAllow, Enabled: true},
				{ID: "audit-specific", Pattern: "network.websearch", Action: ActionAudit, Enabled: true},
				{ID: "confirm-specific", Pattern: "network.websearch", Action: ActionConfirm, Enabled: true},
			},
			wantAction: ActionConfirm,
			wantRuleID: "confirm-specific",
			wantMatch:  true,
		},
		{
			name: "same strength keeps first rule",
			rules: []Rule{
				{ID: "block-first", Pattern: "network.*", Action: ActionBlock, Enabled: true},
				{ID: "block-second", Pattern: "network.websearch", Action: ActionBlock, Enabled: true},
			},
			wantAction: ActionBlock,
			wantRuleID: "block-first",
			wantMatch:  true,
		},
		{
			name: "disabled and invalid actions are ignored",
			rules: []Rule{
				{ID: "disabled-block", Pattern: "network.*", Action: ActionBlock, Enabled: false},
				{ID: "invalid", Pattern: "network.*", Action: "execute", Enabled: true},
			},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.rules, "WebSearch", "network")
			if got.Matched != tt.wantMatch || got.Action != tt.wantAction || got.RuleID != tt.wantRuleID {
				t.Fatalf("Evaluate() = %#v, want matched=%v action=%q rule=%q", got, tt.wantMatch, tt.wantAction, tt.wantRuleID)
			}
		})
	}
}

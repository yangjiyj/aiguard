package handler

import (
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"strings"
	"testing"
)

func TestRestrictedFileDecisionSurvivesDestructiveGate(t *testing.T) {
	for _, tt := range []struct {
		name  string
		args  map[string]any
		parse bool
	}{
		{"parse_rejected", map[string]any{"command": "echo '"}, true},
		{"destructive", map[string]any{"command": "rm 合同.pdf"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			base := agentguard.Decision{RawDecision: agentguard.DecisionBlock, RestrictedFileMatched: true, RestrictedFilePattern: "*.pdf", Evidence: []agentguard.Evidence{{RuleID: "restricted_file_pattern", SourceField: "pattern", MaskedPreview: "*.pdf"}}}
			got := evaluateStructuredToolCall(structuredToolCallInput{ToolName: "exec_command", ToolType: "shell", Mode: agentguard.ModeAudit, Arguments: tt.args, BaseDecision: base})
			if got.Destructive.ParseRejected != tt.parse {
				t.Fatalf("wrong test path: %+v", got.Destructive)
			}
			if !tt.parse && got.Destructive.Category == "" {
				t.Fatal("destructive branch not exercised")
			}
			if !got.Decision.RestrictedFileMatched || got.Decision.RestrictedFilePattern != "*.pdf" {
				t.Fatalf("lost flag: %+v", got.Decision)
			}
			if !strings.Contains(got.Decision.ReasonSummary, "restricted_file_pattern") {
				t.Fatal("summary lost restricted match")
			}
			found := false
			for _, e := range got.Decision.Evidence {
				if e.RuleID == "restricted_file_pattern" && e.SourceField == "pattern" {
					found = true
				}
			}
			if !found {
				t.Fatal("lost restricted file evidence")
			}
		})
	}
}

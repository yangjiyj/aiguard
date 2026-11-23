package agentguard

import "testing"

func TestMergeAnalyzerDecisionCarriesRestrictedFileFlag(t *testing.T) {
	restricted := Decision{RawDecision: DecisionAudit, RestrictedFileMatched: true, RestrictedFilePattern: "*.pdf"}
	stronger := Decision{RawDecision: DecisionBlock, Reason: "destructive"}
	for _, pair := range [][2]Decision{{restricted, stronger}, {stronger, restricted}} {
		got := mergeAnalyzerDecision(pair[0], pair[1])
		if !got.RestrictedFileMatched || got.RestrictedFilePattern != "*.pdf" || got.RawDecision != DecisionBlock {
			t.Fatalf("lost flag or strongest action: %+v", got)
		}
	}
}

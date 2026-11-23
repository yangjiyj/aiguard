package agentguard

import "testing"

// 复审次要项：handler 合并结论用 agentguard 导出的排序，不借端侧的 endpointDecisionRank。
func TestDecisionRank2922Order(t *testing.T) {
	order := []DecisionAction{"", DecisionAllow, DecisionAudit, DecisionConfirm, DecisionBlock}
	for i := 1; i < len(order); i++ {
		if DecisionRank(order[i]) <= DecisionRank(order[i-1]) {
			t.Fatalf("%q must rank above %q", order[i], order[i-1])
		}
	}
	if DecisionRank("unknown") != 0 {
		t.Fatal("an unknown action ranks lowest")
	}
}

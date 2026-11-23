package handler

import (
	"testing"
	"time"
)

func TestRulePackNodePrefixStripsOnlyNumericPidSuffix(t *testing.T) {
	for nodeID, want := range map[string]string{
		"engine-a#123":            "engine-a",
		"engine-a#1#456":          "engine-a#1",
		"security-engine:primary": "security-engine:primary",
		"engine-a#worker":         "engine-a#worker",
		"engine-a#":               "engine-a#",
		"#123":                    "#123",
	} {
		if got := rulePackNodePrefix(nodeID); got != want {
			t.Errorf("rulePackNodePrefix(%q) = %q, want %q", nodeID, got, want)
		}
	}
}

func TestGroupRulePackPullStatusAggregatesWorkersInsteadOfOneRow(t *testing.T) {
	now := time.Now().UTC()
	nodes := []rulePackNodePullView{
		{NodeID: "engine-a#11", Status: rulePackNodeStatusConverged, Converged: true, LastPullAt: now},
		{NodeID: "engine-a#12", Status: rulePackNodeStatusLagging, LastPullAt: now.Add(-time.Second)},
		{NodeID: "engine-a#13", Status: rulePackNodeStatusConverged, Converged: true, LastPullAt: now.Add(-2 * time.Second)},
		{NodeID: "engine-b#21", Status: rulePackNodeStatusEngineUpgradeRequired, LastPullAt: now.Add(-3 * time.Second)},
		{NodeID: "pinned-primary", Status: rulePackNodeStatusConverged, Converged: true, LastPullAt: now.Add(-4 * time.Second)},
	}
	groups := groupRulePackPullStatus(nodes)
	if len(groups) != 3 {
		t.Fatalf("groups = %d, want 3: %+v", len(groups), groups)
	}
	a, b, pinned := groups[0], groups[1], groups[2]
	if a.NodeIDPrefix != "engine-a" || a.Nodes != 3 || a.ConvergedNodes != 2 {
		t.Errorf("engine-a group = %+v, want 3 nodes / 2 converged", a)
	}
	if a.Status != rulePackNodeStatusLagging {
		t.Errorf("engine-a status = %q, want lagging", a.Status)
	}
	if !a.LastPullAt.Equal(now) {
		t.Errorf("engine-a last_pull_at = %v, want newest %v", a.LastPullAt, now)
	}
	if b.NodeIDPrefix != "engine-b" || b.Nodes != 1 || b.Status != rulePackNodeStatusEngineUpgradeRequired {
		t.Errorf("engine-b group = %+v", b)
	}
	if pinned.NodeIDPrefix != "pinned-primary" || pinned.Nodes != 1 || pinned.ConvergedNodes != 1 {
		t.Errorf("pinned group = %+v", pinned)
	}
}

func TestGroupRulePackPullStatusEmptyLedger(t *testing.T) {
	groups := groupRulePackPullStatus(nil)
	if groups == nil || len(groups) != 0 {
		t.Fatalf("empty ledger must produce an empty (non-nil) groups array, got %#v", groups)
	}
}

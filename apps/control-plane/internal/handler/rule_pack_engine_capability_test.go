package handler

import (
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
)

// 旧引擎（未声明 semantic_action 能力）拉到裁剪后的规则包：节点台账要标出"需升级引擎"，
// 而不是一直显示"落后"（它持有的就是给它裁剪过的版本，再等也不会收敛）。
func TestPullStatusFlagsNodesThatNeedEngineUpgrade(t *testing.T) {
	resetRulePackPullLedger(t)
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	setRulePackStatusNow(t, now)
	recordRulePackPull("node-old", "tenant_default", "ver-stripped0001", "ver-stripped0001", now)
	markRulePackNodeEngineUpgrade("tenant_default", "node-old", []string{rules.EngineCapabilitySemanticAction})
	recordRulePackPull("node-new", "tenant_default", "ver-full00000001", "ver-full00000001", now)
	markRulePackNodeEngineUpgrade("tenant_default", "node-new", nil)

	nodes := listRulePackPullStatus("tenant_default", "ver-full00000001", now)
	if len(nodes) != 2 {
		t.Fatalf("nodes=%+v", nodes)
	}
	byID := map[string]rulePackNodePullView{}
	for _, node := range nodes {
		byID[node.NodeID] = node
	}
	old := byID["node-old"]
	if old.Status != rulePackNodeStatusEngineUpgradeRequired || old.Converged {
		t.Fatalf("old engine node status=%q converged=%v", old.Status, old.Converged)
	}
	if len(old.EngineUpgradeRequired) != 1 || old.EngineUpgradeRequired[0] != rules.EngineCapabilitySemanticAction {
		t.Fatalf("old engine node must list missing capability: %+v", old.EngineUpgradeRequired)
	}
	if fresh := byID["node-new"]; fresh.Status != rulePackNodeStatusConverged || len(fresh.EngineUpgradeRequired) != 0 {
		t.Fatalf("capable node=%+v", fresh)
	}

	// 升级后同一节点再次拉取并声明能力：提示清除。
	recordRulePackPull("node-old", "tenant_default", "ver-full00000001", "ver-full00000001", now)
	markRulePackNodeEngineUpgrade("tenant_default", "node-old", nil)
	for _, node := range listRulePackPullStatus("tenant_default", "ver-full00000001", now) {
		if node.NodeID == "node-old" && (node.Status != rulePackNodeStatusConverged || len(node.EngineUpgradeRequired) != 0) {
			t.Fatalf("upgraded node=%+v", node)
		}
	}
}

func TestEngineCapabilitiesHeaderName(t *testing.T) {
	if engineCapabilitiesHeader != "X-Engine-Capabilities" {
		t.Fatalf("header=%q must match security-engine ENGINE_CAPABILITIES_HEADER", engineCapabilitiesHeader)
	}
}

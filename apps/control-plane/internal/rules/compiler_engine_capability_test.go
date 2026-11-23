package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 新控制面 + 旧引擎混跑：旧引擎 CompiledPolicy 是 extra=forbid 严格 DTO，收到
// semantic_action 会拒收整个规则包。旧引擎不声明能力时不下发该字段，并告警需升级引擎。
func TestAdaptForEngineStripsSemanticActionForOldEngines(t *testing.T) {
	pack := Compile("tenant-a", []*repository.Rule{semanticPolicyRule(`{"semantic_action":"block"}`)}, nil)
	fullVersion := pack.Version
	if pack.Policies[0].SemanticAction != "block" {
		t.Fatalf("precondition: semantic_action=%q", pack.Policies[0].SemanticAction)
	}

	for _, header := range []string{"", "  ", "other_feature"} {
		adapted := pack
		adapted.Policies = append([]CompiledPolicy(nil), pack.Policies...)
		missing := AdaptForEngine(&adapted, header)
		if len(missing) != 1 || missing[0] != EngineCapabilitySemanticAction {
			t.Fatalf("header %q: missing=%v", header, missing)
		}
		wire, _ := json.Marshal(adapted)
		if strings.Contains(string(wire), "semantic_action") {
			t.Fatalf("header %q: old engine must not receive semantic_action: %s", header, wire)
		}
		if !adapted.Degraded || !containsString(adapted.Warnings, WarningEngineUpgradeRequired) {
			t.Fatalf("header %q: upgrade warning missing: degraded=%v warnings=%v", header, adapted.Degraded, adapted.Warnings)
		}
		if adapted.Version == fullVersion || adapted.Version != ContentVersion(adapted) {
			t.Fatalf("header %q: version must cover the stripped content: %s vs full %s", header, adapted.Version, fullVersion)
		}
		if pack.Policies[0].SemanticAction != "block" {
			t.Fatal("adapting a copy must not mutate the shared compiled policies")
		}
	}
}

func TestAdaptForEngineKeepsSemanticActionForCapableEngines(t *testing.T) {
	for _, header := range []string{"semantic_action", "foo, semantic_action", " SEMANTIC_ACTION "} {
		pack := Compile("tenant-a", []*repository.Rule{semanticPolicyRule(`{"semantic_action":"block"}`)}, nil)
		version := pack.Version
		if missing := AdaptForEngine(&pack, header); len(missing) != 0 {
			t.Fatalf("header %q: missing=%v", header, missing)
		}
		if pack.Policies[0].SemanticAction != "block" || pack.Version != version || pack.Degraded {
			t.Fatalf("header %q: capable engine pack changed: %+v", header, pack.Policies[0])
		}
	}
}

func TestAdaptForEngineIsNoopWithoutSemanticPolicies(t *testing.T) {
	pack := Compile("tenant-a", []*repository.Rule{semanticPolicyRule(`{}`)}, nil)
	version := pack.Version
	if missing := AdaptForEngine(&pack, ""); len(missing) != 0 {
		t.Fatalf("default packs need no engine capability, missing=%v", missing)
	}
	if pack.Version != version || pack.Degraded || len(pack.Warnings) != 0 {
		t.Fatalf("default pack must be served unchanged to old engines: %+v", pack)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

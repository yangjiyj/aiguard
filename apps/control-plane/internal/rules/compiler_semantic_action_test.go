package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func semanticPolicyRule(scope string) *repository.Rule {
	rule := capabilityPolicy(0)
	rule.ScopeJSON = []byte(scope)
	rule.RuntimeCapabilities = []repository.RuntimePolicyCapability{runtimeCapability("semantic_jailbreak")}
	return rule
}

func TestCompileCarriesConsoleSemanticActionOnlyWhenNonDefault(t *testing.T) {
	for scope, want := range map[string]string{
		`{}`:                            "",
		`{"semantic_action":"audit"}`:   "",
		`{"semantic_action":"block"}`:   "block",
		`{"semantic_action":"observe"}`: "observe",
		`{"semantic_action":"mask"}`:    "",
	} {
		pack := Compile("tenant-a", []*repository.Rule{semanticPolicyRule(scope)}, nil)
		if len(pack.Policies) != 1 {
			t.Fatalf("scope %s: policies=%d skipped=%+v", scope, len(pack.Policies), pack.Skipped)
		}
		if got := pack.Policies[0].SemanticAction; got != want {
			t.Fatalf("scope %s: semantic_action=%q want %q", scope, got, want)
		}
		wire, _ := json.Marshal(pack.Policies[0])
		if want == "" && strings.Contains(string(wire), "semantic_action") {
			t.Fatalf("default semantic action must stay off the wire for older engines: %s", wire)
		}
	}
}

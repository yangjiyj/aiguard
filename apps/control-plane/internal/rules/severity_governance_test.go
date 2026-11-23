package rules

import (
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"testing"
)

func TestCompiledPolicyCarriesBaselineSeverity(t *testing.T) {
	rule := capabilityPolicy(0)
	pack := Compile("tenant-a", []*repository.Rule{rule}, nil)
	if pack.Policies[0].Severity != rule.Severity || pack.Policies[0].Action != rule.Action {
		t.Fatalf("policy=%+v", pack.Policies[0])
	}
}

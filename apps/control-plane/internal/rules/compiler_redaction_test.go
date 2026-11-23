package rules

import (
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"testing"
)

func TestCompiledPolicyRedactionConfigIsVersioned(t *testing.T) {
	makeRule := func(replacement string) *repository.Rule {
		return &repository.Rule{ID: "redaction", PolicyCode: "custom.redaction", RuleType: "regex", Name: "redaction", Severity: "high", Action: "mask", Enabled: true, MatchConfigJSON: []byte(`{"regex":"CUS-[0-9]{5}"}`), ScopeJSON: []byte(`{"scene":"data_security","redaction":{"replacement":"` + replacement + `","restore_response":true}}`)}
	}
	first := Compile("tenant-a", []*repository.Rule{makeRule("[客户编号]")}, nil)
	second := Compile("tenant-a", []*repository.Rule{makeRule("[内部编号]")}, nil)
	if len(first.Policies) != 1 || first.Policies[0].Redaction == nil || !first.Policies[0].Redaction.RestoreResponse {
		t.Fatalf("redaction setting missing: %+v", first)
	}
	if first.Version == second.Version {
		t.Fatal("redaction changed without rule-pack version change")
	}
	broken := makeRule("<JJD_reserved>")
	pack := Compile("tenant-a", []*repository.Rule{broken}, nil)
	if len(pack.Rules) != 0 || len(pack.Policies) != 0 || pack.Diagnostics.SkipReasons["invalid_redaction"] != 1 {
		t.Fatalf("bad redaction was compiled: %+v", pack)
	}
}

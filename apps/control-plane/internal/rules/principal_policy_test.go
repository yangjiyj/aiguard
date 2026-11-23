package rules

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func subjectPolicyRule(scope string) *repository.Rule {
	return &repository.Rule{
		ID: "rule-subject", PolicyCode: "custom.subject", RuleType: "keyword",
		Name: "subject", Severity: "high", Action: "block", Enabled: true,
		ScopeJSON: []byte(scope), MatchConfigJSON: []byte(`{"keywords":["secret"]}`),
	}
}

func TestCompiledPolicyIncludesSubjectBindingAndVersion(t *testing.T) {
	bound := Compile("tenant-a", []*repository.Rule{subjectPolicyRule(`{"scene":"data_leak","subject_binding":{"project_ids":["app-a"]}}`)}, nil)
	global := Compile("tenant-a", []*repository.Rule{subjectPolicyRule(`{"scene":"data_leak"}`)}, nil)
	if len(bound.Policies) != 1 || bound.Policies[0].SubjectBinding == nil || bound.Policies[0].SubjectBinding.ProjectIDs[0] != "app-a" {
		t.Fatalf("compiled binding missing: %+v", bound)
	}
	if bound.Version == global.Version {
		t.Fatal("subject binding did not participate in rule-pack version")
	}
}

func TestInvalidSubjectBindingFailsClosedWithDiagnostic(t *testing.T) {
	pack := Compile("tenant-a", []*repository.Rule{subjectPolicyRule(`{"scene":"data_leak","subject_binding":{"unexpected":["x"]}}`)}, nil)
	if len(pack.Policies) != 0 || pack.Diagnostics.SkipReasons["invalid_subject_binding"] != 1 || !pack.Degraded {
		t.Fatalf("invalid binding did not fail closed: %+v", pack)
	}
}

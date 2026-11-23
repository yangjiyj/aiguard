package rules

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestCompileRequiresExecutableTypeAndMatchingMatcher(t *testing.T) {
	tests := []struct {
		name     string
		ruleType string
		config   string
	}{
		{name: "domain keyword is catalog", ruleType: "prompt_injection", config: `{"keywords":["ignore previous"]}`},
		{name: "unknown type", ruleType: "shell", config: `{"regex":"rm"}`},
		{name: "blank regex", ruleType: "regex", config: `{"regex":"   "}`},
		{name: "blank keyword", ruleType: "keyword", config: `{"keywords":[" ",""]}`},
		{name: "blank field", ruleType: "field_name", config: `{"field_names":[" "]}`},
		{name: "regex mismatch", ruleType: "regex", config: `{"keywords":["secret"]}`},
		{name: "keyword mismatch", ruleType: "keyword", config: `{"regex":"secret"}`},
		{name: "field mismatch", ruleType: "field_name", config: `{"keywords":["password"]}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := &repository.Rule{ID: "rule_test", RuleType: tc.ruleType, Name: tc.name, Severity: "high", Action: "block", Enabled: true, MatchConfigJSON: []byte(tc.config)}
			pack := Compile("tenant-a", []*repository.Rule{rule}, nil)
			if len(pack.Rules) != 0 || len(pack.Skipped) != 1 || pack.Skipped[0].Reason != "no_supported_matcher" {
				t.Fatalf("rules=%+v skipped=%+v, want no_supported_matcher", pack.Rules, pack.Skipped)
			}
		})
	}
}

func TestCompileNormalizesOnlyMatcherForRuntimeType(t *testing.T) {
	rule := &repository.Rule{
		ID: "rule_kw_trim", RuleType: "keyword", Name: "trimmed keyword",
		Severity: "high", Action: "audit", Enabled: true,
		MatchConfigJSON: []byte(`{"regex":"ignored","keywords":[" secret "," ","token"],"field_names":["ignored"],"category":"secret_keyword"}`),
	}
	pack := Compile("tenant-a", []*repository.Rule{rule}, nil)
	if len(pack.Rules) != 1 {
		t.Fatalf("compiled=%d skipped=%+v, want 1", len(pack.Rules), pack.Skipped)
	}
	got := pack.Rules[0]
	if got.Regex != "" || len(got.FieldNames) != 0 || len(got.Keywords) != 2 || got.Keywords[0] != "secret" || got.Keywords[1] != "token" {
		t.Fatalf("compiled matcher not normalized by type: %+v", got)
	}
	if got.Category != "secret_keyword" {
		t.Fatalf("category=%q want secret_keyword", got.Category)
	}
}

package rules

import (
	"fmt"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func runtimeKeywordRule(id string) *repository.Rule {
	return &repository.Rule{
		ID:              id,
		RuleType:        "keyword",
		Name:            "可执行关键词规则 " + id,
		Severity:        "high",
		Action:          "block",
		Enabled:         true,
		MatchConfigJSON: []byte(`{"keywords":["secret"],"category":"data_security"}`),
	}
}

func TestCompileDiagnosticsSeparateRuleCandidatesFromExceptionSkips(t *testing.T) {
	rule := runtimeKeywordRule("rule_ok")
	exception := auditException("exc_invalid", rule.ID, "block")

	pack := Compile("tenant-a", []*repository.Rule{rule}, []*repository.ContentAuditException{exception})

	if pack.Diagnostics.CatalogCount != 1 || pack.Diagnostics.CompiledCount != 1 || pack.Diagnostics.SkippedCount != 0 {
		t.Fatalf("rule diagnostics polluted by exception skip: %+v", pack.Diagnostics)
	}
	if len(pack.Diagnostics.SkipReasons) != 0 {
		t.Fatalf("exception skip must not enter rule skip reasons: %+v", pack.Diagnostics.SkipReasons)
	}
	if len(pack.Skipped) != 1 || pack.Skipped[0].Reason != "exception_invalid_decision" {
		t.Fatalf("legacy detailed skip evidence must retain exception: %+v", pack.Skipped)
	}
}

func TestCompileDiagnosticsClassifyEveryRejectedRuleReason(t *testing.T) {
	rules := []*repository.Rule{
		{
			ID: "rule_invalid_json", RuleType: "regex", Name: "损坏配置",
			Severity: "high", Action: "block", Enabled: true,
			MatchConfigJSON: []byte(`{"regex":`),
		},
		{
			ID: "rule_unsafe", RuleType: "regex", Name: "危险正则",
			Severity: "high", Action: "block", Enabled: true,
			MatchConfigJSON: []byte(`{"regex":"(a+)+$"}`),
		},
		{
			ID: "rule_no_matcher", RuleType: "keyword", Name: "能力目录",
			Severity: "medium", Action: "audit", Enabled: true,
			MatchConfigJSON: []byte(`{}`),
		},
		{
			ID: "rule_disabled", RuleType: "keyword", Name: "停用规则",
			Severity: "medium", Action: "audit", Enabled: false,
			MatchConfigJSON: []byte(`{"keywords":["secret"]}`),
		},
	}

	pack := Compile("tenant-a", rules, nil)

	if pack.Diagnostics.CatalogCount != 4 || pack.Diagnostics.CompiledCount != 0 || pack.Diagnostics.SkippedCount != 4 {
		t.Fatalf("unexpected diagnostic totals: %+v", pack.Diagnostics)
	}
	wantReasons := map[string]int{
		"invalid_match_config": 1,
		"unsafe_regex":         1,
		"no_supported_matcher": 1,
		"disabled":             1,
	}
	if len(pack.Diagnostics.SkipReasons) != len(wantReasons) {
		t.Fatalf("skip reasons=%+v, want %+v", pack.Diagnostics.SkipReasons, wantReasons)
	}
	for reason, want := range wantReasons {
		if got := pack.Diagnostics.SkipReasons[reason]; got != want {
			t.Fatalf("skip reason %q=%d, want %d (all=%+v)", reason, got, want, pack.Diagnostics.SkipReasons)
		}
	}
}

func TestCompileSeparatesCapabilityCatalogFromConfiguredPendingRules(t *testing.T) {
	rules := []*repository.Rule{
		{
			ID: "catalog", Name: "能力目录", RuleType: "prompt_injection",
			Severity: "medium", Action: "audit", Enabled: true,
			MatchConfigJSON: []byte(`{}`),
		},
		{
			ID: "disabled", Name: "停用邮箱规则", RuleType: "regex",
			Severity: "medium", Action: "audit", Enabled: false,
			MatchConfigJSON: []byte(`{"regex":"@example\\.com"}`),
		},
		{
			ID: "unsafe", Name: "危险正则", RuleType: "regex",
			Severity: "high", Action: "block", Enabled: true,
			MatchConfigJSON: []byte(`{"regex":"(a+)+"}`),
		},
	}

	pack := Compile("tenant-a", rules, nil)

	if pack.Diagnostics.PendingCount != 2 {
		t.Fatalf("pending=%d, want 2", pack.Diagnostics.PendingCount)
	}
	if len(pack.Skipped) != 3 {
		t.Fatalf("skipped=%+v, want 3 details", pack.Skipped)
	}
	if pack.Skipped[0].ConfiguredMatcher {
		t.Fatal("capability catalog without matcher must not be customer pending")
	}
	if !pack.Skipped[1].ConfiguredMatcher || pack.Skipped[1].RuleName != "停用邮箱规则" || pack.Skipped[1].RuleType != "regex" {
		t.Fatalf("disabled configured rule detail=%+v", pack.Skipped[1])
	}
	if !pack.Skipped[2].ConfiguredMatcher || pack.Skipped[2].Reason != "unsafe_regex" {
		t.Fatalf("unsafe configured rule detail=%+v", pack.Skipped[2])
	}
}

func TestCompileDiagnosticsTrackPublishedCatalogWithoutChangingSemanticVersion(t *testing.T) {
	rules := make([]*repository.Rule, 0, 260)
	for i := 0; i < 255; i++ {
		rules = append(rules, &repository.Rule{
			ID: fmt.Sprintf("catalog_%03d", i), RuleType: "keyword", Name: fmt.Sprintf("目录能力 %03d", i),
			Severity: "medium", Action: "audit", Enabled: true, MatchConfigJSON: []byte(`{}`),
		})
	}
	for i := 0; i < 5; i++ {
		rules = append(rules, runtimeKeywordRule(fmt.Sprintf("runtime_%d", i)))
	}

	before := Compile("tenant-a", rules, nil)
	if before.Diagnostics.CatalogCount != 260 || before.Diagnostics.CompiledCount != 5 || before.Diagnostics.SkippedCount != 255 {
		t.Fatalf("260-candidate baseline diagnostics=%+v", before.Diagnostics)
	}
	if got := before.Diagnostics.SkipReasons["no_supported_matcher"]; got != 255 {
		t.Fatalf("no_supported_matcher=%d, want 255", got)
	}

	rules[0].Action = "block"
	rules[0].Severity = "critical"
	displayOnly := Compile("tenant-a", rules, nil)
	if displayOnly.Version != before.Version {
		t.Fatalf("non-executable catalog display fields changed semantic version: %q != %q", displayOnly.Version, before.Version)
	}

	rules[0].MatchConfigJSON = []byte(`{"keywords":["activated"]}`)
	afterMatcher := Compile("tenant-a", rules, nil)
	if afterMatcher.Diagnostics.CatalogCount != 260 || afterMatcher.Diagnostics.CompiledCount != 6 || afterMatcher.Diagnostics.SkippedCount != 254 {
		t.Fatalf("activated matcher diagnostics=%+v", afterMatcher.Diagnostics)
	}
	if got := afterMatcher.Diagnostics.SkipReasons["no_supported_matcher"]; got != 254 {
		t.Fatalf("no_supported_matcher=%d, want 254", got)
	}
	if afterMatcher.Version == displayOnly.Version {
		t.Fatalf("adding an executable matcher must change semantic version: %q", afterMatcher.Version)
	}
}

func TestContentVersionIgnoresDiagnosticsWarningsAndDegradedState(t *testing.T) {
	pack := Compile("tenant-a", []*repository.Rule{runtimeKeywordRule("rule_ok")}, nil)
	want := pack.Version

	pack.Diagnostics.CatalogCount = 999
	pack.Diagnostics.CompiledCount = 998
	pack.Diagnostics.SkippedCount = 1
	pack.Diagnostics.SkipReasons["synthetic"] = 1
	pack.Warnings = []string{"规则源暂时不可用，使用最近一次成功快照"}
	pack.Degraded = true

	if got := ContentVersion(pack); got != want {
		t.Fatalf("diagnostic-only fields must not change content version: got %q want %q", got, want)
	}
}

func TestCompileCapsSkippedDetailsButKeepsExactDiagnostics(t *testing.T) {
	rules := make([]*repository.Rule, 0, 250)
	for i := 0; i < 250; i++ {
		rules = append(rules, &repository.Rule{
			ID: fmt.Sprintf("catalog-cap-%03d", i), RuleType: "keyword", Name: "catalog",
			Action: "audit", Enabled: true, MatchConfigJSON: []byte(`{}`),
		})
	}
	pack := Compile("tenant-cap", rules, nil)
	if pack.Diagnostics.SkippedCount != 250 || pack.Diagnostics.SkipReasons["no_supported_matcher"] != 250 {
		t.Fatalf("diagnostic totals must remain exact: %+v", pack.Diagnostics)
	}
	if len(pack.Skipped) != maxSkippedRuleDetails || !pack.Diagnostics.SkippedTruncated {
		t.Fatalf("skipped details must be bounded: details=%d diagnostics=%+v", len(pack.Skipped), pack.Diagnostics)
	}
}

func TestCompileCapsExceptionSkipDetailsWithoutPollutingRuleTotals(t *testing.T) {
	exceptions := make([]*repository.ContentAuditException, 0, 250)
	for i := 0; i < 250; i++ {
		exceptions = append(exceptions, &repository.ContentAuditException{ID: fmt.Sprintf("exception-cap-%03d", i), Enabled: true, Decision: "block"})
	}
	pack := Compile("tenant-cap", nil, exceptions)
	if pack.Diagnostics.CatalogCount != 0 || pack.Diagnostics.SkippedCount != 0 || len(pack.Diagnostics.SkipReasons) != 0 {
		t.Fatalf("exception skips polluted rule diagnostics: %+v", pack.Diagnostics)
	}
	if len(pack.Skipped) != maxSkippedRuleDetails || !pack.Diagnostics.SkippedTruncated {
		t.Fatalf("exception detail cap missing: details=%d diagnostics=%+v", len(pack.Skipped), pack.Diagnostics)
	}
}

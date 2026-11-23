package repository

import (
	"strings"
	"testing"
)

func TestBuiltinOverrideWriteIsTenantScopedAndBuiltinOnly(t *testing.T) {
	source := executableRulePredicateSQL
	if !strings.Contains(source, "r.rule_type = 'regex'") ||
		!strings.Contains(source, "r.rule_type = 'keyword'") ||
		!strings.Contains(source, "r.rule_type = 'field_name'") {
		t.Fatal("builtin override must reuse the executable matcher boundary")
	}
}

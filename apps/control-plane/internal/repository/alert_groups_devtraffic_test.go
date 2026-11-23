package repository

import (
	"strings"
	"testing"
)

func TestExplicitDevelopmentScopeToggle(t *testing.T) {
	a, _, err := buildAlertGroupPageWhere(AlertGroupListFilter{TenantID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := buildAlertGroupPageWhere(AlertGroupListFilter{TenantID: "t1", IncludeDevTraffic: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b)+1 || strings.Contains(strings.Join(a, " "), "agent_type") {
		t.Fatal("toggle must add only trusted-scope predicate")
	}
}

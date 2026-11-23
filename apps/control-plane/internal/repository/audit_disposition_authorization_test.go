package repository

import (
	"strings"
	"testing"
)

func TestAuditDispositionSessionAuthorizationRequiresEveryMemberInScope(t *testing.T) {
	query, err := buildAuditDispositionSubjectAuthorizationQuery("session", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"cl.tenant_id = $1", "cl.session_id = $2", "rl.project_id = ANY($3)",
		"NOT EXISTS", "rl.project_id IS NULL OR NOT",
	} {
		if !strings.Contains(query, required) {
			t.Fatalf("session authorization missing %q: %s", required, query)
		}
	}
}

func TestAuditDispositionAuthorizationQueriesAreTenantScoped(t *testing.T) {
	for _, subjectType := range []string{"request", "security_event", "tool_call"} {
		query, err := buildAuditDispositionSubjectAuthorizationQuery(subjectType, false)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(query, "tenant_id = $1") {
			t.Fatalf("%s query is not tenant scoped: %s", subjectType, query)
		}
	}
}

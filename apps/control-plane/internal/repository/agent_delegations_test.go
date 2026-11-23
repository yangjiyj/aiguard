package repository

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAgentDelegationGrantCeilingPreservesScopeConditionsExpiryAndQuota(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	parent := AgentAuthorizationGrant{ID: "parent-grant", Action: "tickets.update", ResourceType: "ticket", ResourceID: "ticket-7",
		Conditions: map[string]any{"project_id": "project-a", "environment": "staging"}, ExpiresAt: now.Add(12 * time.Hour), QuotaMax: 8, QuotaWindowSeconds: 60}
	child := AgentAuthorizationGrant{Action: parent.Action, ResourceType: parent.ResourceType, ResourceID: parent.ResourceID,
		Conditions: map[string]any{"project_id": "project-a", "environment": "staging", "approval": "required"},
		ExpiresAt:  now.Add(2 * time.Hour), QuotaMax: 3, QuotaWindowSeconds: 300}
	if err := validateDelegatedGrantCeiling(parent, child, "project-a", now.Add(3*time.Hour), now); err != nil {
		t.Fatalf("narrower project grant should pass: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*AgentAuthorizationGrant)
	}{
		{"different action", func(v *AgentAuthorizationGrant) { v.Action = "tickets.delete" }},
		{"different resource", func(v *AgentAuthorizationGrant) { v.ResourceID = "ticket-other" }},
		{"project escape", func(v *AgentAuthorizationGrant) { v.Conditions["project_id"] = "project-b" }},
		{"removed parent condition", func(v *AgentAuthorizationGrant) { delete(v.Conditions, "environment") }},
		{"weakened parent condition", func(v *AgentAuthorizationGrant) { v.Conditions["environment"] = "production" }},
		{"quota max expansion", func(v *AgentAuthorizationGrant) { v.QuotaMax = 9 }},
		{"quota window multiplication", func(v *AgentAuthorizationGrant) { v.QuotaWindowSeconds = 30 }},
		{"grant outlives delegation", func(v *AgentAuthorizationGrant) { v.ExpiresAt = now.Add(4 * time.Hour) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := child
			candidate.Conditions = map[string]any{}
			for k, v := range child.Conditions {
				candidate.Conditions[k] = v
			}
			tc.mutate(&candidate)
			if err := validateDelegatedGrantCeiling(parent, candidate, "project-a", now.Add(3*time.Hour), now); err == nil {
				t.Fatal("expanded delegation was accepted")
			}
		})
	}
}

func TestAgentDelegationInputRejectsCallerGrantIDsAndInvalidProjects(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	input := AgentDelegationCreate{Name: "child", ProjectID: "project-a", ExpiresAt: now.Add(3 * time.Hour), AuthorizationIdempotencyKey: "authorize-delegate-0001", IdempotencyKey: "create-delegate-0001",
		Grants: []AgentAuthorizationGrant{{Action: "tickets.update", ResourceType: "ticket", ResourceID: "ticket-7", Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: now.Add(2 * time.Hour), QuotaMax: 2, QuotaWindowSeconds: 60}}}
	if err := validateDelegationInput(input, now); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
	input.Grants[0].ID = "caller-chosen"
	if err := validateDelegationInput(input, now); err == nil {
		t.Fatal("client grant id accepted")
	}
	input.Grants[0].ID = ""
	input.ProjectID = "*"
	if err := validateDelegationInput(input, now); err == nil {
		t.Fatal("wildcard project accepted")
	}
}

func TestDelegatedProjectBindingAndAuditIdentifiers(t *testing.T) {
	request := AgentAuthorizationRequest{}
	if !bindDelegatedProject(&request, "project-a") || request.Context["project_id"] != "project-a" {
		t.Fatalf("project was not server bound: %#v", request.Context)
	}
	request.Context["project_id"] = "project-b"
	if bindDelegatedProject(&request, "project-a") {
		t.Fatal("caller supplied cross-project context accepted")
	}
	if got := stringContextField(map[string]any{"run_id": "run/17 space-ok"}, "run_id"); got != "run/17 space-ok" {
		t.Fatalf("safe run id lost: %q", got)
	}
	for _, value := range []any{"bad\nid", strings.Repeat("x", 257), 42} {
		if got := stringContextField(map[string]any{"tool_call_id": value}, "tool_call_id"); got != "" {
			t.Errorf("unsafe audit id %v persisted as %q", value, got)
		}
	}
	if got := stringContextField(map[string]any{"instance_id": strings.Repeat("x", 256)}, "instance_id"); len(got) != 256 {
		t.Fatalf("maximal valid correlation id was truncated: len=%d", len(got))
	}
}

func TestAgentDelegationMigrationAndAuthorizeKeepTenantScopedCascadeAndQuota(t *testing.T) {
	migration, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "migrations", "874_agent_delegation_lifecycle.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(migration))
	for _, required := range []string{"agent_delegations", "authorization_idempotency_key", "unique (tenant_id, parent_principal_id, authorization_idempotency_key)", "unique (tenant_id, child_principal_id)", "agent_delegation_grants", "agent_delegation_calls", "foreign key (tenant_id, delegation_id, parent_principal_id, child_principal_id)", "foreign key (tenant_id, child_principal_id, child_grant_id)", "idx_agent_delegation_calls_investigation"} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration missing invariant %q", required)
		}
	}
	source, err := os.ReadFile("agent_authorization.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"lockAgentDelegationChain", "lockAgentDelegationHierarchy(ctx, tx, tenantID, principalID)", "revokeDelegationSubtree(ctx, tx, tenantID, principalID)", "SAVEPOINT agent_delegation_quota", "ROLLBACK TO SAVEPOINT agent_delegation_quota", "recordAgentDelegationCalls", "m.child_grant_id=g.id"} {
		if !strings.Contains(string(source), required) {
			t.Errorf("authorization path missing delegation invariant %q", required)
		}
	}
	delegations, err := os.ReadFile("agent_delegations.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"WHERE tenant_id=$1 AND parent_principal_id=$2 AND delegation_id=$3", "lockAgentDelegationHierarchy(ctx, tx, tenantID, parentID)", "revokeDelegationSubtree(ctx, tx, tenantID, childID)", "authorization_idempotency_key", "WITH RECURSIVE descendants", "run_id", "instance_id", "tool_call_id"} {
		if !strings.Contains(string(delegations), required) {
			t.Errorf("delegation repository missing %q", required)
		}
	}
}

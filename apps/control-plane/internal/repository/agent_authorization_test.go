package repository

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validAgentPrincipalCreate(now time.Time) AgentAuthorizationPrincipalCreate {
	expiry := now.Add(24 * time.Hour)
	return AgentAuthorizationPrincipalCreate{
		Name: "worker-a", CreatedBy: "admin-a", ExpiresAt: expiry,
		Grants: []AgentAuthorizationGrant{{
			Action: "records.read", ResourceType: "record", ResourceID: "record-17",
			Conditions: map[string]any{"environment": "staging"},
			ExpiresAt:  expiry.Add(-time.Hour), QuotaMax: 2, QuotaWindowSeconds: 60,
		}},
	}
}

func TestAgentAuthorizationPrincipalValidation(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	if err := ValidateAgentAuthorizationPrincipalCreate(validAgentPrincipalCreate(now), now); err != nil {
		t.Fatalf("valid registration rejected: %v", err)
	}
	noGrant := validAgentPrincipalCreate(now)
	noGrant.Grants = nil
	if err := ValidateAgentAuthorizationPrincipalCreate(noGrant, now); err != nil {
		t.Fatalf("empty grants must be a valid default-deny principal: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*AgentAuthorizationPrincipalCreate)
	}{
		{"wildcard resource", func(v *AgentAuthorizationPrincipalCreate) { v.Grants[0].ResourceID = "*" }},
		{"expired grant", func(v *AgentAuthorizationPrincipalCreate) { v.Grants[0].ExpiresAt = now }},
		{"grant outlives principal", func(v *AgentAuthorizationPrincipalCreate) { v.Grants[0].ExpiresAt = v.ExpiresAt.Add(time.Second) }},
		{"unbounded quota", func(v *AgentAuthorizationPrincipalCreate) { v.Grants[0].QuotaMax = 0 }},
		{"oversized window", func(v *AgentAuthorizationPrincipalCreate) { v.Grants[0].QuotaWindowSeconds = 86401 }},
		{"identity condition", func(v *AgentAuthorizationPrincipalCreate) {
			v.Grants[0].Conditions = map[string]any{"tenant_id": "other-tenant"}
		}},
		{"duplicate action resource", func(v *AgentAuthorizationPrincipalCreate) { v.Grants = append(v.Grants, v.Grants[0]) }},
		{"principal expiry too long", func(v *AgentAuthorizationPrincipalCreate) { v.ExpiresAt = now.Add(366 * 24 * time.Hour) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validAgentPrincipalCreate(now)
			test.mutate(&value)
			if err := ValidateAgentAuthorizationPrincipalCreate(value, now); err == nil {
				t.Fatal("invalid registration accepted")
			}
		})
	}
}

func TestAgentAuthorizationRequestValidationRejectsIdentityAndReplayAmbiguity(t *testing.T) {
	valid := AgentAuthorizationRequest{
		Action: "records.read", ResourceType: "record", ResourceID: "record-17",
		Context: map[string]any{"environment": "staging"}, IdempotencyKey: "request-2026-0001",
	}
	if err := ValidateAgentAuthorizationRequest(valid); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*AgentAuthorizationRequest)
	}{
		{"caller principal id", func(v *AgentAuthorizationRequest) { v.Context = map[string]any{"principal_id": "attacker"} }},
		{"caller tenant id", func(v *AgentAuthorizationRequest) { v.Context = map[string]any{"tenant_id": "other-tenant"} }},
		{"wildcard resource", func(v *AgentAuthorizationRequest) { v.ResourceID = "*" }},
		{"short idempotency key", func(v *AgentAuthorizationRequest) { v.IdempotencyKey = "short" }},
		{"nested condition context", func(v *AgentAuthorizationRequest) {
			v.Context = map[string]any{"environment": map[string]any{"name": "staging"}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			test.mutate(&value)
			if err := ValidateAgentAuthorizationRequest(value); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestAgentAuthorizationConditionsAreExactAndDefaultDeny(t *testing.T) {
	required := map[string]any{"environment": "staging", "change_window": true}
	if !agentAuthorizationConditionsMatch(required, map[string]any{"environment": "staging", "change_window": true, "trace": "x"}) {
		t.Fatal("matching required context rejected")
	}
	if agentAuthorizationConditionsMatch(required, map[string]any{"environment": "prod", "change_window": true}) {
		t.Fatal("mismatched context accepted")
	}
	if agentAuthorizationConditionsMatch(required, map[string]any{"environment": "staging"}) {
		t.Fatal("missing required context accepted")
	}
	if !agentAuthorizationConditionsMatch(nil, nil) {
		t.Fatal("empty condition set should match")
	}
}

func TestAgentAuthorizationSQLAndMigrationKeepAtomicTenantScopedSemantics(t *testing.T) {
	source, err := os.ReadFile("agent_authorization.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"FOR UPDATE",
		"ON CONFLICT (tenant_id, principal_id, idempotency_key)",
		"agent_authorization_requests.expires_at<=clock_timestamp()",
		"ON CONFLICT (tenant_id, principal_id, grant_id, window_start)",
		"agent_authorization_usage.used < $5",
		"WHERE id=$1 AND tenant_id=$2",
	} {
		if !strings.Contains(string(source), required) {
			t.Errorf("repository missing atomic authorization contract %q", required)
		}
	}
	migration, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "migrations", "861_trusted_agent_authorization.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(migration))
	for _, required := range []string{
		"agent_authorization_principals",
		"credential_hash char(64) not null unique",
		"unique (tenant_id, principal_id, action, resource_type, resource_id)",
		"quota_max bigint not null check",
		"primary key (tenant_id, principal_id, grant_id, window_start)",
		"primary key (tenant_id, principal_id, idempotency_key)",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration missing %q", required)
		}
	}
}

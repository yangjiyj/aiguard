package retentionartifact

import (
	"os"
	"strings"
	"testing"
)

func TestRetainedArtifactMigrationContract(t *testing.T) {
	body, err := os.ReadFile("../../../deploy/migrations/144_retained_artifacts.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	migration := strings.ToLower(string(body))
	for _, required := range []string{
		"create table if not exists retained_artifacts",
		"create table if not exists access_content_artifact_links",
		"references tenants(id)",
		"references request_logs(request_id)",
		"references retained_artifacts(id)",
		"retention_status",
		"check (retention_status in",
		"tenant_id, provider, source_reference_hash",
		"tenant_id, request_id, direction, ordinal",
		"unique (tenant_id, request_id, artifact_id, direction)",
	} {
		if !strings.Contains(migration, required) {
			t.Fatalf("migration missing %q", required)
		}
	}
	for _, forbidden := range []string{"base64", "remote_url", "reference_id", "local_path"} {
		if strings.Contains(migration, forbidden) {
			t.Fatalf("migration must not persist %q", forbidden)

		}
	}
}
func TestArtifactRepositorySQLIsTenantScopedAndIdempotent(t *testing.T) {
	for _, statement := range []string{artifactUpsertSQL, artifactLinkSQL, artifactReferenceLookupSQL} {
		lower := strings.ToLower(statement)
		if !strings.Contains(lower, "tenant_id") {
			t.Fatalf("repository SQL must scope tenant: %s", statement)
		}
	}
	if !strings.Contains(strings.ToLower(artifactUpsertSQL), "on conflict") ||
		!strings.Contains(strings.ToLower(artifactLinkSQL), "on conflict") {
		t.Fatal("replayed artifact and link writes must be idempotent")
	}
	for _, statement := range []string{artifactUpsertSQL, artifactLinkSQL} {
		lower := strings.ToLower(statement)
		if !strings.Contains(lower, "select environment_scope from request_logs") {
			t.Fatalf("artifact writes must inherit the owning request scope: %s", statement)
		}
		if !strings.Contains(lower, "tenant_id = $2::varchar(64)") ||
			!strings.Contains(lower, "request_id = $3::varchar(64)") {
			t.Fatalf("request scope lookup parameters must have one PostgreSQL type: %s", statement)
		}
	}
	if !strings.Contains(artifactUpsertSQL, "retained_artifacts.retention_status = 'retained'") ||
		!strings.Contains(artifactUpsertSQL, "EXCLUDED.retention_status = 'retained'") ||
		!strings.Contains(artifactUpsertSQL, "THEN COALESCE(EXCLUDED.original_object_key, retained_artifacts.original_object_key)") ||
		!strings.Contains(artifactUpsertSQL, "THEN EXCLUDED.preview_object_key") {
		t.Fatal("a fresh retained copy must replace stale retained object keys")
	}
	if !strings.Contains(artifactUpsertSQL, "EXCLUDED.retention_status <> 'retained'") ||
		!strings.Contains(artifactUpsertSQL, "THEN retained_artifacts.original_object_key") ||
		!strings.Contains(artifactUpsertSQL, "THEN retained_artifacts.preview_object_key") {
		t.Fatal("a later reference-only replay must not downgrade retained bytes")
	}
	if !strings.Contains(artifactUpsertSQL, "THEN COALESCE(EXCLUDED.retention_until, retained_artifacts.retention_until)") ||
		!strings.Contains(artifactUpsertSQL, "THEN retained_artifacts.retention_until") {
		t.Fatal("retained object expiry must follow the selected object key, not a later reference call")
	}
	lowerLookup := strings.ToLower(artifactReferenceLookupSQL)
	if !strings.Contains(lowerLookup, "environment_scope = $3") ||
		!strings.Contains(lowerLookup, "source_reference_hash = $4") {
		t.Fatal("reference lookup identity must be tenant/provider/environment/hash scoped")
	}
	if !strings.Contains(strings.ToLower(artifactUpsertSQL), "retained_artifacts.environment_scope = excluded.environment_scope") {
		t.Fatal("artifact id conflicts must fail closed across environment scopes")
	}
}

func TestNormalizeEnvironmentScopeDefaultsAndRejectsUnknown(t *testing.T) {
	for input, want := range map[string]string{
		"":                  LegacyEnvironmentScope,
		" CUSTOMER ":        "customer",
		"codex":             "codex",
		"workspace-spoofed": LegacyEnvironmentScope,
	} {
		if got := NormalizeEnvironmentScope(input); got != want {
			t.Fatalf("NormalizeEnvironmentScope(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestResolveEnvironmentScopeKeepsTrustedDeploymentBoundary(t *testing.T) {
	tests := []struct {
		name, explicit, deployment, want string
	}{
		{name: "deployment wins", explicit: "home", deployment: "customer", want: "customer"},
		{name: "explicit without boundary", explicit: "home", deployment: LegacyEnvironmentScope, want: "home"},
		{name: "invalid explicit without boundary", explicit: "from-header", want: LegacyEnvironmentScope},
		{name: "blank", want: LegacyEnvironmentScope},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveEnvironmentScope(tt.explicit, tt.deployment); got != tt.want {
				t.Fatalf("ResolveEnvironmentScope(%q,%q)=%q, want %q", tt.explicit, tt.deployment, got, tt.want)
			}
		})
	}
}

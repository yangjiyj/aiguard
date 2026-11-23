package principal

import (
	"strings"
	"testing"
)

func TestNormalizeKeepsKeyOwnerSeparateFromUnknownActor(t *testing.T) {
	ctx, err := Normalize(Context{
		TenantID: " tenant-a ", ProjectID: " app-a ", KeyID: " key-a ",
		KeyOwnerUserID: " owner-a ", KeyOwnerDepartmentIDs: []string{"dept-b", "dept-a", "dept-a"},
		Protocol: " OpenAI ", EntryPoint: " API ", IdentitySource: SourceAPIKey, TrustLevel: TrustKeyBound,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ctx.ActorUserID != "" || ctx.KeyOwnerUserID != "owner-a" {
		t.Fatalf("owner was promoted to actor: %+v", ctx)
	}
	if ctx.ProjectID != "app-a" || ctx.ApplicationID != "app-a" {
		t.Fatalf("project/application alias not normalized: %+v", ctx)
	}
	if got := strings.Join(ctx.KeyOwnerDepartmentIDs, ","); got != "dept-a,dept-b" {
		t.Fatalf("department IDs not canonical: %q", got)
	}
	if ctx.Protocol != "openai" || ctx.EntryPoint != "api" || ctx.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("protocol/version not normalized: %+v", ctx)
	}
}

func TestValidateRejectsUntrustedActorClaimsWithoutLeakingValues(t *testing.T) {
	secret := "actor-secret-value"
	_, err := Normalize(Context{
		TenantID: "tenant-a", ActorUserID: secret, ActorDepartmentIDs: []string{"dept-a"},
		IdentitySource: SourceForwardProxy, TrustLevel: TrustUnknown,
	})
	if err == nil {
		t.Fatal("unknown principal accepted actor claims")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("validation error leaked principal value: %v", err)
	}
}

func TestNormalizeRejectsConflictingProjectAndApplication(t *testing.T) {
	_, err := Normalize(Context{
		TenantID: "tenant-a", ProjectID: "project-a", ApplicationID: "project-b",
		IdentitySource: SourceAPIKey, TrustLevel: TrustKeyBound,
	})
	if err == nil {
		t.Fatal("conflicting application identity accepted")
	}
}
func TestWithModelStampsCopy(t *testing.T) {
	base := Context{SchemaVersion: CurrentSchemaVersion, TenantID: "tenant-a", KeyID: "key-1", IdentitySource: SourceAPIKey, TrustLevel: TrustKeyBound}
	stamped := WithModel(base, " gpt-5.5 ")
	if stamped.ModelID != "gpt-5.5" {
		t.Fatalf("model id not trimmed: %q", stamped.ModelID)
	}
	if base.ModelID != "" {
		t.Fatalf("receiver mutated: %q", base.ModelID)
	}
	if got := WithModel(base, "   "); got.ModelID != "" {
		t.Fatalf("empty model should not stamp: %q", got.ModelID)
	}
	if err := stamped.Validate(); err != nil {
		t.Fatalf("stamped context invalid: %v", err)
	}
}

package identityruntime

import (
	"fmt"
	"io"
	"log"
	"strings"
	"testing"
)

func testDesiredIdentitySource(t *testing.T) DesiredIdentitySource {
	t.Helper()
	desired := DesiredIdentitySource{
		Realm: RealmName, Alias: ProviderAlias, DisplayName: "企业账号",
		Endpoints: DiscoveryEndpoints{
			Issuer:        "https://idp.example.com",
			Authorization: "https://idp.example.com/authorize",
			Token:         "https://idp.example.com/token",
			JWKS:          "https://idp.example.com/jwks",
			UserInfo:      "https://idp.example.com/userinfo",
			EndSession:    "https://idp.example.com/logout",
		},
		ClientID: "client-a", ClientSecret: "secret-a",
		Scopes: []string{"openid", "profile", "email"},
		ClaimMappings: []ClaimMapping{
			{Name: "department", Claim: "department_code", UserAttribute: "department_code"},
			{Name: "groups", Claim: "groups", UserAttribute: "groups"},
		},
	}
	digest, err := ComputeDesiredDigest(desired)
	if err != nil {
		t.Fatal(err)
	}
	desired.Digest = digest
	return desired
}

func TestComputeDesiredDigestIsCanonicalAndSecretSensitive(t *testing.T) {
	first := testDesiredIdentitySource(t)
	second := first
	second.Digest = ""
	second.Scopes = []string{"email", "openid", "profile"}
	second.ClaimMappings = []ClaimMapping{first.ClaimMappings[1], first.ClaimMappings[0]}
	digest, err := ComputeDesiredDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if digest != first.Digest {
		t.Fatalf("canonical digest mismatch: %s != %s", digest, first.Digest)
	}

	second.ClientSecret = "secret-b"
	changed, err := ComputeDesiredDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if changed == first.Digest {
		t.Fatal("secret rotation must change digest")
	}
	if strings.Contains(first.Digest, first.ClientSecret) || !strings.HasPrefix(first.Digest, "sha256:") {
		t.Fatalf("unsafe digest=%q", first.Digest)
	}
}

func TestValidateDesiredRejectsRuntimeCoordinateOverride(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	desired.Realm = "master"
	if err := ValidateDesired(desired); err == nil {
		t.Fatal("realm override must be rejected")
	}
	desired = testDesiredIdentitySource(t)
	desired.Alias = "customer-controlled"
	if err := ValidateDesired(desired); err == nil {
		t.Fatal("alias override must be rejected")
	}
}

func TestSensitiveTypesRedactFormattedCredentials(t *testing.T) {
	cfg, err := LoadConfig(ConfigInput{
		PublicURL: "https://sso.example.com", RuntimeURL: "http://chat-idp:8180/sso",
		ClientID: "svc", ClientSecret: "service-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	desired := testDesiredIdentitySource(t)
	provider := desiredProvider(desired, desired.Digest)
	snapshot := RuntimeSnapshot{
		Realm: RealmName, Alias: ProviderAlias, Exists: true,
		Provider: provider, Mappers: []MapperRepresentation{managedMapper(desired.Alias, desired.ClaimMappings[0])},
	}
	client, err := NewClient(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	publication := Publication{Digest: desired.Digest, Previous: snapshot}
	formatted := fmt.Sprintf("%+v %#v %+v %#v %+v %#v %+v %#v %+v %#v",
		cfg, cfg, desired, desired, provider, provider, snapshot, client, publication, publication)
	for _, secret := range []string{"service-secret", desired.ClientSecret} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("formatted value leaked %q: %s", secret, formatted)
		}
	}
}

func TestValidateDesiredRequiresOpenIDScope(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	desired.Scopes = []string{"profile", "email"}
	if err := ValidateDesired(desired); err == nil {
		t.Fatal("openid scope is required")
	}
}

func TestRuntimeStructureDigestIgnoresUnmanagedMappers(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	provider := desiredProvider(desired, desired.Digest)
	managed := []MapperRepresentation{managedMapper(desired.Alias, desired.ClaimMappings[0])}

	expected, err := computeRuntimeStructureDigest(provider, managed)
	if err != nil {
		t.Fatal(err)
	}
	withUnmanaged := append(append([]MapperRepresentation(nil), managed...), MapperRepresentation{
		ID:                     "customer-managed-group-mapper",
		Name:                   "customer-managed-group-mapper",
		IdentityProviderAlias:  ProviderAlias,
		IdentityProviderMapper: "oidc-advanced-group-idp-mapper",
		Config: map[string]string{
			"claims": "[{\"key\":\"groups\",\"value\":\"research\"}]",
		},
	})
	actual, err := computeRuntimeStructureDigest(provider, withUnmanaged)
	if err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatal("unmanaged mapper changed the managed runtime structure digest")
	}
}
